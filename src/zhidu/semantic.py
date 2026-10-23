"""Local ONNX embeddings: immutable model digest, current-chunk joins, no hidden fallback."""

import hashlib
import json
import math
import multiprocessing as mp
import os
import threading
import time
from pathlib import Path

from sqlalchemy import select

from zhidu.indexing import chunk_view
from zhidu.models import ChunkEmbedding, EventRevision, IntelEvent, SearchChunk
from zhidu.query_policy import plan_query, relevant_hits
from zhidu.retrieval import RetrievalHit, rank_chunks


class ModelUnavailable(RuntimeError):
    pass


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()


def content_digest(row):
    return digest([row.revision_id, row.sha256, row.json_pointer, row.start, row.end, row.text])


def model_manifest(settings, *, verify=False):
    try:
        data = json.loads(settings.embedding_manifest.read_text())
        if data["model"] != settings.embedding_model:
            raise ValueError("model configuration changed")
        root = Path(data["path"])
        for name, expected in data["files"].items():
            path = root / name
            if not path.is_file() or (
                verify and hashlib.sha256(path.read_bytes()).hexdigest() != expected
            ):
                raise ValueError("model file missing or modified")
        if digest(data["files"]) != data["digest"]:
            raise ValueError("manifest digest mismatch")
        return data
    except (OSError, KeyError, ValueError) as exc:
        raise ModelUnavailable("本地 embedding 模型暂不可用，请先准备模型文件。") from exc


def prepare_model(settings, model_path=None):
    # Only this explicit CLI operation is allowed to download model artifacts.
    from fastembed import TextEmbedding

    settings.embedding_cache.mkdir(parents=True, exist_ok=True)
    options = (
        {"specific_model_path": str(model_path), "local_files_only": True} if model_path else {}
    )
    model = TextEmbedding(
        settings.embedding_model, cache_dir=str(settings.embedding_cache), threads=2, **options
    )
    vector = list(model.embed(["security evidence"]))[0]
    root = Path(model.model._model_dir).resolve()
    files = {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file() and ".cache" not in p.parts
    }
    data = {
        "model": settings.embedding_model,
        "path": str(root),
        "files": files,
        "digest": digest(files),
        "dimension": len(vector),
        "engine": "fastembed-0.7.4",
    }
    settings.embedding_manifest.write_text(json.dumps(data, indent=2) + "\n")
    return data


def _worker(pipe, manifest):
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    try:
        from fastembed import TextEmbedding

        model = TextEmbedding(
            manifest["model"],
            specific_model_path=manifest["path"],
            local_files_only=True,
            threads=2,
        )
        while True:
            texts = pipe.recv()
            pipe.send({"vectors": [v.tolist() for v in model.embed(texts, batch_size=16)]})
    except EOFError:
        pass
    except Exception as exc:
        pipe.send({"error": type(exc).__name__})
    finally:
        pipe.close()


class LocalEncoder:
    """One serialized process; timeout kills inference, not a leaked background thread."""

    def __init__(self, settings):
        self.settings = settings
        self.lock = threading.Lock()
        self.process = self.pipe = None
        self.key = None

    def close(self):
        if self.process is not None:
            self.process.terminate()
            self.process.join(timeout=0.2)
            self.process = None
        if self.pipe is not None:
            self.pipe.close()
            self.pipe = None

    def encode(self, texts, timeout=15):
        deadline = time.monotonic() + timeout
        if not self.lock.acquire(timeout=max(0, timeout)):
            raise TimeoutError("embedding queue timeout")
        try:
            manifest = model_manifest(self.settings, verify=self.process is None)
            if self.key != manifest["digest"]:
                self.close()
            if self.process is None:
                parent, child = mp.get_context("spawn").Pipe()
                self.process = mp.get_context("spawn").Process(
                    target=_worker, args=(child, manifest), daemon=True
                )
                self.process.start()
                child.close()
                self.pipe, self.key = parent, manifest["digest"]
            self.pipe.send(texts)
            if not self.pipe.poll(max(0, deadline - time.monotonic())):
                self.close()
                raise TimeoutError("embedding inference timeout")
            reply = self.pipe.recv()
            if "error" in reply:
                self.close()
                raise ModelUnavailable("本地 embedding 推理失败。")
            return reply["vectors"]
        except (EOFError, BrokenPipeError) as exc:
            self.close()
            raise ModelUnavailable("本地 embedding 进程不可用。") from exc
        finally:
            self.lock.release()


def active_chunks(session, *, pool="formal", origin="live", event_id=None):
    stmt = (
        select(SearchChunk)
        .join(IntelEvent, IntelEvent.id == SearchChunk.event_id)
        .join(EventRevision, EventRevision.id == SearchChunk.revision_id)
        .where(
            IntelEvent.revision == SearchChunk.revision_number,
            EventRevision.disposition == "current",
            EventRevision.event_id == IntelEvent.id,
            EventRevision.number == SearchChunk.revision_number,
            IntelEvent.withdrawn_at.is_(None),
            SearchChunk.withdrawn.is_(False),
            SearchChunk.pool == pool,
            SearchChunk.origin == origin,
        )
    )
    if event_id:
        stmt = stmt.where(SearchChunk.event_id == event_id)
    return session.scalars(stmt.order_by(SearchChunk.id)).all()


def sync_embeddings(session, settings, encoder):
    manifest = model_manifest(settings)
    rows = session.scalars(select(SearchChunk).order_by(SearchChunk.id)).all()
    changed = 0
    for start in range(0, len(rows), 32):
        pending = []
        for row in rows[start : start + 32]:
            stored = session.get(ChunkEmbedding, row.id)
            if (
                stored is None
                or stored.model_key != manifest["digest"]
                or stored.content_sha256 != content_digest(row)
            ):
                pending.append(row)
        if not pending:
            continue
        vectors = encoder.encode([r.text for r in pending], timeout=120)
        for row, vector in zip(pending, vectors, strict=True):
            if len(vector) != manifest["dimension"] or not all(math.isfinite(x) for x in vector):
                raise ModelUnavailable("invalid embedding vector")
            session.merge(
                ChunkEmbedding(
                    chunk_id=row.id,
                    model_key=manifest["digest"],
                    content_sha256=content_digest(row),
                    vector=vector,
                )
            )
            changed += 1
    session.flush()
    return {
        "model": manifest["model"],
        "model_digest": manifest["digest"],
        "dimension": manifest["dimension"],
        "chunks": len(rows),
        "changed": changed,
    }


def retrieve(
    session,
    query,
    mode,
    settings,
    encoder,
    *,
    pool="formal",
    origin="live",
    event_id=None,
    limit=40,
    min_score=0.35,
    timeout=15,
    query_rewrite=False,
    relevance_gate=False,
):
    plan = plan_query(session, query) if relevance_gate or query_rewrite else None
    original_query = query
    if plan and query_rewrite and mode != "lexical":
        query = plan.search_text
    policy_meta = {"query_policy": plan.metadata()} if plan else {}
    if (
        plan
        and relevance_gate
        and (
            (plan.unresolved and not plan.anchored_event_ids and not event_id)
            or (plan.ambiguous and not event_id)
        )
    ):
        return [], {
            "mode": mode,
            "scanned_chunks": 0,
            "embedding_calls": 0,
            "reason": "unknown_entity_or_missing_context",
            **policy_meta,
        }
    rows = active_chunks(session, pool=pool, origin=origin, event_id=event_id)
    if plan and plan.anchored_event_ids:
        # Scope before both lexical and dense ranking. Filtering only after
        # top-k fusion lets unrelated dense hits displace exact-ID evidence.
        rows = [row for row in rows if row.event_id in plan.anchored_event_ids]
    views = {row.id: chunk_view(row) for row in rows}
    lexical = rank_chunks(list(views.values()), query)
    if mode == "lexical":
        if plan and relevance_gate:
            lexical = relevant_hits(session, lexical, plan, explicit_event_id=event_id)
        return lexical[:limit], {
            "mode": mode,
            "scanned_chunks": len(rows),
            "embedding_calls": 0,
            **policy_meta,
        }
    manifest = model_manifest(settings)
    embeddings = {
        r.chunk_id: r
        for r in session.scalars(
            select(ChunkEmbedding).where(ChunkEmbedding.model_key == manifest["digest"])
        )
    }
    valid = {
        r.id: embeddings[r.id]
        for r in rows
        if r.id in embeddings
        and embeddings[r.id].content_sha256 == content_digest(r)
        and len(embeddings[r.id].vector) == manifest["dimension"]
    }
    if len(valid) != len(rows):
        raise ModelUnavailable("语义索引未覆盖当前版本，请执行 semantic-sync。")
    query_vector = encoder.encode([query], timeout=timeout)[0]
    if len(query_vector) != manifest["dimension"] or not all(
        math.isfinite(v) for v in query_vector
    ):
        raise ModelUnavailable("query embedding dimension or values invalid")
    import numpy as np

    keys = sorted(valid)
    if not keys:
        return [], {"mode": mode, "scanned_chunks": 0, "embedding_calls": 1}
    matrix = np.asarray([valid[key].vector for key in keys], dtype=np.float32)
    q = np.asarray(query_vector, dtype=np.float32)
    scores = matrix @ q / np.maximum(np.linalg.norm(matrix, axis=1) * np.linalg.norm(q), 1e-12)
    if not np.isfinite(scores).all():
        raise ModelUnavailable("invalid semantic score")
    cosine = dict(zip(keys, scores.tolist(), strict=True))
    dense = sorted(
        (key for key in keys if cosine[key] >= min_score), key=lambda k: (-cosine[k], k)
    )[:limit]
    # Reciprocal-rank fusion followed by an explicit, versioned relevance reranker.
    fused = {}
    for ranking in ([h.chunk_id for h in lexical[:limit]], dense):
        for rank, key in enumerate(ranking, 1):
            fused[key] = fused.get(key, 0) + 1 / (60 + rank)
    reranked = sorted(fused, key=lambda k: (-(fused[k] + 0.02 * max(0, cosine[k])), k))
    hits = [
        RetrievalHit(
            **views[k].model_dump(),
            score=round(fused[k] + 0.02 * max(0, cosine[k]), 6),
            matched_terms=[],
        )
        for k in reranked[:limit]
    ]
    if plan and relevance_gate:
        hits = relevant_hits(session, hits, plan, explicit_event_id=event_id)
    return hits, {
        **policy_meta,
        "original_query": original_query,
        "mode": mode,
        "scanned_chunks": len(rows),
        "embedding_calls": 1,
        "model": manifest["model"],
        "model_digest": manifest["digest"],
        "reranker": "rrf60-cosine-v1",
        "threshold": min_score,
    }
