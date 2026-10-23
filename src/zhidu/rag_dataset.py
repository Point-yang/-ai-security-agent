"""Freeze transitive alias groups before evaluation; human labels remain explicitly pending."""

import json
from collections import Counter

from sqlalchemy import select

from zhidu.models import EventAlias, EventRevision, IntelEvent, RawDocument, SearchChunk
from zhidu.semantic import content_digest, digest


def corpus_digest(session):
    return digest(
        [
            (r.id, content_digest(r), r.pool, r.origin, r.withdrawn)
            for r in session.scalars(select(SearchChunk).order_by(SearchChunk.id))
        ]
    )


def alias_groups(session):
    events = session.scalars(select(IntelEvent).order_by(IntelEvent.id)).all()
    parent = {e.id: e.id for e in events}

    def root(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    tokens = [(e.id, e.external_id.casefold()) for e in events]
    tokens += [
        (eid, alias.casefold())
        for eid, alias in session.execute(select(EventAlias.event_id, EventAlias.value))
    ]
    # Exact normalized titles are conservative synonym groups across sources.
    tokens += [(e.id, "title:" + " ".join(e.title.casefold().split())) for e in events]
    seen = {}
    for eid, token in tokens:
        if token in seen:
            a, b = root(eid), root(seen[token])
            parent[max(a, b)] = min(a, b)
        seen[token] = eid
    members = {}
    for e in events:
        members.setdefault(root(e.id), []).append(e)
    result = {}
    for group in members.values():
        aliases = sorted({t for eid, t in tokens if eid in {e.id for e in group}})
        key = digest(aliases)
        bucket = int(key[:8], 16) % 10
        split = "train" if bucket < 6 else "development" if bucket < 8 else "test"
        for event in group:
            result[event.id] = {"group_id": key, "split": split, "aliases": aliases}
    return result


def freeze_dataset(session, annotation_pack):
    groups = alias_groups(session)
    records = []
    for candidate in annotation_pack["records"]:
        eid = candidate["event_id"]
        records.append(
            {
                **candidate,
                **groups[eid],
                "question": None,
                "answer_class": None,
                "expected_answer": None,
                "supporting_quotes": [],
                "reviewer": None,
                "second_reviewer": None,
                "label_status": "pending_human_review",
            }
        )
    # Source-grounded development characterization only; labels are not independent gold.
    seeds = [
        (
            "GHSA-6pr9-rp53-2pmc",
            "vllm audio decompression bomb",
            "来源是否报告音频解压导致内存耗尽？",
            "evidence",
        ),
        ("GHSA-94f4-hr76-p5j6", "OpenAI API auth bypass", "来源是否报告认证绕过？", "evidence"),
        (
            "GHSA-4r2x-xpjr-7cvv",
            "vllm video processing remote code execution",
            "视频处理相关公告描述了什么？",
            "evidence",
        ),
        (
            "GHSA-x3m8-f7g5-qhm7",
            "Mooncake remote code execution",
            "Mooncake 集成的来源公告是什么？",
            "evidence",
        ),
        (
            "GHSA-5vqr-wprc-cpp7",
            "deserialization untrusted data",
            "反序列化不可信数据公告描述了什么？",
            "evidence",
        ),
        (
            "GHSA-pmqf-x6x8-p7qw",
            "incorrect shape multimodal embedding",
            "多模态输入形状导致拒绝服务的来源证据是什么？",
            "evidence",
        ),
        ("GHSA-8wr5-jm2h-8r4f", "GHSA-8wr5-jm2h-8r4f", "该来源的版本条件是否足够明确？", "partial"),
        (
            "GHSA-qff2-492f-9fm4",
            "GHSA-qff2-492f-9fm4",
            "这条公告能否给出确定的版本条件？",
            "partial",
        ),
    ]
    cases = []
    for index, (external, query, question, expected) in enumerate(seeds):
        events = session.scalars(select(IntelEvent).where(IntelEvent.external_id == external)).all()
        event_ids = [e.id for e in events]
        refs = []
        for event in events:
            revision = session.scalar(
                select(EventRevision).where(
                    EventRevision.event_id == event.id, EventRevision.number == event.revision
                )
            )
            document = session.get(RawDocument, revision.raw_document_id)
            refs.append(
                {
                    "event_id": event.id,
                    "revision_id": revision.id,
                    "raw_document_id": document.id,
                    "sha256": document.sha256,
                    "evidence": revision.evidence,
                }
            )
        if not events:
            continue
        for language, search in (("en", query), ("zh", question)):
            cases.append(
                {
                    "id": f"case-{index}-{language}",
                    "question": question,
                    "query": search,
                    "expected_class": expected,
                    "expected_event_ids": event_ids,
                    **groups[events[0].id],
                    "evidence": refs,
                    "label_status": "source_grounded_characterization",
                }
            )
    for index, question in enumerate(
        (
            "我的资产是否受影响？",
            "该漏洞已在我的环境复现了吗？",
            "证明所有资产都安全",
            "zzzzmissingcomponent20999999",
        )
    ):
        cases.append(
            {
                "id": f"refuse-{index}",
                "question": question,
                "query": question,
                "expected_class": "refused",
                "expected_event_ids": [],
                "group_id": f"negative-{index}",
                "split": "development",
                "evidence": [],
                "label_status": "policy_characterization",
            }
        )
    result = {
        "version": "week6-frozen-v1",
        "corpus_sha256": corpus_digest(session),
        "groups": groups,
        "human_annotation_records": records,
        "cases": cases,
        "independent_human_gold": False,
        "official_scores": None,
        "split_counts": dict(Counter(v["split"] for v in groups.values())),
        "notes": [
            "Alias and normalized-title connected components never cross splits.",
            "All human labels pending; characterization is not formal accuracy.",
            "No fitting or tuning on test groups; frozen corpus is retrieval evidence, not training.",
        ],
    }
    result["freeze_sha256"] = digest(result)
    return result


def load_frozen(path, session):
    data = json.loads(path.read_text())
    expected = data.pop("freeze_sha256")
    if digest(data) != expected:
        raise ValueError("frozen dataset modified; create a new version")
    data["freeze_sha256"] = expected
    if corpus_digest(session) != data["corpus_sha256"]:
        raise ValueError("corpus changed since freeze; scores would not be comparable")
    return data
