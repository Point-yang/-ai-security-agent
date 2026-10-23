"""Persistent polling jobs, bounded requests, source health and restart recovery."""

import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode, urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from zhidu.classification import RULE_VERSION
from zhidu.collector import CollectionError, GitHubCollector, retry_delay
from zhidu.ingest import MAX_DOCUMENT_BYTES, ensure_source, ingest_document
from zhidu.locking import WriterBusy, writer_lock
from zhidu.models import CollectionRun, IntelEvent, MonitorState, RecoveryAction, SyncState, now_utc
from zhidu.observability import log_event
from zhidu.sources import SOURCES, prepare, relevant_records
from zhidu.storage import BlobStore


class CursorInvalidated(CollectionError):
    pass


NETWORK_RETRY_CAP_SECONDS = 1800


def failure_retry_seconds(target, failures, error):
    """Retry transport outages promptly; retain long backoff for HTTP/rate limits."""
    exponential = 60 * 2 ** min(failures, 10)
    if error and "network failure after 3 attempts" in error:
        return min(NETWORK_RETRY_CAP_SECONDS, exponential)
    return min(21600, max(target.interval_seconds, exponential))


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z0-9-]{1,100}$")
    source: str
    enabled: bool = True
    query: str = Field(default="vllm", min_length=1, max_length=200)
    ecosystem: str = "pip"
    interval_seconds: int = Field(default=1800, ge=60, le=86400)
    lookback_days: int = Field(default=30, ge=1, le=120)
    max_pages: int = Field(default=5, ge=1, le=100)
    page_size: int = Field(default=100, ge=1, le=100)
    publication_since: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")

    @model_validator(mode="after")
    def supported(self):
        if self.source not in SOURCES:
            raise ValueError("unknown source adapter")
        if self.publication_since:
            datetime.strptime(self.publication_since, "%Y-%m-%d")
        return self

    @property
    def fingerprint(self):
        # Changing query or adapter must never reuse another scope's cursor or HTTP validators.
        body = self.model_dump(exclude={"enabled", "interval_seconds", "max_pages"})
        body["pipeline_version"] = "adapters-v2:" + RULE_VERSION
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def load_targets(path: Path) -> list[Target]:
    config = json.loads(path.read_text())
    targets = [Target.model_validate(t) for t in config["targets"]]
    if len({t.id for t in targets}) != len(targets):
        raise ValueError("duplicate target id")
    return targets


class SourceHTTP:
    def __init__(self, settings, client=None, sleeper=time.sleep):
        self.settings = settings
        self.client = client
        self.sleeper = sleeper
        self.resume_url = None

    def request(self, client, source, url, validators=None):
        base = urlparse(SOURCES[source].base_url)
        target = urlparse(url)
        if (target.scheme, target.netloc, target.path) != (base.scheme, base.netloc, base.path):
            raise CollectionError("untrusted pagination destination")
        headers = {"Accept": "application/json", "User-Agent": "zhidu-intel/0.2.0"}
        if base.hostname == "api.github.com":
            headers["Accept"] = "application/vnd.github+json"
            headers["X-GitHub-Api-Version"] = self.settings.github_api_version
            if token := self.settings.github_token.get_secret_value():
                headers["Authorization"] = f"Bearer {token}"
        headers.update(validators or {})
        for attempt in range(3):
            try:
                with client.stream("GET", url, headers=headers) as response:
                    if response.status_code in {429, 500, 502, 503, 504} or (
                        response.status_code == 403
                        and (
                            "retry-after" in response.headers
                            or response.headers.get("x-ratelimit-remaining") == "0"
                        )
                    ):
                        delay = retry_delay(response, attempt)
                        if attempt == 2:
                            raise CollectionError(
                                f"{source}: HTTP {response.status_code} after retries"
                            )
                        self.sleeper(delay)
                        continue
                    if response.status_code not in {200, 304}:
                        if (
                            source == "crossref"
                            and self.resume_url
                            and response.status_code in {400, 404, 410}
                        ):
                            raise CursorInvalidated(
                                "Crossref continuation invalidated; restart the same window without advancing watermark"
                            )
                        raise CollectionError(f"{source}: HTTP {response.status_code}")
                    size, chunks = 0, []
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > MAX_DOCUMENT_BYTES:
                            raise CollectionError("source response exceeds 15 MiB")
                        chunks.append(chunk)
                    return (
                        response.status_code,
                        dict(response.headers),
                        b"".join(chunks),
                        response.links,
                    )
            except httpx.TransportError as exc:
                if attempt == 2:
                    raise CollectionError(
                        f"{source}: network failure after 3 attempts ({type(exc).__name__})"
                    ) from None
                self.sleeper(2**attempt)
        raise CollectionError("request failed")

    def pages(self, target, start, end, validators):
        if target.source == "github-advisories":
            for p in GitHubCollector(self.settings, self.client, self.sleeper).pages(
                target.query,
                target.ecosystem,
                start,
                end,
                target.max_pages,
                resume_url=self.resume_url,
            ):
                yield p.url, p.content, p.has_next, {}, False, p.next_url
            return
        source = target.source
        base = SOURCES[source].base_url

        def stamp(d):
            return d.astimezone(UTC).isoformat(timespec="seconds")

        if source == "nvd":
            params = {
                "keywordSearch": target.query,
                "lastModStartDate": stamp(start),
                "lastModEndDate": stamp(end),
                "resultsPerPage": target.page_size,
                "startIndex": 0,
            }
        elif source == "crossref":
            params = {
                "query.title": f'"{target.query}"',
                "sort": "score",
                "order": "desc",
                "filter": f"from-index-date:{start.date()},until-index-date:{end.date()}",
                "rows": target.page_size,
                "cursor": "*",
            }
        elif source == "vllm-vendor":
            params = {
                "state": "published",
                "per_page": target.page_size,
                "sort": "updated",
                "direction": "desc",
            }
        elif source == "federal-register-ai":
            params = {
                "conditions[term]": target.query,
                "per_page": min(target.page_size, 100),
                "order": "newest",
            }
        else:
            params = {}
        if source == "crossref" and target.publication_since:
            params["filter"] += f",from-pub-date:{target.publication_since}"
        url = self.resume_url or base + ("?" + urlencode(params) if params else "")
        own = self.client is None
        client = self.client or httpx.Client(timeout=30, follow_redirects=False)
        try:
            for page in range(target.max_pages):
                if page and source == "nvd":
                    self.sleeper(7)
                status, headers, content, links = self.request(
                    client,
                    source,
                    url,
                    validators if source == "cisa-kev" else {},
                )
                if status == 304:
                    if not validators:
                        raise CollectionError("unexpected 304 without stored validators")
                    yield url, b"", False, headers, True
                    return
                if source in {"hf-blog", "nist-ai-rmf", "federal-register-ai", "nuclei-cves"}:
                    # Metadata sources are bounded to one provider page per run;
                    # NDJSON is preserved as bytes, never passed to json.loads.
                    yield url, content, False, headers, False, None
                    return
                data = json.loads(content)
                next_url = None
                if source == "vllm-vendor":
                    next_url = links.get("next", {}).get("url")
                elif source == "nvd":
                    rows = data["vulnerabilities"]
                    offset = data["startIndex"] + len(rows)
                    if offset < data["totalResults"]:
                        if not rows:
                            raise CollectionError("NVD pagination made no progress")
                        params["startIndex"] = offset
                        next_url = base + "?" + urlencode(params)
                elif source == "crossref":
                    message = data["message"]
                    if len(message["items"]) == target.page_size:
                        cursor = message.get("next-cursor")
                        if cursor:
                            params["cursor"] = cursor
                            next_url = base + "?" + urlencode(params)
                yield url, content, bool(next_url), headers, False, next_url
                if not next_url:
                    return
                url = next_url
        finally:
            if own:
                client.close()


def sync_target(sessions, settings, target, *, transport=None, clock=now_utc):
    """Must run under writer_lock. Earlier successful pages survive later failures."""
    started = clock()
    scope = f"monitor:{target.id}:{target.fingerprint[:16]}"
    with sessions.begin() as session:
        spec = SOURCES[target.source]
        ensure_source(session, spec)
        state = session.get(MonitorState, target.id)
        if state is None:
            state = MonitorState(
                target_id=target.id, config_hash=target.fingerprint, next_run_at=started
            )
            session.add(state)
            session.flush()
        if state.status == "running" and state.last_run_id:
            previous = session.get(CollectionRun, state.last_run_id)
            if previous and previous.status == "running":
                previous.status, previous.error, previous.finished_at = (
                    "interrupted",
                    "previous worker exited before completion",
                    started,
                )
                session.add(
                    RecoveryAction(
                        action_type="restart_interrupted_collection",
                        target_id=target.id,
                        status="completed",
                        occurred_at=started,
                        detail={"previous_run_id": previous.id, "watermark_advanced": False},
                    )
                )
        if state.config_hash != target.fingerprint:
            state.config_hash, state.etag, state.last_modified = target.fingerprint, None, None
            state.last_success_at, state.failures = None, 0
            state.continuation = None
        cursor = session.get(SyncState, scope)
        start = (
            cursor.watermark - timedelta(days=1)
            if cursor
            else started - timedelta(days=target.lookback_days)
        )
        # NVD accepts bounded windows; catch up in slices, never discard the older backlog.
        end = min(start + timedelta(days=119), started) if target.source == "nvd" else started
        continuation = state.continuation
        if continuation:
            start = datetime.fromisoformat(continuation["start"])
            end = datetime.fromisoformat(continuation["end"])
        validators = {}
        if state.etag:
            validators["If-None-Match"] = state.etag
        if state.last_modified:
            validators["If-Modified-Since"] = state.last_modified
        run = CollectionRun(source_id=spec.id, scope=scope, started_at=started)
        session.add(run)
        session.flush()
        run_id = run.id
        state.status, state.last_run_id = "running", run_id
        state.heartbeat_at = started
    stats = dict(
        pages=0,
        observed=0,
        filtered=0,
        records=0,
        created=0,
        updated=0,
        unchanged=0,
        stale=0,
        conflict=0,
        not_modified=0,
    )
    status, error, last_next, http_headers = "completed", None, False, {}
    cursor_invalidated = False
    http = transport or SourceHTTP(settings)
    if isinstance(http, SourceHTTP):
        http.resume_url = continuation["url"] if continuation else None
    try:
        for page_data in http.pages(target, start, end, validators):
            url, content, has_next, headers, unchanged, *remaining = page_data
            next_url = remaining[0] if remaining else None
            if unchanged:
                stats["not_modified"] += 1
                http_headers = headers
                continue
            if target.source in {"hf-blog", "nist-ai-rmf", "federal-register-ai", "nuclei-cves"}:
                from zhidu.catalog import ingest_catalog

                with sessions.begin() as session:
                    result = ingest_catalog(
                        session,
                        BlobStore(settings.raw_dir),
                        content,
                        source_id=target.source,
                        url=url,
                        fetched_at=clock(),
                        origin="live",
                    )
                    session.get(MonitorState, target.id).continuation = None
                    session.get(MonitorState, target.id).heartbeat_at = clock()
                for key in ("created", "updated", "unchanged"):
                    stats[key] += result[key]
                stats["records"] += result["observed"]
                stats["observed"] += result["observed"]
                stats["pages"] += 1
                last_next, http_headers = False, headers
                continue
            prepared, observed = prepare(target.source, content)
            selected = relevant_records(prepared)
            # A changed/withdrawn advisory must still update an already tracked event,
            # even if its new text no longer matches the AI keywords.
            with sessions() as session:
                known = set(
                    session.scalars(
                        select(IntelEvent.external_id).where(IntelEvent.source_id == spec.id)
                    ).all()
                )
            selected_ids = {r.normalized["external_id"] for r in selected}
            selected += [r for r in prepared if r.normalized["external_id"] in known - selected_ids]
            with sessions.begin() as session:
                result = ingest_document(
                    session,
                    BlobStore(settings.raw_dir),
                    content,
                    url,
                    clock(),
                    "live",
                    spec=spec,
                    prepared=selected,
                )
                session.get(MonitorState, target.id).continuation = (
                    {"start": start.isoformat(), "end": end.isoformat(), "url": next_url}
                    if has_next and next_url
                    else None
                )
                session.get(MonitorState, target.id).heartbeat_at = clock()
            for key in ("records", "created", "updated", "unchanged", "stale", "conflict"):
                stats[key] += result[key]
            stats["pages"] += 1
            stats["observed"] += observed
            stats["filtered"] += observed - len(selected)
            last_next, http_headers = has_next, headers
        if last_next:
            status, error = "partial", "page limit reached; watermark and validators not advanced"
    except Exception as exc:
        cursor_invalidated = isinstance(exc, CursorInvalidated)
        status = "failed"
        error = (
            str(exc)
            if isinstance(exc, CollectionError)
            else f"{type(exc).__name__}: source parsing or storage failed"
        )
    finished = clock()
    with sessions.begin() as session:
        state = session.get(MonitorState, target.id)
        run = session.get(CollectionRun, run_id)
        run.status, run.error, run.stats, run.finished_at = status, error, stats, finished
        state.status = status
        state.heartbeat_at = finished
        if status == "completed":
            state.continuation = None
            state.failures, state.last_success_at = 0, finished
            cursor = session.get(SyncState, scope)
            if cursor is None:
                session.add(SyncState(scope=scope, watermark=end))
            else:
                cursor.watermark = max(cursor.watermark, end)
            if target.source == "cisa-kev":
                state.etag = (
                    http_headers.get("etag", state.etag)
                    if stats["not_modified"]
                    else http_headers.get("etag")
                )
                state.last_modified = (
                    http_headers.get("last-modified", state.last_modified)
                    if stats["not_modified"]
                    else http_headers.get("last-modified")
                )
            delay = target.interval_seconds
        elif status == "partial":
            # Drain a bounded backlog promptly instead of waiting for the normal
            # polling interval. Provider-invalidated cursors are handled separately.
            delay = 30
        else:
            state.failures += 1
            delay = failure_retry_seconds(target, state.failures, error)
            if cursor_invalidated:
                state.continuation = {
                    "start": start.isoformat(),
                    "end": end.isoformat(),
                    "url": None,
                }
                delay = 60
        state.next_run_at = finished + timedelta(seconds=delay)
    log_event(
        "collection_finished",
        target=target.id,
        run_id=run_id,
        status=status,
        seconds=(finished - started).total_seconds(),
        pages=stats["pages"],
        records=stats["records"],
    )
    return {"target": target.id, "run_id": run_id, "status": status, "error": error, **stats}


def run_due(sessions, settings, targets, force=False, transport=None):
    results = []
    with writer_lock(settings.database_url):
        for target in targets:
            if not target.enabled:
                continue
            with sessions() as session:
                state = session.get(MonitorState, target.id)
                due = (
                    not state
                    or state.config_hash != target.fingerprint
                    or state.status == "running"
                    or state.next_run_at <= now_utc()
                )
            if force or due:
                results.append(sync_target(sessions, settings, target, transport=transport))
    return results


def resilient_cycle(sessions, settings, targets, **kwargs):
    """Transient database/lock failures are retried by the next bounded service cycle."""
    try:
        return run_due(sessions, settings, targets, **kwargs)
    except (WriterBusy, SQLAlchemyError) as exc:
        log_event("monitor_retry", error_type=type(exc).__name__)
        return [{"target": "scheduler", "status": "failed", "error": type(exc).__name__}]
