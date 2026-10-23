import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import urlencode, urlparse

import httpx
from sqlalchemy import select

from zhidu.config import Settings
from zhidu.ingest import SOURCE_ID, ensure_source, ingest_document
from zhidu.models import CollectionRun, SyncState, now_utc
from zhidu.storage import BlobStore


class CollectionError(Exception):
    pass


@dataclass
class Page:
    content: bytes
    url: str
    fetched_at: datetime
    has_next: bool
    next_url: str | None = None


def check_url(url: str):
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "api.github.com"
        or parsed.path != "/advisories"
        or parsed.fragment
    ):
        raise CollectionError("refused untrusted pagination URL")


def retry_delay(response: httpx.Response, attempt: int) -> float:
    retry_after = response.headers.get("retry-after")
    if retry_after:
        try:
            delay = float(retry_after)
        except ValueError:
            try:
                delay = (parsedate_to_datetime(retry_after) - now_utc()).total_seconds()
            except (TypeError, ValueError):
                delay = 2**attempt
    elif response.headers.get("x-ratelimit-remaining") == "0":
        try:
            delay = float(response.headers["x-ratelimit-reset"]) - time.time() + 1
        except (ValueError, KeyError):
            delay = 60
    else:
        delay = 2**attempt
    if delay > 30:
        raise CollectionError("rate limited; retry later (watermark remains unchanged)")
    return max(0, delay)


class GitHubCollector:
    def __init__(
        self, settings: Settings, client: httpx.Client | None = None, sleeper: Callable = time.sleep
    ):
        self.settings, self.client, self.sleeper = settings, client, sleeper

    def pages(
        self,
        package: str,
        ecosystem: str,
        start: datetime,
        end: datetime,
        max_pages: int,
        resume_url=None,
    ):
        def stamp(value):
            return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")

        params = {
            "affects": package,
            "ecosystem": ecosystem,
            "per_page": 100,
            "sort": "updated",
            "direction": "asc",
            "type": "reviewed",
            "modified": f"{stamp(start)}..{stamp(end)}",
        }
        url = resume_url or "https://api.github.com/advisories?" + urlencode(params)
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.settings.github_api_version,
            "User-Agent": "zhidu-intel/0.1.0",
        }
        token = self.settings.github_token.get_secret_value()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        own_client = self.client is None
        client = self.client or httpx.Client(timeout=30, follow_redirects=False)
        try:
            for _ in range(max_pages):
                check_url(url)
                response = None
                for attempt in range(3):
                    try:
                        response = client.get(url, headers=headers)
                    except httpx.TransportError as exc:
                        if attempt == 2:
                            raise CollectionError(
                                f"network failure after 3 attempts ({type(exc).__name__})"
                            ) from None
                        self.sleeper(2**attempt)
                        continue
                    if response.status_code in {429, 500, 502, 503, 504} or (
                        response.status_code == 403
                        and (
                            response.headers.get("x-ratelimit-remaining") == "0"
                            or "retry-after" in response.headers
                        )
                    ):
                        delay = retry_delay(response, attempt)
                        if attempt == 2:
                            raise CollectionError(
                                f"GitHub HTTP {response.status_code} after retries"
                            )
                        self.sleeper(delay)
                        continue
                    if response.status_code != 200:
                        raise CollectionError(
                            f"GitHub HTTP {response.status_code}; no data committed for this page"
                        )
                    break
                next_url = response.links.get("next", {}).get("url")
                if next_url:
                    check_url(next_url)
                yield Page(response.content, str(response.url), now_utc(), bool(next_url), next_url)
                if not next_url:
                    return
                url = next_url
        finally:
            if own_client:
                client.close()


def collect(
    sessions,
    settings: Settings,
    package: str,
    ecosystem: str = "pip",
    since: datetime | None = None,
    max_pages: int = 10,
    collector: GitHubCollector | None = None,
) -> dict:
    if not package.strip() or len(package) > 400 or not 1 <= max_pages <= 100:
        raise ValueError("invalid package or max_pages")
    end = now_utc()
    scope = f"{SOURCE_ID}:{ecosystem}:{package}"
    with sessions.begin() as session:
        ensure_source(session)
        state = session.get(SyncState, scope)
        start = since or (
            state.watermark - timedelta(minutes=10) if state else end - timedelta(days=30)
        )
        if start.tzinfo is None or start >= end:
            raise ValueError("since must be a past timestamp with timezone")
        run = CollectionRun(source_id=SOURCE_ID, scope=scope, started_at=end)
        session.add(run)
        session.flush()
        run_id = run.id
    totals = dict(pages=0, records=0, created=0, updated=0, unchanged=0, stale=0, conflict=0)
    status, error = "completed", None
    try:
        last_has_next = False
        for page in (collector or GitHubCollector(settings)).pages(
            package,
            ecosystem,
            start,
            end,
            max_pages,
        ):
            with sessions.begin() as session:
                result = ingest_document(
                    session,
                    BlobStore(settings.raw_dir),
                    page.content,
                    page.url,
                    page.fetched_at,
                    "live",
                )
            # Count only committed pages; a failed DB commit must not inflate run metrics.
            for key in totals:
                if key != "pages":
                    totals[key] += result[key]
            totals["pages"] += 1
            last_has_next = page.has_next
        if last_has_next:
            status = "partial"
            error = "page budget reached; watermark unchanged; rerun with a larger --max-pages"
    except Exception as exc:
        status = "failed"
        # Do not persist arbitrary upstream payloads, request headers, or token-bearing exceptions.
        error = (
            str(exc)
            if isinstance(exc, CollectionError)
            else f"{type(exc).__name__}: page ingestion failed"
        )
    with sessions.begin() as session:
        run = session.get(CollectionRun, run_id)
        run.status, run.error, run.stats, run.finished_at = status, error, totals, now_utc()
        if status == "completed":
            state = session.scalar(
                select(SyncState).where(SyncState.scope == scope).with_for_update()
            )
            if state is None:
                session.add(SyncState(scope=scope, watermark=end))
            else:
                state.watermark = max(state.watermark, end)
    return {
        "run_id": run_id,
        "status": status,
        "error": error,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        **totals,
    }
