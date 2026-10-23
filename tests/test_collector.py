import json
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import event, func, select

from zhidu.collector import CollectionError, GitHubCollector, collect
from zhidu.models import IntelEvent, SyncState

START = datetime(2025, 1, 1, tzinfo=UTC)
END = datetime(2026, 2, 1, tzinfo=UTC)


def test_live_collection_watermark_and_overlap(database, settings, advisory):
    seen = []

    def respond(request):
        seen.append(request)
        return httpx.Response(200, json=[advisory])

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        collector = GitHubCollector(settings, client, sleeper=lambda _: None)
        result = collect(database, settings, "example-ai-demo", since=START, collector=collector)
        assert result["status"] == "completed" and result["created"] == 1
        result2 = collect(database, settings, "example-ai-demo", collector=collector)
        assert result2["unchanged"] == 1
    assert seen[0].url.params["affects"] == "example-ai-demo"
    assert seen[0].url.params["ecosystem"] == "pip"
    with database() as session:
        assert session.scalar(select(SyncState)) is not None
    assert datetime.fromisoformat(result2["window_start"]) < datetime.fromisoformat(
        result["window_end"]
    )


def test_pagination_budget_does_not_advance_watermark(database, settings, advisory):
    def respond(request):
        return httpx.Response(
            200,
            json=[advisory],
            headers={
                "Link": '<https://api.github.com/advisories?after=next>; rel="next"',
            },
        )

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        result = collect(
            database,
            settings,
            "example-ai-demo",
            since=START,
            max_pages=1,
            collector=GitHubCollector(settings, client),
        )
    assert result["status"] == "partial" and result["created"] == 1
    with database() as session:
        assert session.scalar(select(SyncState)) is None


def test_failed_second_page_preserves_first_and_replay_is_safe(database, settings, advisory):
    def respond(request):
        if "after" in request.url.params:
            return httpx.Response(200, content=b'{"bad": true}')
        return httpx.Response(
            200,
            json=[advisory],
            headers={
                "Link": '<https://api.github.com/advisories?after=next>; rel="next"',
            },
        )

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        result = collect(
            database,
            settings,
            "example-ai-demo",
            since=START,
            collector=GitHubCollector(settings, client),
        )
    assert result["status"] == "failed" and result["pages"] == 1
    with database() as session:
        assert session.scalar(select(func.count()).select_from(IntelEvent)) == 1
        assert session.scalar(select(SyncState)) is None


def test_transient_error_retry(settings, advisory):
    attempts, sleeps = [], []

    def respond(request):
        attempts.append(1)
        return httpx.Response(503) if len(attempts) == 1 else httpx.Response(200, json=[advisory])

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        pages = list(
            GitHubCollector(settings, client, sleeps.append).pages("vllm", "pip", START, END, 2)
        )
    assert len(attempts) == 2 and len(pages) == 1 and sleeps == [1]
    assert json.loads(pages[0].content)[0]["ghsa_id"] == advisory["ghsa_id"]


def test_long_rate_limit_fails_without_waiting(database, settings):
    sleeps = []
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                429,
                headers={"Retry-After": "300"},
            )
        )
    ) as client:
        result = collect(
            database,
            settings,
            "vllm",
            since=START,
            collector=GitHubCollector(settings, client, sleeps.append),
        )
    assert result["status"] == "failed" and "rate limited" in result["error"]
    assert sleeps == []


def test_pagination_never_forwards_token_to_other_host(settings, advisory):
    calls = []

    def respond(request):
        calls.append(request.url.host)
        return httpx.Response(
            200,
            json=[advisory],
            headers={
                "Link": '<https://attacker.invalid/advisories>; rel="next"',
            },
        )

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(CollectionError, match="untrusted"):
            list(GitHubCollector(settings, client).pages("vllm", "pip", START, END, 2))
    assert calls == ["api.github.com"]


def test_failed_commit_does_not_inflate_success_counts(database, settings, advisory):
    commits = []

    def fail_page_commit(session):
        commits.append(1)
        if len(commits) == 2:
            raise RuntimeError("simulated commit failure")

    event.listen(database.class_, "before_commit", fail_page_commit)
    try:
        with httpx.Client(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=[advisory]))
        ) as client:
            result = collect(
                database,
                settings,
                "example-ai-demo",
                since=START,
                collector=GitHubCollector(settings, client),
            )
    finally:
        event.remove(database.class_, "before_commit", fail_page_commit)
    assert result["status"] == "failed"
    assert result["created"] == 0 and result["pages"] == 0
    with database() as session:
        assert session.scalar(select(func.count()).select_from(IntelEvent)) == 0
        assert session.scalar(select(SyncState)) is None
