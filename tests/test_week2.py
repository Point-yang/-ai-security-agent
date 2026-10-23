import copy
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from zhidu.api import create_app
from zhidu.classification import classify
from zhidu.locking import WriterBusy, writer_lock
from zhidu.models import CollectionRun, EventRevision, IntelEvent, MonitorState, SyncState
from zhidu.monitor import SourceHTTP, Target, load_targets, run_due, sync_target
from zhidu.sources import SOURCES, prepare, resolve_pointer

NOW = datetime(2026, 9, 19, tzinfo=UTC)


def fixtures(advisory):
    ghsa = copy.deepcopy(advisory)
    ghsa["summary"] = "vLLM security vulnerability"
    ghsa["vulnerabilities"][0]["package"]["name"] = "vllm"
    nvd = {
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": ghsa["cve_id"],
                    "published": "2026-01-01T08:00:00.000",
                    "lastModified": "2026-01-02T08:00:00.000",
                    "descriptions": [{"lang": "en", "value": "vLLM has a security vulnerability."}],
                    "metrics": {},
                    "references": [],
                    "vulnStatus": "Analyzed",
                }
            }
        ],
    }
    kev = {
        "dateReleased": "2026-09-18T00:00:00Z",
        "vulnerabilities": [
            {
                "cveID": ghsa["cve_id"],
                "vulnerabilityName": "vLLM vulnerability",
                "shortDescription": "vLLM security vulnerability under exploitation.",
                "dateAdded": "2026-09-17",
                "requiredAction": "Apply vendor update.",
            }
        ],
    }
    crossref = {
        "message": {
            "items": [
                {
                    "DOI": "10.1234/ai-test",
                    "title": ["Prompt injection in large language models"],
                    "abstract": "<jats:p>AI security study.</jats:p>",
                    "published": {"date-parts": [[2026, 9]]},
                    "indexed": {"date-time": "2026-09-18T00:00:00Z"},
                    "created": {"date-time": "2026-09-01T00:00:00Z"},
                }
            ]
        }
    }
    return {
        "github-advisories": [ghsa],
        "vllm-vendor": [ghsa],
        "nvd": nvd,
        "cisa-kev": kev,
        "crossref": crossref,
    }


class Pages:
    def __init__(self, content, more=False, headers=None, unchanged=False):
        self.content, self.more, self.headers, self.unchanged = (
            content,
            more,
            headers or {},
            unchanged,
        )
        self.windows = []

    def pages(self, target, start, end, validators):
        self.windows.append((start, end, validators))
        yield SOURCES[target.source].base_url, self.content, self.more, self.headers, self.unchanged


@pytest.mark.parametrize(
    "source", ["github-advisories", "vllm-vendor", "nvd", "cisa-kev", "crossref"]
)
def test_all_adapters_preserve_b_citations(source, database, settings, store, advisory):
    data = fixtures(advisory)[source]
    content = json.dumps(data).encode()
    target = Target(id="test", source=source)
    result = sync_target(database, settings, target, transport=Pages(content), clock=lambda: NOW)
    assert result["status"] == "completed", result
    assert result["created"] == 1
    with TestClient(create_app(settings)) as client:
        event = client.get("/api/v1/events").json()["items"][0]
        chunks = client.get(f"/api/v1/retrieval/events/{event['id']}").json()
        assert chunks
        for chunk in chunks:
            citation = chunk["citation"]
            raw = client.get(f"/api/v1/raw-documents/{citation['raw_document_id']}/content")
            assert raw.content == content
            value = resolve_pointer(raw.json(), citation["json_pointer"])
            text = (
                value
                if isinstance(value, str)
                else json.dumps(value, ensure_ascii=False, sort_keys=True)
            )
            assert text[chunk["start"] : chunk["end"]] == chunk["text"]
        detail = client.get(f"/api/v1/events/{event['id']}").json()
        assert detail["triage"]["label"] in ["relevant", "needs_review"]
        if source == "crossref":
            assert event["kind"] == "paper"
            assert detail["current_revision"]["normalized"]["publication_precision"] == "month"


def test_source_records_are_linked_without_merging(database, settings, store, advisory):
    data = fixtures(advisory)
    for source in ["github-advisories", "vllm-vendor", "nvd"]:
        sync_target(
            database,
            settings,
            Target(id=source, source=source),
            transport=Pages(json.dumps(data[source]).encode()),
            clock=lambda: NOW,
        )
    with TestClient(create_app(settings)) as client:
        events = client.get("/api/v1/events").json()["items"]
        assert len(events) == 3
        related = client.get(f"/api/v1/events/{events[0]['id']}/related").json()["items"]
        assert len(related) == 2
        assert all(not x["independent_confirmation"] for x in related)
        assert client.get("/api/v1/events", params={"source_id": "nvd"}).json()["total"] == 1


def test_paper_unknown_publication_date_is_not_invented(advisory):
    data = fixtures(advisory)["crossref"]
    data["message"]["items"][0].pop("published")
    record = prepare("crossref", json.dumps(data).encode())[0][0]
    assert record.normalized["publication_precision"] == "registration_fallback"
    assert record.fields["published_at"].endswith("/created/date-time")


def test_rule_classifier_does_not_confuse_electrical_transformers(advisory):
    from zhidu.ingest import normalize
    from zhidu.schemas import AdvisoryInput

    record = normalize(AdvisoryInput.model_validate(advisory))
    record.update(title="Electrical transformers in a power grid", description="", packages=[])
    assert classify(record)["label"] == "unrelated"
    record["title"] = "Prompt injection methods"
    assert classify(record)["label"] == "needs_review"
    record["description"] = "Security of large language models"
    assert classify(record)["label"] == "relevant"


def test_filter_retains_changed_existing_events(database, settings, advisory):
    data = fixtures(advisory)["github-advisories"]
    target = Target(id="ghsa-test", source="github-advisories")
    assert (
        sync_target(
            database,
            settings,
            target,
            transport=Pages(json.dumps(data).encode()),
            clock=lambda: NOW,
        )["created"]
        == 1
    )
    data[0].update(
        summary="Record withdrawn",
        description="",
        vulnerabilities=[],
        updated_at="2026-09-18T00:00:00Z",
        withdrawn_at="2026-09-18T00:00:00Z",
    )
    result = sync_target(
        database, settings, target, transport=Pages(json.dumps(data).encode()), clock=lambda: NOW
    )
    assert result["updated"] == 1
    with database() as session:
        assert session.scalar(select(IntelEvent)).withdrawn_at is not None


def test_partial_keeps_watermark_and_validators(database, settings, advisory):
    content = json.dumps(fixtures(advisory)["cisa-kev"]).encode()
    target = Target(id="kev", source="cisa-kev")
    result = sync_target(
        database,
        settings,
        target,
        transport=Pages(content, more=True, headers={"etag": "bad"}),
        clock=lambda: NOW,
    )
    assert result["status"] == "partial"
    with database() as session:
        assert session.scalar(select(SyncState)) is None
        state = session.get(MonitorState, "kev")
        assert state.etag is None and state.failures == 0 and state.next_run_at > NOW


def test_etag_304_reuses_content_without_empty_document(database, settings, advisory):
    content = json.dumps(fixtures(advisory)["cisa-kev"]).encode()
    target = Target(id="kev", source="cisa-kev")
    sync_target(
        database,
        settings,
        target,
        transport=Pages(content, headers={"etag": "one"}),
        clock=lambda: NOW,
    )
    transport = Pages(b"", unchanged=True)
    result = sync_target(
        database, settings, target, transport=transport, clock=lambda: NOW + timedelta(hours=1)
    )
    assert result["not_modified"] == 1 and result["created"] == 0
    assert transport.windows[0][2] == {"If-None-Match": "one"}
    with database() as session:
        assert session.scalar(select(func.count()).select_from(EventRevision)) == 1


def test_config_change_resets_cursor_and_validators(database, settings, advisory):
    content = json.dumps(fixtures(advisory)["cisa-kev"]).encode()
    target = Target(id="kev", source="cisa-kev")
    sync_target(
        database,
        settings,
        target,
        transport=Pages(content, headers={"etag": "one"}),
        clock=lambda: NOW,
    )
    target.query = "new-scope"
    transport = Pages(content)
    sync_target(
        database, settings, target, transport=transport, clock=lambda: NOW + timedelta(days=1)
    )
    assert transport.windows[0][2] == {}
    assert transport.windows[0][0] == NOW + timedelta(days=1 - target.lookback_days)


def test_failed_source_does_not_block_other_jobs(database, settings, advisory):
    data = fixtures(advisory)

    class Mixed:
        def pages(self, target, *args):
            if target.id == "failed":
                raise httpx.ConnectError("upstream failed")
            yield (
                SOURCES[target.source].base_url,
                json.dumps(data[target.source]).encode(),
                False,
                {},
                False,
            )

    targets = [Target(id="failed", source="nvd"), Target(id="ok", source="github-advisories")]
    results = run_due(database, settings, targets, transport=Mixed())
    assert [r["status"] for r in results] == ["failed", "completed"]
    assert run_due(database, settings, targets, transport=Mixed()) == []


def test_interrupted_run_recovers_under_writer_lock(database, settings, advisory):
    target = Target(id="test", source="github-advisories")
    transport = Pages(json.dumps(fixtures(advisory)["github-advisories"]).encode())
    result = sync_target(database, settings, target, transport=transport, clock=lambda: NOW)
    with database.begin() as session:
        session.get(MonitorState, "test").status = "running"
        session.get(CollectionRun, result["run_id"]).status = "running"
    new = run_due(database, settings, [target], transport=transport)
    assert new[0]["unchanged"] == 1
    with database() as session:
        assert session.get(CollectionRun, result["run_id"]).status == "interrupted"


def test_writer_lock_prevents_duplicate_workers(settings):
    with writer_lock(settings.database_url), pytest.raises(WriterBusy):
        with writer_lock(settings.database_url):
            pass


def test_source_http_keeps_credentials_on_github_only(settings):
    requests = []

    def response(req):
        requests.append(req)
        return httpx.Response(200, json={"message": {"items": []}})

    with httpx.Client(transport=httpx.MockTransport(response)) as client:
        transport = SourceHTTP(settings, client)
        list(
            transport.pages(
                Target(id="papers", source="crossref"), NOW - timedelta(days=1), NOW, {}
            )
        )
        assert "authorization" not in requests[0].headers
        with pytest.raises(Exception, match="untrusted"):
            transport.request(client, "crossref", "https://example.org/works")


def test_duplicate_target_rejected(tmp_path):
    path = tmp_path / "sources.json"
    path.write_text(json.dumps({"targets": [{"id": "same", "source": "nvd"}] * 2}))
    with pytest.raises(ValueError, match="duplicate"):
        load_targets(path)


def test_vendor_missing_package_metadata_and_patched_range(advisory):
    data = fixtures(advisory)["vllm-vendor"]
    v = data[0]["vulnerabilities"][0]
    v["package"] = {"name": "", "ecosystem": ""}
    v.pop("first_patched_version", None)
    v["patched_versions"] = ">= 1.2.0, < 2.0.0"
    records, _ = prepare("vllm-vendor", json.dumps(data).encode())
    normalized = records[0].normalized
    assert normalized["packages"][0]["ecosystem"] == "unknown"
    assert normalized["packages"][0]["name"] == "unknown"
    assert normalized["packages"][0]["fixed_version"] is None
    assert normalized["vendor_patched_ranges"] == [">= 1.2.0, < 2.0.0"]
    assert resolve_pointer(data, records[0].fields["packages"])[0]["package"]["name"] == ""


def test_crossref_resumes_partial_page_with_fixed_window(database, settings, advisory):
    requests = []
    data = fixtures(advisory)["crossref"]
    data["message"]["next-cursor"] = "second-page"

    def respond(req):
        requests.append(req)
        if req.url.params["cursor"] == "second-page":
            return httpx.Response(200, json={"message": {"items": []}})
        return httpx.Response(200, json=data)

    target = Target(id="papers", source="crossref", max_pages=1, page_size=1)
    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        transport = SourceHTTP(settings, client)
        first = sync_target(database, settings, target, transport=transport, clock=lambda: NOW)
        assert first["status"] == "partial" and first["created"] == 1
        with database() as session:
            assert session.get(MonitorState, "papers").continuation["end"] == NOW.isoformat()
            assert session.scalar(select(SyncState)) is None
        second = sync_target(
            database, settings, target, transport=transport, clock=lambda: NOW + timedelta(hours=1)
        )
    assert requests[1].url.params["cursor"] == "second-page"
    assert requests[1].url.params["filter"] == requests[0].url.params["filter"]
    assert second["status"] == "completed" and second["created"] == 0
    with database() as session:
        assert session.get(MonitorState, "papers").continuation is None
        assert session.scalar(select(SyncState)).watermark == NOW


def test_nvd_resume_does_not_reset_offset(database, settings, advisory):
    requested = []
    page = fixtures(advisory)["nvd"]
    page["totalResults"] = 2

    def respond(req):
        requested.append(int(req.url.params["startIndex"]))
        body = copy.deepcopy(page)
        body["startIndex"] = requested[-1]
        return httpx.Response(200, json=body)

    target = Target(id="nvd", source="nvd", max_pages=1, page_size=1)
    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        transport = SourceHTTP(settings, client, sleeper=lambda _: None)
        assert (
            sync_target(database, settings, target, transport=transport, clock=lambda: NOW)[
                "status"
            ]
            == "partial"
        )
        assert (
            sync_target(database, settings, target, transport=transport, clock=lambda: NOW)[
                "status"
            ]
            == "completed"
        )
    assert requested == [0, 1]


def test_invalidated_cursor_restarts_same_window(database, settings, advisory):
    data = fixtures(advisory)["crossref"]
    data["message"]["next-cursor"] = "invalidated"
    target = Target(id="papers", source="crossref", max_pages=1, page_size=1)
    requests = []

    def respond(req):
        requests.append(req)
        if req.url.params["cursor"] == "invalidated":
            return httpx.Response(410)
        if len(requests) == 1:
            return httpx.Response(200, json=data)
        return httpx.Response(200, json={"message": {"items": []}})

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        transport = SourceHTTP(settings, client)
        sync_target(database, settings, target, transport=transport, clock=lambda: NOW)
        result = sync_target(
            database,
            settings,
            target,
            transport=transport,
            clock=lambda: NOW + timedelta(minutes=6),
        )
        assert result["status"] == "failed" and "invalidated" in result["error"]
        with database() as session:
            assert session.scalar(select(SyncState)) is None
            assert session.get(MonitorState, "papers").continuation["url"] is None
        result = sync_target(
            database,
            settings,
            target,
            transport=transport,
            clock=lambda: NOW + timedelta(minutes=7),
        )
    assert result["status"] == "completed"
    assert requests[-1].url.params["filter"] == requests[0].url.params["filter"]


def test_retrieval_can_exclude_review_candidates(database, settings, advisory):
    rows = fixtures(advisory)["crossref"]
    candidate = copy.deepcopy(rows["message"]["items"][0])
    candidate.update(
        DOI="10.1234/general", title=["Artificial intelligence in engineering"], abstract=""
    )
    rows["message"]["items"].append(candidate)
    sync_target(
        database,
        settings,
        Target(id="papers", source="crossref"),
        transport=Pages(json.dumps(rows).encode()),
        clock=lambda: NOW,
    )
    with TestClient(create_app(settings)) as client:
        unfiltered = client.get("/api/v1/retrieval/search", params={"q": "engineering"}).json()
        filtered = client.get(
            "/api/v1/retrieval/search", params={"q": "engineering", "ai_label": "relevant"}
        ).json()
        assert unfiltered["total"] > 0 and filtered["total"] == 0
