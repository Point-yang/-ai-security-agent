import hashlib
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from test_member_a_rag_context import fixture_advisory, ingest

from zhidu.api import create_app
from zhidu.catalog import (
    audit_catalog,
    catalog_associations,
    ingest_catalog,
    parse_catalog,
    resolve_catalog_locator,
)
from zhidu.models import CatalogItem, CatalogRevision, IntelEvent, RawDocument, now_utc
from zhidu.monitor import Target, sync_target
from zhidu.sources import SOURCES


def fixture(source):
    if source == "hf-blog":
        return {
            "allBlogs": [
                {
                    "_id": "article-1",
                    "title": "AI Security Incident Analysis",
                    "url": "/blog/ai-security-analysis",
                    "publishedAt": "2026-09-24T10:00:00Z",
                    "editedAt": "2026-09-24T11:00:00Z",
                }
            ]
        }
    if source == "nist-ai-rmf":
        return {
            "message": {
                "DOI": "10.6028/NIST.AI.100-1",
                "title": ["Artificial Intelligence Risk Management Framework"],
                "publisher": "National Institute of Standards and Technology (U.S.)",
                "published": {"date-parts": [[2023, 1, 26]]},
                "indexed": {"date-time": "2026-09-24T10:00:00Z"},
            }
        }
    if source == "federal-register-ai":
        return {
            "results": [
                {
                    "title": "Artificial Intelligence Safety Policy Request",
                    "type": "Proposed Rule",
                    "abstract": "Comments requested; no rule is yet final.",
                    "document_number": "2026-00101",
                    "publication_date": "2026-09-24",
                    "html_url": "https://www.federalregister.gov/documents/2026/09/24/2026-00101/ai-safety",
                    "agencies": [{"name": "Test Agency"}],
                }
            ]
        }
    return b'{"ID":"CVE-2026-22778","Info":{"Name":"vLLM - Information Disclosure","Description":"A metadata-only vLLM template.","Severity":"critical"},"file_path":"http/cves/2026/CVE-2026-22778.yaml"}\n'


def content(source):
    value = fixture(source)
    return value if isinstance(value, bytes) else json.dumps(value).encode()


@pytest.mark.parametrize("source", ["hf-blog", "nist-ai-rmf", "federal-register-ai", "nuclei-cves"])
def test_catalog_preserves_source_bytes_and_does_not_create_vulnerability_events(
    database, store, settings, source
):
    original = content(source)
    with database.begin() as session:
        result = ingest_catalog(
            session,
            store,
            original,
            source_id=source,
            url=SOURCES[source].base_url,
            fetched_at=now_utc(),
            origin="replay",
        )
        assert result["created"] == 1 and result["scope"] == "source_metadata_only_no_poc_execution"
        assert (
            ingest_catalog(
                session,
                store,
                original,
                source_id=source,
                url=SOURCES[source].base_url,
                fetched_at=now_utc(),
                origin="replay",
            )["unchanged"]
            == 1
        )
    with database() as session:
        row = session.scalar(select(CatalogItem))
        raw = session.get(RawDocument, row.raw_document_id)
        assert store.read(raw.sha256) == original
        assert hashlib.sha256(original).hexdigest() == raw.sha256
        assert row.normalized["payload_executed"] is False
        assert resolve_catalog_locator(original, row.evidence_locator)
        assert session.scalar(select(func.count()).select_from(IntelEvent)) == 0
        assert session.scalar(select(func.count()).select_from(CatalogRevision)) == 1
        assert audit_catalog(session, store)["status"] == "passed"
    with TestClient(create_app(settings)) as client:
        response = client.get("/api/v1/catalog/items", params={"source_id": source})
        assert response.status_code == 200 and response.json()["total"] == 1
        item = response.json()["items"][0]
        assert item["raw_sha256"] == raw.sha256 and item["payload_executed"] is False
        assert item["origin"] == "replay"
        stored = client.get(f"/api/v1/raw-documents/{raw.id}/content")
        assert stored.content == original
        if source == "nuclei-cves":
            assert stored.headers["content-type"].startswith("application/x-ndjson")
        assert client.get(f"/api/v1/catalog/items/{row.id}/history").json()[0]["number"] == 1
        assert client.get("/catalog").status_code == 200


def test_catalog_update_preserves_history_and_date_scope(database, store):
    first = content("nist-ai-rmf")
    with database.begin() as session:
        ingest_catalog(
            session,
            store,
            first,
            source_id="nist-ai-rmf",
            url="offline://nist",
            fetched_at=now_utc(),
            origin="replay",
        )
        item_id = session.scalar(select(CatalogItem.id))
    changed = fixture("nist-ai-rmf")
    changed["message"]["title"] = ["NIST AI RMF updated metadata"]
    with database.begin() as session:
        assert (
            ingest_catalog(
                session,
                store,
                json.dumps(changed).encode(),
                source_id="nist-ai-rmf",
                url="offline://nist",
                fetched_at=now_utc(),
                origin="replay",
            )["updated"]
            == 1
        )
    with database() as session:
        row = session.get(CatalogItem, item_id)
        assert row.revision == 2
        assert row.published_at.year == 2023
        assert row.normalized["metadata"]["full_text_collected"] is False
        assert session.scalar(select(func.count()).select_from(CatalogRevision)) == 2


def test_live_catalog_observation_promotes_replay_without_later_demotion(database, store):
    original = content("hf-blog")
    with database.begin() as session:
        replay = ingest_catalog(
            session,
            store,
            original,
            source_id="hf-blog",
            url="https://huggingface.co/api/blog",
            fetched_at=now_utc(),
            origin="replay",
        )
        live = ingest_catalog(
            session,
            store,
            original,
            source_id="hf-blog",
            url="https://huggingface.co/api/blog",
            fetched_at=now_utc(),
            origin="live",
        )
        item = session.scalar(select(CatalogItem))
        assert replay["created"] == 1 and live["updated"] == 1
        assert item.revision == 2
        assert session.get(RawDocument, item.raw_document_id).origin == "live"
        changed = fixture("hf-blog")
        changed["allBlogs"][0]["title"] = "AI Security Incident Analysis changed by replay"
        later_replay = ingest_catalog(
            session,
            store,
            json.dumps(changed).encode(),
            source_id="hf-blog",
            url="offline://hf-blog-replay",
            fetched_at=now_utc(),
            origin="replay",
        )
        assert later_replay["unchanged"] == 1
        assert (
            item.revision == 2 and session.get(RawDocument, item.raw_document_id).origin == "live"
        )
        assert audit_catalog(session, store)["status"] == "passed"


def test_catalog_filters_irrelevant_blog_and_policy_titles():
    blog = fixture("hf-blog")
    blog["allBlogs"].append(
        {
            "_id": "unrelated",
            "title": "New tabular prediction benchmark",
            "url": "/blog/tabular-benchmark",
        }
    )
    assert [
        row.data["external_id"] for row in parse_catalog("hf-blog", json.dumps(blog).encode())
    ] == ["article-1"]
    policy = fixture("federal-register-ai")
    policy["results"].append(
        {
            **policy["results"][0],
            "document_number": "2026-00102",
            "title": "Proposed Information Collection; Artificial Intelligence Questions",
        }
    )
    assert [
        row.data["external_id"]
        for row in parse_catalog("federal-register-ai", json.dumps(policy).encode())
    ] == ["2026-00101"]


def test_catalog_exact_cve_association_is_candidate_only(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    poc = {
        "ID": advisory["cve_id"],
        "Info": {
            "Name": "vLLM metadata template",
            "Description": "Metadata-only template for " + advisory["cve_id"],
            "Severity": "high",
        },
        "file_path": "http/cves/2026/CVE-2026-22778.yaml",
    }
    # Keep the catalog fixture's external ID aligned with the event alias.
    with database.begin() as session:
        ingest_catalog(
            session,
            store,
            (json.dumps(poc) + "\n").encode(),
            source_id="nuclei-cves",
            url="https://example.test/cves.json",
            fetched_at=now_utc(),
            origin="live",
        )
        row = session.scalar(select(CatalogItem).where(CatalogItem.source_id == "nuclei-cves"))
        result = catalog_associations(session, row)
        assert result["candidates"]
        candidate = result["candidates"][0]
        assert candidate["match_type"] == "exact_cve_identifier"
        assert candidate["review_status"] == "candidate_requires_human_review"
        assert candidate["does_not_prove_vulnerability"] is True
    with TestClient(create_app(settings)) as client:
        response = client.get(f"/api/v1/catalog/items/{row.id}/associations")
        assert response.status_code == 200
        assert response.json()["candidates"][0]["event_id"] == candidate["event_id"]


@pytest.mark.parametrize("source", ["hf-blog", "nist-ai-rmf", "federal-register-ai", "nuclei-cves"])
def test_catalog_monitor_uses_persistent_run_and_no_source_code_execution(
    database, store, settings, source
):
    class Pages:
        def pages(self, target, start, end, validators):
            yield SOURCES[source].base_url, content(source), False, {}, False

    result = sync_target(
        database, settings, Target(id="catalog-test", source=source), transport=Pages()
    )
    assert result["status"] == "completed", result
    assert result["created"] == 1
    with database() as session:
        assert session.scalar(select(func.count()).select_from(CatalogItem)) == 1


def test_poc_index_is_metadata_without_downloaded_template_or_invented_date():
    row = parse_catalog("nuclei-cves", content("nuclei-cves"))[0]
    assert row.data["published_at"] is None
    assert row.data["metadata"]["template_executed"] is False
    assert row.data["metadata"]["publication_date_known"] is False


def test_catalog_audit_detects_tampered_raw_without_changing_metadata(database, store):
    original = content("nuclei-cves")
    with database.begin() as session:
        ingest_catalog(
            session,
            store,
            original,
            source_id="nuclei-cves",
            url="offline://poc",
            fetched_at=now_utc(),
            origin="replay",
        )
        document = session.scalar(select(RawDocument))
        digest = document.sha256
    store.path_for(digest).write_bytes(b"tampered")
    with database() as session:
        result = audit_catalog(session, store)
        assert result["status"] == "failed"
        assert result["failed"] == 1
        assert session.scalar(select(func.count()).select_from(CatalogItem)) == 1


@pytest.mark.parametrize("bad", [b"[]", b'{"allBlogs":{}}', b'{"results":{}}'])
def test_wrong_feed_shape_is_rejected(bad):
    with pytest.raises((ValueError, TypeError, KeyError)):
        parse_catalog(
            "hf-blog" if b"allBlogs" in bad or bad == b"[]" else "federal-register-ai", bad
        )
