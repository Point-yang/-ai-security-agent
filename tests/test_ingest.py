import copy
import json

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from zhidu.ingest import ingest_document
from zhidu.models import EventRevision, IntelEvent, RawDocument, now_utc


def ingest(database, store, obj, content=None):
    with database.begin() as session:
        return ingest_document(
            session,
            store,
            content or json.dumps(obj).encode(),
            "https://api.github.com/advisories",
            now_utc(),
            "replay",
        )


def test_preserves_exact_bytes_and_resolvable_evidence(database, store, advisory):
    payload = json.dumps([advisory], ensure_ascii=False, indent=4).encode() + b"\n"
    result = ingest(database, store, advisory, payload)
    assert result["created"] == 1
    with database() as session:
        doc = session.get(RawDocument, result["raw_document_id"])
        assert store.read(doc.sha256) == payload
        revision = session.scalar(select(EventRevision))
        parsed = json.loads(store.read(doc.sha256))
        for evidence in revision.evidence:
            cursor = parsed
            for part in evidence["json_pointer"].split("/")[1:]:
                cursor = cursor[int(part)] if isinstance(cursor, list) else cursor[part]
            assert cursor == evidence["value"]


def test_repeat_is_idempotent(database, store, advisory):
    ingest(database, store, advisory)
    assert ingest(database, store, advisory)["unchanged"] == 1
    with database() as session:
        for model in [IntelEvent, EventRevision, RawDocument]:
            assert session.scalar(select(func.count()).select_from(model)) == 1


def test_update_keeps_history_and_invalidates_verified_review(database, store, advisory):
    ingest(database, store, advisory)
    with database.begin() as session:
        event = session.scalar(select(IntelEvent))
        event.review_status, event.analyst_note = "verified", "previous review"
    advisory["updated_at"] = "2026-01-02T08:00:00Z"
    advisory["vulnerabilities"][0]["first_patched_version"] = "1.2.0"
    advisory["withdrawn_at"] = "2026-01-02T08:00:00Z"
    assert ingest(database, store, advisory)["updated"] == 1
    with database() as session:
        event = session.scalar(select(IntelEvent))
        assert event.revision == 2 and event.withdrawn_at is not None
        assert event.review_status == "needs_evidence" and event.annotation_version == 1
        assert event.analyst_note == "previous review"
        history = session.scalars(select(EventRevision).order_by(EventRevision.number)).all()
        assert [r.disposition for r in history] == ["superseded", "current"]
        assert history[0].normalized["packages"][0]["fixed_version"] is None
        assert history[1].normalized["packages"][0]["fixed_version"] == "1.2.0"


def test_stale_record_cannot_overwrite_current(database, store, advisory):
    latest = copy.deepcopy(advisory)
    latest["updated_at"] = "2026-01-03T00:00:00Z"
    latest["summary"] = "newest title"
    ingest(database, store, latest)
    assert ingest(database, store, advisory)["stale"] == 1
    with database() as session:
        event = session.scalar(select(IntelEvent))
        assert event.title == "newest title" and event.revision == 1
        assert (
            session.scalar(select(EventRevision).where(EventRevision.number == 2)).disposition
            == "stale"
        )


def test_equal_timestamp_conflict_preserves_both(database, store, advisory):
    ingest(database, store, advisory)
    old_title = advisory["summary"]
    advisory["summary"] = "contradictory title"
    assert ingest(database, store, advisory)["conflict"] == 1
    assert ingest(database, store, advisory)["unchanged"] == 1
    with database() as session:
        assert session.scalar(select(IntelEvent)).title == old_title
        assert session.scalar(select(func.count()).select_from(EventRevision)) == 2


def test_invalid_batch_rolls_back_entire_page(database, store, advisory):
    invalid = copy.deepcopy(advisory)
    invalid["updated_at"] = "not a date"
    with pytest.raises(ValidationError):
        ingest(database, store, [advisory, invalid])
    with database() as session:
        assert session.scalar(select(func.count()).select_from(IntelEvent)) == 0
        assert session.scalar(select(func.count()).select_from(RawDocument)) == 0


def test_timezone_required(database, store, advisory):
    advisory["updated_at"] = "2026-01-02T08:00:00"
    with pytest.raises(ValidationError):
        ingest(database, store, advisory)
