"""Unknown normalized field names get a local catalog, not an absence claim."""

import json

from test_member_a_rag_context import fixture_advisory, ingest
from test_read_fields_pagination import scoped_tools


def test_missing_names_expose_only_available_fields_and_no_fake_evidence(
    database, store, settings, advisory
):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        scope = scoped_tools(session, store, settings)
        text, result = scope.invoke(
            "read_fields",
            {
                "event_id": next(iter(scope.events)),
                "fields": ["invented_affected_versions", "invented_score"],
            },
        )
        value = json.loads(text)["result"]
        assert result["status"] == "completed"
        assert value["fields"] == [] and scope.evidence == {}
        assert (
            "packages" in value["available_fields"] and "description" in value["available_fields"]
        )
        assert value["missing_requested_fields"] == ["invented_affected_versions", "invented_score"]
        assert scope.no_progress_calls == 0 and scope.attempted_calls == 1
        assert scope.field_catalog[next(iter(scope.events))] == value["available_fields"]
        assert scope.evidence == {}  # Navigation progress is not source evidence.
        _, repaired = scope.invoke(
            "read_fields", {"event_id": next(iter(scope.events)), "fields": ["packages"]}
        )
        assert repaired["status"] == "completed" and scope.evidence


def test_valid_and_unknown_fields_keep_requested_source_text(database, store, settings, advisory):
    ingest(database, store, fixture_advisory(advisory))
    with database() as session:
        scope = scoped_tools(session, store, settings)
        text, _ = scope.invoke(
            "read_fields",
            {"event_id": next(iter(scope.events)), "fields": ["packages", "unknown_version_type"]},
        )
        value = json.loads(text)["result"]
        assert value["missing_requested_fields"] == ["unknown_version_type"]
        assert value["fields"][0]["citation"]["field"] == "packages"
        assert '"first_patched_version": "1.2.0"' in value["fields"][0]["text"]
