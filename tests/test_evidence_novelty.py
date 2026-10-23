import copy
import hashlib

import pytest

from zhidu.evidence_novelty import evidence_novelty


def citation(start=0, end=10, **updates):
    value = {
        "chunk_id": "different-index-id",
        "sha256": "a" * 64,
        "json_pointer": "/0/description",
        "revision": 1,
        "field": "description",
        "start": start,
        "end": end,
        "text": "x" * (end - start),
        "span_provenance": {
            "source_field_sha256": hashlib.sha256(b"x" * 100).hexdigest(),
            "source_field_chars": 100,
            "offset_unit": "unicode_codepoint",
            "serialization": "string-verbatim",
            "boundary_complete": True,
        },
    }
    value.update(updates)
    return value


def test_same_source_interval_new_chunk_and_evidence_ids_is_zero():
    original = citation()
    another = {**original, "chunk_id": "new-chunk-id", "evidence_id": "new-evidence-id"}
    result = evidence_novelty({"first": original}, {"second": another})
    assert result["status"] == "known" and result["new_source_chars"] == 0
    assert result["new_source_spans"] == []
    assert result["semantic_support_verified"] is False


def test_overlaps_adjacency_and_disjoint_windows_use_interval_union():
    before = [citation(0, 10), citation(5, 20), citation(30, 40)]
    after = [*before, citation(10, 30), citation(25, 50), citation(60, 70), citation(62, 68)]
    result = evidence_novelty(before, after)
    assert result["new_source_chars"] == 30
    assert [(v["start"], v["end"]) for v in result["new_source_spans"]] == [
        (20, 30),
        (40, 50),
        (60, 70),
    ]
    assert [(v["start"], v["end"]) for v in result["after_source_spans"]] == [(0, 50), (60, 70)]


@pytest.mark.parametrize(
    "updates",
    [
        {"sha256": "b" * 64},
        {"json_pointer": "/1/description"},
        {"revision": 2},
        {"field": "packages"},
    ],
)
def test_source_identity_changes_are_explicit_new_coordinates(updates):
    result = evidence_novelty([citation()], [citation(**updates)])
    assert result["new_source_chars"] == 10


def test_missing_provenance_is_unknown_never_assumed_new_or_zero():
    invalid = citation()
    invalid.pop("span_provenance")
    result = evidence_novelty([], [citation(), invalid])
    assert result["status"] == "unknown" and result["new_source_chars"] is None
    assert result["known_new_source_chars"] == 10
    assert result["unknown_after"][0]["reason"] == "missing_source_span_provenance"


def test_unknown_before_prevents_confirmed_novelty_total():
    result = evidence_novelty([{"text": "prior evidence without provenance"}], [citation()])
    assert result["new_source_chars"] is None
    assert result["known_new_source_chars"] == 10


@pytest.mark.parametrize(
    "mutate",
    [
        lambda v: v.update(start=True),
        lambda v: v.update(end=101),
        lambda v: v.update(text="short"),
        lambda v: v.update(revision=0),
        lambda v: v["span_provenance"].update(offset_unit="bytes"),
    ],
)
def test_invalid_source_coordinates_are_unknown(mutate):
    value = citation()
    mutate(value)
    assert evidence_novelty([], [value])["new_source_chars"] is None


def test_comparison_does_not_mutate_evidence_or_claim_semantic_novelty():
    before, after = [citation()], [citation(10, 20)]
    original = copy.deepcopy((before, after))
    result = evidence_novelty(before, after)
    assert (before, after) == original
    assert result["new_source_chars"] == 10
    assert result["quality_gain_proven"] is False


def test_empty_ledgers_have_a_known_zero_delta():
    assert evidence_novelty({}, {})["new_source_chars"] == 0
