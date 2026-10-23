"""Pure source metadata/own-quote contracts; no network or model calls."""

import copy
import hashlib
import json

import pytest

from zhidu.agent_requirements import normalize_plan, verifier_packet
from zhidu.agent_state import AgentAnswer
from zhidu.agent_team_state import TaskPlan
from zhidu.source_semantics import (
    CONTEXT_VERSION,
    quoted_context_coverage,
    source_context_provenance,
    source_semantics,
)


def citation(
    start=0,
    end=10,
    *,
    source="github-advisories",
    version=CONTEXT_VERSION,
    complete=False,
    context_start=0,
    context_end=20,
    continuation=None,
):
    field_text = "abcdefghijklmnopqrst"
    return {
        "source_id": source,
        "field": "description",
        "sha256": "a" * 64,
        "json_pointer": "/description",
        "revision": 1,
        "start": start,
        "end": end,
        "text": field_text[start:end],
        "span_provenance": {
            "version": version,
            "source_field_sha256": hashlib.sha256(field_text.encode()).hexdigest(),
            "source_field_chars": len(field_text),
            "serialization": "string-verbatim",
            "offset_unit": "unicode_codepoint",
            "boundary_complete": True,
            "context": {
                "kind": "list_with_intro",
                "start": context_start,
                "end": context_end,
                "complete": complete,
                "continuation_offset": continuation,
            },
        },
    }


def test_source_contract_only_observes_metadata_and_never_reads_patch_values():
    evidence = {
        "one": {
            "source_id": "github-advisories",
            "field": "packages",
            "json_pointer": "/0/vulnerabilities",
            "text": '{"first_patched_version": "SECRET_VALUE"}',
        }
    }
    before = copy.deepcopy(evidence)
    result = source_semantics(evidence)
    channel = result["sources"][0]["channels"]["packages"]
    assert channel["observation"] == "observed"
    assert channel["first_patch_point_key"] == "first_patched_version"
    assert channel["affected_range_key"] == "vulnerable_version_range"
    assert (
        channel["patched_versions_is_range"] is True
        and channel["empty_patch_value_means_no_fix"] is False
    )
    evidence["one"]["text"] = '{"first_patched_version": ""}'
    assert source_semantics(evidence) == result
    assert "SECRET_VALUE" not in json.dumps(result)
    assert before["one"]["text"] != evidence["one"]["text"]
    assert result["container_observation_is_value_support"] is False
    assert (
        result["contracts_are_question_requirements"] is False
        and result["semantic_support_verified"] is False
    )


def test_nvd_native_narrative_does_not_require_github_fields_or_equate_configs_to_first_patch():
    result = source_semantics(
        [
            {
                "source_id": "nvd",
                "field": "description",
                "json_pointer": "/vulnerabilities/0/cve/descriptions/0/value",
            },
            {
                "source_id": "nvd",
                "field": "configurations",
                "json_pointer": "/vulnerabilities/0/cve/configurations",
            },
            {
                "source_id": "nvd",
                "field": "nvd_affected_data_0_0",
                "json_pointer": "/vulnerabilities/0/cve/affected/0/affectedData/0",
            },
        ]
    )
    source = result["sources"][0]
    assert source["source_id"] == "nvd" and source["native_contract"] == "nvd_native"
    assert source["channels"]["description"]["observation"] == "observed"
    assert (
        source["channels"]["description"]["role"] == "narrative_affected_or_fixed_wording_if_quoted"
    )
    assert source["channels"]["configurations"]["observation"] == "observed"
    assert source["channels"]["affected_data"]["observation"] == "observed"
    assert source["github_same_named_patch_field_required"] is False
    assert (
        source["configurations_equate_first_patch"] is False
        and source["affected_data_equate_first_patch"] is False
    )


def test_missing_container_is_only_not_observed_and_source_ids_are_not_rewritten():
    result = source_semantics(
        [
            {"source_id": "nvd", "field": "title"},
            {"source_id": "github-advisories", "field": "title"},
            {"source_id": "NVD", "field": "description"},
            {"source_id": None, "field": "packages"},
        ]
    )
    rows = {row["source_id"]: row for row in result["sources"]}
    assert rows["nvd"]["channels"]["description"]["observation"] == "not_observed"
    assert rows["github-advisories"]["channels"]["packages"]["observation"] == "not_observed"
    assert rows["NVD"]["native_contract"] == "unmapped"
    assert result["source_absence_inferred"] is False and result["unknown_metadata_count"] == 1


def test_old_sentence_boundary_does_not_prove_complete_condition_list():
    legacy = citation(version="source-span-v1", complete=True)
    context = source_context_provenance(legacy)
    assert context["status"] == "unknown" and context["context_complete"] is None
    coverage = quoted_context_coverage([legacy])
    assert coverage["complete"] is False and coverage["unknown_citations"] == 1
    assert coverage["complete_contexts"] == coverage["incomplete_contexts"] == []


def test_known_incomplete_context_carries_only_safe_continuation_metadata():
    value = citation(continuation=10)
    value["span_provenance"]["context"]["next_text"] = "SECRET_UNQUOTED_NEXT_PAGE"
    projected = source_context_provenance(value)
    assert projected["status"] == "incomplete" and projected["context_complete"] is False
    assert (
        projected["kind"] == "list_with_intro"
        and projected["start"] == 0
        and projected["end"] == 20
    )
    assert projected["continuation_offset"] == 10
    assert "SECRET_UNQUOTED_NEXT_PAGE" not in json.dumps(projected)


def test_two_incomplete_pages_cover_one_context_without_text_join_or_new_handles():
    first, second = citation(0, 10, continuation=10), citation(10, 20)
    result = quoted_context_coverage([first, second, copy.deepcopy(first)])
    assert result["complete"] is True and result["unknown_citations"] == 0
    assert len(result["complete_contexts"]) == 1 and result["incomplete_contexts"] == []
    context = result["complete_contexts"][0]
    assert context["quoted_intervals"] == [{"start": 0, "end": 20}]
    assert context["continuation_offsets"] == [10] and context["kind"] == "list_with_intro"
    assert "abcdefghij" not in json.dumps(result) and result["semantic_support_verified"] is False


def test_id_selected_context_preserves_its_version_and_uses_actual_quoted_pages():
    first = citation(0, 10, version="source-context-span-v2", continuation=10)
    second = citation(10, 20, version="source-context-span-v2")
    for item in (first, second):
        item["span_provenance"]["context_id"] = "ctx_" + "a" * 64
    assert source_context_provenance(first)["version"] == "source-context-span-v2"
    assert not quoted_context_coverage([first])["complete"]
    assert quoted_context_coverage([first, second])["complete"]
    second["json_pointer"] = "/other"
    assert not quoted_context_coverage([first, second])["complete"]


def test_missing_middle_page_and_last_page_without_cursor_remain_incomplete():
    result = quoted_context_coverage([citation(0, 5, continuation=5), citation(10, 20)])
    assert result["complete"] is False and len(result["incomplete_contexts"]) == 1
    assert result["incomplete_contexts"][0]["quoted_intervals"] == [
        {"start": 0, "end": 5},
        {"start": 10, "end": 20},
    ]
    tail_only = quoted_context_coverage([citation(10, 20)])
    assert tail_only["complete"] is False
    assert source_context_provenance(citation(10, 20))["continuation_offset"] is None


@pytest.mark.parametrize(
    "changed",
    [
        "source_id",
        "sha256",
        "json_pointer",
        "revision",
        "field",
        "field_hash",
        "kind",
        "context_end",
    ],
)
def test_foreign_source_or_context_metadata_cannot_fill_another_pages_gap(changed):
    first, second = citation(0, 10), citation(10, 20)
    if changed == "source_id":
        second[changed] = "nvd"
    elif changed == "sha256":
        second[changed] = "b" * 64
    elif changed == "json_pointer":
        second[changed] = "/other"
    elif changed == "revision":
        second[changed] = 2
    elif changed == "field":
        second[changed] = "other"
    elif changed == "field_hash":
        second["span_provenance"]["source_field_sha256"] = "b" * 64
    elif changed == "kind":
        second["span_provenance"]["context"]["kind"] = "section"
    else:
        first["span_provenance"]["context"]["end"] = 19
    result = quoted_context_coverage([first, second])
    assert not result["complete_contexts"] and result["complete"] is False


@pytest.mark.parametrize(
    "invalid",
    [
        "short_text",
        "bad_hash",
        "bad_offset",
        "string_complete",
        "false_complete",
        "wrong_version",
        "bad_cursor",
    ],
)
def test_invalid_context_cannot_be_promoted_to_complete(invalid):
    value = citation(0, 20, complete=True)
    if invalid == "short_text":
        value["text"] = value["text"][:-1]
    elif invalid == "bad_hash":
        value["sha256"] = "invalid"
    elif invalid == "bad_offset":
        value["span_provenance"]["context"]["end"] = 999
    elif invalid == "string_complete":
        value["span_provenance"]["context"]["complete"] = "true"
    elif invalid == "false_complete":
        value["end"] = 10
        value["text"] = value["text"][:10]
    elif invalid == "wrong_version":
        value["span_provenance"]["version"] = "unknown"
    else:
        value["span_provenance"]["context"]["continuation_offset"] = True
    result = quoted_context_coverage([value])
    assert result["unknown_citations"] == 1 and result["complete_contexts"] == []


def test_legacy_entire_canonical_field_is_a_field_proof_not_inferred_list_proof():
    value = citation(0, 20, version="source-span-v1")
    result = quoted_context_coverage([value])
    assert result["complete"] is True and result["complete_contexts"][0]["kind"] == "field"
    assert result["complete_contexts"][0]["proof"] == "legacy_canonical_entire_field"
    value["span_provenance"]["source_field_sha256"] = "b" * 64
    assert quoted_context_coverage([value])["unknown_citations"] == 1


def test_verifier_contract_and_context_are_local_to_each_actual_claim_quote():
    question = "对照两个来源的原始修复措辞。"
    plan = TaskPlan.model_validate(
        {
            "tasks": [
                {
                    "task_id": "repair",
                    "requirement": question,
                    "source_ids": ["github-advisories", "nvd"],
                    "fields": ["packages", "description"],
                    "keywords": [],
                    "question_spans": [{"quote": question}],
                    "source_policy": "each",
                    "required_elements": ["各来源修复措辞"],
                }
            ]
        }
    )
    gh, nvd, other = "a" * 24, "b" * 24, "c" * 24
    github = citation(0, 10, continuation=10)
    github["field"] = "packages"
    github["json_pointer"] = "/0/vulnerabilities"
    nvd_value = citation(0, 20, source="nvd", version="source-span-v1")
    evidence = {
        gh: github,
        nvd: nvd_value,
        other: {
            "source_id": "private-unused-source",
            "field": "description",
            "text": "SECRET_UNQUOTED_CONTEXT",
        },
    }
    candidate = AgentAnswer.model_validate(
        {
            "answer_class": "partial",
            "statements": [
                {"text": "GitHub 的包字段原值如引文。", "evidence": [{"evidence_id": gh}]},
                {"text": "NVD 的描述措辞如引文。", "evidence": [{"evidence_id": nvd}]},
            ],
            "required_facts": [question],
            "missing_facts": [],
            "limitations": [],
            "message": "",
        }
    )
    before = copy.deepcopy(evidence)
    packet = verifier_packet(question, plan, candidate, evidence, scope="ownquote-test")
    first, second = packet["statements"]
    assert [source["source_id"] for source in first["source_contracts"]["sources"]] == [
        "github-advisories"
    ]
    assert first["source_contracts"]["sources"][0]["observed_fields"] == ["packages"]
    assert [source["source_id"] for source in second["source_contracts"]["sources"]] == ["nvd"]
    assert first["quotes"][0]["source_context"]["context_complete"] is False
    assert second["quotes"][0]["source_context"]["status"] == "unknown"
    assert "SECRET_UNQUOTED_CONTEXT" not in json.dumps(
        packet
    ) and "private-unused-source" not in json.dumps(packet)
    assert (
        first["quotes"][0]["quote"] == github["text"]
        and second["quotes"][0]["quote"] == nvd_value["text"]
    )
    assert evidence == before
    assert packet["tasks"] == normalize_plan(question, plan).model_dump()["tasks"]


def test_field_context_and_full_field_hash_cannot_describe_a_partial_or_changed_field():
    partial = citation(5, 20, complete=True, context_start=5)
    partial["span_provenance"]["context"]["kind"] = "field"
    assert source_context_provenance(partial)["status"] == "unknown"
    assert quoted_context_coverage([partial])["unknown_citations"] == 1
    changed = citation(0, 20, complete=True)
    changed["text"] = "X" * 20
    assert quoted_context_coverage([changed])["unknown_citations"] == 1
