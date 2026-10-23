"""Observed source-native channels and literal structural coverage proofs.

Contracts describe field meaning, never a new requirement or a claim verdict.
Context proofs use actual quoted intervals only; no missing source text is
returned, and neither provenance nor interval coverage proves semantic support.
"""

import hashlib
import re
from collections.abc import Mapping

VERSION = "observed-source-semantics-v1"
CONTEXT_VERSION = "source-context-span-v1"
CONTEXT_VERSIONS = {CONTEXT_VERSION, "source-context-span-v2"}
_SHA = re.compile(r"^[a-f0-9]{64}$")
_CONTEXT_KINDS = {"list_with_intro", "section", "field"}


def _citations(evidence):
    if isinstance(evidence, Mapping):
        return [evidence] if "source_id" in evidence else list(evidence.values())
    return list(evidence)


def source_semantics(evidence):
    """Describe only sources/containers present in the supplied metadata.

    A container marked observed does not establish that every native key/value
    occurs in its quote. Native descriptions are schema guidance, not evidence.
    Callers choose whole scope for planning and only own references for review.
    """
    groups, unknown = {}, 0
    for citation in _citations(evidence):
        if (
            not isinstance(citation, Mapping)
            or not isinstance(citation.get("source_id"), str)
            or not citation["source_id"].strip()
        ):
            unknown += 1
            continue
        group = groups.setdefault(citation["source_id"], {"fields": set(), "pointers": set()})
        if isinstance(citation.get("field"), str) and citation["field"]:
            group["fields"].add(citation["field"])
        if isinstance(citation.get("json_pointer"), str):
            group["pointers"].add(citation["json_pointer"])

    def observed(available):
        return "observed" if available else "not_observed"

    sources = []
    for source_id, metadata in sorted(groups.items()):
        fields, pointers = metadata["fields"], metadata["pointers"]
        row = {"source_id": source_id, "observed_fields": sorted(fields)}
        if source_id == "github-advisories":
            packages = "packages" in fields or any(
                "vulnerabilities" in pointer.split("/") for pointer in pointers
            )
            row.update(
                native_contract="github_advisory_packages",
                channels={
                    "packages": {
                        "observation": observed(packages),
                        "affected_range_key": "vulnerable_version_range",
                        "first_patch_point_key": "first_patched_version",
                        "patched_versions_is_range": True,
                        "empty_patch_value_means_no_fix": False,
                    }
                },
            )
        elif source_id == "nvd":
            narrative = "description" in fields or any(
                "descriptions" in pointer.split("/") for pointer in pointers
            )
            affected = any(field.startswith("nvd_affected_data_") for field in fields) or any(
                "affectedData" in pointer.split("/") for pointer in pointers
            )
            configurations = bool(fields & {"configurations", "cpe", "cpeMatch"}) or any(
                {"configurations", "cpeMatch"} & set(pointer.split("/")) for pointer in pointers
            )
            row.update(
                native_contract="nvd_native",
                channels={
                    "description": {
                        "observation": observed(narrative),
                        "role": "narrative_affected_or_fixed_wording_if_quoted",
                    },
                    "affected_data": {
                        "observation": observed(affected),
                        "role": "source_asserted_affected_status_or_versions",
                    },
                    "configurations": {
                        "observation": observed(configurations),
                        "role": "cpe_applicability_or_version_match",
                    },
                },
                github_same_named_patch_field_required=False,
                configurations_equate_first_patch=False,
                affected_data_equate_first_patch=False,
            )
        else:
            row.update(
                native_contract="unmapped",
                interpretation="retain_actual_source_and_field_identifiers",
            )
        sources.append(row)
    return {
        "version": VERSION,
        "scope": "supplied_observed_metadata_only",
        "sources": sources,
        "unknown_metadata_count": unknown,
        "container_observation_is_value_support": False,
        "contracts_are_question_requirements": False,
        "source_absence_inferred": False,
        "semantic_support_verified": False,
    }


def _canonical(citation):
    if not isinstance(citation, Mapping) or not isinstance(
        citation.get("span_provenance"), Mapping
    ):
        return None
    provenance = citation["span_provenance"]
    if (
        provenance.get("version") not in {"source-span-v1", *CONTEXT_VERSIONS}
        or not isinstance(citation.get("source_id"), str)
        or not citation["source_id"].strip()
        or not isinstance(citation.get("field"), str)
        or not citation["field"]
        or not _SHA.fullmatch(str(citation.get("sha256", "")))
        or not isinstance(citation.get("json_pointer"), str)
        or not citation["json_pointer"].startswith("/")
        or type(citation.get("revision")) is not int
        or citation["revision"] < 1
        or not _SHA.fullmatch(str(provenance.get("source_field_sha256", "")))
        or provenance.get("offset_unit") != "unicode_codepoint"
        or provenance.get("serialization") not in {"string-verbatim", "json-sorted-default-v1"}
        or type(provenance.get("source_field_chars")) is not int
        or provenance["source_field_chars"] < 1
        or type(citation.get("start")) is not int
        or type(citation.get("end")) is not int
        or not 0 <= citation["start"] < citation["end"] <= provenance["source_field_chars"]
        or not isinstance(citation.get("text"), str)
        or len(citation["text"]) != citation["end"] - citation["start"]
    ):
        return None
    if (
        citation["start"] == 0
        and citation["end"] == provenance["source_field_chars"]
        and hashlib.sha256(citation["text"].encode()).hexdigest()
        != provenance["source_field_sha256"]
    ):
        return None
    return provenance


def source_context_provenance(citation):
    """Safe quote-local projection. Old sentence boundaries stay unknown."""
    unknown = {
        "version": None,
        "status": "unknown",
        "context_complete": None,
        "kind": "unknown",
        "start": None,
        "end": None,
        "continuation_offset": None,
        "semantic_support_verified": False,
    }
    provenance = _canonical(citation)
    if (
        provenance is None
        or provenance["version"] not in CONTEXT_VERSIONS
        or not isinstance(provenance.get("context"), Mapping)
    ):
        return unknown
    context = provenance["context"]
    start, end, complete = context.get("start"), context.get("end"), context.get("complete")
    continuation = context.get("continuation_offset")
    if (
        context.get("kind") not in _CONTEXT_KINDS
        or type(start) is not int
        or type(end) is not int
        or not 0 <= start < end <= provenance["source_field_chars"]
        or type(complete) is not bool
        or context.get("kind") == "field"
        and (start != 0 or end != provenance["source_field_chars"])
        or min(end, citation["end"]) <= max(start, citation["start"])
        or complete
        and not (citation["start"] <= start and end <= citation["end"])
        or continuation is not None
        and (
            type(continuation) is not int
            or not 0 <= continuation <= provenance["source_field_chars"]
        )
    ):
        return unknown
    return {
        "version": provenance["version"],
        "status": "complete" if complete else "incomplete",
        "context_complete": complete,
        "kind": context["kind"],
        "start": start,
        "end": end,
        "continuation_offset": continuation,
        "semantic_support_verified": False,
    }


def _merged(intervals):
    result = []
    for start, end in sorted(intervals):
        if result and start <= result[-1][1]:
            result[-1] = (result[-1][0], max(result[-1][1], end))
        else:
            result.append((start, end))
    return result


def quoted_context_coverage(citations):
    """Union only actual cited coordinates within the same canonical context.

    Each complete context is a literal block proof, not a proof that all user
    requirements are answered. Partial/unknown citations do not imply a source
    lacks anything. Caller applies source policy and semantic review separately.
    """
    groups, unknown = {}, 0
    for citation in _citations(citations):
        provenance = _canonical(citation)
        if provenance is None:
            unknown += 1
            continue
        context = source_context_provenance(citation)
        if provenance["version"] == "source-span-v1":
            full_field = (
                citation["start"] == 0
                and citation["end"] == provenance["source_field_chars"]
                and hashlib.sha256(citation["text"].encode()).hexdigest()
                == provenance["source_field_sha256"]
            )
            if not full_field:
                unknown += 1
                continue
            context = {
                "kind": "field",
                "start": 0,
                "end": provenance["source_field_chars"],
                "continuation_offset": None,
            }
            proof = "legacy_canonical_entire_field"
        elif context["status"] == "unknown":
            unknown += 1
            continue
        else:
            proof = "canonical_context_quoted_interval_union"
        key = (
            citation["source_id"],
            citation["sha256"],
            citation["json_pointer"],
            citation["revision"],
            citation["field"],
            provenance["source_field_sha256"],
            context["kind"],
            context["start"],
            context["end"],
        )
        entry = groups.setdefault(
            key, {"intervals": [], "continuation_offsets": set(), "proof": proof}
        )
        entry["intervals"].append(
            (max(context["start"], citation["start"]), min(context["end"], citation["end"]))
        )
        if context.get("continuation_offset") is not None:
            entry["continuation_offsets"].add(context["continuation_offset"])
    complete_contexts, incomplete_contexts = [], []
    for key, entry in sorted(groups.items()):
        intervals = _merged(entry["intervals"])
        complete = len(intervals) == 1 and intervals[0] == (key[7], key[8])
        row = {
            "source_id": key[0],
            "sha256": key[1],
            "json_pointer": key[2],
            "revision": key[3],
            "field": key[4],
            "source_field_sha256": key[5],
            "kind": key[6],
            "start": key[7],
            "end": key[8],
            "quoted_intervals": [{"start": start, "end": end} for start, end in intervals],
            "continuation_offsets": sorted(entry["continuation_offsets"]),
            "complete": complete,
            "proof": entry["proof"],
        }
        (complete_contexts if complete else incomplete_contexts).append(row)
    return {
        "complete_contexts": complete_contexts,
        "incomplete_contexts": incomplete_contexts,
        "unknown_citations": unknown,
        "complete": bool(complete_contexts) and not incomplete_contexts and not unknown,
        "scope": "actual_cited_canonical_context_intervals_only",
        "semantic_support_verified": False,
        "source_absence_inferred": False,
    }
