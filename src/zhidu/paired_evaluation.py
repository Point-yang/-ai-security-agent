"""Semantic paired evaluation. Source bytes alone never establish answer quality."""

import hashlib
import json
import random
import statistics
from collections import defaultdict
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

MODES = ("rag", "workflow", "langchain")
DIMENSIONS = ("affected_range", "remediation", "conditions", "source_difference")


def digest(value):
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def rate(n, d):
    return n / d if d else None


class EvidenceField(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    source_id: str
    event_id: str
    chunk_id: str
    json_pointer: str
    sha256: str
    text: str
    quote: str = Field(min_length=8)

    @model_validator(mode="after")
    def exact(self):
        if self.quote not in self.text:
            raise ValueError("quote_not_verbatim")
        return self


class DimensionObservation(BaseModel):
    """Absence, access failure and lack of integration have different denominators."""

    model_config = ConfigDict(extra="forbid", strict=True)
    dimension: str
    state: Literal[
        "found",
        "partial",
        "not_found_in_scope",
        "not_public",
        "interface_error",
        "not_connected",
        "not_applicable",
    ]
    scope: str = Field(min_length=1)
    conclusion: str = Field(min_length=1)
    evidence: list[EvidenceField] = Field(default_factory=list)

    @model_validator(mode="after")
    def evidence_required(self):
        if self.state in {"found", "partial", "not_public"} and not self.evidence:
            raise ValueError("positive_source_evidence_required")
        return self


class FactVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    fact_id: str
    covered: bool
    grounded: bool
    reason: str = Field(min_length=1)


class ClaimVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    statement_index: int = Field(ge=1)
    supported: bool
    reason: str = Field(min_length=1)


class SemanticVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    facts: list[FactVerdict]
    claims: list[ClaimVerdict]
    boundary_ok: bool
    boundary_reason: str = Field(min_length=1)


def validate_verdict(case, result, value):
    verdict = SemanticVerdict.model_validate(value)
    ids = [f.fact_id for f in verdict.facts]
    expected = [f["id"] for f in case["facts"]]
    claims = [c.statement_index for c in verdict.claims]
    if len(ids) != len(set(ids)) or set(ids) != set(expected):
        raise ValueError("judge_fact_set_mismatch")
    if sorted(claims) != list(range(1, len(result.get("generated_claims", [])) + 1)):
        raise ValueError("judge_claim_set_mismatch")
    return verdict


def quote_check(result):
    citations = result.get("citations", [])
    refs = [r for s in result.get("generated_claims", []) for r in s.get("evidence", [])]
    return {
        "total": len(refs),
        "exact": sum(
            type(r.get("citation")) is int
            and 1 <= r["citation"] <= len(citations)
            and isinstance(r.get("quote"), str)
            and bool(r["quote"].strip())
            and r["quote"] in citations[r["citation"] - 1].get("text", "")
            for r in refs
        ),
    }


def judge_packet(case, result, anonymous_id):
    """Do not let the judge substitute unquoted source context for a quotation."""
    return {
        "anonymous_id": anonymous_id,
        "question": case["question"],
        "facts": [{k: f[k] for k in ("id", "dimension", "expected")} for f in case["facts"]],
        "answer": result["answer"],
        "generated_claims": result.get("generated_claims", []),
        "citations": [
            {
                k: c[k]
                for k in ("source_id", "external_id", "field", "event_id", "chunk_id")
                if k in c
            }
            for c in result.get("citations", [])
        ],
        "review_policy": "facts.expected is a scoring target, not quotation support; only each generated_claim.evidence.quote supports its statement; full source bytes remain in the frozen local source packet",
    }


def score_answer(case, result, verdict=None):
    """A failed generation's raw excerpts cannot be passed off as a semantic answer."""
    verdict = validate_verdict(case, result, verdict) if verdict is not None else None
    complete = result.get("generation", {}).get("status") == "completed"
    quotes = quote_check(result)
    quotes_ok = quotes["total"] > 0 and quotes["total"] == quotes["exact"]
    facts = {f.fact_id: f for f in verdict.facts} if verdict else {}
    dimensions = defaultdict(lambda: {"required": 0, "covered": 0, "grounded": 0})
    for fact in case["facts"]:
        entry = dimensions[fact["dimension"]]
        entry["required"] += 1
        observed = facts.get(fact["id"])
        entry["covered"] += bool(complete and observed and observed.covered)
        entry["grounded"] += bool(
            complete and quotes_ok and observed and observed.covered and observed.grounded
        )
    supported = (
        sum(c.supported for c in verdict.claims) if verdict and complete and quotes_ok else 0
    )
    total = len(result.get("generated_claims", []))
    grounded = sum(d["grounded"] for d in dimensions.values())
    return {
        "case_id": case["id"],
        "group_id": case["group_id"],
        "generation_completed": complete,
        "judge_available": verdict is not None,
        "required_facts": len(case["facts"]),
        "grounded_facts": grounded,
        "fact_recall": rate(grounded, len(case["facts"])) if verdict else None,
        "claims": total,
        "supported_claims": supported,
        "citation_entailment_precision": rate(supported, total) if verdict else None,
        "verbatim": quotes,
        "dimensions": dict(dimensions),
        "strict_pass": bool(
            complete
            and verdict
            and quotes_ok
            and verdict.boundary_ok
            and grounded == len(case["facts"])
            and total > 0
            and supported == total
        ),
    }


def paired_difference(records, challenger, baseline, *, samples=10000):
    """Resample identifier groups, never calls or repeated questions independently."""
    by_case = defaultdict(dict)
    for row in records:
        by_case[row["case_id"]][row["mode"]] = row
    groups = defaultdict(list)
    wins = losses = 0
    for pair in by_case.values():
        if challenger not in pair or baseline not in pair:
            raise ValueError("incomplete_pair")
        a, b = pair[challenger], pair[baseline]
        delta = int(a["strict_pass"]) - int(b["strict_pass"])
        groups[a["group_id"]].append(delta)
        wins += delta == 1
        losses += delta == -1
    if not groups:
        return {"delta": None, "group_bootstrap_95_ci": None, "groups": 0}
    keys = sorted(groups)
    rng = random.Random(20261012)
    draws = []
    for _ in range(samples):
        deltas = [d for k in rng.choices(keys, k=len(keys)) for d in groups[k]]
        draws.append(statistics.mean(deltas))
    draws.sort()
    return {
        "delta": statistics.mean(d for values in groups.values() for d in values),
        "group_bootstrap_95_ci": [draws[int(samples * 0.025)], draws[int(samples * 0.975)]],
        "groups": len(groups),
        "paired_wins": wins,
        "paired_losses": losses,
        "interpretation": "small identifier-group cohort; interval is exploratory",
    }


def summarize(records, modes=MODES, challenger="langchain"):
    modes = tuple(modes)
    if not modes or len(set(modes)) != len(modes) or challenger not in modes:
        raise ValueError("invalid_summary_modes")
    by_mode = {}
    for mode in modes:
        rows = [r for r in records if r["mode"] == mode]
        judged = [r for r in rows if r["judge_available"]]
        dimension_scores = {}
        for name in DIMENSIONS:
            values = [r["dimensions"][name] for r in judged if name in r["dimensions"]]
            required = sum(d["required"] for d in values)
            grounded = sum(d["grounded"] for d in values)
            dimension_scores[name] = {
                "required_facts": required,
                "grounded_facts": grounded,
                "recall": rate(grounded, required),
                "complete_accuracy": rate(
                    sum(d["grounded"] == d["required"] for d in values), len(values)
                ),
                "cases": len(values),
            }
        known_tokens = [r["cost"].get("billed_tokens") for r in rows]
        by_mode[mode] = {
            "cases": len(rows),
            "judge_coverage": rate(len(judged), len(rows)),
            "confirmed_strict_passes": sum(r["strict_pass"] for r in rows),
            "confirmed_strict_accuracy_all_attempts": rate(
                sum(r["strict_pass"] for r in rows), len(rows)
            ),
            "fact_recall_judged": rate(
                sum(r["grounded_facts"] for r in judged), sum(r["required_facts"] for r in judged)
            ),
            "citation_entailment_precision_judged": rate(
                sum(r["supported_claims"] for r in judged), sum(r["claims"] for r in judged)
            ),
            "generation_failures": sum(not r["generation_completed"] for r in rows),
            "mean_elapsed_ms": statistics.mean(r["elapsed_ms"] for r in rows) if rows else None,
            "external_requests": sum(r["cost"].get("external_requests", 0) for r in rows),
            "known_billed_tokens": sum(t for t in known_tokens if t is not None),
            "token_usage_unknown_answers": sum(t is None for t in known_tokens),
            "api_cost_usd": None,
            "dimensions": dimension_scores,
        }
    return {
        "modes": by_mode,
        "paired": {
            base: paired_difference(records, challenger, base)
            for base in modes
            if base != challenger
        },
        "agent_gain_proven": False,
        "scope": "project-adopted AI review; exploratory paired cohort, not organizer score",
    }
