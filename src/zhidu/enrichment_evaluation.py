"""Fixed regression assertions; these are not independently human-labeled gold data."""

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from zhidu.evidence import verify_revision_evidence
from zhidu.models import EnrichmentEvaluation, EventEnrichment, EventRevision, IntelEvent


class EntityExpectation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str
    value: str
    ecosystem: str | None = None


class PackageExpectation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ecosystem: str
    name: str
    vulnerable_raw: str | None = None


class EnrichmentCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=100)
    source_id: str
    external_id: str
    kind: str | None = None
    severity: str | None = None
    quality_flags: list[str] | None = None
    entities: list[EntityExpectation] = Field(default_factory=list)
    packages: list[PackageExpectation] = Field(default_factory=list)
    has_cvss: bool | None = None
    has_cpe: bool | None = None
    has_version_scope: bool | None = None


class EnrichmentSuite(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = Field(min_length=1, max_length=100)
    labeled_at: str
    cases: list[EnrichmentCase] = Field(min_length=1)


def load_enrichment_suite(path: Path) -> EnrichmentSuite:
    return EnrichmentSuite.model_validate(json.loads(path.read_text()))


def _entity_match(actual: list[dict], expected: EntityExpectation) -> bool:
    return any(
        item.get("type") == expected.type
        and str(item.get("value", "")).casefold() == expected.value.casefold()
        and (expected.ecosystem is None or item.get("ecosystem") == expected.ecosystem)
        for item in actual
    )


def _package_match(actual: list[dict], expected: PackageExpectation) -> bool:
    return any(
        item.get("ecosystem") == expected.ecosystem
        and str(item.get("package", "")).casefold() == expected.name.casefold()
        and (
            expected.vulnerable_raw is None
            or (item.get("vulnerable") or {}).get("raw") == expected.vulnerable_raw
        )
        for item in actual
    )


def evaluate_enrichment(session, store, suite: EnrichmentSuite) -> EnrichmentEvaluation:
    details = []
    assertion_count = passed_count = positive_count = positive_passed = verified_cases = 0
    for case in suite.cases:
        event = session.scalar(
            select(IntelEvent).where(
                IntelEvent.source_id == case.source_id,
                IntelEvent.external_id == case.external_id,
            )
        )
        enrichment = session.get(EventEnrichment, event.id) if event else None
        assertions = []

        def check(name, passed, *, positive=False, expected=None, actual=None, _items=assertions):
            nonlocal assertion_count, passed_count, positive_count, positive_passed
            assertion_count += 1
            passed_count += bool(passed)
            positive_count += positive
            positive_passed += bool(positive and passed)
            _items.append(
                {"name": name, "passed": bool(passed), "expected": expected, "actual": actual}
            )

        check("event_exists", event is not None, expected=True, actual=bool(event))
        check(
            "enrichment_exists",
            enrichment is not None,
            expected=True,
            actual=bool(enrichment),
        )
        # Missing records still contribute every expected assertion to the
        # denominator, including negative assertions. Absence is not a pass.
        for field in ("kind", "severity"):
            expected = getattr(case, field)
            if expected is not None:
                actual = getattr(event, field, None)
                check(field, bool(event) and actual == expected, expected=expected, actual=actual)
        if case.quality_flags is not None:
            actual = sorted(enrichment.quality_flags) if enrichment else None
            check(
                "quality_flags",
                actual == sorted(case.quality_flags),
                expected=sorted(case.quality_flags),
                actual=actual,
            )
        for expected in case.entities:
            check(
                f"entity:{expected.type}:{expected.value}",
                bool(enrichment) and _entity_match(enrichment.entities, expected),
                positive=True,
                expected=expected.model_dump(),
            )
        for expected in case.packages:
            check(
                f"package:{expected.ecosystem}:{expected.name}",
                bool(enrichment) and _package_match(enrichment.version_ranges, expected),
                positive=True,
                expected=expected.model_dump(),
            )
        for name, expected, actual in (
            (
                "has_cvss",
                case.has_cvss,
                bool(enrichment.cvss.get("entries")) if enrichment else None,
            ),
            ("has_cpe", case.has_cpe, bool(enrichment.cpe_matches) if enrichment else None),
            (
                "has_version_scope",
                case.has_version_scope,
                bool(enrichment.version_ranges) if enrichment else None,
            ),
        ):
            if expected is not None:
                check(
                    name,
                    bool(enrichment) and actual is expected,
                    positive=expected,
                    expected=expected,
                    actual=actual,
                )
        revision = session.get(EventRevision, enrichment.revision_id) if enrichment else None
        if (
            revision
            and event
            and revision.event_id == event.id
            and revision.number == event.revision
        ):
            verification = verify_revision_evidence(session, store, revision)
            evidence_pass = (
                verification["summary"]["failed"] == 0 and verification["summary"]["total"] > 0
            )
            verified_cases += evidence_pass
        else:
            evidence_pass = False
        details.append(
            {
                "id": case.id,
                "source_id": case.source_id,
                "external_id": case.external_id,
                "revision_id": revision.id if revision else None,
                "revision_fingerprint": revision.fingerprint if revision else None,
                "assertions": assertions,
                "passed": bool(assertions) and all(item["passed"] for item in assertions),
                "evidence_pass": evidence_pass,
            }
        )
    row = EnrichmentEvaluation(
        suite_version=suite.version,
        case_count=len(suite.cases),
        assertion_count=assertion_count,
        assertion_accuracy=passed_count / assertion_count if assertion_count else 0,
        expected_fact_recall=positive_passed / positive_count if positive_count else 0,
        evidence_verifiable_rate=verified_cases / len(suite.cases),
        details=details,
    )
    session.add(row)
    session.flush()
    return row


def enrichment_evaluation_view(row: EnrichmentEvaluation) -> dict:
    data = {column.name: getattr(row, column.name) for column in row.__table__.columns}
    data["metric_scope"] = (
        "regression characterization assertions derived from inspected outputs; "
        "not independently human-labeled gold data and "
        "not population-wide enrichment accuracy or recall"
    )
    return data
