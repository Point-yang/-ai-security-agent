"""Fixed-suite evaluation for asset exposure and comparison evidence boundaries."""

import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select

from zhidu.models import (
    Asset,
    AssetComponent,
    AssetEvaluation,
    AssetExposure,
    EventRevision,
    IntelEvent,
    IntelligenceComparison,
    RawDocument,
)
from zhidu.sources import resolve_pointer


class AssetEvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=100)
    kind: Literal["exposure", "no_identity", "comparison"]
    expected_status: Literal[
        "affected", "not_affected", "unknown", "absent", "agreement", "variation", "conflict"
    ]
    external_id: str | None = None
    source_id: str | None = None
    component_name: str | None = None
    component_version: str | None = None
    identifier: str | None = None
    field: str | None = None

    @model_validator(mode="after")
    def required_selectors(self):
        if self.kind in {"exposure", "no_identity"} and not (
            self.external_id and self.component_name and self.component_version
        ):
            raise ValueError("exposure cases require external_id, component_name and version")
        if self.kind == "comparison" and not (self.identifier and self.field):
            raise ValueError("comparison cases require identifier and field")
        return self


class AssetEvaluationSuite(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = Field(min_length=1, max_length=100)
    asset_name: str = Field(min_length=1, max_length=300)
    cases: list[AssetEvaluationCase] = Field(min_length=1)


def load_asset_suite(path: Path) -> AssetEvaluationSuite:
    return AssetEvaluationSuite.model_validate(json.loads(path.read_text()))


def _verify_revision(session, store, revision_id: str, raw_document_id=None, pointer=None) -> bool:
    revision = session.get(EventRevision, revision_id)
    if revision is None:
        return False
    document = session.get(RawDocument, revision.raw_document_id)
    if document is None or (raw_document_id and document.id != raw_document_id):
        return False
    try:
        content = store.read(document.sha256)
        if hashlib.sha256(content).hexdigest() != document.sha256:
            return False
        if pointer:
            resolve_pointer(json.loads(content), pointer)
    except (OSError, ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError):
        return False
    return True


def _component(session, asset_id, name, version):
    return session.scalar(
        select(AssetComponent).where(
            AssetComponent.asset_id == asset_id,
            AssetComponent.name == name.casefold(),
            AssetComponent.version == version,
        )
    )


def _event(session, external_id, source_id=None):
    stmt = select(IntelEvent).where(IntelEvent.external_id == external_id)
    if source_id:
        stmt = stmt.where(IntelEvent.source_id == source_id)
    return session.scalar(stmt.order_by(IntelEvent.source_id, IntelEvent.id))


def _evaluate_exposure_case(session, store, asset, case):
    component = _component(session, asset.id, case.component_name, case.component_version)
    event = _event(session, case.external_id, case.source_id)
    row = None
    if component and event:
        row = session.scalar(
            select(AssetExposure).where(
                AssetExposure.component_id == component.id,
                AssetExposure.event_id == event.id,
            )
        )
    actual = row.status if row else "absent"
    verifications = []
    if row:
        for item in row.evidence:
            source = item.get("source") or {}
            verifications.append(
                item.get("event_id") == row.event_id
                and item.get("revision_id") == row.revision_id
                and _verify_revision(
                    session,
                    store,
                    row.revision_id,
                    pointer=source.get("json_pointer"),
                )
            )
        boundary_pass = bool(row.reason) and all(
            item.get("verification") == "source_asserted_asset_comparison" for item in row.evidence
        )
    else:
        # An absence conclusion is anchored to the chosen component and current event revision.
        revision = (
            session.scalar(
                select(EventRevision).where(
                    EventRevision.event_id == event.id,
                    EventRevision.number == event.revision,
                )
            )
            if event
            else None
        )
        verifications.append(
            bool(component and revision and _verify_revision(session, store, revision.id))
        )
        boundary_pass = case.kind == "no_identity" and actual == "absent"
    return {
        "actual_status": actual,
        "status_pass": actual == case.expected_status,
        "evidence_pass": bool(verifications) and all(verifications),
        "boundary_pass": boundary_pass,
        "component_id": component.id if component else None,
        "event_id": event.id if event else None,
        "revision_id": row.revision_id if row else (revision.id if event and revision else None),
        "evidence_items": len(verifications),
        "reason": row.reason if row else "no component/event exposure identity match",
    }


def _evaluate_comparison_case(session, store, case):
    row = session.scalar(
        select(IntelligenceComparison).where(
            IntelligenceComparison.identifier == case.identifier.upper(),
            IntelligenceComparison.field == case.field,
            IntelligenceComparison.is_active.is_(True),
        )
    )
    actual = row.status if row else "absent"
    verified = []
    for item in row.observations if row else []:
        verified.append(
            _verify_revision(
                session,
                store,
                item.get("revision_id"),
                raw_document_id=item.get("raw_document_id"),
                pointer=item.get("json_pointer"),
            )
        )
    return {
        "actual_status": actual,
        "status_pass": actual == case.expected_status,
        "evidence_pass": bool(verified) and all(verified),
        "boundary_pass": bool(row and row.status == "conflict"),
        "comparison_id": row.id if row else None,
        "observation_count": len(verified),
        "automatic_resolution": False,
    }


def evaluate_assets(session, store, suite: AssetEvaluationSuite) -> AssetEvaluation:
    asset = session.scalar(select(Asset).where(Asset.name == suite.asset_name))
    if asset is None:
        raise LookupError("evaluation asset not found")
    details = []
    for case in suite.cases:
        if case.kind == "comparison":
            result = _evaluate_comparison_case(session, store, case)
        else:
            result = _evaluate_exposure_case(session, store, asset, case)
        details.append({**case.model_dump(), **result})

    def rate(field):
        return round(sum(bool(item[field]) for item in details) / len(details), 4)

    row = AssetEvaluation(
        suite_version=suite.version,
        asset_id=asset.id,
        case_count=len(details),
        status_accuracy=rate("status_pass"),
        evidence_verifiable_rate=rate("evidence_pass"),
        boundary_pass_rate=rate("boundary_pass"),
        details=details,
    )
    session.add(row)
    session.flush()
    return row


def asset_evaluation_view(row: AssetEvaluation) -> dict:
    return {
        **{column.name: getattr(row, column.name) for column in row.__table__.columns},
        "metric_scope": (
            "fixed demo asset source-condition comparisons; not exploit reproduction or a "
            "complete asset safety assessment"
        ),
    }
