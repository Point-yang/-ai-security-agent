"""Fixed evaluation for persistent conversations and deterministic evidence hops."""

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from zhidu.conversations import (
    comparison_review_context,
    create_conversation,
    replay_conversation,
    submit_turn,
)
from zhidu.models import (
    Asset,
    ConversationEvaluation,
    IntelEvent,
    IntelligenceComparison,
)
from zhidu.schemas import ConversationTurnCreate


class ConversationEvaluationSuite(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = Field(min_length=1, max_length=100)
    primary_asset_name: str = Field(min_length=1, max_length=300)
    secondary_asset_name: str = Field(min_length=1, max_length=300)
    conflict_external_id: str = Field(min_length=1, max_length=100)
    conflict_source_id: str = Field(min_length=1, max_length=50)
    unknown_external_id: str = Field(min_length=1, max_length=100)
    unknown_source_id: str = Field(min_length=1, max_length=50)


def load_conversation_suite(path: Path) -> ConversationEvaluationSuite:
    return ConversationEvaluationSuite.model_validate_json(path.read_text())


def _asset(session, name):
    row = session.scalar(select(Asset).where(Asset.name == name))
    if row is None:
        raise LookupError(f"asset not found: {name}")
    return row


def _event(session, external_id, source_id):
    row = session.scalar(
        select(IntelEvent).where(
            IntelEvent.external_id == external_id,
            IntelEvent.source_id == source_id,
        )
    )
    if row is None:
        raise LookupError(f"event not found: {source_id}/{external_id}")
    return row


def _turn(question, event, asset_id=None):
    return ConversationTurnCreate(
        question=question,
        query=event.external_id,
        asset_id=asset_id,
        event_id=event.id,
        origin="live",
        limit=1,
    )


def _detail(case_id, category, passed, **values):
    return {"id": case_id, "category": category, "passed": passed, **values}


def evaluate_conversations(session, store, suite: ConversationEvaluationSuite):
    primary = _asset(session, suite.primary_asset_name)
    secondary = _asset(session, suite.secondary_asset_name)
    conflict_event = _event(session, suite.conflict_external_id, suite.conflict_source_id)
    unknown_event = _event(session, suite.unknown_external_id, suite.unknown_source_id)
    details = []

    inherited_session = create_conversation(
        session, f"{suite.version}:context-inheritance", primary.id
    )
    inherited = submit_turn(
        session,
        store,
        inherited_session,
        _turn("它对当前资产有什么影响？", conflict_event),
    )
    inherited_pass = (
        inherited["context_policy"]["asset_inherited"]
        and inherited["assistant_message"]["effective_asset_id"] == primary.id
    )
    details.append(
        _detail(
            "context-inheritance",
            "multiturn",
            inherited_pass,
            conversation_id=inherited_session.id,
            effective_asset_id=inherited["assistant_message"]["effective_asset_id"],
        )
    )

    switch_session = create_conversation(session, f"{suite.version}:asset-switch", primary.id)
    switched = submit_turn(
        session,
        store,
        switch_session,
        _turn("显式切换资产后重新检查。", conflict_event, secondary.id),
    )
    switch_pass = switched["conversation"]["active_asset"]["id"] == secondary.id
    details.append(
        _detail(
            "explicit-asset-switch",
            "multiturn",
            switch_pass,
            conversation_id=switch_session.id,
            effective_asset_id=switched["assistant_message"]["effective_asset_id"],
        )
    )

    refused_session = create_conversation(session, f"{suite.version}:implicit-rejection")
    refused = submit_turn(
        session,
        store,
        refused_session,
        _turn("另一个资产是否受影响？", conflict_event),
    )
    refusal_pass = (
        refused["assistant_message"]["answer_status"] == "asset_context_required"
        and not refused["assistant_message"]["citations"]
        and refused["context_policy"]["natural_language_asset_guessing"] is False
    )
    details.append(
        _detail(
            "implicit-asset-rejection",
            "multiturn",
            refusal_pass,
            conversation_id=refused_session.id,
            answer_status=refused["assistant_message"]["answer_status"],
        )
    )

    chain_session = create_conversation(session, f"{suite.version}:full-chain", primary.id)
    chain = submit_turn(
        session,
        store,
        chain_session,
        _turn("沿完整证据链核验该公告。", conflict_event),
    )
    hops = chain["assistant_message"]["hops"]
    expected_hops = [
        "event_selection",
        "cross_source_comparison",
        "asset_exposure",
        "event_trace",
        "raw_evidence",
    ]
    complete_refs = all(
        item["evidence_refs"]
        and all(
            {"event_id", "revision_id", "raw_document_id", "json_pointer"} <= set(ref)
            for ref in item["evidence_refs"]
        )
        for item in hops
    )
    replay_one = replay_conversation(session, chain_session)
    replay_two = replay_conversation(session, chain_session)
    replay_pass = replay_one["replay_sha256"] == replay_two["replay_sha256"]
    recommendation = chain["recommendations"]
    recommendation_pass = (
        recommendation["selected_asset"]["id"] == primary.id
        and recommendation["ranking_is_probability"] is False
        and all(
            set(item["basis"])
            <= {
                f"asset.environment={primary.environment}",
                f"asset.criticality={primary.criticality}",
                "exposure.status=affected",
                "exposure.status=unknown",
            }
            for item in recommendation["recommendations"]
        )
    )
    chain_pass = [item["hop_type"] for item in hops] == expected_hops and complete_refs
    details.append(
        _detail(
            "complete-five-hop-chain",
            "multihop",
            chain_pass,
            conversation_id=chain_session.id,
            hop_types=[item["hop_type"] for item in hops],
            evidence_refs_complete=complete_refs,
            replay_deterministic=replay_pass,
            recommendation_boundary_pass=recommendation_pass,
        )
    )

    unknown_session = create_conversation(session, f"{suite.version}:unknown-task", primary.id)
    unknown = submit_turn(
        session,
        store,
        unknown_session,
        _turn("unknown 结果需要补充哪些证据？", unknown_event),
    )
    unknown_tasks = [
        item
        for item in unknown["assistant_message"]["evidence_tasks"]
        if item["task_type"] == "unknown_asset_condition"
    ]
    unknown_pass = bool(unknown_tasks) and all(
        item["status"] == "pending"
        and item["network_verification_status"] == "not_started"
        and item["completion_conditions"]
        for item in unknown_tasks
    )
    details.append(
        _detail(
            "unknown-dynamic-evidence-task",
            "multihop",
            unknown_pass,
            conversation_id=unknown_session.id,
            evidence_tasks=unknown_tasks,
        )
    )

    conflict_ids = [
        item["comparison_id"]
        for item in chain["assistant_message"]["evidence_tasks"]
        if item.get("comparison_id")
    ]
    conflict = next(
        (
            session.get(IntelligenceComparison, comparison_id)
            for comparison_id in conflict_ids
            if session.get(IntelligenceComparison, comparison_id).field == "severity"
        ),
        None,
    )
    if conflict is None:
        raise LookupError("severity conflict not found for fixed evaluation case")
    context = comparison_review_context(session, store, conflict)
    conflict_pass = (
        context["automatic_resolution"] is False
        and len(context["source_traces"]) >= 2
        and all(item["evidence_refs"] for item in context["source_traces"])
    )
    details.append(
        _detail(
            "severity-conflict-review-context",
            "multihop",
            conflict_pass,
            comparison_id=conflict.id,
            source_trace_count=len(context["source_traces"]),
            automatic_resolution=context["automatic_resolution"],
        )
    )

    conversation_pass_rate = sum(item["passed"] for item in details) / len(details)
    hop_cases = [item for item in details if item["category"] == "multihop"]
    hop_evidence_rate = sum(item["passed"] for item in hop_cases) / len(hop_cases)
    task_boundary_rate = float(unknown_pass)
    result = ConversationEvaluation(
        suite_version=suite.version,
        case_count=len(details),
        conversation_pass_rate=conversation_pass_rate,
        hop_evidence_rate=hop_evidence_rate,
        replay_determinism_rate=float(replay_pass),
        task_boundary_rate=task_boundary_rate,
        recommendation_boundary_rate=float(recommendation_pass),
        details=_json_safe(details),
    )
    session.add(result)
    session.flush()
    return result


def _json_safe(value):
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def conversation_evaluation_view(row: ConversationEvaluation) -> dict:
    data = {column.name: getattr(row, column.name) for column in row.__table__.columns}
    data["metric_scope"] = (
        "fixed persistent-session and deterministic-evidence-path cases; "
        "not free-form reasoning accuracy or network verification"
    )
    return data
