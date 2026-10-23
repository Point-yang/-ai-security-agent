"""Persistent multi-turn research sessions and deterministic evidence hops."""

import hashlib
import json

from sqlalchemy import func, select, update

from zhidu.answers import ExtractiveAnswerRequest, make_extractive_answer
from zhidu.comparisons import comparison_view
from zhidu.evidence import event_trace
from zhidu.models import (
    Asset,
    AssetComponent,
    AssetExposure,
    Conversation,
    ConversationHop,
    ConversationMessage,
    EventAlias,
    EventEnrichment,
    EventRevision,
    EvidenceTask,
    IntelEvent,
    IntelligenceComparison,
    RawDocument,
    now_utc,
)

TRACE_VERSION = "conversation-trace-v1"
RECOMMENDATION_RULE_VERSION = "asset-priority-v1"
EXPLICIT_SWITCH_TERMS = (
    "另一个资产",
    "其他资产",
    "切换资产",
    "换一个资产",
    "another asset",
    "different asset",
    "switch asset",
)


def _safe(value):
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def _canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _unique_refs(refs: list[dict]) -> list[dict]:
    result, seen = [], set()
    for ref in refs:
        key = (
            ref.get("event_id"),
            ref.get("revision_id"),
            ref.get("raw_document_id"),
            ref.get("json_pointer"),
        )
        if None in key or key in seen:
            continue
        seen.add(key)
        result.append(ref)
    return sorted(
        result,
        key=lambda item: (
            item["event_id"],
            item["revision_id"],
            item["raw_document_id"],
            item["json_pointer"],
        ),
    )


def _revision_ref(session, event_id: str, revision_id: str, pointer: str | None) -> dict | None:
    if not pointer:
        return None
    revision = session.get(EventRevision, revision_id)
    if revision is None:
        return None
    document = session.get(RawDocument, revision.raw_document_id)
    if document is None:
        return None
    return {
        "event_id": event_id,
        "revision_id": revision.id,
        "raw_document_id": document.id,
        "json_pointer": pointer,
        "sha256": document.sha256,
        "verification": "stored_evidence_reference",
    }


def _fallback_revision_ref(session, event_id: str, revision_id: str) -> dict | None:
    revision = session.get(EventRevision, revision_id)
    if revision is None:
        return None
    pointer = next(
        (item.get("json_pointer") for item in revision.evidence if item.get("json_pointer")), None
    )
    return _revision_ref(session, event_id, revision_id, pointer)


def _hop(hop_order: int, hop_type: str, input_data, output_data, refs) -> dict:
    return {
        "hop_order": hop_order,
        "hop_type": hop_type,
        "input_data": _safe(input_data),
        "output_data": _safe(output_data),
        "evidence_refs": _safe(_unique_refs([item for item in refs if item])),
    }


def _event_view(event: IntelEvent) -> dict:
    return {
        "id": event.id,
        "source_id": event.source_id,
        "external_id": event.external_id,
        "title": event.title,
        "severity": event.severity,
        "revision": event.revision,
    }


def _comparison_refs(session, comparison: IntelligenceComparison) -> list[dict]:
    refs = []
    for observation in comparison.observations:
        ref = _revision_ref(
            session,
            observation.get("event_id"),
            observation.get("revision_id"),
            observation.get("json_pointer"),
        ) or _fallback_revision_ref(
            session, observation.get("event_id"), observation.get("revision_id")
        )
        if ref:
            refs.append(ref)
    return _unique_refs(refs)


def build_hops(session, store, audit, request: dict, asset_id: str | None) -> list[dict]:
    citation_refs = [
        {
            "event_id": item.get("event_id"),
            "revision_id": item.get("revision_id"),
            "raw_document_id": item.get("raw_document_id"),
            "json_pointer": item.get("json_pointer"),
            "sha256": item.get("sha256"),
            "verification": item.get("verification"),
        }
        for item in audit.citations
    ]
    event_ids = {item.get("event_id") for item in audit.citations if item.get("event_id")}
    events = [session.get(IntelEvent, event_id) for event_id in sorted(event_ids)]
    events = [event for event in events if event]
    hops = [
        _hop(
            1,
            "event_selection",
            {
                "question": request["question"],
                "query": request.get("query") or request["question"],
                "explicit_event_id": request.get("event_id"),
            },
            {"events": [_event_view(event) for event in events]},
            citation_refs,
        )
    ]

    identifier_rows = (
        session.execute(
            select(EventAlias.event_id, EventAlias.value).where(EventAlias.event_id.in_(event_ids))
        ).all()
        if event_ids
        else []
    )
    identifiers = sorted(
        {value.upper() for _, value in identifier_rows if value.upper().startswith("CVE-")}
    )
    comparisons = (
        session.scalars(
            select(IntelligenceComparison)
            .where(
                IntelligenceComparison.identifier.in_(identifiers),
                IntelligenceComparison.is_active.is_(True),
            )
            .order_by(IntelligenceComparison.identifier, IntelligenceComparison.field)
        ).all()
        if identifiers
        else []
    )
    comparison_refs = []
    comparison_output = []
    comparison_event_ids = set(event_ids)
    for comparison in comparisons:
        refs = _comparison_refs(session, comparison)
        comparison_refs.extend(refs)
        comparison_event_ids.update(
            item.get("event_id") for item in comparison.observations if item.get("event_id")
        )
        comparison_output.append(
            {
                "id": comparison.id,
                "identifier": comparison.identifier,
                "field": comparison.field,
                "status": comparison.status,
                "review_status": comparison.review_status,
                "annotation_version": comparison.annotation_version,
                "observations": comparison.observations,
                "automatic_resolution": False,
            }
        )
    hops.append(
        _hop(
            2,
            "cross_source_comparison",
            {"identifiers": identifiers, "event_ids": sorted(event_ids)},
            {"comparisons": comparison_output, "automatic_resolution": False},
            comparison_refs or citation_refs,
        )
    )

    exposures = []
    exposure_refs = []
    if asset_id and comparison_event_ids:
        exposures = session.scalars(
            select(AssetExposure)
            .where(
                AssetExposure.asset_id == asset_id,
                AssetExposure.event_id.in_(comparison_event_ids),
            )
            .order_by(AssetExposure.status, AssetExposure.event_id, AssetExposure.component_id)
        ).all()
        for exposure in exposures:
            ref_count = len(exposure_refs)
            for evidence in exposure.evidence:
                pointer = (evidence.get("source") or {}).get("json_pointer")
                ref = _revision_ref(session, exposure.event_id, exposure.revision_id, pointer)
                if ref:
                    exposure_refs.append(ref)
            if len(exposure_refs) == ref_count:
                fallback = _fallback_revision_ref(session, exposure.event_id, exposure.revision_id)
                if fallback:
                    exposure_refs.append(fallback)
    exposure_output = []
    for exposure in exposures:
        component = session.get(AssetComponent, exposure.component_id)
        event = session.get(IntelEvent, exposure.event_id)
        exposure_output.append(
            {
                "id": exposure.id,
                "status": exposure.status,
                "reason": exposure.reason,
                "component": {
                    "id": component.id,
                    "ecosystem": component.ecosystem,
                    "name": component.name,
                    "version": component.version,
                },
                "event": _event_view(event),
                "revision_id": exposure.revision_id,
                "evidence": exposure.evidence,
                "independent_verification": False,
            }
        )
    hops.append(
        _hop(
            3,
            "asset_exposure",
            {"asset_id": asset_id, "event_ids": sorted(comparison_event_ids)},
            {"exposures": exposure_output, "independent_verification": False},
            exposure_refs or comparison_refs or citation_refs,
        )
    )

    trace_event_ids = sorted(comparison_event_ids | {row.event_id for row in exposures})
    trace_output, trace_refs = [], []
    for event_id in trace_event_ids:
        event = session.get(IntelEvent, event_id)
        if event is None:
            continue
        trace = event_trace(session, store, event)
        trace_output.append(
            {
                "event": trace["event"],
                "summary": trace["summary"],
                "timeline": [
                    {
                        "revision_id": item["revision_id"],
                        "number": item["number"],
                        "disposition": item["disposition"],
                        "is_effective_current": item["is_effective_current"],
                        "raw_document": item["raw_document"],
                        "delta_from_previous_observation": item["delta_from_previous_observation"],
                    }
                    for item in trace["timeline"]
                ],
            }
        )
        for item in trace["timeline"]:
            revision = item["evidence_verification"]
            for evidence in revision["items"]:
                ref = _revision_ref(
                    session, event_id, item["revision_id"], evidence.get("json_pointer")
                )
                if ref:
                    ref["integrity_status"] = evidence.get("status")
                    trace_refs.append(ref)
    hops.append(
        _hop(
            4,
            "event_trace",
            {"event_ids": trace_event_ids},
            {"traces": trace_output, "integrity_scope": "stored_source_evidence"},
            trace_refs or exposure_refs or comparison_refs or citation_refs,
        )
    )

    all_refs = _unique_refs(citation_refs + comparison_refs + exposure_refs + trace_refs)
    hops.append(
        _hop(
            5,
            "raw_evidence",
            {"reference_count": len(all_refs)},
            {
                "verified_reference_count": sum(
                    item.get("integrity_status", "verified") == "verified" for item in all_refs
                ),
                "references": all_refs,
                "verification_scope": "integrity_and_provenance_not_source_truth",
            },
            all_refs,
        )
    )
    return hops


def _task(
    task_type,
    missing_fields,
    target_sources,
    completion_conditions,
    refs,
    comparison_id=None,
):
    return {
        "comparison_id": comparison_id,
        "task_type": task_type,
        "status": "pending",
        "missing_fields": sorted(set(missing_fields)),
        "target_sources": sorted(set(target_sources)),
        "completion_conditions": completion_conditions,
        "evidence_refs": _unique_refs(refs),
        "network_verification_status": "not_started",
    }


def derive_evidence_tasks(session, hops: list[dict]) -> list[dict]:
    tasks = []
    exposure_hop = next(item for item in hops if item["hop_type"] == "asset_exposure")
    comparison_hop = next(item for item in hops if item["hop_type"] == "cross_source_comparison")
    for exposure in exposure_hop["output_data"]["exposures"]:
        if exposure["status"] != "unknown":
            continue
        tasks.append(
            _task(
                "unknown_asset_condition",
                ["parseable_source_version_condition"],
                [exposure["event"]["source_id"]],
                [
                    "来源发布新的 event revision",
                    "版本条件可安全解析并重新生成 exposure",
                    "新 revision 的原文 SHA-256 与 JSON Pointer 可复验",
                ],
                exposure_hop["evidence_refs"],
            )
        )
    for comparison in comparison_hop["output_data"]["comparisons"]:
        if comparison["status"] != "conflict":
            continue
        refs = _comparison_refs(session, session.get(IntelligenceComparison, comparison["id"]))
        tasks.append(
            _task(
                "cross_source_conflict",
                [f"resolved_or_source_scoped_{comparison['field']}_rationale"],
                [item["source_id"] for item in comparison["observations"]],
                [
                    "人工复核记录各来源适用范围与评分版本",
                    "保留冲突 observation，不自动选择最高值",
                    "每项结论绑定 event/revision/raw document/JSON Pointer",
                ],
                refs,
                comparison_id=comparison["id"],
            )
        )
    event_ids = {
        ref["event_id"] for hop in hops for ref in hop["evidence_refs"] if ref.get("event_id")
    }
    for event_id in sorted(event_ids):
        enrichment = session.get(EventEnrichment, event_id)
        if enrichment is None or not enrichment.quality_flags:
            continue
        event = session.get(IntelEvent, event_id)
        refs = [
            ref for hop in hops for ref in hop["evidence_refs"] if ref.get("event_id") == event_id
        ]
        tasks.append(
            _task(
                "source_quality_gap",
                enrichment.quality_flags,
                [event.source_id],
                [
                    "目标来源提供缺失字段或可解析表达式",
                    "新 revision 通过字段证据完整性复验",
                    "重新富化后对应 quality flag 消失",
                ],
                refs,
            )
        )
    unique = {}
    for task in tasks:
        key = (task["task_type"], task.get("comparison_id"), tuple(task["missing_fields"]))
        unique[key] = task
    return list(unique.values())


def asset_recommendations(session, asset: Asset, limit: int = 20) -> dict:
    components = session.scalars(
        select(AssetComponent)
        .where(AssetComponent.asset_id == asset.id)
        .order_by(AssetComponent.ecosystem, AssetComponent.name, AssetComponent.version)
    ).all()
    exposures = session.scalars(
        select(AssetExposure)
        .where(AssetExposure.asset_id == asset.id)
        .order_by(AssetExposure.status, AssetExposure.event_id)
    ).all()
    criticality_weight = {"critical": 40, "high": 30, "medium": 20, "low": 10}.get(
        asset.criticality, 10
    )
    environment_weight = {
        "production": 20,
        "prod": 20,
        "staging": 10,
        "demo": 5,
        "development": 5,
        "dev": 5,
    }.get(asset.environment.casefold(), 0)
    recommendations = []
    for exposure in exposures:
        if exposure.status == "not_affected":
            continue
        component = session.get(AssetComponent, exposure.component_id)
        event = session.get(IntelEvent, exposure.event_id)
        status_weight = 30 if exposure.status == "affected" else 20
        fixed_values = sorted(
            {
                ((item.get("source") or {}).get("fixed") or {}).get("raw")
                for item in exposure.evidence
                if ((item.get("source") or {}).get("fixed") or {}).get("raw")
            }
        )
        if exposure.status == "unknown":
            action = "优先复核"
            advice = f"核对 {event.external_id} 的版本条件：{exposure.reason}"
        elif fixed_values:
            action = "升级建议"
            advice = f"评估来源声明的修复版本 {', '.join(fixed_values)}，变更前仍需兼容性验证。"
        else:
            action = "优先复核"
            advice = "来源条件命中但没有可用修复版本；先核对上游公告与缓解措施。"
        score = criticality_weight + environment_weight + status_weight
        recommendations.append(
            {
                "action": action,
                "priority": "P0" if score >= 80 else "P1" if score >= 60 else "P2",
                "rule_score": score,
                "score_semantics": "workflow_order_not_probability",
                "component": {
                    "id": component.id,
                    "ecosystem": component.ecosystem,
                    "name": component.name,
                    "version": component.version,
                },
                "event": _event_view(event),
                "exposure_id": exposure.id,
                "exposure_status": exposure.status,
                "advice": advice,
                "basis": [
                    f"asset.environment={asset.environment}",
                    f"asset.criticality={asset.criticality}",
                    f"exposure.status={exposure.status}",
                ],
            }
        )
    recommendations.sort(
        key=lambda item: (-item["rule_score"], item["component"]["name"], item["event"]["id"])
    )
    return {
        "rule_version": RECOMMENDATION_RULE_VERSION,
        "selected_asset": {
            "id": asset.id,
            "name": asset.name,
            "environment": asset.environment,
            "criticality": asset.criticality,
            "sbom_sha256": asset.sbom_sha256,
            "components": [
                {
                    "id": item.id,
                    "ecosystem": item.ecosystem,
                    "name": item.name,
                    "version": item.version,
                }
                for item in components
            ],
        },
        "recommendations": recommendations[:limit],
        "ranking_is_probability": False,
        "independent_verification": False,
        "note": "建议只使用明确选择资产的环境、重要度、组件和来源条件比较。",
    }


def create_conversation(session, title: str, asset_id: str | None = None) -> Conversation:
    if asset_id and session.get(Asset, asset_id) is None:
        raise LookupError("asset not found")
    row = Conversation(title=title, active_asset_id=asset_id)
    session.add(row)
    session.flush()
    return row


def conversation_view(session, row: Conversation) -> dict:
    message_count = (
        session.scalar(
            select(func.count())
            .select_from(ConversationMessage)
            .where(ConversationMessage.conversation_id == row.id)
        )
        or 0
    )
    task_count = (
        session.scalar(
            select(func.count())
            .select_from(EvidenceTask)
            .where(
                EvidenceTask.conversation_id == row.id,
                EvidenceTask.status == "pending",
            )
        )
        or 0
    )
    asset = session.get(Asset, row.active_asset_id) if row.active_asset_id else None
    return {
        "id": row.id,
        "title": row.title,
        "active_asset": (
            {
                "id": asset.id,
                "name": asset.name,
                "environment": asset.environment,
                "criticality": asset.criticality,
            }
            if asset
            else None
        ),
        "state_version": row.state_version,
        "message_count": message_count,
        "pending_evidence_tasks": task_count,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def hop_view(row: ConversationHop) -> dict:
    return {column.name: getattr(row, column.name) for column in row.__table__.columns}


def task_view(row: EvidenceTask) -> dict:
    return {column.name: getattr(row, column.name) for column in row.__table__.columns}


def message_view(session, row: ConversationMessage) -> dict:
    data = {column.name: getattr(row, column.name) for column in row.__table__.columns}
    data["hops"] = [
        hop_view(item)
        for item in session.scalars(
            select(ConversationHop)
            .where(ConversationHop.assistant_message_id == row.id)
            .order_by(ConversationHop.hop_order)
        ).all()
    ]
    data["evidence_tasks"] = [
        task_view(item)
        for item in session.scalars(
            select(EvidenceTask)
            .where(EvidenceTask.message_id == row.id)
            .order_by(EvidenceTask.created_at, EvidenceTask.id)
        ).all()
    ]
    return data


def replay_conversation(session, row: Conversation) -> dict:
    messages = [
        message_view(session, item)
        for item in session.scalars(
            select(ConversationMessage)
            .where(ConversationMessage.conversation_id == row.id)
            .order_by(ConversationMessage.sequence)
        ).all()
    ]
    snapshot = {
        "trace_version": TRACE_VERSION,
        "conversation": conversation_view(session, row),
        "messages": messages,
    }
    snapshot["replay_sha256"] = hashlib.sha256(_canonical(_safe(snapshot)).encode()).hexdigest()
    return snapshot


def conversation_context_status(session, row: Conversation) -> dict:
    """Live validity overlay, deliberately excluded from immutable replay hashes."""
    from zhidu.rag_context import citation_freshness

    messages = session.scalars(
        select(ConversationMessage).where(ConversationMessage.conversation_id == row.id)
    ).all()
    comparisons = {}
    for message in messages:
        for hop in session.scalars(
            select(ConversationHop).where(ConversationHop.assistant_message_id == message.id)
        ):
            for snapshot in hop.output_data.get("comparisons", []):
                current = session.get(IntelligenceComparison, snapshot["id"])
                key = (snapshot["id"], snapshot.get("annotation_version"))
                comparisons[key] = {
                    "id": snapshot["id"],
                    "identifier": snapshot["identifier"],
                    "snapshot_version": snapshot.get("annotation_version"),
                    "current_version": current.annotation_version if current else None,
                    "is_active": bool(current and current.is_active),
                    "retired_at": current.retired_at if current else None,
                    "stale": not current
                    or not current.is_active
                    or current.annotation_version != snapshot.get("annotation_version"),
                }
    return {
        "conversation_id": row.id,
        "comparisons": list(comparisons.values()),
        "citations": citation_freshness(
            session, [c for message in messages for c in message.citations]
        ),
        "historical_snapshot_unchanged": True,
        "note": "历史快照用于追溯；归档或已更新的比较项不能作为当前结论。",
    }


def submit_turn(session, store, conversation: Conversation, body) -> dict:
    session.execute(
        update(Conversation)
        .where(Conversation.id == conversation.id)
        .values(state_version=Conversation.state_version)
    )
    session.refresh(conversation)
    explicit_asset_id = body.asset_id
    switch_requested = any(term in body.question.casefold() for term in EXPLICIT_SWITCH_TERMS)
    if explicit_asset_id:
        if session.get(Asset, explicit_asset_id) is None:
            raise LookupError("asset not found")
        effective_asset_id = explicit_asset_id
        conversation.active_asset_id = explicit_asset_id
    elif switch_requested:
        effective_asset_id = None
    else:
        effective_asset_id = conversation.active_asset_id
    answer_request = ExtractiveAnswerRequest(
        question=body.question,
        query=body.query,
        pool=body.pool,
        origin=body.origin,
        asset_id=effective_asset_id,
        event_id=body.event_id,
        limit=body.limit,
    )
    audit = make_extractive_answer(session, answer_request)
    if switch_requested and not explicit_asset_id and audit.status != "asset_context_required":
        audit.status = "asset_context_required"
        audit.answer = "问题要求切换资产，但没有显式提供 asset_id；会话不会从自然语言猜测资产。"
        audit.citations = []
        audit.constraints = [
            {
                "code": "explicit_asset_switch_required",
                "rule": "切换资产必须显式提交 asset_id，不能根据自然语言名称或指代猜测。",
            }
        ]
        audit.asset_id = None
        audit.asset_context = None
    next_sequence = (
        session.scalar(
            select(func.max(ConversationMessage.sequence)).where(
                ConversationMessage.conversation_id == conversation.id
            )
        )
        or 0
    ) + 1
    request_snapshot = body.model_dump()
    user_message = ConversationMessage(
        conversation_id=conversation.id,
        sequence=next_sequence,
        role="user",
        content=body.question,
        request=request_snapshot,
        explicit_asset_id=explicit_asset_id,
        effective_asset_id=effective_asset_id,
        selected_event_ids=[body.event_id] if body.event_id else [],
        citations=[],
        constraints=[],
    )
    session.add(user_message)
    session.flush()
    selected_event_ids = sorted(
        {item.get("event_id") for item in audit.citations if item.get("event_id")}
    )
    assistant_message = ConversationMessage(
        conversation_id=conversation.id,
        sequence=next_sequence + 1,
        role="assistant",
        content=audit.answer,
        request=None,
        answer_status=audit.status,
        explicit_asset_id=explicit_asset_id,
        effective_asset_id=effective_asset_id,
        selected_event_ids=selected_event_ids,
        citations=audit.citations,
        constraints=audit.constraints,
        answer_audit_id=audit.id,
    )
    session.add(assistant_message)
    session.flush()
    hops = build_hops(session, store, audit, request_snapshot, effective_asset_id)
    for item in hops:
        session.add(ConversationHop(assistant_message_id=assistant_message.id, **item))
    tasks = derive_evidence_tasks(session, hops)
    for item in tasks:
        session.add(
            EvidenceTask(
                conversation_id=conversation.id,
                message_id=assistant_message.id,
                **item,
            )
        )
    conversation.state_version += 1
    conversation.updated_at = now_utc()
    session.flush()
    recommendation = None
    if effective_asset_id:
        recommendation = asset_recommendations(session, session.get(Asset, effective_asset_id))
    return {
        "conversation": conversation_view(session, conversation),
        "user_message": message_view(session, user_message),
        "assistant_message": message_view(session, assistant_message),
        "recommendations": recommendation,
        "context_policy": {
            "asset_inherited": bool(
                effective_asset_id and not explicit_asset_id and not switch_requested
            ),
            "asset_switch_requires_explicit_id": True,
            "natural_language_asset_guessing": False,
        },
    }


def comparison_review_context(session, store, comparison: IntelligenceComparison) -> dict:
    from zhidu.models import ComparisonReviewChange

    sources = []
    for observation in comparison.observations:
        event = session.get(IntelEvent, observation["event_id"])
        sources.append(
            {
                "observation": observation,
                "trace": event_trace(session, store, event),
                "evidence_refs": _comparison_refs(session, comparison),
            }
        )
    changes = session.scalars(
        select(ComparisonReviewChange)
        .where(ComparisonReviewChange.comparison_id == comparison.id)
        .order_by(ComparisonReviewChange.annotation_version, ComparisonReviewChange.created_at)
    ).all()
    transitions = []
    before = {"version": 0, "review_status": "unreviewed", "analyst_note": ""}
    for change in changes:
        after = {
            "version": change.annotation_version,
            "review_status": change.review_status,
            "analyst_note": change.analyst_note,
            "created_at": change.created_at,
        }
        transitions.append(
            {
                "before": before,
                "after": after,
                "change_kind": change.change_kind,
                "observations": change.observations,
            }
        )
        before = after
    return {
        "comparison": comparison_view(comparison),
        "source_traces": sources,
        "review_transitions": transitions,
        "automatic_resolution": False,
        "note": "人工复核保存前后版本与备注，不改变来源 observation 或自动选取胜方。",
    }
