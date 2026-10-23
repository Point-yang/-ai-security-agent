"""Evidence-only answer packets and immutable server-side audit snapshots."""

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select

from zhidu.asset_matching import exposure_view
from zhidu.indexing import search_index
from zhidu.models import (
    AnswerAudit,
    Asset,
    AssetExposure,
    EventEnrichment,
    EventRevision,
    IntelEvent,
    SearchChunk,
)

POLICY_VERSION = "source-boundaries-v4"
ASSET_QUESTION_TERMS = (
    "我的资产",
    "该资产",
    "此资产",
    "资产是否",
    "my asset",
    "our asset",
)

CONSTRAINT_USAGE_RULE = (
    "constraints 是本轮检索与结构化字段的使用规则，不是可引用事实。"
    "不得将规则中的缺失、未解析或元数据边界改写为来源记录或公开资料不存在相应信息。"
    "limitations 只说明本轮证据范围，不复述未经引用支持的缺失事实；"
    "事实性否定结论也必须另列 statement 并引用支持它的来源原文。"
)

QUALITY_FLAG_RULES = {
    "missing_affected_scope": "若本次已检索片段及结构化字段未提供可用影响范围，不能据此判断版本是否受影响，也不能断言来源不存在该范围。",
    "missing_cpe_scope": "若本次 NVD 结构化字段未提供可用 CPE 条件，不能据此推断产品或资产不受影响，也不能断言 NVD 记录没有 CPE 条件。",
    "missing_cvss": "若本次已检索片段及结构化字段未提供可用 CVSS，不能把缺失值表述为零分或无风险，也不能断言来源没有评分。",
    "unparsed_version_range": "若本次结构化处理未能安全解析版本表达式，只能展示有引用支持的原始字符串，不能据此进行版本比较或修复版本推断。",
    "unknown_package_identity": "若本次结构化字段把软件包身份标为 unknown，不能把 unknown 当作真实组件名，也不能据此断言来源没有组件身份。",
    "metadata_only": "若本轮证据仅包含论文元数据，不能声称已读取或验证论文全文，也不能据此断言全文不存在或无法公开获取。",
    "catalog_scope_only": "若本轮证据仅包含目录字段，结论只能限于已引用字段，不能据此补全完整影响版本范围，也不能据此断言来源没有该范围。",
}

UNCERTAINTY_CODES = {
    "missing_affected_scope",
    "missing_cpe_scope",
    "missing_cvss",
    "unparsed_version_range",
    "unknown_package_identity",
    "metadata_only",
    "catalog_scope_only",
    "cvss_multiple_scores",
    "cpe_condition_not_asset_match",
}


class AuditCitationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    chunk_id: str = Field(min_length=1, max_length=64)
    retrieval_score: float = Field(ge=0)
    rank: int = Field(ge=1)


class AnswerAuditCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=10000)
    answer: str = Field(min_length=1, max_length=100000)
    retrieval_query: str = Field(min_length=1, max_length=10000)
    pool: Literal["formal", "candidate", "excluded"]
    model: str = Field(min_length=1, max_length=100)
    prompt_version: str = Field(min_length=1, max_length=100)
    asset_id: str | None = Field(default=None, max_length=36)
    citations: list[AuditCitationInput] = Field(min_length=1, max_length=100)

    @field_validator("question", "answer", "retrieval_query", "model", "prompt_version")
    @classmethod
    def non_blank(cls, value):
        if not value.strip():
            raise ValueError("must contain non-whitespace characters")
        return value.strip()


class ExtractiveAnswerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=1000)
    query: str | None = Field(default=None, max_length=200)
    pool: Literal["formal", "candidate"] = "formal"
    origin: Literal["live", "replay"] = "live"
    asset_id: str | None = Field(default=None, max_length=36)
    event_id: str | None = Field(default=None, max_length=36)
    limit: int = Field(default=5, ge=1, le=10)

    @field_validator("question")
    @classmethod
    def question_not_blank(cls, value):
        if not value.strip():
            raise ValueError("question must contain non-whitespace characters")
        return value.strip()

    @field_validator("query")
    @classmethod
    def query_not_blank(cls, value):
        if value is not None and not value.strip():
            raise ValueError("query must contain non-whitespace characters")
        return value.strip() if value else value


def source_constraints(source_id: str, kind: str, normalized: dict) -> list[dict]:
    constraints = [
        {
            "code": "source_asserted",
            "rule": "引用只支持来源声明，不得表述为独立验证。",
        },
        {"code": "constraint_usage", "rule": CONSTRAINT_USAGE_RULE},
    ]
    if source_id == "vllm-vendor":
        constraints.append(
            {
                "code": "vendor_patched_range",
                "rule": "vendor_patched_ranges 是范围，不得把首个边界表述为唯一修复版本。",
            }
        )
    if source_id == "nvd":
        constraints.append(
            {
                "code": "nvd_unparsed_scope",
                "rule": "NVD 结论只能使用本次已读取并引用的字段；若 CPE 或版本范围缺失或未解析，不得据此推断产品或资产不受影响；CVSS 不能替代影响范围证据。",
            }
        )
    if source_id == "cisa-kev":
        constraints.append(
            {
                "code": "kev_date_semantics",
                "rule": "dateAdded 是加入 KEV 日期，catalog release 不是单条漏洞修改时间。",
            }
        )
    if source_id == "crossref" or kind == "paper":
        precision = normalized.get("publication_precision", "unknown")
        constraints.extend(
            [
                {
                    "code": "metadata_only",
                    "rule": QUALITY_FLAG_RULES["metadata_only"],
                },
                {
                    "code": "publication_precision",
                    "rule": f"本次元数据的发布日期精度标为 {precision}，不得虚构更精确日期。",
                },
            ]
        )
    if normalized.get("packages"):
        constraints.append(
            {
                "code": "no_asset_match",
                "rule": "来源版本范围不等于具体资产已确认受影响。",
            }
        )
    return constraints


def structured_constraints(enrichment: EventEnrichment | None) -> list[dict]:
    if enrichment is None:
        return [
            {
                "code": "structured_data_unavailable",
                "rule": "本次未载入该事件的结构化富化结果，回答只能使用本轮已读取并引用的来源片段；这不表示来源缺少相应信息。",
            },
            {"code": "constraint_usage", "rule": CONSTRAINT_USAGE_RULE},
        ]
    constraints = [
        {
            "code": "derived_structured_data",
            "rule": (
                f"结构化摘要来自可重建派生数据 {enrichment.schema_version}，"
                "事实引用仍须指向来源原文。"
            ),
        },
        {"code": "constraint_usage", "rule": CONSTRAINT_USAGE_RULE},
    ]
    constraints.extend(
        {"code": flag, "rule": QUALITY_FLAG_RULES[flag]}
        for flag in enrichment.quality_flags
        if flag in QUALITY_FLAG_RULES
    )
    entries = enrichment.cvss.get("entries", [])
    if enrichment.cvss.get("selected"):
        constraints.append(
            {
                "code": "selected_cvss_display_only",
                "rule": "selected CVSS 只是按透明规则选出的展示项，不是系统重新评分。",
            }
        )
    if len({entry.get("score") for entry in entries}) > 1:
        constraints.append(
            {
                "code": "cvss_multiple_scores",
                "rule": "本次结构化字段收录多个不同 CVSS 分数，必须结合原文引用说明版本或来源差异，不能只称为唯一评分。",
            }
        )
    if enrichment.cpe_matches:
        constraints.append(
            {
                "code": "cpe_condition_not_asset_match",
                "rule": "CPE vulnerable 条件不是本地资产命中；没有资产清单和版本求值时不得断言资产受影响或不受影响。",
            }
        )
    return constraints


def event_constraints(session, event_id: str, revision: EventRevision | None = None) -> list[dict]:
    event = session.get(IntelEvent, event_id)
    if event is None:
        raise LookupError("event not found")
    if revision is None:
        revision = session.scalar(
            select(EventRevision).where(
                EventRevision.event_id == event_id,
                EventRevision.number == event.revision,
            )
        )
    rules = source_constraints(event.source_id, event.kind, revision.normalized)
    rules.extend(structured_constraints(session.get(EventEnrichment, event_id)))
    return list({rule["code"]: rule for rule in rules}.values())


def constraints_for_chunk(session, row: SearchChunk, revision: EventRevision) -> list[dict]:
    rules = source_constraints(row.source_id, row.kind, revision.normalized)
    rules.extend(structured_constraints(session.get(EventEnrichment, row.event_id)))
    return list({rule["code"]: rule for rule in rules}.values())


def requires_asset_context(question: str) -> bool:
    folded = question.casefold()
    return any(term in folded for term in ASSET_QUESTION_TERMS)


def asset_context_snapshot(session, asset_id: str, event_ids: set[str]) -> dict:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise LookupError("asset not found")
    stmt = select(AssetExposure).where(AssetExposure.asset_id == asset_id)
    if event_ids:
        stmt = stmt.where(AssetExposure.event_id.in_(event_ids))
    else:
        stmt = stmt.where(AssetExposure.event_id.in_(set()))
    exposures = session.scalars(stmt.order_by(AssetExposure.status, AssetExposure.id)).all()
    return {
        "asset": {
            "id": asset.id,
            "name": asset.name,
            "environment": asset.environment,
            "criticality": asset.criticality,
            "sbom_sha256": asset.sbom_sha256,
            "imported_at": asset.imported_at.isoformat(),
        },
        "selected_event_ids": sorted(event_ids),
        "exposures": json.loads(
            json.dumps([exposure_view(session, row) for row in exposures], default=str)
        ),
    }


def asset_constraints(context: dict) -> list[dict]:
    rules = [
        {
            "code": "asset_context_selected",
            "rule": "资产判断仅适用于本次明确选择的 SBOM，不得外推到其他资产或环境。",
        }
    ]
    exposures = context["exposures"]
    if not exposures:
        rules.append(
            {
                "code": "no_identity_match_not_not_affected",
                "rule": "所选资产与本次证据事件没有 exposure；无身份匹配不能表述为不受影响。",
            }
        )
    if any(item["status"] == "affected" for item in exposures):
        rules.append(
            {
                "code": "affected_is_source_condition_match",
                "rule": "affected 只表示组件匹配来源声明的身份与版本条件，不代表漏洞已复现。",
            }
        )
    if any(item["status"] == "not_affected" for item in exposures):
        rules.append(
            {
                "code": "not_affected_is_source_scoped",
                "rule": "not_affected 只针对当前来源记录的范围，不能外推为资产安全。",
            }
        )
    if any(item["status"] == "unknown" for item in exposures):
        rules.append(
            {
                "code": "unknown_asset_exposure",
                "rule": "unknown 必须连同版本或来源条件无法确定的原因展示。",
            }
        )
    return rules


def reconcile_asset_constraints(constraints: dict[str, dict], context: dict) -> None:
    """Replace generic no-asset warnings once a selected asset has a matching exposure."""
    if context["exposures"]:
        constraints.pop("no_asset_match", None)
        constraints.pop("cpe_condition_not_asset_match", None)


def citation_snapshot(session, row: SearchChunk, score: float, rank: int) -> tuple[dict, list]:
    revision = session.get(EventRevision, row.revision_id)
    enrichment = session.get(EventEnrichment, row.event_id)
    constraints = constraints_for_chunk(session, row, revision)
    return (
        {
            "chunk_id": row.id,
            "retrieval_score": score,
            "rank": rank,
            "event_id": row.event_id,
            "revision_id": row.revision_id,
            "revision": row.revision_number,
            "raw_document_id": row.raw_document_id,
            "json_pointer": row.json_pointer,
            "sha256": row.sha256,
            "source_id": row.source_id,
            "kind": row.kind,
            "external_id": row.external_id,
            "title": row.title,
            "source_url": session.get(IntelEvent, row.event_id).source_url,
            "field": row.field,
            "start": row.start,
            "end": row.end,
            "origin": row.origin,
            "verification": row.verification,
            "pool": row.pool,
            "ai_label": row.ai_label,
            "text": row.text,
            "enrichment_schema_version": enrichment.schema_version if enrichment else None,
            "quality_flags": enrichment.quality_flags if enrichment else [],
        },
        constraints,
    )


def save_audit(session, body: AnswerAuditCreate) -> AnswerAudit:
    ids = [citation.chunk_id for citation in body.citations]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate citation chunk_id")
    rows = {
        row.id: row for row in session.scalars(select(SearchChunk).where(SearchChunk.id.in_(ids)))
    }
    if set(rows) != set(ids):
        raise LookupError("citation chunk not found; refresh retrieval before saving")
    snapshots, constraints = [], {}
    for citation in sorted(body.citations, key=lambda item: item.rank):
        row = rows[citation.chunk_id]
        if row.pool != body.pool:
            raise ValueError("citation pool does not match answer pool")
        snapshot, rules = citation_snapshot(session, row, citation.retrieval_score, citation.rank)
        snapshots.append(snapshot)
        constraints.update((rule["code"], rule) for rule in rules)
    context = None
    if body.asset_id:
        context = asset_context_snapshot(
            session, body.asset_id, {snapshot["event_id"] for snapshot in snapshots}
        )
        constraints.update((rule["code"], rule) for rule in asset_constraints(context))
        reconcile_asset_constraints(constraints, context)
    elif requires_asset_context(body.question):
        constraints["asset_context_required"] = {
            "code": "asset_context_required",
            "rule": "问题要求判断具体资产，但请求没有明确选择 asset_id，回答不得给出资产结论。",
        }
    audit = AnswerAudit(
        question=body.question,
        answer=body.answer,
        retrieval_query=body.retrieval_query,
        pool=body.pool,
        model=body.model,
        prompt_version=body.prompt_version,
        policy_version=POLICY_VERSION,
        status=(
            "policy_review_required" if "asset_context_required" in constraints else "recorded"
        ),
        citations=snapshots,
        constraints=list(constraints.values()),
        asset_id=body.asset_id,
        asset_context=context,
    )
    session.add(audit)
    session.flush()
    return audit


def make_extractive_answer(session, request: ExtractiveAnswerRequest) -> AnswerAudit:
    query = request.query or request.question
    if request.event_id and session.get(IntelEvent, request.event_id) is None:
        raise LookupError("event not found")
    if request.asset_id is None and requires_asset_context(request.question):
        audit = AnswerAudit(
            question=request.question,
            answer="问题要求判断具体资产，但没有明确选择 asset_id，不能注入或推断任何资产状态。",
            retrieval_query=query,
            pool=request.pool,
            model="extractive-template-v1",
            prompt_version="evidence-packet-v3",
            policy_version=POLICY_VERSION,
            status="asset_context_required",
            citations=[],
            constraints=[
                {
                    "code": "asset_context_required",
                    "rule": "只有用户明确选择 asset_id 时才能注入该资产的 exposure。",
                }
            ],
            asset_id=None,
            asset_context=None,
        )
        session.add(audit)
        session.flush()
        return audit
    hits, _ = search_index(
        session,
        query,
        event_id=request.event_id,
        pool=request.pool,
        origin=request.origin,
        include_withdrawn=False,
    )
    selected, seen_events = [], set()
    for hit in hits:
        if hit.citation.event_id in seen_events:
            continue
        selected.append(hit)
        seen_events.add(hit.citation.event_id)
        if len(selected) == request.limit:
            break
    if not selected:
        context = (
            asset_context_snapshot(session, request.asset_id, set()) if request.asset_id else None
        )
        constraints = [
            {
                "code": "insufficient_evidence",
                "rule": "当前检索集合没有可引用证据，必须拒绝给出事实性结论。",
            }
        ]
        if context:
            constraints.extend(asset_constraints(context))
        audit = AnswerAudit(
            question=request.question,
            answer="当前检索集合中没有找到可引用证据，不能据此作答。",
            retrieval_query=query,
            pool=request.pool,
            model="extractive-template-v1",
            prompt_version="evidence-packet-v3",
            policy_version=POLICY_VERSION,
            status="no_evidence",
            citations=[],
            constraints=constraints,
            asset_id=request.asset_id,
            asset_context=context,
        )
        session.add(audit)
        session.flush()
        return audit
    lines = ["以下为来源证据片段，需结合引用核对："]
    citations, constraints = [], {}
    for rank, hit in enumerate(selected, 1):
        excerpt = " ".join(hit.text.split())[:360]
        lines.append(f"[{rank}] {hit.title}（{hit.external_id}）：{excerpt}")
        row = session.get(SearchChunk, hit.chunk_id)
        snapshot, rules = citation_snapshot(session, row, hit.score, rank)
        citations.append(snapshot)
        constraints.update((rule["code"], rule) for rule in rules)
    context = None
    if request.asset_id:
        context = asset_context_snapshot(session, request.asset_id, seen_events)
        context_rules = asset_constraints(context)
        constraints.update((rule["code"], rule) for rule in context_rules)
        reconcile_asset_constraints(constraints, context)
        asset = context["asset"]
        lines.append(
            f"资产上下文：{asset['name']} · {asset['environment']} · SBOM {asset['sbom_sha256']}"
        )
        if context["exposures"]:
            for item in context["exposures"]:
                component = item["component"]
                lines.append(
                    f"- {component['ecosystem']}/{component['name']}@{component['version']} · "
                    f"{item['event']['external_id']} · {item['status']}：{item['reason']}"
                )
        else:
            lines.append("- 本次证据事件与所选资产没有 exposure；不能据此表述为不受影响。")
        lines.append("资产判断边界：")
        lines.extend(f"- {rule['rule']}" for rule in context_rules)
    uncertainty = [rule for code, rule in constraints.items() if code in UNCERTAINTY_CODES]
    if uncertainty:
        lines.append("不确定性说明：")
        lines.extend(f"- {rule['rule']}" for rule in uncertainty)
    audit = AnswerAudit(
        question=request.question,
        answer="\n".join(lines),
        retrieval_query=query,
        pool=request.pool,
        model="extractive-template-v1",
        prompt_version="evidence-packet-v3",
        policy_version=POLICY_VERSION,
        status="completed",
        citations=citations,
        constraints=list(constraints.values()),
        asset_id=request.asset_id,
        asset_context=context,
    )
    session.add(audit)
    session.flush()
    return audit


def audit_view(row: AnswerAudit) -> dict:
    return {column.name: getattr(row, column.name) for column in AnswerAudit.__table__.columns}
