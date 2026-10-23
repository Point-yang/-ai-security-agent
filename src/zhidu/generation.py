"""One bounded DeepSeek generation call over locally verified evidence.

Citation/quote checks verify attribution, not the truth of a model's paraphrase.
Never return upstream error bodies or persist keys/hidden reasoning.
"""

import hashlib
import json
import time
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from zhidu.agent_state import AgentAnswer
from zhidu.grounded_answer import (
    CONTRACT_VERSION,
    FINAL_SYSTEM,
    contains_written_citation,
    evidence_id,
    render_answer,
)

PROMPT_VERSION = "grounded-conversation-v5"
SYSTEM_PROMPT = FINAL_SYSTEM


class Reference(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    citation: int = Field(ge=1, le=24)
    quote: str = Field(min_length=8, max_length=1200)


class Statement(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: str = Field(min_length=1, max_length=1800)
    evidence: list[Reference] = Field(min_length=1, max_length=5)


class GroundedOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    statements: list[Statement] = Field(max_length=8)


class GenerationError(Exception):
    pass


def endpoint(settings):
    base = settings.deepseek_base_url.rstrip("/")
    parts = urlsplit(base)
    # Credentials only go to the official provider. No redirects or user-supplied URL.
    if (
        parts.scheme != "https"
        or parts.netloc != "api.deepseek.com"
        or parts.path not in ("", "/v1")
        or parts.query
        or parts.fragment
    ):
        raise GenerationError("invalid_endpoint")
    return base + "/chat/completions"


def generation_status(settings):
    if settings.llm_provider == "model":
        from zhidu.model_provider import generation_target, model_profile

        try:
            profile = model_profile(settings)
            generation_target(settings, profile)
            status = "configured"
        except (ValueError, GenerationError) as exc:
            return {
                "provider": "model",
                "configured": False,
                "status": str(exc),
                "model": settings.agent_model_name or "unconfigured",
                "inference_checked": False,
            }
        return {
            "provider": "model",
            "adapter_provider": profile.provider,
            "configured": True,
            "status": status,
            "model": profile.model,
            "inference_checked": False,
        }
    configured = bool(settings.deepseek_api_key.get_secret_value().strip())
    valid = True
    try:
        endpoint(settings)
    except GenerationError:
        valid = False
    return {
        "provider": settings.llm_provider,
        "configured": configured,
        "status": "configured"
        if configured and valid
        else "missing_api_key"
        if valid
        else "invalid_endpoint",
        "model": settings.deepseek_model,
        "inference_checked": False,
    }


def apply_generation(
    settings,
    question,
    result,
    *,
    transport=None,
    history=None,
    profile=None,
    session=None,
    store=None,
):
    """Mutate an already verified evidence result; retain it on provider failure."""
    start = time.monotonic()
    audit = {
        "provider": profile.provider if profile else "deepseek",
        "status": "fallback",
        "requested_model": profile.model if profile else settings.deepseek_model,
        "prompt_version": PROMPT_VERSION,
        "citation_checks_passed": False,
        "semantic_support_verified": False,
        "answer_contract": CONTRACT_VERSION,
        "temperature": settings.llm_temperature,
    }
    result["generation"] = audit
    step = {
        "tool": "generate_answer",
        "status": "running",
        "input": {"model": settings.deepseek_model},
    }
    result["tools"].append(step)
    try:
        generation_citations = result["citations"]
        if session is not None and store is not None:
            from zhidu.models import SearchChunk
            from zhidu.source_spans import source_span

            generation_citations = [
                {**c, **source_span(session, store, session.get(SearchChunk, c["chunk_id"]))}
                for c in result["citations"]
            ]
        if profile:
            from zhidu.model_provider import generation_target

            try:
                url, key = generation_target(settings, profile)
            except ValueError as exc:
                raise GenerationError(str(exc)) from None
        else:
            key = settings.deepseek_api_key.get_secret_value().strip()
            if not key:
                raise GenerationError("missing_api_key")
            url = endpoint(settings)
        evidence, remaining = [], min(20000, settings.agent_max_output_chars)
        audit["evidence_char_limit"] = remaining
        handles = {}
        for i, citation in enumerate(generation_citations, 1):
            text = citation.get("text", "")
            if not text:
                continue
            # A verified source span is indivisible: clipping its text would
            # invalidate offsets/provenance after a paid provider request.
            if len(text) > min(4000, remaining):
                continue
            visible = {**citation, "text": text}
            handle = evidence_id(visible)
            handles[handle] = visible
            evidence.append(
                {
                    "citation": i,
                    "evidence_id": handle,
                    "external_id": citation["external_id"],
                    "text": text,
                    "quote_policy": "server_fills_verified_span",
                    "span_provenance": {
                        k: citation["span_provenance"][k]
                        for k in ("boundary_complete", "selection_kind", "source_field_chars")
                    }
                    if "span_provenance" in citation
                    else {},
                    **{
                        k: citation[k]
                        for k in ("source_id", "revision", "field", "source_url", "title")
                        if k in citation
                    },
                }
            )
            remaining -= len(text)
        if not evidence:
            raise GenerationError("no_evidence")
        # Omit full SBOM, asset names, raw files and secrets; history is bounded reference text.
        payload = {
            "question": question,
            "sources": evidence,
            "constraints": result["constraints"][:30],
            "asset_note": "只解释公告证据，不根据这些片段猜测用户资产状态。资产判断由本地规则单独展示。",
        }
        if history is not None:
            payload["history"] = history[-6:]
            payload["history_policy"] = "historical_reference_only_not_evidence"
            audit["history_messages"] = len(payload["history"])
        user_text = json.dumps(payload, ensure_ascii=False)
        audit["input_sha256"] = hashlib.sha256(user_text.encode()).hexdigest()
        audit["evidence_chars"] = sum(len(e["text"]) for e in evidence)
        audit["source_spans"] = len(evidence)
        result["cost"].update(external_requests=1, billed_tokens=None, api_usd=None)
        # No automatic retries: bounded cost and unambiguous failures.
        with httpx.Client(
            timeout=httpx.Timeout(settings.deepseek_timeout_seconds, connect=10),
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        ) as client:
            response = client.post(
                url,
                headers={"Authorization": f"Bearer {key}"},
                json={
                    "model": audit["requested_model"],
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_text},
                    ],
                    "response_format": {"type": "json_object"},
                    **(
                        {"thinking": {"type": "disabled"}}
                        if audit["provider"] == "deepseek"
                        else {}
                    ),
                    "max_tokens": settings.deepseek_max_tokens,
                    "temperature": settings.llm_temperature,
                    "stream": False,
                },
            )
        if response.status_code != 200:
            reason = {
                401: "authentication_failed",
                402: "insufficient_balance",
                429: "rate_limited",
            }.get(response.status_code, "upstream_error")
            audit["http_status"] = response.status_code
            raise GenerationError(reason)
        data = response.json()
        audit["provider_response_id"] = data.get("id")
        audit["billed_at"] = data.get("created")
        usage = data.get("usage") or {}
        audit["usage"] = {
            k: usage[k]
            for k in (
                "prompt_tokens",
                "completion_tokens",
                "total_tokens",
                "prompt_cache_hit_tokens",
                "prompt_cache_miss_tokens",
            )
            if type(usage.get(k)) is int and usage[k] >= 0
        }
        result["cost"]["billed_tokens"] = audit["usage"].get("total_tokens")
        from zhidu.model_costs import cost_for_usage

        money = cost_for_usage(
            audit["provider"],
            audit["requested_model"],
            audit["usage"],
            settings.model_pricing_path,
            billed_at=audit["billed_at"],
        )
        result["cost"]["monetary"] = money
        if money["currency"] == "USD":
            result["cost"]["api_usd"] = money["amount"]
        actual_model = data.get("model")
        if isinstance(actual_model, str):
            audit["returned_model"] = actual_model[:120]
        choice = data["choices"][0]
        audit["finish_reason"] = choice.get("finish_reason")
        if choice.get("finish_reason") != "stop":
            raise GenerationError("incomplete_output")
        message = choice["message"]
        if message.get("tool_calls"):
            raise GenerationError("unexpected_tool_call")
        raw_output = json.loads(message["content"])
        if "answer_class" in raw_output:
            candidate = AgentAnswer.model_validate(raw_output)
            try:
                rendered = render_answer(candidate, handles)
            except ValueError as exc:
                raise GenerationError(str(exc)) from None
            if session is not None and store is not None:
                from zhidu.agent_result import verify_citations

                checks = verify_citations(session, store, rendered["citations"])
                audit["final_citation_check"] = checks
                if checks["verified"] != checks["total"]:
                    raise GenerationError("evidence_invalid")
            initial_partial = result["answer_class"] == "partial"
            result["extractive_answer"] = result["answer"]
            result.update(rendered)
            if initial_partial and result["answer_class"] == "evidence":
                result["answer_class"] = "partial"
                result["answer"] += "\n\n证据仍有缺口或来源分歧，以上不能作为完整结论。"
            result["answer_requirements"] = {
                "required_facts": candidate.required_facts,
                "missing_facts": candidate.missing_facts,
            }
            result["generation_model"] = audit.get("returned_model") or audit["requested_model"]
            result["reason"] = "grounded_generation"
            audit.update(status="completed", citation_checks_passed=bool(result["citations"]))
            step["status"] = "completed"
            return
        # Historical numeric/quote clients remain readable. New prompts require
        # the same server-owned reference contract as the native agent.
        audit["answer_contract"] = "legacy_numeric_quotes"
        output = GroundedOutput.model_validate_json(message["content"])
        if not output.statements:
            raise GenerationError("insufficient_evidence")
        sources = {e["citation"]: e["text"] for e in evidence}
        claims, lines = [], []
        for statement_index, statement in enumerate(output.statements, 1):
            if not statement.text.strip() or contains_written_citation(statement.text):
                audit["validation_error"] = {
                    "kind": "statement_contains_citation_marker_or_empty",
                    "statement_index": statement_index,
                }
                raise GenerationError("invalid_citation")
            for ref in statement.evidence:
                if ref.citation not in sources:
                    audit["validation_error"] = {
                        "kind": "citation_out_of_range",
                        "statement_index": statement_index,
                        "citation": ref.citation,
                    }
                    raise GenerationError("invalid_citation")
                if not ref.quote.strip() or ref.quote not in sources[ref.citation]:
                    audit["validation_error"] = {
                        "kind": "quote_not_verbatim",
                        "statement_index": statement_index,
                        "citation": ref.citation,
                    }
                    raise GenerationError("invalid_citation")
            ids = sorted({ref.citation for ref in statement.evidence})
            lines.append(statement.text.strip() + " " + " ".join(f"[{i}]" for i in ids))
            claims.append(
                {"text": statement.text, "evidence": [r.model_dump() for r in statement.evidence]}
            )
        if result["answer_class"] == "partial":
            lines.append("证据仍有缺口或来源分歧，以上不能作为完整结论。")
        if result.get("asset_id"):
            lines.append(
                "以上解释公告资料；资产是否命中以本地资产判断为准，条件匹配不代表漏洞复现。"
            )
        if session is not None and store is not None:
            from zhidu.agent_result import verify_citations

            checks = verify_citations(session, store, generation_citations)
            audit["final_citation_check"] = checks
            if checks["verified"] != checks["total"]:
                raise GenerationError("evidence_invalid")
        result["extractive_answer"] = result["answer"]
        result["citations"] = generation_citations
        result["answer"] = "\n\n".join(lines)
        result["generated_claims"] = claims
        result["generation_model"] = audit.get("returned_model") or audit["requested_model"]
        # Existing claims remain source excerpts. Never score them as generated entailment.
        result["reason"] = "grounded_generation"
        audit.update(status="completed", citation_checks_passed=True)
        step["status"] = "completed"
    except GenerationError as exc:
        audit["reason"] = str(exc)
    except httpx.TimeoutException:
        audit["reason"] = "timeout"
    except httpx.HTTPError:
        audit["reason"] = "network_error"
    except (ValueError, KeyError, IndexError, TypeError, AttributeError, ValidationError):
        audit["reason"] = "invalid_response"
    finally:
        audit["elapsed_ms"] = round((time.monotonic() - start) * 1000, 3)
        step["elapsed_ms"] = audit["elapsed_ms"]
        if audit["status"] != "completed":
            step.update(status="failed", error=audit.get("reason", "generation_failed"))
        step["output"] = {"generation_status": audit["status"]}
