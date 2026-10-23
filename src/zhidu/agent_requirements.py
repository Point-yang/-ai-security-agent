"""Question-bound requirements and independent support/completeness review.

Exact-span and source-policy checks are deterministic. Whether a question asks
for a requirement and whether prose expresses it remain the verifier's AI
semantic judgments; this module never substitutes a keyword score for them.
"""

from zhidu.agent_team_state import (
    AnswerAnchorBinding,
    AnswerSpan,
    ElementCoverage,
    QuestionSpan,
    ResearchGap,
    TaskCoverage,
    UnplannedRequirement,
    VerifierOutput,
)
from zhidu.answer_anchors import (
    VERSION as ANCHOR_VERSION,
)
from zhidu.answer_anchors import (
    anchor_binding_prefix,
    build_answer_anchors,
    candidate_fingerprint,
    question_fingerprint,
    scope_fingerprint,
)
from zhidu.grounded_answer import render_answer
from zhidu.source_semantics import source_context_provenance, source_semantics

VERSION = "question-coverage-ledger-v1"


def _bind(text, value, *, member, error):
    fragment = getattr(value, member)
    if not fragment.strip():
        raise ValueError(error)
    start, end = value.start, value.end
    if (start is None) != (end is None):
        raise ValueError(error)
    if start is None:
        start = text.find(fragment)
        if start < 0 or text.find(fragment, start + 1) >= 0:
            raise ValueError(error)
        end = start + len(fragment)
    if (
        not 0 <= start < end <= len(text)
        or end - start != len(fragment)
        or text[start:end] != fragment
    ):
        raise ValueError(error)
    return value.model_copy(update={"start": start, "end": end})


def normalize_plan(question, plan):
    tasks = []
    for task in plan.tasks:
        if len(set(task.source_ids)) != len(task.source_ids):
            raise ValueError("invalid_task_source_policy")
        if task.source_policy == "each" and not task.source_ids:
            raise ValueError("invalid_task_source_policy")
        if task.source_policy == "compare" and len(task.source_ids) < 2:
            raise ValueError("invalid_task_source_policy")
        if len(set(task.required_elements)) != len(task.required_elements) or any(
            not item.strip() for item in task.required_elements
        ):
            raise ValueError("invalid_required_elements")
        spans = [
            _bind(question, span, member="quote", error="invalid_task_question_span")
            for span in task.question_spans
        ]
        tasks.append(task.model_copy(update={"question_spans": spans}))
    return plan.model_copy(update={"tasks": tasks})


def validate_task_plan(question, plan):
    return normalize_plan(question, plan)


def verifier_packet(question, plan, candidate, evidence, scope=None):
    plan = normalize_plan(question, plan)
    anchors = build_answer_anchors(question, plan, candidate, evidence, scope)
    rendered = render_answer(candidate, evidence)
    metadata = (
        "source_id",
        "external_id",
        "field",
        "event_id",
        "revision_id",
        "revision",
        "raw_document_id",
        "json_pointer",
        "sha256",
        "start",
        "end",
    )
    answer_ids = {item["statement_index"]: item["anchor_id"] for item in anchors["answer_anchors"]}
    quote_ids = {
        (item["statement_index"], item["reference_index"]): item["quote_id"]
        for item in anchors["source_quotes"]
    }
    statements = []
    for index, claim in enumerate(rendered["generated_claims"], 1):
        quotes, own_citations = [], []
        for reference_index, reference in enumerate(claim["evidence"], 1):
            citation = rendered["citations"][reference["citation"] - 1]
            own_citations.append(citation)
            field_chars = citation.get("span_provenance", {}).get("source_field_chars")
            quotes.append(
                {
                    "quote_id": quote_ids[index, reference_index],
                    "quote": reference["quote"],
                    **{key: citation.get(key) for key in metadata},
                    "source_field_chars": field_chars,
                    "source_context": source_context_provenance(citation),
                    "quote_covers_entire_field": citation.get("start") == 0
                    and citation.get("end") == field_chars
                    if type(field_chars) is int
                    else None,
                }
            )
        statements.append(
            {
                "statement_index": index,
                "answer_anchor_id": answer_ids[index],
                "text": claim["text"],
                "quotes": quotes,
                "source_contracts": source_semantics(own_citations),
            }
        )
    return {
        "question": question,
        "question_must_be_reviewed_independently_of_plan": True,
        "tasks": plan.model_dump()["tasks"],
        "statements": statements,
        "answer_anchor_protocol": {
            "version": ANCHOR_VERSION,
            "scope_digest": anchors["scope_digest"],
            "candidate_digest": anchors["candidate_digest"],
        },
        # Full text appears once, in statements. These tables only locate it.
        "answer_anchors": [
            {
                key: item[key]
                for key in ("anchor_id", "statement_index", "start", "end", "quote_ids")
            }
            for item in anchors["answer_anchors"]
        ],
        "source_quotes": [
            {key: item[key] for key in ("quote_id", "statement_index", "reference_index")}
            for item in anchors["source_quotes"]
        ],
        "missing_facts": candidate.missing_facts,
        "answer_class": candidate.answer_class,
        "review_scope": "actual_attached_quotes_only",
        "source_absence_inferred": False,
        "coverage_rule": "A requirement needs its meaning in candidate prose and its own supporting quote. Text appearing only in a quote is not an answer.",
        "support_rule": "Claim support concerns only the claim and its own quotes. Missing another source or task is completeness, never an unsupported-claim reason.",
        "omission_rule": "Independently review the original question. unplanned_requirements contains only still-unanswered user requirements, not plan omissions already answered.",
        "anchor_rule": "Select only current ans_ IDs for prose coverage. src_ IDs locate supporting quotations and cannot answer a requirement. IDs locate text; they do not establish semantic coverage.",
        "source_contract_rule": "Use each statement's own source-native contract; contracts are metadata guidance, not new user requirements or evidence. NVD narrative affected/fixed wording does not require GitHub same-named package fields. not_observed means absent from this supplied scope, never absent from the source.",
        "source_context_rule": "Context completeness concerns only the quoted structure, not semantic support or whole-question coverage. Unknown old context proves neither completeness nor omitted conditions. Incomplete context may require continuation, never source-absence claims. Missing required conditions is completeness; supported necessary subconditions remain supported.",
    }


def expand_verifier_decision(question, plan, candidate, decision, evidence, scope=None):
    """Expand server-owned IDs; never infer support or coverage from selection."""
    anchors = build_answer_anchors(question, plan, candidate, evidence, scope)
    registry = {item["anchor_id"]: item for item in anchors["answer_anchors"]}

    def expand_ids(ids):
        if len(set(ids)) != len(ids):
            raise ValueError("invalid_verifier_duplicate_anchor")
        if any(not anchor_id.startswith("ans_") for anchor_id in ids):
            raise ValueError("invalid_verifier_anchor_id")
        if any(anchor_id not in registry for anchor_id in ids):
            raise ValueError("invalid_verifier_anchor_id")
        return [
            AnswerSpan(
                statement_index=registry[anchor_id]["statement_index"],
                text=registry[anchor_id]["text"],
                start=registry[anchor_id]["start"],
                end=registry[anchor_id]["end"],
            )
            for anchor_id in ids
        ]

    coverage = []
    for item in decision.coverage:
        spans = expand_ids(item.anchor_ids)
        elements = []
        for element in item.element_coverage:
            bound = expand_ids(element.anchor_ids)
            if not set(element.anchor_ids).issubset(set(item.anchor_ids)):
                raise ValueError("invalid_verifier_element_anchor")
            elements.append(
                ElementCoverage(element=element.element, status=element.status, answer_spans=bound)
            )
        coverage.append(
            TaskCoverage(
                task_id=item.task_id,
                status=item.status,
                note=item.note,
                statement_indices=[span.statement_index for span in spans],
                answer_spans=spans,
                element_coverage=elements,
            )
        )
    binding = AnswerAnchorBinding(
        question_digest=anchors["question_digest"],
        scope_digest=anchors["scope_digest"],
        candidate_digest=anchors["candidate_digest"],
        statement_anchor_ids={
            str(item["statement_index"]): item["anchor_id"] for item in anchors["answer_anchors"]
        },
    )
    internal = VerifierOutput(
        coverage=coverage,
        claim_support=decision.claim_support,
        gaps=[
            ResearchGap.model_validate(item.model_dump(exclude={"reason"}))
            for item in decision.gaps
        ],
        unplanned_requirements=[
            UnplannedRequirement(
                requirement=item.requirement,
                question_span=QuestionSpan(quote=item.question_quote),
                reason=item.reason,
            )
            for item in decision.unplanned_requirements
        ],
        anchor_binding=binding,
    )
    return normalize_verification(question, plan, candidate, internal, evidence)


def _validate_anchor_binding(question, candidate, verification, evidence, scope=None):
    binding = verification.anchor_binding
    if binding is None:
        return {}
    if evidence is None or question is None:
        raise ValueError("verifier_anchor_context_required")
    candidate_digest, _ = candidate_fingerprint(candidate, evidence)
    if (
        binding.candidate_digest != candidate_digest
        or binding.question_digest != question_fingerprint(question)
    ):
        raise ValueError("invalid_verifier_anchor_binding")
    if scope is not None and binding.scope_digest != scope_fingerprint(question, scope):
        raise ValueError("verifier_anchor_scope_mismatch")
    prefix = anchor_binding_prefix(binding.scope_digest, candidate_digest)
    expected = {
        str(index): f"ans_{prefix}_{index}" for index in range(1, len(candidate.statements) + 1)
    }
    if binding.statement_anchor_ids != expected:
        raise ValueError("invalid_verifier_anchor_binding")
    return expected


def _answer_span(candidate, span):
    if span.statement_index > len(candidate.statements):
        raise ValueError("invalid_verifier_statement_reference")
    return _bind(
        candidate.statements[span.statement_index - 1].text,
        span,
        member="text",
        error="invalid_verifier_answer_span",
    )


def _source_check(task, candidate, spans, evidence):
    if evidence is None:
        return {
            "checked": False,
            "sufficient": task.source_policy == "any" and not task.source_ids,
            "observed": [],
            "missing": list(task.source_ids),
        }
    per_statement = []
    for index in sorted({span.statement_index for span in spans}):
        refs = candidate.statements[index - 1].evidence
        if any(ref.evidence_id not in evidence for ref in refs):
            raise ValueError("unknown_evidence_id")
        per_statement.append(
            {
                value
                for ref in refs
                if isinstance(value := evidence[ref.evidence_id].get("source_id"), str)
                and value.strip()
            }
        )
    observed = set().union(*per_statement) if per_statement else set()
    requested = set(task.source_ids)
    if task.source_policy == "any":
        sufficient = bool(observed & requested) if requested else bool(observed)
    elif task.source_policy == "each":
        sufficient = requested.issubset(observed)
    else:
        # A comparison statement must itself quote the sources it compares.
        sufficient = any(requested.issubset(sources) for sources in per_statement)
    return {
        "checked": True,
        "sufficient": sufficient,
        "observed": sorted(value for value in observed if value),
        "missing": sorted(requested - observed),
    }


def _context_check(task, candidate, spans, evidence):
    """Physical quoted-context coverage, never a semantic completeness score."""
    if task.coverage_scope != "complete_context":
        return {"required": False, "sufficient": True, "semantic_support_verified": False}
    from zhidu.source_semantics import quoted_context_coverage

    requested = set(task.source_ids)
    per_statement = []
    for index in sorted({span.statement_index for span in spans}):
        citations = []
        for ref in candidate.statements[index - 1].evidence:
            if evidence is not None and ref.evidence_id not in evidence:
                raise ValueError("unknown_evidence_id")
            citation = evidence.get(ref.evidence_id) if evidence is not None else None
            if citation and (not requested or citation.get("source_id") in requested):
                citations.append(citation)
        per_statement.append(citations)
    all_citations = [citation for group in per_statement for citation in group]
    audit = quoted_context_coverage(all_citations)

    def source_audits(citations):
        sources = {citation.get("source_id") for citation in citations if citation.get("source_id")}
        return {
            source: quoted_context_coverage(
                [citation for citation in citations if citation.get("source_id") == source]
            )
            for source in sorted(sources)
        }

    by_source = source_audits(all_citations)
    complete_sources = {source for source, proof in by_source.items() if proof["complete"]}
    if task.source_policy == "compare":
        sufficient = any(
            requested
            <= {source for source, proof in source_audits(group).items() if proof["complete"]}
            for group in per_statement
        )
    elif task.source_policy == "each":
        sufficient = bool(requested) and requested <= complete_sources
    else:
        sufficient = bool(requested & complete_sources) if requested else bool(complete_sources)
    return {
        "required": True,
        "sufficient": sufficient,
        "complete_sources": sorted(complete_sources),
        "coverage": audit,
        "by_source": by_source,
        "semantic_support_verified": False,
    }


def _gap_kind(blockers):
    if "answer" in blockers:
        return "answer"
    if "source" in blockers or "unsupported" in blockers:
        return "source"
    return "context" if "context" in blockers else "answer"


def _coverage_missing_label(requirement, blockers):
    if set(blockers) == {"context"}:
        return "完整结构引用待补核：" + requirement
    if "answer" not in blockers and ("source" in blockers or "unsupported" in blockers):
        return "来源引用待补核：" + requirement
    return requirement


def normalize_verification(question, plan, candidate, verification, evidence=None):
    anchor_ids = _validate_anchor_binding(question, candidate, verification, evidence)
    plan = normalize_plan(question, plan) if question is not None else plan
    expected = {task.task_id: task for task in plan.tasks}
    observed = [item.task_id for item in verification.coverage]
    if len(observed) != len(expected) or set(observed) != set(expected):
        raise ValueError("invalid_verifier_task_coverage")
    supports = [item.statement_index for item in verification.claim_support]
    if len(supports) != len(candidate.statements) or set(supports) != set(
        range(1, len(candidate.statements) + 1)
    ):
        raise ValueError("invalid_verifier_claim_support")
    unsupported = {item.statement_index for item in verification.unsupported}
    gaps = list(verification.gaps)
    if any(gap.task_id not in expected for gap in gaps):
        raise ValueError("invalid_verifier_gap_task")
    coverage = []
    for item in verification.coverage:
        task = expected[item.task_id]
        semantic_status = item.semantic_status or item.status
        if len(set(item.statement_indices)) != len(item.statement_indices):
            raise ValueError("invalid_verifier_duplicate_reference")
        spans = [_answer_span(candidate, span) for span in item.answer_spans]
        if anchor_ids and any(
            span.start != 0 or span.end != len(candidate.statements[span.statement_index - 1].text)
            for span in spans
        ):
            raise ValueError("invalid_verifier_anchor_binding")
        if set(item.statement_indices) != {span.statement_index for span in spans}:
            raise ValueError("invalid_verifier_statement_reference")
        elements = [element.element for element in item.element_coverage]
        if len(elements) != len(task.required_elements) or set(elements) != set(
            task.required_elements
        ):
            raise ValueError("invalid_verifier_element_coverage")
        normalized_elements = []
        for element in item.element_coverage:
            indices = element.answer_span_indices
            if indices and element.answer_spans:
                raise ValueError("element_cannot_mix_span_formats")
            if len(set(indices)) != len(indices):
                raise ValueError("invalid_verifier_duplicate_span_reference")
            if any(index < 1 or index > len(spans) for index in indices):
                raise ValueError("invalid_verifier_span_reference")
            # This expands only indices into the task's exact prose anchors.
            # It does not infer that a requirement is semantically covered.
            bound = (
                [spans[index - 1] for index in indices]
                if indices
                else [_answer_span(candidate, span) for span in element.answer_spans]
            )
            if anchor_ids and any(
                span.start != 0
                or span.end != len(candidate.statements[span.statement_index - 1].text)
                for span in bound
            ):
                raise ValueError("invalid_verifier_anchor_binding")
            if not {span.statement_index for span in bound}.issubset(set(item.statement_indices)):
                raise ValueError("invalid_verifier_statement_reference")
            element_semantic_status = element.semantic_status or element.status
            status = element_semantic_status
            if status == "covered" and (
                not bound or unsupported.intersection(span.statement_index for span in bound)
            ):
                status = "partial"
            normalized_elements.append(
                element.model_copy(
                    update={
                        "answer_spans": bound,
                        "answer_span_indices": [],
                        "status": status,
                        "semantic_status": element_semantic_status,
                    }
                )
            )
        retained_spans = [span for span in spans if span.statement_index not in unsupported]
        source_check = _source_check(task, candidate, retained_spans, evidence)
        context_check = _context_check(task, candidate, retained_spans, evidence)
        blockers = []
        if (
            semantic_status != "covered"
            or not spans
            or any(
                element.semantic_status != "covered" or not element.answer_spans
                for element in normalized_elements
            )
        ):
            blockers.append("answer")
        if unsupported.intersection(item.statement_indices):
            blockers.append("unsupported")
        if retained_spans and not source_check["sufficient"]:
            blockers.append("source")
        if retained_spans and context_check["required"] and not context_check["sufficient"]:
            blockers.append("context")
        # An explicit prose gap cannot be hidden by simultaneous physical
        # blockers. Generated source/context gaps keep their category on
        # re-entry; an unsupported blocker already accounts for a source gap.
        task_gaps = [gap for gap in gaps if gap.task_id == item.task_id]
        if any(gap.kind == "answer" for gap in task_gaps) and "answer" not in blockers:
            blockers.insert(0, "answer")
        if any(gap.kind == "source" for gap in task_gaps) and not {"source", "unsupported"} & set(
            blockers
        ):
            blockers.append("source")
        if any(gap.kind == "context" for gap in task_gaps) and "context" not in blockers:
            blockers.append("context")
        status = "partial" if semantic_status == "covered" and blockers else semantic_status
        gap_kind = _gap_kind(blockers)
        gaps = [
            gap.model_copy(update={"context": "section" if "context" in blockers else gap.context})
            if gap.task_id == item.task_id
            else gap
            for gap in gaps
        ]
        if status != "covered" and not any(gap.task_id == item.task_id for gap in gaps):
            missing = [
                element.element
                for element in normalized_elements
                if element.semantic_status != "covered" or not element.answer_spans
            ]
            prefix = {
                "answer": "本轮正文尚需回答：",
                "source": "本轮来源引用尚需支持：",
                "context": "完整结构引用待补核：",
            }[gap_kind]
            requirement = prefix + "；".join(missing or [task.requirement])
            missing_source = (
                source_check["missing"][0]
                if gap_kind == "source" and source_check["missing"]
                else None
            )
            gaps.append(
                ResearchGap(
                    task_id=item.task_id,
                    requirement=requirement[:350],
                    source_id=missing_source,
                    field=None if missing_source else task.fields[0] if task.fields else None,
                    contains=task.contains,
                    context="section" if "context" in blockers else None,
                    kind=gap_kind,
                )
            )
        coverage.append(
            item.model_copy(
                update={
                    "answer_spans": spans,
                    "element_coverage": normalized_elements,
                    "status": status,
                    "semantic_status": semantic_status,
                    "coverage_blockers": blockers,
                }
            )
        )
    omissions = []
    for omission in verification.unplanned_requirements:
        if question is None:
            raise ValueError("question_required_for_omission_review")
        span = _bind(
            question, omission.question_span, member="quote", error="invalid_omitted_question_span"
        )
        omissions.append(omission.model_copy(update={"question_span": span}))
    return verification.model_copy(
        update={"coverage": coverage, "gaps": gaps[:8], "unplanned_requirements": omissions}
    )


def coverage_ledger(plan, candidate, verification, *, question=None, evidence=None, scope=None):
    normalized = normalize_verification(question, plan, candidate, verification, evidence)
    anchor_ids = _validate_anchor_binding(question, candidate, normalized, evidence, scope)
    plan = normalize_plan(question, plan) if question is not None else plan
    tasks = {task.task_id: task for task in plan.tasks}
    bad = {item.statement_index for item in normalized.unsupported}
    mapping = {
        old: new
        for new, old in enumerate(
            (index for index in range(1, len(candidate.statements) + 1) if index not in bad), 1
        )
    }
    rows = []
    for item in normalized.coverage:
        task = tasks[item.task_id]
        final_spans = [
            span.model_copy(update={"statement_index": mapping[span.statement_index]})
            for span in item.answer_spans
            if span.statement_index in mapping
        ]
        retained = [span for span in item.answer_spans if span.statement_index in mapping]
        final_elements = [
            element.model_copy(
                update={
                    "answer_spans": [
                        span.model_copy(update={"statement_index": mapping[span.statement_index]})
                        for span in element.answer_spans
                        if span.statement_index in mapping
                    ]
                }
            )
            for element in item.element_coverage
        ]
        element_rows = [element.model_dump() for element in final_elements]
        for element_row, original in zip(element_rows, item.element_coverage, strict=True):
            element_row["candidate_answer_anchor_ids"] = (
                [anchor_ids[str(span.statement_index)] for span in original.answer_spans]
                if anchor_ids
                else []
            )
            element_row["answer_anchor_ids"] = (
                [
                    anchor_ids[str(span.statement_index)]
                    for span in original.answer_spans
                    if span.statement_index in mapping
                ]
                if anchor_ids
                else []
            )
        rows.append(
            {
                "task_id": task.task_id,
                "requirement": task.requirement,
                "source_ids": task.source_ids,
                "status": item.status,
                "source_policy": task.source_policy,
                "semantic_status": item.semantic_status,
                "coverage_blockers": item.coverage_blockers,
                "context_only": item.semantic_status == "covered"
                and set(item.coverage_blockers) == {"context"},
                "coverage_scope": task.coverage_scope,
                "question_spans": [span.model_dump() for span in task.question_spans],
                "required_elements": task.required_elements,
                "answer_spans": [span.model_dump() for span in final_spans],
                "element_coverage": element_rows,
                "candidate_answer_anchor_ids": [
                    anchor_ids[str(span.statement_index)] for span in item.answer_spans
                ]
                if anchor_ids
                else [],
                "answer_anchor_ids": [anchor_ids[str(span.statement_index)] for span in retained]
                if anchor_ids
                else [],
                "candidate_answer_spans": [span.model_dump() for span in item.answer_spans],
                "candidate_element_coverage": [
                    element.model_dump() for element in item.element_coverage
                ],
                "candidate_statement_indices": item.statement_indices,
                "final_statement_indices": [
                    mapping[index] for index in item.statement_indices if index in mapping
                ],
                "source_check": _source_check(task, candidate, retained, evidence),
                "context_check": _context_check(task, candidate, retained, evidence),
                "candidate_source_check": _source_check(
                    task, candidate, item.answer_spans, evidence
                ),
            }
        )
    return {
        "version": VERSION,
        "method": "AI_semantic_review_with_exact_text_and_source_policy_checks",
        "independent_gold": False,
        "question_independently_reviewed_by_verifier": True,
        "tasks": rows,
        "unplanned_requirements": [item.model_dump() for item in normalized.unplanned_requirements],
        "claim_support": [
            {
                **item.model_dump(),
                "candidate_statement_index": item.statement_index,
                "final_statement_index": mapping.get(item.statement_index),
            }
            for item in normalized.claim_support
        ],
        "unsupported_statement_indices": sorted(bad),
        "final_statement_index_map": {str(key): value for key, value in mapping.items()},
        "answer_anchor_protocol": ANCHOR_VERSION if anchor_ids else None,
        "answer_anchor_statement_map": [
            {
                "anchor_id": anchor_id,
                "candidate_statement_index": int(index),
                "final_statement_index": mapping.get(int(index)),
            }
            for index, anchor_id in anchor_ids.items()
        ],
        "complete": bool(rows)
        and all(row["status"] == "covered" for row in rows)
        and not normalized.unplanned_requirements
        and not bad,
    }


def validate_verification(plan, candidate, verification, *, question=None, evidence=None):
    return coverage_ledger(plan, candidate, verification, question=question, evidence=evidence)


def reviewed_candidate(plan, candidate, verification, *, question=None, evidence=None):
    normalized = normalize_verification(question, plan, candidate, verification, evidence)
    tasks = {task.task_id: task for task in plan.tasks}
    bad = {item.statement_index for item in normalized.unsupported}
    statements = [claim for index, claim in enumerate(candidate.statements, 1) if index not in bad]
    required = list(candidate.required_facts)
    missing = list(candidate.missing_facts)
    for item in normalized.coverage:
        if item.status != "covered":
            missing.append(
                _coverage_missing_label(tasks[item.task_id].requirement, item.coverage_blockers)
            )
    for omission in normalized.unplanned_requirements:
        required.append(omission.requirement)
        missing.append(omission.requirement)
    if bad:
        missing.extend(item.reason for item in normalized.unsupported)

    def bounded_labels(labels):
        values = list(dict.fromkeys(labels))
        # Preserve every requirement even when the answer schema allows only
        # eight display entries. The ledger retains individual identities.
        return values if len(values) <= 8 else [*values[:7], "；".join(values[7:])]

    required = bounded_labels(required)
    missing = bounded_labels(missing)
    if not statements:
        return candidate.model_copy(
            update={
                "answer_class": "refused",
                "statements": [],
                "required_facts": required,
                "missing_facts": missing,
                "message": "本轮实际引文未支持完整事实结论，尚需补充问题所需证据。",
            }
        )
    return candidate.model_copy(
        update={
            "answer_class": "partial"
            if missing or candidate.answer_class == "partial"
            else "evidence",
            "statements": statements,
            "required_facts": required,
            "missing_facts": missing,
        }
    )
