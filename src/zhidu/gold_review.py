"""Blinded human QA review packets and an explicit two-reviewer release gate.

Reviewer identities are self-attested local metadata, not authenticated accounts.
This module never creates human answers or signs reviews on a user's behalf.
"""

import json
from collections import Counter
from datetime import datetime

from zhidu.semantic import digest
from zhidu.sources import resolve_pointer


def seal(data):
    return {**data, "sha256": digest(data)}


def validate_seal(data):
    copy = dict(data)
    expected = copy.pop("sha256")
    if digest(copy) != expected:
        raise ValueError("Packet checksum mismatch")


def make_packet(frozen):
    records = []
    for item in frozen["human_annotation_records"]:
        records.append(
            {
                k: item[k]
                for k in (
                    "event_id",
                    "revision_id",
                    "source_id",
                    "external_id",
                    "raw_document_id",
                    "sha256",
                    "record_pointer",
                    "raw_record",
                    "group_id",
                    "split",
                )
            }
        )
    tasks = [
        {
            "id": r["event_id"],
            "group_id": r["group_id"],
            "split": r["split"],
            "question": f"依据 {r['source_id']} 的 {r['external_id']}，可确认哪些来源结论，哪些结论证据不足？",
            "record_ids": [r["event_id"]],
        }
        for r in records
    ]
    return seal(
        {
            "version": "human-qa-packet-v1",
            "parent_freeze_sha256": frozen["freeze_sha256"],
            "corpus_sha256": frozen["corpus_sha256"],
            "tasks": tasks,
            "records": records,
            "model_outputs_included": False,
            "split_counts": dict(Counter(t["split"] for t in tasks)),
            "status": "awaiting_independent_human_reviews",
        }
    )


def review_template(packet, slot):
    return {
        "packet_sha256": packet["sha256"],
        "slot": slot,
        "reviewer_id": None,
        "review_method": "human",
        "independent_review_attested": False,
        "reviews": [
            {
                "task_id": t["id"],
                "reviewed_at": None,
                "answer_class": None,
                "complete_answer": None,
                "supported_fields": [],
                "refusal_reason": None,
                "citations": [],
            }
            for t in packet["tasks"]
        ],
    }


def nonblank(value):
    return isinstance(value, str) and bool(value.strip())


def validate_answer(packet, task, answer):
    status = answer.get("answer_class")
    if status not in {"evidence", "partial", "refused"}:
        raise ValueError("answer_class must be evidence/partial/refused")
    if not nonblank(answer.get("complete_answer")):
        raise ValueError("A full human answer is required")
    if status in {"partial", "refused"} and not nonblank(answer.get("refusal_reason")):
        raise ValueError("Partial/refused answers require an evidence limitation reason")
    citations = answer.get("citations", [])
    if status != "refused" and (not citations or not answer.get("supported_fields")):
        raise ValueError("Evidence answers need supporting fields and quotations")
    records = {r["event_id"]: r for r in packet["records"]}
    cited_fields = set()
    for citation in citations:
        record = records.get(citation.get("record_id"))
        if not record or record["group_id"] != task["group_id"]:
            raise ValueError("Citation must belong to the question's frozen alias group")
        try:
            value = resolve_pointer(record["raw_record"], citation["pointer"])
        except (KeyError, ValueError, IndexError, TypeError) as exc:
            raise ValueError("Citation pointer does not resolve in blinded source record") from exc
        text = (
            value
            if isinstance(value, str)
            else json.dumps(value, ensure_ascii=False, sort_keys=True)
        )
        if not nonblank(citation.get("quote")) or citation["quote"] not in text:
            raise ValueError("Human supporting quote does not match frozen source")
        cited_fields.add(citation["pointer"])
    for field in answer.get("supported_fields", []):
        if not nonblank(field) or "/" + field.lstrip("/") not in cited_fields:
            raise ValueError("Each supported field requires a matching citation pointer")


def _reviews(packet, document, slot):
    if document.get("packet_sha256") != packet["sha256"] or document.get("slot") != slot:
        raise ValueError("Review is for the wrong packet or slot")
    completed = [r for r in document["reviews"] if r.get("answer_class") is not None]
    if not completed:
        return {}, None
    if (
        document.get("review_method") != "human"
        or document.get("independent_review_attested") is not True
    ):
        raise ValueError("Human independent review attestation is required")
    reviewer = document.get("reviewer_id")
    if not nonblank(reviewer):
        raise ValueError("Reviewer identity required")
    tasks = {t["id"]: t for t in packet["tasks"]}
    output = {}
    for answer in completed:
        task_id = answer["task_id"]
        if task_id not in tasks or task_id in output:
            raise ValueError("Unknown or duplicate task")
        try:
            stamp = datetime.fromisoformat(answer["reviewed_at"].replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                raise ValueError("timezone required")
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ValueError("Human review timestamp required with timezone") from exc
        validate_answer(packet, tasks[task_id], answer)
        output[task_id] = answer
    return output, reviewer.strip()


def _decision(answer):
    return {
        k: answer.get(k)
        for k in (
            "answer_class",
            "complete_answer",
            "supported_fields",
            "refusal_reason",
            "citations",
        )
    }


def reconcile(packet, first, second, adjudications=None):
    validate_seal(packet)
    if not packet["tasks"]:
        raise ValueError("An empty packet cannot become human gold")
    a, reviewer_a = _reviews(packet, first, "A")
    b, reviewer_b = _reviews(packet, second, "B")
    if reviewer_a and reviewer_b and reviewer_a.casefold() == reviewer_b.casefold():
        raise ValueError("The two reviewers must be distinct")
    adjudications = adjudications or {"packet_sha256": packet["sha256"], "decisions": []}
    if adjudications.get("packet_sha256") != packet["sha256"]:
        raise ValueError("Adjudications reference wrong packet")
    decisions = {}
    for item in adjudications["decisions"]:
        if item["task_id"] not in {t["id"] for t in packet["tasks"]}:
            raise ValueError("Unknown adjudication task")
        if item["task_id"] in decisions:
            raise ValueError("Duplicate adjudication")
        decisions[item["task_id"]] = item
    agreed, pending, conflicts = [], [], []
    for task in packet["tasks"]:
        task_id = task["id"]
        if task_id not in a or task_id not in b:
            pending.append(task_id)
            continue
        if _decision(a[task_id]) == _decision(b[task_id]):
            agreed.append(
                {
                    **task,
                    **_decision(a[task_id]),
                    "reviewers": [reviewer_a, reviewer_b],
                    "resolution": "independent_agreement",
                }
            )
            continue
        decision = decisions.get(task_id)
        if not decision:
            conflicts.append(task_id)
            continue
        adjudicator = decision.get("adjudicator_id")
        if not nonblank(adjudicator) or adjudicator.casefold() in {
            reviewer_a.casefold(),
            reviewer_b.casefold(),
        }:
            raise ValueError("Disagreement requires a distinct adjudicator")
        if not nonblank(decision.get("reason")):
            raise ValueError("Adjudication rationale required")
        if decision.get("review_method") != "human":
            raise ValueError("Adjudication must be an actual human review")
        try:
            if (
                datetime.fromisoformat(decision["reviewed_at"].replace("Z", "+00:00")).tzinfo
                is None
            ):
                raise ValueError("Timezone required")
        except (ValueError, KeyError, AttributeError) as exc:
            raise ValueError("Adjudication timestamp with timezone required") from exc
        validate_answer(packet, task, decision["answer"])
        agreed.append(
            {
                **task,
                **_decision(decision["answer"]),
                "reviewers": [reviewer_a, reviewer_b],
                "resolution": "adjudicated",
                "adjudicator": adjudicator,
                "rationale": decision["reason"],
            }
        )
    return {
        "version": "human-qa-gate-v1",
        "packet_sha256": packet["sha256"],
        "status": "ready_to_freeze" if not pending and not conflicts else "pending_human_review",
        "tasks": len(packet["tasks"]),
        "completed": len(agreed),
        "pending": pending,
        "conflicts": conflicts,
        "labels": agreed,
        "independent_review_identity_scope": "local_self_attestation_not_authenticated_accounts",
        "official_answer_scores": None,
    }


def freeze_release(packet, first, second, adjudications=None):
    result = reconcile(packet, first, second, adjudications)
    if result["status"] != "ready_to_freeze":
        raise ValueError("Gold cannot be released: missing independent reviews or adjudication")
    return seal(
        {
            **result,
            "status": "human_gold_frozen",
            "corpus_sha256": packet["corpus_sha256"],
            "parent_freeze_sha256": packet["parent_freeze_sha256"],
            "first_review_sha256": digest(first),
            "second_review_sha256": digest(second),
            "adjudication_sha256": digest(adjudications),
        }
    )
