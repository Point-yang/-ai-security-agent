"""Server-authored whole-statement anchors and separate own-quote identities."""

import hashlib
import json

from zhidu.grounded_answer import render_answer

VERSION = "candidate-answer-anchors-v1"
QUOTE_METADATA = (
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


def _digest(value):
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def candidate_fingerprint(candidate, evidence):
    """Bind all answer fields and actual attached quote/provenance, not other text."""
    rendered = render_answer(candidate, evidence)
    own_quotes = []
    for statement_index, claim in enumerate(rendered["generated_claims"], 1):
        for ref_index, reference in enumerate(claim["evidence"], 1):
            citation = rendered["citations"][reference["citation"] - 1]
            own_quotes.append(
                {
                    "statement_index": statement_index,
                    "reference_index": ref_index,
                    "quote": reference["quote"],
                    **{key: citation.get(key) for key in QUOTE_METADATA},
                }
            )
            provenance = citation.get("span_provenance", {})
            if provenance.get("version") in {"source-context-span-v1", "source-context-span-v2"}:
                # Keep old citation fingerprints stable, but bind new physical
                # context proofs as well as their text and source coordinates.
                own_quotes[-1]["context_provenance"] = provenance
    return _digest({"candidate": candidate.model_dump(), "own_quotes": own_quotes}), own_quotes


def anchor_binding_prefix(scope_digest, candidate_digest):
    return _digest({"version": VERSION, "scope": scope_digest, "candidate": candidate_digest})[:16]


def question_fingerprint(question):
    return _digest(question)


def scope_fingerprint(question, scope):
    return _digest({"question": question, "scope": scope})


def build_answer_anchors(question, plan, candidate, evidence, scope=None):
    """Build IDs without editing prose or inferring any semantic coverage."""
    del plan  # Requirements do not change the candidate's physical text identity.
    scope_digest = scope_fingerprint(question, scope)
    candidate_digest, quotes = candidate_fingerprint(candidate, evidence)
    binding = anchor_binding_prefix(scope_digest, candidate_digest)
    source_quotes = []
    for quote in quotes:
        source_quotes.append(
            {
                **quote,
                "quote_id": f"src_{binding}_{quote['statement_index']}_{quote['reference_index']}",
            }
        )
    answer_anchors = [
        {
            "anchor_id": f"ans_{binding}_{index}",
            "statement_index": index,
            "text": claim.text,
            "start": 0,
            "end": len(claim.text),
            "quote_ids": [
                quote["quote_id"] for quote in source_quotes if quote["statement_index"] == index
            ],
        }
        for index, claim in enumerate(candidate.statements, 1)
    ]
    return {
        "version": VERSION,
        "question_digest": question_fingerprint(question),
        "scope_digest": scope_digest,
        "candidate_digest": candidate_digest,
        "answer_anchors": answer_anchors,
        "source_quotes": source_quotes,
    }
