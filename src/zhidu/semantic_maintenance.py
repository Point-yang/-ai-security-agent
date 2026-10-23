"""Opt-in semantic repair after collection; model failures do not undo source ingestion."""

from sqlalchemy.exc import SQLAlchemyError

from zhidu.locking import WriterBusy, writer_lock
from zhidu.models import RecoveryAction, now_utc
from zhidu.observability import log_event


def maintain_semantics(sessions, settings, *, encoder=None):
    from zhidu.semantic import LocalEncoder, ModelUnavailable, sync_embeddings

    own_encoder = encoder is None
    encoder = encoder or LocalEncoder(settings)
    try:
        with writer_lock(settings.database_url), sessions.begin() as session:
            result = {"status": "completed", **sync_embeddings(session, settings, encoder)}
            session.add(
                RecoveryAction(
                    action_type="semantic_reconcile",
                    status="completed",
                    detail=result,
                    occurred_at=now_utc(),
                )
            )
        return result
    except (ModelUnavailable, TimeoutError, OSError, SQLAlchemyError, WriterBusy) as exc:
        # A later cycle retries. Query-side completeness checks continue to
        # reject a stale or partial index; do not silently downgrade retrieval.
        result = {"status": "failed", "error_type": type(exc).__name__}
        log_event("semantic_reconcile_failed", **result)
        return result
    finally:
        if own_encoder:
            encoder.close()
