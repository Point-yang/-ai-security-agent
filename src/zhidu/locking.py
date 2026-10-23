"""One writer per database. File lock on SQLite; advisory lock on PostgreSQL."""

from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


class WriterBusy(RuntimeError):
    pass


@contextmanager
def writer_lock(database_url):
    url = make_url(database_url)
    if url.get_backend_name() == "postgresql":
        engine = create_engine(database_url)
        try:
            with engine.connect() as conn:
                acquired = conn.scalar(text("SELECT pg_try_advisory_lock(873465102)"))
                conn.commit()
                if not acquired:
                    raise WriterBusy("another collector holds the database writer lock")
                try:
                    yield
                finally:
                    conn.execute(text("SELECT pg_advisory_unlock(873465102)"))
                    conn.commit()
        finally:
            engine.dispose()
    elif url.get_backend_name() == "sqlite":
        import fcntl

        if not url.database or url.database == ":memory:":
            raise ValueError("monitor requires a persistent SQLite database")
        path = Path(url.database).resolve().with_suffix(".collect.lock")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as file:
            try:
                fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise WriterBusy("another collector holds the database writer lock") from None
            try:
                yield
            finally:
                fcntl.flock(file, fcntl.LOCK_UN)
    else:
        raise ValueError("unsupported monitor database")
