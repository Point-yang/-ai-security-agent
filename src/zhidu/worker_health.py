"""A worker liveness pulse independent of long source polling cycles."""

import fcntl
import os
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from zhidu.locking import WriterBusy


@contextmanager
def worker_pulse(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    lease = path.with_suffix(".worker.lock").open("a")
    try:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lease.close()
        raise WriterBusy("a monitor already owns this worker heartbeat") from None
    stopped = threading.Event()

    def write_pulse():
        temporary = path.with_suffix(f".{os.getpid()}.tmp")
        temporary.write_text(str(os.getpid()))
        os.replace(temporary, path)

    def pulse():
        while not stopped.is_set():
            # Health is deliberately based on the writer mtime; source progress
            # has separate persisted per-target timestamps and alerts.
            write_pulse()
            stopped.wait(5)

    thread = threading.Thread(target=pulse, daemon=True)
    try:
        write_pulse()
        thread.start()
        yield
    finally:
        stopped.set()
        if thread.ident is not None:
            thread.join(timeout=6)
        try:
            if path.read_text() == str(os.getpid()):
                path.unlink()
        except FileNotFoundError:
            pass
        finally:
            fcntl.flock(lease, fcntl.LOCK_UN)
            lease.close()


def healthy(path: Path) -> bool:
    try:
        pid = int(path.read_text())
        os.kill(pid, 0)
        return 0 <= time.time() - path.stat().st_mtime < 30
    except (OSError, ValueError):
        return False


def worker_snapshot(path: Path) -> dict:
    """Independent process/pulse observation; disclose no PID or local path."""
    checked_at = datetime.now(UTC).isoformat()
    age = None
    try:
        pid = int(path.read_text())
        if pid <= 0:
            raise ValueError("invalid pid")
        age = max(0.0, time.time() - path.stat().st_mtime)
        os.kill(pid, 0)
        status = "healthy" if age < 30 else "stale"
    except FileNotFoundError:
        status = "not_started"
    except ProcessLookupError:
        status = "not_running"
    except PermissionError:
        status = "unverified"
    except (OSError, ValueError):
        status = "unavailable"
    return {
        "status": status,
        "checked_at": checked_at,
        "pulse_age_seconds": round(age, 3) if age is not None else None,
        "check_method": "process_exists_and_independent_heartbeat_file",
        "target_progress_heartbeat_used": False,
        "process_uptime_measured": False,
    }


if __name__ == "__main__":
    from zhidu.config import Settings

    raise SystemExit(0 if healthy(Settings().raw_dir.parent / "collector.heartbeat") else 1)
