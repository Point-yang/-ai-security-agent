import hashlib
import os
import tempfile
from pathlib import Path


class BlobStore:
    """Content-addressed, atomic, byte-preserving storage; never executes content."""

    def __init__(self, root: Path):
        self.root = root

    def path_for(self, digest: str) -> Path:
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("invalid SHA-256")
        return self.root / digest[:2] / f"{digest}.json"

    def put(self, content: bytes) -> str:
        digest = hashlib.sha256(content).hexdigest()
        path = self.path_for(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            self.read(digest)
            return digest
        fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".write-")
        try:
            with os.fdopen(fd, "wb") as file:
                file.write(content)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temp, path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
        return digest

    def read(self, digest: str) -> bytes:
        data = self.path_for(digest).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("raw document integrity check failed")
        return data
