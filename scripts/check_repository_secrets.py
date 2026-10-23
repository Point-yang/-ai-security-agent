#!/usr/bin/env python3
"""Check Git upload candidates without displaying credential values."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

LOCAL_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".venv",
    ".idea",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "archives",
    "build",
    "data",
    "dist",
    "node_modules",
    "output",
    "release",
    "tmp",
    "venv",
}
PRIVATE_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".crt", ".cer", ".keystore", ".jks"}
DATABASE_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".db3"}
TOKEN_RULES = {
    "github-token": rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b",
    "provider-api-key": rb"\bsk-(?:proj-|svcacct-|ant-api\d{2}-)?[A-Za-z0-9_-]{24,256}\b",
    "aws-access-key": rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "google-api-key": rb"\bAIza[0-9A-Za-z_-]{35}\b",
    "slack-token": rb"\bxox[baprs]-[0-9A-Za-z-]{20,255}\b",
    "private-key-header": rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----",
}
COMPILED_RULES = [(name, re.compile(pattern)) for name, pattern in TOKEN_RULES.items()]
ENV_ASSIGNMENT = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
ENV_SECRET_NAME = re.compile(r"(?:^|_)(?:KEY|TOKEN|PASSWORD|SECRET)(?:_|$)", re.IGNORECASE)
SHORT_SECRET_CONTEXT = (
    rb"(?i:\b(?:[A-Za-z_][A-Za-z0-9_]*_)?(?:KEY|TOKEN|PASSWORD|SECRET)"
    rb"(?:_[A-Za-z0-9_]+)*\b)[\"']?\s*[:=]\s*[\"']?"
)


def git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("Git could not read the repository or index.")
    return result.stdout


def local_secrets(root: Path) -> set[bytes]:
    """Read literal local dotenv values; never include templates or follow links."""
    secrets: set[bytes] = set()
    for path in sorted(root.glob(".env*")):
        if path.name == ".env.example" or not path.is_file() or path.is_symlink():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            match = ENV_ASSIGNMENT.match(line.strip())
            if not match or not ENV_SECRET_NAME.search(match[1]):
                continue
            value = match[2].strip()
            if value.startswith(("'", '"')):
                quote = value[0]
                end = value.find(quote, 1)
                if end < 0:
                    raise ValueError("A local dotenv secret has an unterminated quote.")
                value = value[1:end]
            else:
                value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
            if value:
                secrets.add(value.encode("utf-8"))
    return secrets


def forbidden_path(name: str) -> str | None:
    path = PurePosixPath(name)
    if any(part in LOCAL_DIRECTORIES for part in path.parts):
        return "local-artifact-directory"
    if path.name.startswith(".env") and path.name != ".env.example":
        return "local-dotenv-file"
    if path.name in {".envrc", ".DS_Store", ".coverage"}:
        return "local-configuration-file"
    if path.suffix.lower() in PRIVATE_SUFFIXES:
        return "private-key-or-certificate-file"
    if path.suffix.lower() in DATABASE_SUFFIXES or re.search(
        r"\.(?:db|sqlite|sqlite3|db3)-(?:wal|shm|journal)$", path.name, re.IGNORECASE
    ):
        return "local-database-file"
    return None


def scan(root: Path, staged: bool) -> tuple[int, list[tuple[str, int, str]]]:
    arguments = ["ls-files", "--cached"]
    if not staged:
        arguments.extend(["--others", "--exclude-standard"])
    arguments.append("-z")
    names = sorted({os.fsdecode(name) for name in git(root, *arguments).split(b"\0") if name})
    secrets = []
    for value in local_secrets(root):
        # Short demo values also occur as ordinary numbers/words in public records.
        # Only flag them in credential assignments; document the manual-review gap.
        prefix = SHORT_SECRET_CONTEXT if len(value.decode("utf-8")) < 8 else rb"(?<![A-Za-z0-9_])"
        secrets.append(re.compile(prefix + re.escape(value) + rb"(?![A-Za-z0-9_])"))
    findings: set[tuple[str, int, str]] = set()
    checked = 0
    for name in names:
        rule = forbidden_path(name)
        if rule:
            findings.add((name, 1, rule))
        if staged:
            content = git(root, "show", f":{name}")
        else:
            path = root / name
            if path.is_symlink():
                content = os.fsencode(os.readlink(path))
            elif not path.exists():
                # A tracked deletion has no upload content in the worktree.
                continue
            else:
                content = path.read_bytes()
        checked += 1
        for rule_name, pattern in COMPILED_RULES:
            for match in pattern.finditer(content):
                findings.add((name, content.count(b"\n", 0, match.start()) + 1, rule_name))
        for secret in secrets:
            for match in secret.finditer(content):
                findings.add(
                    (name, content.count(b"\n", 0, match.start()) + 1, "local-dotenv-secret-value")
                )
    return checked, sorted(findings)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true", help="scan the entire Git index")
    args = parser.parse_args()
    try:
        root = Path(os.fsdecode(git(Path.cwd(), "rev-parse", "--show-toplevel")).strip())
    except (RuntimeError, OSError):
        print(
            "ERROR: current directory is not inside an accessible Git repository.", file=sys.stderr
        )
        return 2
    try:
        checked, findings = scan(root, args.staged)
    except (RuntimeError, OSError, UnicodeError, ValueError):
        print(
            "ERROR: could not completely read Git candidates or local dotenv files.",
            file=sys.stderr,
        )
        return 2
    for path, line, rule in findings:
        # repr keeps unusual filenames on one line; matched values are never printed.
        print(f"{path!r}:{line}: {rule}")
    if findings:
        print(f"FAIL: {len(findings)} finding(s) in {checked} checked file(s).")
        return 1
    print(f"PASS: {checked} Git candidate file(s) checked; no configured secret rule matched.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
