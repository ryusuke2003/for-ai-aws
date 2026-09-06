#!/usr/bin/env python3
"""Fail when tracked text files contain common credential/private-key patterns.

This intentionally uses only the Python standard library and `git ls-files` so the
security check itself does not add a third-party CI dependency.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


TEXT_SUFFIXES = {
    ".py", ".md", ".yml", ".yaml", ".json", ".toml", ".txt", ".sh", ".ini", ".cfg", ".env"
}

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "AWS secret access key assignment",
        re.compile(
            r"(?i)\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\b\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b"
        ),
    ),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    (
        "private key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    ),
)


def tracked_files() -> list[Path]:
    proc = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    return [Path(raw.decode("utf-8")) for raw in proc.stdout.split(b"\0") if raw]


def scan_text(path: Path, text: str) -> list[tuple[str, int]]:
    findings: list[tuple[str, int]] = []
    for label, pattern in PATTERNS:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append((label, line))
    return findings


def main() -> int:
    findings: list[tuple[Path, str, int]] = []

    for path in tracked_files():
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"Dockerfile", "Makefile"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for label, line in scan_text(path, text):
            findings.append((path, label, line))

    if not findings:
        print("Secret scan passed: no common credential patterns found in tracked text files.")
        return 0

    print("Secret scan failed. Potential secrets were found:", file=sys.stderr)
    for path, label, line in findings:
        # Never echo the matched value itself into CI logs.
        print(f"- {path}:{line}: {label}", file=sys.stderr)
    print("Remove/rotate any real credential before pushing again.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
