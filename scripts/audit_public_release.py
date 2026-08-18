#!/usr/bin/env python3
"""Fail closed on common private-infrastructure and credential disclosures."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_PUBLIC_HOSTED_MCP_URL = "https://mcp.hirenimbus.com/mcp"
REQUIRED_FILES = (
    "LICENSE",
    "README.md",
    ".env.example",
    "Dockerfile",
    "Dockerfile.lambda",
    "template.yaml",
    "server.json",
    "skills/home-service-concierge/SKILL.md",
)

FORBIDDEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("first-party hosted endpoint", re.compile(r"https?://[^\s\"'<>]*hirenimbus\.com", re.I)),
    ("private Supabase endpoint", re.compile(r"https?://[^\s\"'<>]*supabase\.co", re.I)),
    ("service-role credential", re.compile(r"\bservice[_-]?role\s*[:=]", re.I)),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Stripe live secret", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("GitHub access token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
)

SENSITIVE_ASSIGNMENT = re.compile(
    r"(?im)^\s*(?:[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY))\s*=\s*['\"](?!['\"])[^'\"]+['\"]"
)
IGNORED_BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".pyc"}


def tracked_release_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [
        ROOT / item
        for item in result.stdout.decode("utf-8", errors="replace").split("\0")
        if item
    ]


def main() -> int:
    errors: list[str] = []
    for required in REQUIRED_FILES:
        if not (ROOT / required).is_file():
            errors.append(f"missing required release file: {required}")

    for path in tracked_release_files():
        if path.name in {".env", ".env.local", "local.config.json"}:
            errors.append(f"private configuration file is tracked: {path.relative_to(ROOT)}")
            continue
        if path.suffix.lower() in IGNORED_BINARY_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        audit_text = text.replace(ALLOWED_PUBLIC_HOSTED_MCP_URL, "")
        for label, pattern in FORBIDDEN_PATTERNS:
            if pattern.search(audit_text):
                errors.append(f"{label} pattern found in {path.relative_to(ROOT)}")
        if path.name != ".env.example" and SENSITIVE_ASSIGNMENT.search(text):
            errors.append(f"non-example sensitive assignment found in {path.relative_to(ROOT)}")

    if errors:
        print("Public release audit failed:", file=sys.stderr)
        for error in sorted(set(errors)):
            print(f"- {error}", file=sys.stderr)
        return 1

    print("Public release audit passed for the tracked release tree.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
