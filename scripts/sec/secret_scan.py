#!/usr/bin/env python3
"""Secret scanner for the red-alert defensive baseline.

High-precision provider patterns plus a conservative entropy heuristic for
generic credential assignments. Every hit is a LEAD that must be triaged by a
human: the tool never decides whether a value is a live credential.

    scripts/sec/secret_scan.py .
    scripts/sec/secret_scan.py src/ --json --out findings.json
    scripts/sec/secret_scan.py . --fail-on high

Values are redacted in the output. Exit code is 1 when findings at or above
--fail-on are present.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from collections import Counter

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "target",
    "__pycache__", ".venv", "venv", ".next", ".nuxt", "coverage", ".terraform",
    ".gradle", "Pods", "third_party", "third-party", ".mypy_cache", ".pytest_cache",
    ".tox", ".idea", ".vscode", "site-packages", "bower_components", ".redalert",
}

SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg", ".pdf", ".zip",
    ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".tgz", ".mp3", ".mp4", ".mov", ".avi",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".so", ".dylib", ".dll", ".exe", ".class",
    ".jar", ".pyc", ".pyo", ".o", ".a", ".bin", ".dat", ".db", ".sqlite", ".sqlite3",
    ".pcap", ".pcapng", ".har", ".saz", ".wasm", ".onnx", ".pb", ".safetensors", ".gguf",
}

SKIP_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock", "poetry.lock",
    "gemfile.lock", "composer.lock", "go.sum", "uv.lock", "bun.lockb",
}

SENSITIVE_FILENAMES = {
    ".env": "environment file with secrets",
    ".env.local": "environment file with secrets",
    ".env.production": "environment file with secrets",
    ".npmrc": "npm registry credentials may live here",
    ".pypirc": "PyPI credentials may live here",
    ".netrc": "stored login credentials",
    ".htpasswd": "password hashes",
    "id_rsa": "private key",
    "id_dsa": "private key",
    "id_ecdsa": "private key",
    "id_ed25519": "private key",
    "credentials": "credential store",
    "secrets.yaml": "secret store",
    "secrets.yml": "secret store",
    "secrets.json": "secret store",
}

SUPPRESSION_MARKERS = ("red-alert:ignore", "gitleaks:allow", "nosec", "secret-scan:ignore")

PROVIDER_PATTERNS = [
    ("aws-access-key-id", "critical", re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|A3T[A-Z0-9])[A-Z0-9]{16})\b")),
    ("aws-secret-access-key", "critical", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})")),
    ("github-token", "critical", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{20,255})\b")),
    ("gitlab-pat", "high", re.compile(r"\b(glpat-[A-Za-z0-9_-]{20,})\b")),
    ("slack-token", "high", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("slack-webhook", "medium", re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_/]{20,})")),
    ("stripe-key", "critical", re.compile(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b")),
    ("google-api-key", "high", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b")),
    ("google-oauth-secret", "high", re.compile(r"\b(GOCSPX-[A-Za-z0-9_-]{20,})\b")),
    ("anthropic-key", "critical", re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{40,})\b")),
    ("openai-key", "critical", re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,})\b")),
    ("twilio-key", "high", re.compile(r"\b(SK[0-9a-fA-F]{32})\b")),
    ("sendgrid-key", "high", re.compile(r"\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b")),
    ("private-key-block", "critical", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)")),
    ("jwt", "medium", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")),
    ("npm-auth-token", "critical", re.compile(r"(?m)^_authToken\s*=\s*(\S+)")),
    ("pypi-password", "high", re.compile(r"(?m)^\s*password\s*=\s*(\S+)")),
    ("basic-auth-url", "medium", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]{1,64}:([^\s/@]{3,64})@[^\s/]+")),
]

GENERIC_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|"
    r"refresh[_-]?token|session[_-]?key|private[_-]?key|passwd|password|pwd)\b"
    r"\s*[:=]\s*[\"']([^\"'\n]{8,200})[\"']"
)

PLACEHOLDER_EXACT = {
    "akiaiosfodnn7example", "akiai44qh8dhbexample", "akiaexample",
    "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey", "examplekey", "changeme",
    "password", "secret", "example", "test", "dummy", "yourapikeyhere",
    "xxxxxxxx", "00000000", "11111111", "12345678901234567890123456789012",
}

PLACEHOLDER_SUBSTRINGS = (
    "changeme", "change_me", "your-", "your_", "redacted", "placeholder",
    "xxxx", "notreal", "fixme", "todo", "dummy", "fake-key", "fakekey",
    "process.env", "os.environ", "getenv", "secretmanager", "aws_secrets",
    "op://", "env:", "{{", "${",
)

PLACEHOLDER_PREFIXES = (
    "your", "my-", "my_", "example", "sample", "test-", "test_", "fake",
    "dummy", "placeholder", "redacted", "insert", "replace",
)

TEXT_SUFFIXES = {
    ".txt", ".md", ".markdown", ".json", ".json5", ".yaml", ".yml", ".toml", ".ini",
    ".cfg", ".conf", ".config", ".env", ".properties", ".sh", ".bash", ".zsh", ".fish",
    ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".rb", ".php", ".pl", ".lua",
    ".go", ".rs", ".java", ".kt", ".swift", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs",
    ".ps1", ".psm1", ".bat", ".cmd", ".sql", ".html", ".htm", ".xml", ".gradle", ".tf",
    ".tfvars", ".dockerfile", ".mk", ".cmake", ".envrc", ".npmrc", ".pypirc", ".netrc",
}

TEXT_FILENAMES = {
    ".env", ".npmrc", ".pypirc", ".netrc", "Dockerfile", "Makefile", "Procfile",
    ".gitconfig", ".npmignore", ".yarnrc", ".babelrc", ".eslintrc", ".dockerignore",
}


def shannon(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def redact(value: str) -> str:
    if len(value) <= 8:
        return value[:2] + "*" * max(len(value) - 2, 0)
    return f"{value[:4]}...{value[-2:]}[REDACTED:{len(value)}]"


def is_placeholder(value: str) -> bool:
    lowered = value.lower()
    if lowered in PLACEHOLDER_EXACT:
        return True
    if any(marker in lowered for marker in PLACEHOLDER_SUBSTRINGS):
        return True
    if lowered.startswith(PLACEHOLDER_PREFIXES):
        return True
    if len(set(value)) <= 3:
        return True
    if value.count("*") > len(value) // 3:
        return True
    return False


def iter_files(root: str):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git")]
        for filename in filenames:
            yield os.path.join(dirpath, filename)


def is_scannable(path: str) -> bool:
    name = os.path.basename(path)
    if name in SKIP_FILENAMES:
        return False
    suffix = os.path.splitext(name)[1].lower()
    if suffix in SKIP_SUFFIXES:
        return False
    if suffix in TEXT_SUFFIXES or name in TEXT_FILENAMES or name.startswith(".env"):
        return True
    try:
        with open(path, "rb") as handle:
            chunk = handle.read(4096)
    except OSError:
        return False
    if b"\x00" in chunk:
        return False
    try:
        chunk.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def scan_file(path: str) -> list[dict]:
    findings: list[dict] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return findings

    for number, line in enumerate(lines, start=1):
        if len(line) > 4000:
            continue
        if any(marker in line.lower() for marker in SUPPRESSION_MARKERS):
            continue

        for name, severity, pattern in PROVIDER_PATTERNS:
            for match in pattern.finditer(line):
                value = match.group(1)
                if is_placeholder(value):
                    continue
                findings.append(
                    {
                        "file": path,
                        "line": number,
                        "rule": name,
                        "severity": severity,
                        "match": redact(value),
                        "context": line.strip()[:160].replace(value, redact(value)),
                    }
                )

        for match in GENERIC_ASSIGNMENT.finditer(line):
            value = match.group(2)
            if is_placeholder(value) or shannon(value) < 3.0:
                continue
            findings.append(
                {
                    "file": path,
                    "line": number,
                    "rule": "generic-credential-assignment",
                    "severity": "medium",
                    "match": redact(value),
                    "context": line.strip()[:160].replace(value, redact(value)),
                }
            )

    return findings


def scan(root: str) -> dict:
    findings: list[dict] = []
    sensitive_files: list[dict] = []
    scanned = 0
    skipped = 0

    for path in iter_files(root):
        name = os.path.basename(path)
        if name in SENSITIVE_FILENAMES or name.startswith(".env."):
            sensitive_files.append({"file": path, "reason": SENSITIVE_FILENAMES.get(name, "secret store")})
        if not is_scannable(path):
            skipped += 1
            continue
        scanned += 1
        findings.extend(scan_file(path))

    findings.sort(key=lambda item: (-SEVERITY_ORDER.get(item["severity"], 0), item["file"], item["line"]))
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1

    return {
        "root": root,
        "files_scanned": scanned,
        "files_skipped": skipped,
        "findings": findings,
        "by_severity": counts,
        "sensitive_files": sensitive_files,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a tree for credential leaks.")
    parser.add_argument("path", nargs="?", default=".", help="file or directory to scan")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--out", help="write JSON findings to this file")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info", "none"],
        default="none",
        help="exit 1 when a finding at or above this severity exists",
    )
    args = parser.parse_args()

    root = os.path.abspath(args.path)
    if not os.path.exists(root):
        print(f"error: path does not exist: {root}", file=sys.stderr)
        return 2

    result = scan(root)

    if args.json or args.out:
        payload = json.dumps(result, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(payload + "\n")
            print(f"findings written: {args.out}")
        else:
            print(payload)
    else:
        print(f"scanned {result['files_scanned']} file(s), skipped {result['files_skipped']}")
        if not result["findings"]:
            print("no secret patterns matched")
        for finding in result["findings"]:
            print(
                f"[{finding['severity'].upper():8}] {finding['file']}:{finding['line']} "
                f"{finding['rule']} -> {finding['match']}"
            )
        if result["sensitive_files"]:
            print("\nsensitive files present (verify they contain no live secrets):")
            for item in result["sensitive_files"]:
                print(f"  {item['file']} - {item['reason']}")

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f["severity"], 0) >= threshold for f in result["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
