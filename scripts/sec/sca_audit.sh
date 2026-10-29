#!/usr/bin/env bash
# Dependency and supply-chain audit across the ecosystems present in a tree.
#
#   scripts/sec/sca_audit.sh [PATH]
#
# Reports what was checked, which tooling was available, and what was found.
# It never installs an audit tool: a missing tool is reported as a coverage gap.
set -euo pipefail

ROOT="${1:-.}"
ROOT="$(cd "$ROOT" && pwd)"
RESULTS=()
NOTES=()

have() { command -v "$1" >/dev/null 2>&1; }

record() { RESULTS+=("$1"); }
note() { NOTES+=("$1"); }

# ---------------------------------------------------------------- npm / node
if [ -f "$ROOT/package.json" ]; then
  if have npm && [ -f "$ROOT/package-lock.json" ]; then
    if npm audit --omit=dev --json --prefix "$ROOT" >/tmp/redalert-npm-audit.json 2>/dev/null; then
      VULN_TOTAL=$(python3 - <<'PY' 2>/dev/null || echo "unknown"
import json
try:
    with open('/tmp/redalert-npm-audit.json') as fh:
        data = json.load(fh)
    print(data.get('metadata', {}).get('vulnerabilities', {}).get('total', 0))
except Exception:
    print('unknown')
PY
)
      record "npm:audit:total=$VULN_TOTAL"
      python3 - <<'PY' 2>/dev/null || true
import json
try:
    with open('/tmp/redalert-npm-audit.json') as fh:
        data = json.load(fh)
except Exception:
    raise SystemExit(0)
vulns = data.get('vulnerabilities') or {}
for name, info in sorted(vulns.items()):
    severity = info.get('severity', 'unknown')
    via = ', '.join(str(v.get('title', v.get('name', '?'))) if isinstance(v, dict) else str(v) for v in info.get('via', [])[:3])
    print(f"  npm  {severity:9} {name}  {via}")
PY
    else
      note "npm audit did not complete (offline or registry unreachable) - coverage gap"
      record "npm:audit:unavailable"
    fi
  else
    note "package.json present without package-lock.json - install reproducibility not enforced"
    record "npm:lockfile:missing"
  fi

  UNPINNED=$(python3 - "$ROOT/package.json" <<'PY' 2>/dev/null || echo 0
import json, sys
try:
    with open(sys.argv[1]) as fh:
        pkg = json.load(fh)
except Exception:
    print(0); raise SystemExit(0)
count = 0
for section in ('dependencies', 'devDependencies'):
    for name, spec in (pkg.get(section) or {}).items():
        if spec in ('latest', '*', '') or spec.startswith('http'):
            count += 1
            print(f"  npm  unpinned  {section}.{name} = {spec}", file=sys.stderr)
if pkg.get('scripts'):
    for hook in ('preinstall', 'install', 'postinstall', 'prepare'):
        if hook in pkg['scripts']:
            print(f"  npm  install-script  {hook}: {pkg['scripts'][hook]}", file=sys.stderr)
print(count)
PY
)
  record "npm:unpinned=$UNPINNED"
fi

# ---------------------------------------------------------------- python
if [ -f "$ROOT/requirements.txt" ] || [ -f "$ROOT/Pipfile" ] || [ -f "$ROOT/pyproject.toml" ]; then
  if have pip-audit; then
    if [ -f "$ROOT/requirements.txt" ]; then
      if pip-audit -r "$ROOT/requirements.txt" --format=columns 2>/dev/null | sed 's/^/  /'; then
        record "python:pip-audit:ok"
      else
        record "python:pip-audit:findings"
      fi
    else
      note "pip-audit available but no requirements.txt to audit"
      record "python:pip-audit:no-requirements"
    fi
  else
    note "pip-audit not installed - python dependency CVEs were not checked (coverage gap)"
    record "python:pip-audit:unavailable"
  fi

  python3 - "$ROOT" <<'PY' 2>/dev/null || true
import os, re, sys
root = sys.argv[1]
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in {'.git', 'node_modules', '.venv', 'venv', '__pycache__'}]
    for name in filenames:
        if name != 'requirements.txt':
            continue
        path = os.path.join(dirpath, name)
        with open(path, encoding='utf-8', errors='replace') as fh:
            for number, line in enumerate(fh, start=1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if re.match(r'^[A-Za-z0-9_.-]+\s*==\s*[A-Za-z0-9_.+!-]+$', line):
                    continue
                print(f"  py   unpinned  {os.path.relpath(path, root)}:{number}  {line[:70]}", file=sys.stderr)
PY
fi

# ---------------------------------------------------------------- rust
if [ -f "$ROOT/Cargo.toml" ]; then
  if have cargo-audit; then
    (cd "$ROOT" && cargo audit 2>&1 | sed 's/^/  /') || record "rust:cargo-audit:findings"
    record "rust:cargo-audit:ok"
  else
    note "cargo-audit not installed - rust dependency CVEs were not checked (coverage gap)"
    record "rust:cargo-audit:unavailable"
  fi
fi

# ---------------------------------------------------------------- go
if [ -f "$ROOT/go.mod" ]; then
  if have govulncheck; then
    (cd "$ROOT" && govulncheck ./... 2>&1 | sed 's/^/  /') || true
    record "go:govulncheck:ok"
  else
    note "govulncheck not installed - go dependency CVEs were not checked (coverage gap)"
    record "go:govulncheck:unavailable"
  fi
  python3 - "$ROOT/go.mod" <<'PY' 2>/dev/null || true
import re, sys
with open(sys.argv[1], encoding='utf-8', errors='replace') as fh:
    for number, line in enumerate(fh, start=1):
        if line.startswith('replace') or '=>' in line and 'golang.org' not in line:
            print(f"  go   replace-directive  go.mod:{number}  {line.strip()[:70]}")
PY
fi

# ---------------------------------------------------------------- java
if [ -f "$ROOT/pom.xml" ] || [ -f "$ROOT/build.gradle" ]; then
  note "java dependency audit requires OWASP dependency-check and a JDK - not run (coverage gap)"
  record "java:audit:unavailable"
fi

# ---------------------------------------------------------------- report
if [ "${REPORT_JSON:-0}" = "1" ]; then
  RESULTS_JSON="$(printf '%s\n' "${RESULTS[@]:-}" | python3 -c 'import sys,json; print(json.dumps([l for l in sys.stdin.read().splitlines() if l.strip()]))')"
  NOTES_JSON="$(printf '%s\n' "${NOTES[@]:-}" | python3 -c 'import sys,json; print(json.dumps([l for l in sys.stdin.read().splitlines() if l.strip()]))')"
  printf '{"results": %s, "notes": %s}\n' "$RESULTS_JSON" "$NOTES_JSON"
else
  echo "dependency audit: ${ROOT}"
  for entry in "${RESULTS[@]:-}"; do [ -n "$entry" ] && echo "  $entry"; done
  if [ ${#NOTES[@]} -gt 0 ]; then
    echo
    echo "coverage gaps:"
    for entry in "${NOTES[@]:-}"; do [ -n "$entry" ] && echo "  - $entry"; done
  fi
fi
