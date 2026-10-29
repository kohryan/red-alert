#!/usr/bin/env bash
# Defensive security baseline for a tree.
#
#   scripts/sec/baseline.sh [--path .] [--format text|json] [--fail-on high]
#
# Layers: L0 repository hygiene, L1 dependency audit, L2 secret scan.
# Findings are leads, not verdicts: each one needs a human decision.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PATH_ARG="."
FORMAT="text"
FAIL_ON="none"

while [ $# -gt 0 ]; do
  case "$1" in
    --path) PATH_ARG="${2:-.}"; shift 2 ;;
    --format) FORMAT="${2:-text}"; shift 2 ;;
    --fail-on) FAIL_ON="${2:-none}"; shift 2 ;;
    -h|--help)
      echo "usage: baseline.sh [--path DIR] [--format text|json] [--fail-on LEVEL]"
      exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

TARGET="$(cd "$PATH_ARG" && pwd)"
OUT_DIR="${TARGET}/.redalert"
mkdir -p "$OUT_DIR"

# ------------------------------------------------------------------ L0 hygiene
HYGIENE="$(cd "$TARGET" && python3 - "$TARGET" <<'PY'
import json, os, re, stat, subprocess, sys

root = sys.argv[1]
findings = []
notes = []

SENSITIVE = re.compile(
    r"(^|/)(\.env(\..*)?|id_rsa|id_dsa|id_ecdsa|id_ed25519|.*\.pem|.*\.p12|.*\.pfx|"
    r"credentials(\..*)?|secrets?\.(ya?ml|json)|\.npmrc|\.pypirc|\.netrc|\.htpasswd)$",
    re.IGNORECASE,
)

def run(args):
    try:
        return subprocess.run(args, cwd=root, capture_output=True, text=True, timeout=60)
    except Exception:
        return None

is_git = run(["git", "rev-parse", "--is-inside-work-tree"])
tracked = []
if is_git and is_git.stdout.strip() == "true":
    res = run(["git", "ls-files"])
    tracked = res.stdout.splitlines() if res else []

for path in tracked:
    if SENSITIVE.search(path):
        findings.append({
            "layer": "hygiene", "severity": "high", "rule": "tracked-sensitive-file",
            "file": path, "detail": "a credential-bearing path is tracked in git",
        })

    full = os.path.join(root, path)
    try:
        mode = os.stat(full).st_mode
    except OSError:
        continue
    if mode & stat.S_IWOTH:
        findings.append({
            "layer": "hygiene", "severity": "medium", "rule": "world-writable-file",
            "file": path, "detail": "file is world-writable",
        })
    if mode & stat.S_IXUSR and not path.endswith((".sh", ".py", ".js", ".mjs", ".ts")):
        findings.append({
            "layer": "hygiene", "severity": "low", "rule": "unexpected-executable-bit",
            "file": path, "detail": "tracked file has the executable bit set",
        })

gitignore = os.path.join(root, ".gitignore")
if os.path.exists(gitignore):
    with open(gitignore, encoding="utf-8", errors="replace") as fh:
        content = fh.read()
    for required in (".env", "*.pem", "id_rsa", "node_modules"):
        if required not in content:
            findings.append({
                "layer": "hygiene", "severity": "low", "rule": "gitignore-gap",
                "file": ".gitignore", "detail": f"pattern {required!r} is not covered",
            })
else:
    findings.append({
        "layer": "hygiene", "severity": "medium", "rule": "missing-gitignore",
        "file": ".gitignore", "detail": "no .gitignore in the reviewed tree",
    })

for required in ("LICENSE", "SECURITY.md"):
    if not os.path.exists(os.path.join(root, required)):
        notes.append(f"{required} is missing from the reviewed tree")

if not tracked:
    if is_git and is_git.stdout.strip() == "true":
        notes.append("git repository has no tracked files yet (nothing committed) - tracked-file hygiene checks were skipped")
    else:
        notes.append("not a git working tree - tracked-file hygiene checks were skipped")

print(json.dumps({"findings": findings, "notes": notes, "tracked_files": len(tracked)}))
PY
)"

# ------------------------------------------------------------------ L2 secrets
SECRET_JSON="$OUT_DIR/secrets.json"
python3 "${SCRIPT_DIR}/secret_scan.py" "$TARGET" --json --out "$SECRET_JSON" >/dev/null

# ------------------------------------------------------------------ L1 deps
REPORT_JSON=1 "${SCRIPT_DIR}/sca_audit.sh" "$TARGET" > "$OUT_DIR/deps.json" 2>/dev/null || \
  echo '{"results": [], "notes": ["dependency audit did not complete"]}' > "$OUT_DIR/deps.json"

# ------------------------------------------------------------------ report
python3 - "$TARGET" "$FORMAT" "$FAIL_ON" "$HYGIENE" "$SECRET_JSON" "$OUT_DIR/deps.json" <<'PY'
import json, sys

target, fmt, fail_on, hygiene_json, secret_path, deps_path = sys.argv[1:7]
hygiene = json.loads(hygiene_json)
secrets = json.loads(open(secret_path).read())
deps = json.loads(open(deps_path).read())

SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

findings = list(hygiene["findings"])
for item in secrets["findings"]:
    findings.append({
        "layer": "secrets",
        "severity": item["severity"],
        "rule": item["rule"],
        "file": f"{item['file']}:{item['line']}",
        "detail": item["match"],
    })
for item in secrets.get("sensitive_files", []):
    findings.append({
        "layer": "secrets",
        "severity": "info",
        "rule": "sensitive-file-present",
        "file": item["file"],
        "detail": item["reason"],
    })

findings.sort(key=lambda f: -SEV.get(f["severity"], 0))
counts = {}
for finding in findings:
    counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1

result = {
    "target": target,
    "layers": {
        "hygiene": {"findings": len(hygiene["findings"]), "notes": hygiene["notes"],
                    "tracked_files": hygiene["tracked_files"]},
        "secrets": {"scanned_files": secrets["files_scanned"], "skipped_files": secrets["files_skipped"],
                    "findings": len(secrets["findings"])},
        "dependencies": deps,
    },
    "findings": findings,
    "by_severity": counts,
}

if fmt == "json":
    print(json.dumps(result, indent=2))
else:
    print(f"defensive baseline: {target}")
    print()
    print(f"  hygiene      : {len(hygiene['findings'])} finding(s), {hygiene['tracked_files']} tracked file(s)")
    print(f"  secrets      : {secrets['files_scanned']} file(s) scanned, {len(secrets['findings'])} pattern hit(s)")
    print(f"  dependencies : {len(deps.get('results', []))} check(s) run")
    print()
    if findings:
        print("findings (LEADS - each needs a manual decision):")
        for finding in findings:
            print(f"  [{finding['severity'].upper():8}] {finding['layer']:<12} {finding['rule']:<28} {finding['file']}")
            print(f"             {finding['detail']}")
    else:
        print("no findings")
    notes = hygiene["notes"] + deps.get("notes", [])
    if notes:
        print()
        print("coverage gaps and notes:")
        for note in notes:
            print(f"  - {note}")
    print()
    print("These are leads, not verdicts. Triage each one before reporting.")

if fail_on != "none":
    threshold = SEV[fail_on]
    if any(SEV.get(f["severity"], 0) >= threshold for f in findings):
        sys.exit(1)
PY
