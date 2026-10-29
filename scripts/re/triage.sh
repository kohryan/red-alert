#!/usr/bin/env bash
# Static triage of an unknown artifact.
#
#   scripts/re/triage.sh <path> [--out DIR]
#
# Reads bytes only. Never executes, unpacks or otherwise runs the target.
# Produces a triage sheet (triage.txt), a machine record (analysis.json),
# the extracted strings, and any system-tool output that was available.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

usage() {
  cat <<'EOF'
usage: triage.sh <path> [--out DIR]

  <path>   file to triage (read-only)
  --out    output directory (default: labs/triage-<basename>)

The triage is static: no part of the target is executed.
EOF
}

TARGET=""
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "unknown option: $1" >&2; usage; exit 2 ;;
    *) TARGET="$1"; shift ;;
  esac
done

if [ -z "$TARGET" ]; then usage >&2; exit 2; fi
if [ ! -f "$TARGET" ]; then echo "error: not a regular file: $TARGET" >&2; exit 2; fi

ABS_TARGET="$(cd "$(dirname "$TARGET")" && pwd)/$(basename "$TARGET")"
BASENAME="$(basename "$ABS_TARGET")"
[ -n "$OUT" ] || OUT="${REPO_ROOT}/labs/triage-${BASENAME}"
mkdir -p "$OUT"

sha256() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else echo "unavailable"; fi
}

DIGEST="$(sha256 "$ABS_TARGET")"

# --- machine analysis --------------------------------------------------------
python3 "${SCRIPT_DIR}/lib_analyze.py" "$ABS_TARGET" --json > "$OUT/analysis.json"

# --- strings dump ------------------------------------------------------------
python3 - "$SCRIPT_DIR" "$ABS_TARGET" "$OUT" > "$OUT/.stringcount" <<'PY'
import os, sys
script_dir, target, out = sys.argv[1:]
sys.path.insert(0, script_dir)
import lib_analyze
data = open(target, 'rb').read()
strings = lib_analyze.extract_strings(data) + lib_analyze.extract_utf16_strings(data)
with open(os.path.join(out, 'strings.txt'), 'w') as fh:
    fh.write('\n'.join(strings))
print(len(strings))
PY

# --- optional system tool output --------------------------------------------
: > "$OUT/tool-output.txt"
{
  echo "== file =="
  if command -v file >/dev/null 2>&1; then file -b "$ABS_TARGET" || true; else echo "file(1) not available"; fi
  echo
  echo "== first 64 bytes =="
  if command -v xxd >/dev/null 2>&1; then xxd -l 64 "$ABS_TARGET" || true; else od -A x -t x1z -N 64 "$ABS_TARGET" || true; fi
  echo
  echo "== symbols (nm) =="
  if command -v nm >/dev/null 2>&1; then nm -a "$ABS_TARGET" 2>&1 | head -60 || true; else echo "nm(1) not available"; fi
  echo
  echo "== sections =="
  if command -v otool >/dev/null 2>&1 && otool -l "$ABS_TARGET" >/dev/null 2>&1; then otool -l "$ABS_TARGET" | head -80
  elif command -v readelf >/dev/null 2>&1 && readelf -S "$ABS_TARGET" >/dev/null 2>&1; then readelf -S "$ABS_TARGET" | head -80
  elif command -v objdump >/dev/null 2>&1; then objdump -h "$ABS_TARGET" 2>&1 | head -60 || true
  else echo "no section dumper available"; fi
  echo
  echo "== code signature =="
  if command -v codesign >/dev/null 2>&1; then codesign -dvvv "$ABS_TARGET" 2>&1 | head -20 || true; else echo "codesign(1) not available"; fi
} >> "$OUT/tool-output.txt" 2>&1

# --- triage sheet ------------------------------------------------------------
python3 - "$ABS_TARGET" "$OUT" "$DIGEST" <<'PY'
import json, os, sys

target, out, digest = sys.argv[1], sys.argv[2], sys.argv[3]
with open(os.path.join(out, "analysis.json")) as fh:
    a = json.load(fh)

fmt = a["format"]
lines = []
add = lines.append
add("=" * 78)
add("STATIC TRIAGE SHEET")
add("=" * 78)
add(f"path      : {target}")
add(f"sha256    : {digest}")
add(f"size      : {a['size']} bytes")
add(f"format    : {fmt['label']} ({fmt['kind']})")
add(f"magic     : {a['magic_hex']}")
ent = a["entropy"]
add(f"entropy   : {ent['overall']} -> {ent['verdict']} "
    f"(high blocks: {ent['high_entropy_blocks']}, low blocks: {ent['low_entropy_blocks']})")
add("")

for key, title in (("elf", "ELF"), ("macho", "MACH-O"), ("pe", "PE"), ("zip", "ZIP/CONTAINER")):
    info = a.get(key)
    if not info:
        continue
    add(f"-- {title} " + "-" * (74 - len(title)))
    if "error" in info:
        add(f"  parse error: {info['error']}")
        continue
    if key == "elf":
        add(f"  class={info['class']} machine={info['machine']} type={info['type']} entry={info['entry']}")
        add(f"  program headers={info['program_headers']} sections={len(info['sections'])}")
        for s in info["sections"][:24]:
            ent_s = s["entropy"]
            add(f"    {s['name']:<20} off=0x{s['offset']:x} size={s['size']:<10} entropy={ent_s}")
    elif key == "macho":
        if info.get("fat"):
            add(f"  universal binary, {len(info['slices'])} slice(s)")
            for s in info["slices"]:
                add(f"    cputype={s['cputype']} offset=0x{s['offset']:x} size={s['size']}")
        else:
            add(f"  cputype={info['cputype']} filetype={info['filetype']} flags={info['flags']}")
            for seg in info["segments"]:
                add(f"    segment {seg['name']}: {', '.join(seg['sections'][:8])}")
    elif key == "pe":
        add(f"  machine={info['machine']} {info['optional_header']} dll={info['dll']}")
        for s in info["sections"][:24]:
            add(f"    {s['name']:<10} vaddr={s['virtual_address']:<12} raw={s['raw_size']:<10} entropy={s['entropy']}")
    elif key == "zip":
        if "error" in info:
            add(f"  parse error: {info['error']}")
        else:
            add(f"  members={info['members']} hints={info['hints']} exec_member={info['has_executable_member']}")
            for name in info["sample"][:20]:
                add(f"    {name}")
    add("")

add("-- INTERESTING STRINGS " + "-" * 52)
interesting = a.get("interesting_strings", [])
if not interesting:
    add("  (none matched the built-in patterns)")
for item in interesting[:60]:
    kinds = ", ".join(sorted({h["kind"] for h in item["hits"]}))
    add(f"  [{kinds}] {item['value']}")
add("")

add("-- KEYWORD SIGNALS " + "-" * 55)
hits = a.get("keyword_hits", {})
if not hits:
    add("  (none)")
for name, values in hits.items():
    add(f"  {name}: {len(values)} sample(s)")
    for v in values[:5]:
        add(f"    {v}")
add("")

add("-- STRING COUNTS " + "-" * 57)
s = a["strings"]
add(f"  ascii strings (>=4 chars): {s['ascii_count']}")
add(f"  utf16le strings (>=4 chars): {s['utf16_count']}")
add("")

add("-- COVERAGE " + "-" * 63)
add("  examined: header magic, format-specific header/section tables, printable string")
add("            tables (ASCII + UTF-16LE), entropy profile over 64 KiB blocks,")
add("            container member listing for ZIP-like inputs.")
add("  not examined: code semantics, runtime behaviour, encrypted/compressed payloads,")
add("            symbol demangling, dynamic relocations, resource contents.")
add("")
add("  Every line above is an observation. None of it establishes behaviour.")
add("=" * 78)

sheet = "\n".join(lines)
with open(os.path.join(out, "triage.txt"), "w") as fh:
    fh.write(sheet + "\n")
print(sheet)
PY

echo
echo "artifacts: $OUT/{triage.txt,analysis.json,strings.txt,tool-output.txt}"
