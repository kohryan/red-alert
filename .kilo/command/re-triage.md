---
description: Static triage of an unknown artifact (digest, format, container, entropy, strings)
agent: re-analyst
---

Triage the artifact `$1` and produce a triage sheet with evidence rows.

Target: `$1`

Do this, in order:

1. **Never execute the target.** Static only. If `$1` is a directory or archive, inspect the
   container listing without extracting into the original location.
2. Run the repo tool:
   ```bash
   scripts/re/triage.sh "$1" --out labs/triage-$(basename "$1")
   ```
   If the tool is missing or fails, fall back to `file -b`, `shasum -a 256`, `xxd -l 64`,
   `strings -a -n 4`, and the format-specific inventory (`otool -l` / `readelf -S` /
   `objdump -x`), and say in the output that the fallback was used.
3. Record the identity: SHA-256, size, format (from magic bytes), container, provenance.
4. Identify the artifact class and select the next technique using
   `.kilo/skills/reverse-engineer/references/target-routing.md`.
5. Extract the interesting strings: URLs, hosts, IPs, file paths, registry keys, emails,
   crypto constants, base64 blobs, JWTs, build paths.
6. Write the evidence rows into `labs/triage-<name>/ledger.md` using the format in
   `templates/evidence-record.md`. Each row gets an ID, a locator, an epistemic label
   (`observed`/`derived`/`inferred`/`unknown`), coverage, and limits.
7. Report back:
   - what the artifact is (one paragraph, with the digest),
   - the coverage of the triage (what you read, what you did not),
   - the interesting observations (each labelled and located),
   - bounded negatives,
   - the single best next step and the tool it needs.

Do not claim behaviour. A string is present, not executed. Do not install tooling to extend the
triage; report the missing prerequisite instead.
