# Playbook — unknown binary intake

**Trigger:** someone hands you a file: "what is this?"

**Goal:** a defensible identification and a route to the next technique. No behaviour claims yet.

## 0. Authorisation

Confirm the file is one the user owns or is authorised to examine. One question, then proceed.

## 1. Intake (never execute)

```bash
scripts/re/triage.sh /path/to/file --out labs/intake-<name>
```

This produces `triage.txt` (human sheet), `analysis.json` (machine record), `strings.txt`, and
`tool-output.txt` (system-tool output).

Manual equivalents when the script is unavailable:

```bash
shasum -a 256 file; file -b file; xxd -l 64 file
strings -a -n 4 file | head -200
```

## 2. Record the identity

| Field | Value |
| --- | --- |
| SHA-256 | |
| Size | |
| Format (from magic) | |
| Container | |
| Provenance | who/where/when, if known |

## 3. Classify the artifact

Use [`../methodology/02-target-routing.md`](../methodology/02-target-routing.md). Decide:

- Is this the payload, or a wrapper (installer, archive, container, loader)?
- Is it a native binary, managed assembly, script bundle, or data file?
- Is it packed or encrypted? (entropy profile, packer stub)

If the format is still unknown after the triage, run the unknown-blob path in
`.kilo/skills/reverse-engineer/references/static-and-artifact-analysis.md` §8 (carving).

## 4. Extract the interesting strings

From `triage.txt`:

- URLs and hosts → candidate network surface
- File paths → platform and data locations
- Registry keys → Windows persistence/config
- Emails and usernames → accounts or attribution
- Crypto constants → algorithm identification
- Build paths → build environment, sometimes a developer identity

Each becomes a ledger row with a locator. A string is **present**, not **executed**.

## 5. Container inventory (if applicable)

```bash
unzip -l archive.zip | head -50      # APK/IPA/JAR/wheel
ls -R /path/to/electron-app/Resources
```

Enumerate every executable member. Each inner binary gets its own digest and its own rows.

## 6. Choose the next technique

Write down, explicitly:

```text
Next technique: <class> → <technique>
Tool: <tool + version, or "unavailable">
Questions this will answer: Q1, Q3
Coverage it will give: <what it examines>
```

## 7. Close the intake

Report:

1. What the file is, with the digest.
2. What it contains (container inventory if any).
3. The interesting observations, each labelled and located.
4. Bounded negatives.
5. The next technique and why.

Do not report behaviour. Intake identifies.

## Artefacts

```text
labs/intake-<name>/
├── triage.txt
├── analysis.json
├── strings.txt
├── tool-output.txt
└── ledger.md
```
