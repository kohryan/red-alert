# 01 — Workflow

The staged investigation. Read this once; the skill reference
`.kilo/skills/reverse-engineer/references/investigation-workflow.md` is the operational checklist
an agent follows.

## Stage 1 — Intake

Fix the identity before you analyse.

```text
sha256      the exact bytes you will analyse
format      from magic bytes (the extension is a claim by someone else)
container   is this the payload, or a wrapper around a payload?
provenance  where did it come from, and is the provenance itself relevant?
```

Working directory per investigation:

```text
labs/<slug>/
├── checklist.md   the question checklist
├── ledger.md      the evidence ledger
├── artifacts/     tool outputs (not the original binary)
└── report.md      the deliverable
```

## Stage 2 — Route

Artifact class → technique. Never question wording → technique.

| Class | First move |
| --- | --- |
| Native binary | header, sections, symbols, mitigations |
| Managed assembly | metadata tables, IL |
| Electron / ASAR / JS bundle | module graph, entry, preload, IPC |
| APK / IPA | manifest, permissions, classes |
| Firmware | regions, extraction |
| WASM / EVM / model file | header, declared interfaces |
| Website | DOM, scripts, network |
| PCAP / HAR | flows, requests, API surface |
| Source repository | **ordinary repository tools** — this workflow does not apply |

Full table: [`02-target-routing.md`](02-target-routing.md).

## Stage 3 — Scope

Convert the request into questions, each with the evidence type that closes it.

```text
Q1. Does it phone home, and to where?
    closes with: static endpoint strings + observed outbound requests
Q2. What is collected before upload?
    closes with: observed calls into the collector + the request body
Q3. Is the binary signed and hardened?
    closes with: signature verification output + mitigation flags
```

Decompose compound questions ("does it phone home and what does it send?" is two). Refuse
unanswerable framings ("is it malware?") — convert them into observable criteria.

## Stage 4 — Investigate

```text
overview → hypothesis → targeted query → evidence → ledger update → next query
```

Discipline:

- **One query per question.** "Read the whole binary" is a way of avoiding choosing.
- **Cheapest sufficient layer.** Strings and metadata before decompilation; decompilation before
  runtime; runtime before speculation.
- **Trace from the entry point.** input → transform → sink. A sink without a reachable input is
  not exploitable; an input without a sink is not a vulnerability. Say which one you have.
- **Corroborate across evidence types** for anything that will be a finding.
- **Record as you go.** The ledger is written during the investigation, not reconstructed after.
- **Stop when the question is answered.** Extra evidence dilutes the report.

### Summary-first

Request the count first, the rows second. This keeps the transcript small and the coverage
statement honest:

```text
"412 records"  → complete coverage, and you can page the 3 you need
"here are 50"  → you know neither the total nor whether 50 is representative
```

### Negative results

A negative is a result. Record it with its boundary:

```text
CLAIM:    No licence-check routine is present.
EPISTEMIC: observed (bounded negative)
COVERAGE: complete for ASCII strings ≥4 chars in .text and .rodata; 0 hits in 3,100 symbols
LIMITS:   obfuscated or encrypted strings would not be visible
```

## Stage 5 — Parallelise (only when independent)

Give each worker a distinct scope, the existing evidence IDs, the coverage boundaries, and this
output contract: **sources, conclusions, unresolved gaps**. Reconcile disagreements with
evidence, and record them if they cannot be reconciled.

## Stage 6 — Compare (only for "what changed")

Analyse both sides once, with identical tools and settings. Compare symmetric collections. Report:

- **observed difference** — present on one side, absent on the other, with complete coverage on both,
- **candidate difference** — coverage incomplete, or the matching heuristic is loose,
- **unknown** — coverage insufficient.

A static difference is a candidate for a behavioural change, never its cause.

## Stage 7 — Rebuild (only for "build it back")

Behavioural spec → obligation ledger → implementation → finite verification. Details in
`.kilo/skills/reverse-engineer/references/reconstruction-and-verification.md`.

## Stage 8 — Report

Question checklist with status, target identity, findings ordered by impact, the ledger,
coverage and limitations, open questions, and exact reproduction commands.

Template: [`../../templates/investigation-report.md`](../../templates/investigation-report.md).

## Stage 9 — Audit before shipping

```bash
scripts/re/ledger.py labs/<slug>/ledger.md --check
```

Then have the `re-evidence-auditor` review the report against the ledger. Fix every blocking
defect. A report that has not been audited is a draft.

## Stage 10 — Close

- Re-verify the artifact digest (proving non-modification).
- Record what was not covered.
- Keep the artefacts; do not keep the sensitive parts of them.

---

Next: [`02-target-routing.md`](02-target-routing.md).
