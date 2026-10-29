---
name: reverse-engineer
description: Reverse engineer unknown artifacts and black-box behaviour with strict evidence discipline. Use when a task involves a shipped artifact without source (native binary, .NET/managed assembly, APK/IPA, Electron/ASAR or JS bundle, WASM, model file, firmware image, PCAP/HAR capture), when a feature must be explained from a build, or when a reconstruction must be verified. Covers target routing, epistemics (observed/derived/inferred/unknown), the staged investigation workflow, safe handling of untrusted targets, an evidence ledger, and report format. Triggers on "reverse engineer", "decompile", "how does this binary/app work", "what does this package do", "analyze this executable", "teach me this algorithm", "figure out the protocol".
metadata:
  version: "1.0.0"
  origin: "methodology adapted from morluto/rea (MIT) — see docs/tooling/rea-integration.md"
---

# Reverse Engineer

Operate as an analyst, not a guesser. Produce **evidence-backed conclusions** about artifacts you
cannot read the source of, and make the limits of that evidence explicit.

This skill is the default procedure for every reverse-engineering task in this repository. If a
step below conflicts with convenience, the step wins.

---

## 0. Non-negotiables

1. **Label every claim.** `observed` · `derived` · `inferred` · `unknown`. A conclusion without a
   label is a guess wearing a suit.
2. **Cite the evidence.** Every claim names an evidence ID, file:line, byte offset, address,
   request record, or command output it rests on.
3. **Static ≠ runtime.** Decompiled code proves a *path exists*, never that it *runs*. Use
   "the code path exists" and "I observed the call" as different claims.
4. **A failed search is a bounded negative.** Record what scope you searched (file, format,
   pattern, coverage). Absence is not proven by one search.
5. **Exhausting a page is not completeness.** "50 of 900 rows read" is a coverage statement.
6. **Missing data is unknown, not absent.** A missing metadata section does not prove a binary has
   no dependencies; an unreadable byte range is missing coverage, not zeros.
7. **Stay inside the caller's scope.** The user chose the target, the depth, and the tools. Do not
   widen to neighbouring systems, accounts, or repositories.
8. **Read-only by default.** Analysis tooling must not modify the original artifact. Keep the
   original digest. Work on copies.
9. **Never execute an untrusted artifact on the host.** Use a disposable VM/container. No
   "just run it and see".
10. **Do not repair a tool by installing software.** Diagnose the blocker, name the prerequisite,
    continue with what works.
11. **Track unknowns.** An open question enters the ledger with the authority or environment
    still required to close it. Unknowns are not dropped, and they are not quietly answered.
12. **Report only what you did.** Never claim a run, a measurement, or a reproduction you did not
    perform.

---

## 1. Authorization and safety (before touching anything)

Confirm the target is one the user owns or is authorized to examine. If authorization is
ambiguous, ask once, then proceed.

Before any dynamic step:

- Target runs in a **disposable** environment: throwaway VM or container, no access to real
  accounts, real networks, or the user's home directory.
- Network is **isolated or sinkholed**. A target that phones home must not reach a real host
  during analysis. Record the posture you used.
- You **will not** disable Gatekeeper/XProtect or bypass OS security controls on the host; inside
  the disposable environment, and only if recorded.
- You **will not** run installers, `pip install`/`npm install` inside a target tree, `make` in a
  target tree, or `open` a downloaded app.

Full checklists: [references/runtime-and-instrumentation.md](references/runtime-and-instrumentation.md).

---

## 2. Phase map

| Phase | Goal | Output |
| --- | --- | --- |
| 1 Intake | Identify the target and fix its identity | digest, format, container, context |
| 2 Route | Pick the technique for this artifact class | selected tools + plan |
| 3 Scope | Turn the request into a question checklist | questions + required evidence per question |
| 4 Investigate | Smallest useful overview → trace → corroborate | observations with coverage |
| 5 Compare | Version / build / behaviour deltas | symmetric comparison |
| 6 Rebuild | Reimplement, with an obligation ledger | verified reconstruction |
| 7 Report | Claim → evidence → confidence → unknown → fix | investigation report |

---

## 3. Phase 1 — Intake (identity before analysis)

Never analyse "the file". Analyse **the artifact with its identity**.

Establish and record:

- **Digest** — SHA-256 of the exact bytes you will analyse. Hash the original; hash again after
  analysis to prove non-modification.
- **Format** — detect from bytes, never from the extension. `file` is a hint, the magic bytes are
  the fact.
- **Container** — is the binary inside an APK/IPA/DMG/asar/zip/PyInstaller/PKG/MSIX? Is the file
  the payload, or the loader?
- **Context** — what is it supposed to do, from the user? Which feature is the question about?
- **Provenance** — where did it come from, and is that provenance itself relevant (a "decoder" that
  is actually a dropper)?

Helper: `scripts/re/triage.sh <path>` produces a triage sheet (digest, type, container hints,
entropy profile, string candidates, format-specific sections). Run it before deeper work.

**Never infer behaviour from filenames, strings, or layout alone.** A file called
`license_checker.exe` may be exactly that. Verify.

---

## 4. Phase 2 — Route the target

Pick the technique from the artifact class, not from the question's wording.

| Target | Start with | Deep dive |
| --- | --- | --- |
| Native binary (ELF/PE/Mach-O) | header + section inventory, symbols, strings | [references/native-binary-analysis.md](references/native-binary-analysis.md) |
| .NET / managed assembly | metadata tables, IL | [references/native-binary-analysis.md](references/native-binary-analysis.md) |
| Electron / ASAR / JS bundle | module graph, entrypoint, IPC surface | [references/static-and-artifact-analysis.md](references/static-and-artifact-analysis.md) |
| APK / IPA / mobile app | manifest, permissions, classes | [references/mobile-and-firmware.md](references/mobile-and-firmware.md) |
| Firmware image | regions, extraction | [references/mobile-and-firmware.md](references/mobile-and-firmware.md) |
| WASM / EVM / model file | header + declared interfaces | [references/static-and-artifact-analysis.md](references/static-and-artifact-analysis.md) |
| Website / web app | DOM, scripts, network | [references/web-and-network.md](references/web-and-network.md) |
| PCAP / HAR / SAZ | flows, requests, API surface | [references/web-and-network.md](references/web-and-network.md) |
| Core dump / crash | threads, registers, notes | [references/native-binary-analysis.md](references/native-binary-analysis.md) |
| Plain source repository | **normal repository tools** | this skill does not apply |

Full routing table with concrete commands and REA tool names:
[references/target-routing.md](references/target-routing.md).

**If the target is ambiguous, ask.** Do not pick an example app on the user's behalf.

---

## 5. Phase 3 — Scope the investigation

Turn the request into a **checklist of questions**, each with the evidence type that would answer
it.

```text
Q1. Does the app phone home?          → needs: network capture / endpoint strings
Q2. What data does it collect?        → needs: runtime observation of the collector
Q3. Is the update check signed?       → needs: signature verification evidence
Q4. Which local files are read?       → needs: syscall/file-access observation
```

Then, before starting:

- Identify the entry point for each question (the earliest code that could answer it).
- Decide static-first: use runtime only where static evidence cannot close a question, and only
  if the runtime environment and permissions are available.
- Decompose into independent questions. Parallelise only questions that do not depend on each
  other, and give each worker a distinct scope plus the existing evidence IDs.

Re-visit this checklist at the end. Mark each question `answered` / `partially answered` /
`unresolved`. Never describe a broad investigation as complete while a required question is open.

---

## 6. Phase 4 — Investigate (the core loop)

The loop, repeated until the checklist is answered:

```
overview  →  hypothesis  →  targeted query  →  evidence  →  update ledger  →  next query
```

Rules of the loop:

- **Summary-first.** Start with the smallest useful overview (inventory, counts, module list).
  Request detail only for the specific thing that answers an open question.
- **Do not repeat an identical call.** If a result already answers the question, use it. If you
  need a different slice, change the input (page, filter, selected fields).
- **Trace from the entry point** through data and state changes to the effect: input → transform →
  sink. A sink without an input is not a vulnerability; an input without a reachable sink is not
  exploitable. Say which one you have.
- **Corroborate with the evidence type the claim needs.** A claim about runtime needs runtime
  evidence. A claim about an algorithm needs a reconstruction, not a plausible decompile.
- **Batch around a hypothesis.** When you believe feature X is implemented in module M, fetch the
  related facts in one round instead of one round per fact.
- **Preserve identity.** When a path, symbol, channel or endpoint appears in several places, keep
  them separate; a single path can hold several roles.

### Epistemic language (use these words literally)

| Label | Use when | Example |
| --- | --- | --- |
| `observed` | You read it directly | "The manifest declares `debuggable=true`" |
| `derived` | You computed it from observations | "Extracted `libmain.so` digest equals the bundled digest" |
| `inferred` | You reasoned it; state the basis | "This handler is probably the clipboard bridge (it is the only caller of `clipboard.write`)" |
| `unknown` | Not established | "Whether the updater is signed is unknown — no signature was checked" |

A finding template:

> **Claim** — <one sentence> — `observed`
> **Evidence** — `EV-004`: `/path/file.bin` offset `0x1a40`, string `https://…`
> **Confidence** — High | Medium | Low
> **Unknown** — <what remains unestablished, and what would close it>

---

## 7. Phase 5 — Compare (versions, builds, behaviour)

Only claim equivalence or absence when both sides were examined with **compatible, complete**
coverage.

- Compare like with like: same artifact class, same tool, same settings, same scope.
- Unpaired observations do not prove additions or removals.
- A static difference is a **candidate** for a behavioural change, not its cause.
- If one side is incomplete, report `unknown`, not `absent`.

---

## 8. Phase 6 — Rebuild (reconstruction)

When the goal is "build it back":

1. Extract the **behavioural specification** from evidence: inputs, outputs, edge cases, error
   paths, numeric precision, ordering.
2. Write an **obligation ledger**: one row per behaviour that must be reproduced, each with its
   evidence ID and its verification method.
3. Implement against the ledger.
4. Verify with a **finite, typed specification**: the same inputs, compared on outputs, tolerance
   and case. A passing verification covers only the declared comparable claims — never "the
   implementation is equivalent".

Details: [references/reconstruction-and-verification.md](references/reconstruction-and-verification.md).

---

## 9. Evidence ledger

Every investigation maintains a ledger file (default `evidence/ledger.md`, schema in
`templates/evidence-record.md`). One row per observation:

```text
ID | Target | Source (file/offset/addr/record) | Observation | Epistemic | Coverage | Limits | Unknowns
```

The ledger is the single source of truth for the report. Validate it with:

```bash
scripts/re/ledger.py evidence/ledger.md --check
scripts/re/ledger.py evidence/ledger.md --report
```

Rules: a claim in the report must exist in the ledger; a ledger row with no claim is fine (it is
raw material); an `unknown` row must name the authority or environment needed to close it.

---

## 10. Tooling: REA first, local fallback second

If the **REA MCP server is connected** (`rea_*` tools available), use it — it wraps Hopper, Ghidra,
IDA, JADX, mitmproxy, tshark, binwalk, Frida and dozens of static parsers behind one evidence
contract, and its results carry evidence IDs natively. Tool-by-tool mapping:
[references/rea-tool-reference.md](references/rea-tool-reference.md).

If REA is **not** connected, do not stall. Fall back to the local ladder in
[references/target-routing.md](references/target-routing.md): `file`, `strings`, `otool`/`objdump`/
`readelf`, `nm`, `codesign`, `lipo`, `xxd`, `python3`, `openssl`, plus `rizin`/`radare2`,
`jadx`, `apktool`, `frida`, `mitmproxy`/`tshark` when installed.

Rules for both paths:

- If a tool is missing, **name the prerequisite**; do not install it.
- Distinguish a tool that is unavailable (unknown) from a tool that ran and found nothing.
- Do not run the same analysis twice to obtain a different display of the same result; re-read
  the retained result instead.

---

## 11. Context and token discipline

Agent tokens are the scarcest resource in an investigation. Optimise in this order:

1. **Tokens/context** — smallest sufficient answer; summary views, pagination, selected fields,
   retained evidence over re-fetching.
2. **Analysis time** — reuse validated results; cache with result-affecting inputs in the key.
3. **CPU/memory** — bound concurrency, stream large outputs to files instead of the transcript.

Practical rules:

- Send large command output to a file and grep it; never paste megabytes into the conversation.
- Prefer `detail=summary` over `detail=full` for inventories; page for the specific rows.
- When a response is truncated, treat the visible part as a **preview**, not the record.
- Report elapsed time and the artifacts you created, not just the conclusion.

---

## 12. Failure and recovery

| Symptom | Meaning | Do |
| --- | --- | --- |
| Tool missing / not registered | configuration problem | diagnose registration; do not reinstall engines |
| Provider unavailable | missing prerequisite (Ghidra, IDA, JDK) | continue with static-only work; state the gap |
| Deadline exceeded | client vs server deadline | check which one; raise only the server budget, then restart |
| Truncated response | display limit | request a smaller page or export to file |
| Rejected by client policy | approval gate | respect it; report the exact operation blocked |
| Unexpected crash mid-analysis | target instability | preserve partial evidence first, then re-run in isolation |

Never claim "analysis complete" after a timeout. A timeout establishes partial coverage only.

---

## 13. Report contract

The deliverable is a report that another engineer can act on:

1. **Question checklist** with status per question.
2. **Target identity** — digest, format, container, environment used.
3. **Findings** — ordered by impact; each with claim, epistemic label, evidence IDs, confidence,
   unknowns, and remediation.
4. **Evidence ledger** — the raw observation table.
5. **Coverage & limitations** — what was examined, what was not, what the tools could not see.
6. **Open questions** — with the next concrete step for each.

Templates: `templates/investigation-report.md`, `templates/finding.md`.

---

## 14. Reference map

| File | Use it for |
| --- | --- |
| [references/epistemics-and-evidence.md](references/epistemics-and-evidence.md) | Claim labels, evidence records, coverage language, bounded negatives |
| [references/investigation-workflow.md](references/investigation-workflow.md) | Checklist design, the investigation loop, decomposition, ledger mechanics |
| [references/target-routing.md](references/target-routing.md) | Artifact class → technique → tool → fallback |
| [references/static-and-artifact-analysis.md](references/static-and-artifact-analysis.md) | Containers, packers, metadata, JS/ASAR/Electron, WASM/EVM/model files |
| [references/native-binary-analysis.md](references/native-binary-analysis.md) | ELF/PE/Mach-O, mitigations, decompilation workflow, managed code, cores |
| [references/runtime-and-instrumentation.md](references/runtime-and-instrumentation.md) | Sandboxing, browser/Electron, process capture, Frida, LLDB, network capture |
| [references/mobile-and-firmware.md](references/mobile-and-firmware.md) | APK/IPA, IL2CPP, Godot, Flutter, firmware images |
| [references/web-and-network.md](references/web-and-network.md) | Website structure, HAR/SAZ, PCAP, API surface reconstruction |
| [references/reconstruction-and-verification.md](references/reconstruction-and-verification.md) | Behavioural spec, obligation ledger, verification, coverage proof |
| [references/reporting.md](references/reporting.md) | Report structure, finding quality, disclosure |
| [references/rea-tool-reference.md](references/rea-tool-reference.md) | REA MCP tool mapping and evidence contract, when connected |
