# 00 — Principles

The rules that make an investigation defensible. Everything else in this repository is an
application of these.

## 1. Epistemics before conclusions

A conclusion is only as good as its label. Four states, used literally:

| Label | Test | Example |
| --- | --- | --- |
| `observed` | Can you point at the bytes/record that says it? | "The manifest declares `debuggable=true`" |
| `derived` | Can you state the rule you applied? | "SHA-256 of the extracted `.so` equals the bundled one" |
| `inferred` | Can you state the basis and the falsifier? | "Likely telemetry (basis: collector → queue → upload path)" |
| `unknown` | Can you state what would close it? | "Signing not checked — needs `codesign --verify`" |

The most common failure is not ignorance; it is an **unlabelled inference** that reads like an
observation. Audit for that specifically.

## 2. Absence is a claim with a boundary

Three different statements, three different obligations:

| Statement | Obligation |
| --- | --- |
| "The function does not exist" | Enumerate the complete collection |
| "I did not find it" | State the scope searched (corpus, patterns, encodings, limits) |
| "It was not executed" | State that the observation type cannot establish execution |

Never let the second become the first.

## 3. Coverage is part of every claim

Every observation carries its boundary: how many functions, which pages, which files, which time
window, which tool version. "Complete" is a strong word — use it only when the tool enumerated
the whole collection without truncation and without error.

## 4. Authority belongs to the caller

The user chose the target, the depth, and the tools. The analyst's job is to answer the question
asked, with the evidence needed to answer it, and to say what else was not covered.

- Do not widen scope to neighbouring systems, accounts, or repositories.
- Do not install engines, package managers, or system software to unblock a task.
- Configuration changes are additive, idempotent, backed up, and previewed before they are applied.
- Preserve the caller's inputs and the local evidence: outputs, URLs, paths, digests, metadata.

## 5. Fail closed

A capability is not integrated while scope, authority, side-effect, or verification questions
remain open. Concretely:

- A missing tool is a **coverage gap**, not a reason to install one.
- A timed-out analysis is **partial coverage**, not "no results".
- A truncated response is a **preview**, not the record.
- An unreadable collection is **unknown**, not empty.

## 6. Least effect

Read-only by default. Analysis tooling must not modify the target, the environment, or the user's
configuration. Any operation that writes, executes, mutates, or sends network traffic is
**declared before it happens**.

For untrusted targets, the effect budget is zero on the host: no execution outside a disposable
environment, no real network, no real credentials.

## 7. Separate ownership from validity

A file, process, or record can be *owned* (we created it) without being *valid* (it parses), and
*valid* without being *ready* (we can use it). Keep these apart:

- Malformed owned data is still safe to remove.
- Unresolved identity or applicability stays **unknown**, never silently treated as absent,
  foreign, or aligned.
- A PID plus a path does not establish process ownership after exit or reuse.

## 8. Performance is a first-class concern

Optimise in this order:

1. **Agent tokens and context** — smallest sufficient answer, with provenance, coverage, and
   limitations attached.
2. **Analysis time** — reuse validated results; cache keys must include every result-affecting
   input; validate freshness before reporting a cached live state as current.
3. **CPU and memory** — bound concurrency, retained state, and serialization growth.

Fewer bytes alone does not mean fewer tokens or a faster analysis. Measure elapsed time, CPU
time, and peak memory when a change claims a performance win.

## 9. Evidence is a contract

An evidence record has: an ID, a target identity, a source locator, the observation, an epistemic
label, coverage, limits, and links to related evidence. It is:

- **citable** — a report can point at it,
- **immutable in meaning** — IDs are never reused or renumbered,
- **bounded** — the limits travel with it, so a later reader cannot over-read it.

## 10. Report only what happened

Never claim a run, a measurement, a reproduction, or a tool result you did not produce. Never
present a static observation as a runtime one. When something failed, report the failure and its
partial coverage — that is more useful than a confident wrong answer.

## 11. Human ownership

Analysis output is proposed, not deployed. A human reviews the diff, the evidence, and the
claims. Automation may prepare, check, and flag; it does not declare the work ready.

## 12. Responsible use

Analysis is for lawful research, education, interoperability, software preservation, and
defensive security on systems you own or are authorised to examine. Commercial analysis tools
must be legally obtained and used under their licences. See `SECURITY.md`.

---

Next: [`01-workflow.md`](01-workflow.md).
