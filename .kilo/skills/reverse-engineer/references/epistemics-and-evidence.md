# Epistemics and evidence

The single discipline that separates analysis from guessing. Every sentence in an investigation
report is one of four kinds, and the kind is stated.

## 1. The four epistemic states

### `observed`
You read it directly from the artifact or its runtime, and you can point at the bytes.

- A string at file offset `0x1a40`.
- A manifest attribute.
- An HTTP request record #17 in a HAR capture.
- A register value in a core dump.
- The literal text of a config file.

Requirement: the source must be re-checkable. If you cannot say *where* it came from, it is not
observed.

### `derived`
You computed it from observations using a stated rule.

- "SHA-256 of the extracted `libmain.so` equals the bundled digest" (derived from two observations).
- "This file is a Mach-O 64-bit executable" (derived from magic bytes + header fields).
- "Total request count is 412" (derived from a complete page set).

Requirement: the rule must be explicit. "It looks like" is not a rule.

### `inferred`
You reasoned beyond the observations. Inference is allowed — it is how hypotheses work — but it must
carry its basis and its confidence.

- "The 60-second interval suggests a polling heartbeat (basis: single `sleep(60)` in the update
  module, plus a matching API path in the captured traffic)."

Requirement: state the basis, state what would falsify it.

### `unknown`
Not established. This is a first-class result, not a failure.

- "Whether the update check is signed is unknown — no signature verification was performed.
  Closing it requires running `codesign --verify --strict` against the bundle."

Requirement: name the authority or environment that would close it. An unknown without a closure
path is a dropped question.

## 2. Claim grammar

Use this shape in notes and in reports:

```text
CLAIM:    <one sentence>
EPISTEMIC: observed | derived | inferred | unknown
EVIDENCE: EV-007 → <source> (<locator>)
CONFIDENCE: High | Medium | Low
LIMITS:   <what the evidence does not cover>
NEXT:     <what would close the remaining gap, if anything>
```

Good:

```text
CLAIM:    The renderer forwards clipboard writes to the main process over IPC channel "clip-write".
EPISTEMIC: observed
EVIDENCE: EV-007 → app.asar/out/renderer/clipboard.js:41 (ipcRenderer.invoke("clip-write", …));
           EV-011 → app.asar/out/preload.js:9 (contextBridge.exposeInMainWorld("clip", { write: … }))
CONFIDENCE: High
LIMITS:   Static observation only; no runtime capture confirms the channel is live.
NEXT:     Capture the IPC traffic at runtime to confirm the channel is used.
```

Bad (and why):

| Bad | Problem | Good |
| --- | --- | --- |
| "The app exfiltrates data." | No label, no evidence, no scope | "The app POSTs the collected field to `https://…` (`observed`, EV-021)" |
| "There is no crypto code." | Absence from one grep | "No crypto routine was found in the 3,100 functions searched by `crypto`/`cipher`/`aes` (`bounded negative`)" |
| "The update check runs." | Static code proven to be runtime | "The update check code path exists; no runtime capture was performed to observe execution" |
| "It's malware." | Conclusion without criteria | "Behaviour matches the dropper criteria in `security/threat-model.md` §4.2 (observed, EV-033/034/035)" |
| "Probably sends telemetry." | Inference without basis | "Likely telemetry: the module writes a device ID to a queue that is drained by an upload path (inferred, basis: EV-030 → EV-031)" |

## 3. Evidence records

One record per observation. Fields:

| Field | Meaning |
| --- | --- |
| `id` | Stable local ID (`EV-001`). Never reused, never renumbered. |
| `target` | The artifact identity the observation belongs to (digest or labelled copy). |
| `source` | Where it came from: file path + offset/line/address, tool + record ordinal, command + output file. |
| `observation` | The fact, quoted or precisely paraphrased. Quote strings verbatim. |
| `epistemic` | `observed` / `derived` / `inferred` / `unknown`. |
| `coverage` | The boundary: format, page, function set, pattern set, time window. |
| `limits` | What the tool could not see (stripped symbols, obfuscation, undecoded payload, missing provider). |
| `related` | Other evidence IDs (corroboration, contradiction). |

Blanket `templates/evidence-record.md` and the machine-checkable table format in
`scripts/re/ledger.py`.

### Quoting rules

- Quote strings **verbatim**, including trailing whitespace and non-ASCII, when the string matters.
- Preserve case. Base64 and hex are case-sensitive.
- When you truncate, mark it: `https://collector.example/v1/…` (truncated, full string in
  `evidence/strings.txt`).
- Never "clean up" a string to make it look like a URL.

## 4. Confidence rubric

Confidence is **independent** of the epistemic label. An `observed` fact can be low confidence
(if the tool's parsing is uncertain), and an `inference` can be high confidence.

| Level | Meaning |
| --- | --- |
| High | Direct read of the artifact with a precise locator, or an inference with multiple independent corroborating observations and no contradicting evidence. |
| Medium | Direct read but with a known caveat (partial coverage, a lossy tool, an ambiguous locator), or an inference with one supporting observation. |
| Low | Single weak signal, ambiguous locator, or an inference from pattern similarity only. |

Never raise confidence because the conclusion is convenient.

## 5. Coverage vocabulary

Use these phrases precisely:

- `complete` — the tool enumerated the whole collection with no truncation and no error.
- `partial (n/N)` — a known subset was examined.
- `unknown` — the collection could not be enumerated.
- `bounded negative` — a defined scope was searched and produced no match.

Examples:

```text
COVERAGE: complete (412 of 412 request records)
COVERAGE: partial (2 of 9 sections parsed; parser rejected the compressed payload)
COVERAGE: bounded negative — searched all 3,100 functions for the patterns
          [crypto, cipher, aes, rsa, hmac]; no match
```

## 6. Bounded negatives

The most common way an investigation goes wrong is turning "I did not find it" into "it is not
there".

A bounded negative must carry:

1. **What was searched** — the corpus and the patterns.
2. **How completely** — page counts, tool limits, encoding assumptions.
3. **What would change the answer** — e.g. "strings are UTF-16LE here, so a plain `strings` run
   would not find them".

```text
CLAIM:    No licence-check routine is present in the shipped binary.
EPISTEMIC: observed (bounded negative)
EVIDENCE: EV-044 → `strings -a -n 4 libapp.dylib | rg -i 'licen|serial|registr|trial'` → 0 hits
           over 3,100 exported+local symbols
COVERAGE: complete for ASCII strings ≥4 chars in the .text and .rodata sections
LIMITS:   Encrypted or obfuscated strings would not be visible; the .data blob was not decoded.
NEXT:     Trace the `validate` xrefs and read the referenced data by hand.
```

## 7. Unknown lifecycle

```text
OPEN      → recorded in the ledger as epistemic=unknown, with the closure path
WORKING   → evidence gathered; update the row with the new evidence IDs
RESOLVED  → replaced with a new evidence row of the correct epistemic state; the old row
            is annotated "resolved by EV-0xx", never deleted
STALE     → the question no longer matters (e.g. the artifact was superseded); mark it
            "closed: not pursued — <reason>"
```

Unknowns are resolved by evidence, never by assumption. An unknown that is silently dropped
becomes a false negative in the final report.

## 8. Artifact identity and chain of custody

- Hash the original before analysis: `SHA-256`.
- Work on a copy. If the tool must run against the original (rare, read-only), hash again after.
- Keep one identity per artifact; when you extract an inner artifact, it gets **its own** digest
  and its own ledger target — do not conflate `app.apk` with `lib/arm64-v8a/libmain.so`.
- When comparing two builds, state both digests. "Version 1.2.3" is not an identity.
- Record who produced the file and when, if known. Untrusted provenance is itself a finding.
