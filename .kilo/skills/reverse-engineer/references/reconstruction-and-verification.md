# Reconstruction and verification

"Figure out how it works" and "build it back" are different jobs. The second one needs an
**obligation ledger**: every behaviour you promise to reproduce, bound to evidence and to a test.

## 1. Behavioural specification

Before writing code, extract a spec from the evidence. A spec is a set of typed claims:

```text
SPEC-1  parse_header(data: bytes) -> {magic: uint32, version: uint16, flags: uint16}
         source: EV-020 (read at 0x400), EV-021 (write at 0x812)
         edge:   data < 8 bytes -> returns None (EV-022)

SPEC-2  position_to_pan(x: int16, y: int16) -> int16
         source: EV-030 (assembly 0x1400-0x14b0)
         range:  observed inputs x∈[-32768, 32767]; behaviour beyond is UNKNOWN
         scale:  observed values are (x >> 9) - 0x20; rounding on negatives UNKNOWN
```

Each spec row: inputs, outputs, types, ranges, error/edge behaviour, and the evidence IDs.
Anything the evidence does not cover is explicitly `UNKNOWN` in the row — never silently
simplified.

## 2. Obligation ledger

One row per behaviour to reproduce:

```text
| ID | Obligation | Spec | Evidence | Verification method | Status |
|----|-----------|------|----------|---------------------|--------|
| O-1 | magic check returns true for 0x4D5A | SPEC-1 | EV-020 | unit test: 1 case | done |
| O-2 | short input returns None | SPEC-1 | EV-022 | unit test: 1 case | done |
| O-3 | negative x rounds toward zero | SPEC-2 | EV-030 | differential vs original, 3000 cases | open |
```

Rules:

- No obligation without an evidence ID.
- No obligation marked done without a **verification method that actually ran**.
- "The code looks right" is not a verification method.
- A verification that covers only declared claims never establishes global equivalence. Say so
  in the report.

## 3. Verification strategies

| Strategy | How | Strength |
| --- | --- | --- |
| Differential | Feed identical inputs to the original and the reimplementation; compare outputs | Strongest for algorithms |
| Golden vectors | Fix N inputs/outputs from the original | Good regression anchor |
| Property tests | Assert invariants (monotonicity, range, idempotence) | Catches edge classes the samples miss |
| Structural | Compare control-flow graph / basic-block counts / call counts | Cheap sanity check |
| Byte-level | Compare compiled output bytes (when the same toolchain is used) | Very strong, rarely possible |
| Trace equivalence | Compare executed call sequences on one input | Good for control-flow reconstruction |
| Behavioural | Same scenario against both, compare observable results | Good for apps |

For numeric algorithms, specify the **exact** semantics: rounding mode, saturation, overflow
behaviour, and the behaviour for out-of-range inputs (often unknown).

## 4. Coverage proof

The strongest available statement about a reconstruction is a coverage proof over the original's
behaviour space. The DX-Ball-style pattern is the reference: reconstruct the calculation, then
run thousands of original-generated cases plus compare the compiled function bytes.

```text
CLAIM:    The reimplementation reproduces position_to_pan for all observed input classes.
EPISTEMIC: derived
EVIDENCE: EV-101 (3,205 original-generated x86 cases, 100% agreement),
           EV-102 (63/63 function bytes identical)
COVERAGE: x ∈ [-32768, 32767], y ∈ [-32768, 32767], 3,205 sampled pairs + boundary set
LIMITS:   Inputs outside the observed range are UNKNOWN; compiler version differed.
```

When you cannot reach byte-identity, say which parts match (semantics, control flow, instruction
count) and which do not.

## 5. Anti-patterns

| Anti-pattern | Why it fails |
| --- | --- |
| Reimplement from decompiled pseudocode alone | The pseudocode omits UB, exact widths, and ordering |
| "Equivalent" based on one test vector | One vector cannot cover a behaviour space |
| Silently choosing a spec for unknown behaviour | Your choice becomes an unverified claim |
| Comparing against a *different* build | The baseline moved |
| Assuming the compiler preserved semantics | UB, optimisation, and aliasing can change it |
| Reporting "reconstructed" without a ledger | No way to know what was left out |

## 6. Interaction with the security track

A reconstruction is often the proof for a vulnerability:

- Reconstructing a parser shows whether the input is validated before use.
- Reconstructing a length/offset calculation shows whether an integer overflow is reachable.
- Reconstructing a crypto routine shows whether the key/IV handling is sound.

Keep the two ledgers linked: each security finding cites the obligation and evidence that
supports the vulnerable path.

## 7. Deliverables

```text
1. SPEC   — the behavioural specification (typed claims + unknowns)
2. LEDGER — obligations ↔ evidence ↔ verification
3. CODE   — the reimplementation, with the spec/ledger IDs in comments where non-obvious
4. TESTS  — the differential/golden/property suite that ran
5. REPORT — coverage proof, limitations, and open questions
```

Never ship a reconstruction whose ledger has open obligations without stating them in the report.
