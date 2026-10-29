# Playbook — suspicious binary triage

**Trigger:** "this might be malicious" / "is this a dropper?" / a file from an untrusted source.

**Goal:** an evidence-based assessment against explicit criteria, and a defensible statement of
what is still unknown. Not a vibe.

## 0. Framing

"Is it malware?" is not a question. Convert it into **observable criteria** before you look, and
write them down. Typical criteria:

| # | Criterion | Why it matters |
| --- | --- | --- |
| C1 | Executes code from a remote or bundled payload | Loader behaviour |
| C2 | Persists across reboot | Impact |
| C3 | Exfiltrates data to an external endpoint | Impact |
| C4 | Disables or evades security tooling | Defence evasion |
| C5 | Contains obfuscated/encrypted content | Concealment |
| C6 | Ships with credentials or exploits | Weaponisation |
| C7 | Targets a specific victim or organisation | Targeting |

A criterion is met only with evidence. A criterion that cannot be assessed stays **unknown**.

## 1. Safety posture (before any dynamic work)

```text
[ ] Disposable VM or container only
[ ] No real credentials, no real accounts
[ ] Network isolated or sinkholed
[ ] Snapshot before the run
[ ] Original artifact hashed; analysis on a copy
[ ] Host security controls untouched
```

If no disposable environment exists: static analysis only, and the dynamic criteria stay
`unknown`. That is a legitimate outcome.

## 2. Static pass (always safe)

```bash
scripts/re/triage.sh suspect --out labs/suspect-<name>
```

Then, by class:

- Native → mitigations, imports (network/process/registry APIs), embedded strings, packer signals,
  section entropy, digital signature.
- Script/app → entrypoint, capability use (`child_process`, `eval`, `fs`, `http`), obfuscation
  markers, install hooks.
- Installer/archive → install scripts, payload members, signatures.

Record each criterion's evidence in the ledger. Format:

```text
| EV-014 | sha256:… | imports @ 0x… | socket, connect, sendto imported | observed | complete import table | dynamic resolution may hide more | — |
```

## 3. Capability triage

| Observed | Suggests | Confidence limit |
| --- | --- | --- |
| Network APIs + URLs | C3 candidate | APIs may be unused |
| Service/registry persistence APIs | C2 candidate | path may never be taken |
| `VirtualAlloc`/`mmap` + RWX | in-memory payload | may be legitimate JIT |
| Process hollowing patterns | loader | needs dynamic confirmation |
| Certificate/extension checks | targeting | checks can be bypassed elsewhere |
| Anti-debug strings | C4 candidate | presence ≠ active |

## 4. Dynamic pass (only with authorisation and a sandbox)

Run the target with the posture above, and collect:

```text
process: argv, exit code/signal, stdout/stderr, child processes
network: DNS, connections, HTTP requests (full capture)
filesystem: files created/modified, with paths
persistence: launch agents, run keys, scheduled tasks created
```

Compare before/after snapshots. Every observation is `observed` with a locator (timestamp,
capture record, syscall).

## 5. Verdict

Use a bounded verdict, never a bare "malicious":

```text
VERDICT: <behavioural summary>
CONFIDENCE: High | Medium | Low
CRITERIA MET: C1 (evidence EV-…), C3 (evidence EV-…)
CRITERIA UNKNOWN: C2 (needs a reboot observation), C7 (needs attribution data)
```

Examples of good verdicts:

- "Behaviour matches a download-and-execute loader: a remote payload URL is embedded and the
  loader writes it to disk and spawns it — High confidence, criteria C1 met (EV-011/014/022)."
- "No persistence mechanism was observed in the 40-second run — **Low** confidence: the run did
  not include a reboot, and the persistence criterion cannot be excluded."

## 6. Reporting

Use `templates/finding.md`. Include:

- what it does (behaviour, not adjectives),
- the evidence and its epistemic labels,
- the criteria met and the ones still unknown,
- the network destinations observed (redacted if they carry credentials),
- the impact for a victim,
- remediation: what to block, what to patch, what to rotate.

## 7. If this is someone else's system

- Preserve evidence: hash, copy, timeline, logs.
- Do not "clean it up" before documenting.
- Report to the owner; if you are not the owner, hand the evidence over.
- Do not publish operational details before the owner has responded.

## 8. What not to do

- Do not run it on your workstation to "see".
- Do not write a detection rule from a single string match without the surrounding context.
- Do not name a malware family from a partial resemblance.
- Do not publish indicators before the owner has been notified.
