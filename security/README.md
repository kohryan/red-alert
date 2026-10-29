# Security foundation

The defensive half of this repository. `security/` holds the policies and standards that make the
analysis half of the repo trustworthy: if the workspace itself leaks secrets or models bad
practice, the reverse-engineering output inherits that weakness.

| File | What it is |
| --- | --- |
| [`threat-model.md`](threat-model.md) | The workspace's own threat model: assets, actors, boundaries, abuse cases, controls |
| [`secure-coding-standards.md`](secure-coding-standards.md) | Language-agnostic standards every script and workflow must follow |
| [`secrets-policy.md`](secrets-policy.md) | Handling, detection, rotation, and history hygiene for secrets |
| [`supply-chain.md`](supply-chain.md) | Dependency, CI, build, and release integrity |
| [`incident-response.md`](incident-response.md) | What to do when something leaks or is compromised |
| [`risk-register.md`](risk-register.md) | Live risk tracking with owners and review dates |
| [`hardening/`](hardening/) | Per-stack checklists (general, node, python, containers, CI) |

## The baseline

```bash
make baseline        # hygiene + dependency audit + secret scan over this repository
make doctor          # which optional analysis tools are present
```

`make baseline` produces **leads**, not verdicts. Every hit needs a human decision before it
becomes a finding — the workflow is in `.kilo/skills/red-alert-audit/SKILL.md`.

## Principles

1. **Authorisation precedes action.** Ask once, then proceed.
2. **Read-only by default.** Analysis tooling must not modify targets or the environment.
3. **Least privilege.** No credentials for analysis, no network for unknown binaries.
4. **Evidence over assertion.** Security claims cite code, configuration, or observation.
5. **Blast radius awareness.** A typo in a scanner or a triage script is still a vulnerability.
6. **Fail closed.** Missing tooling is a coverage gap to report, not a reason to install.
