# Security Policy

This repository is an analysis and defensive-security workspace. It holds a method, tooling, and
policy — not a product with an exposed attack surface. The policy below covers both the reporting
of vulnerabilities in this repository and the responsible use of the material it contains.

## Reporting a vulnerability in this repository

If you find a weakness in this repository's tooling (for example a secret scanner that silently
skips a file class, or a script that executes what it inspects):

- Open a private security advisory on this repository, or email the maintainers.
- Include: the file and line, the impact, and a reproduction.
- Do not include real credentials, real user data, or live third-party endpoints in the report.
- You will get an acknowledgement within 7 days and a remediation plan within 30 days.

Please do not open a public issue for a vulnerability before it is fixed.

## Responsible use

Everything in this repository exists to help with **lawful research, interoperability, software
preservation, education, and defensive security on systems you own or are authorised to
examine**.

Out of scope, and not supported:

- Accessing systems you do not own or have written permission to test.
- Credential theft, persistence on third-party systems, or malware deployment.
- Bypassing licensing, activation, or access controls of commercial tools (Hopper, IDA, JEB,
  Hex-Rays, and similar).
- Evading detection on production infrastructure you are not authorised to operate.
- Bulk collection of personal data.

The reverse-engineering method and the tooling in `scripts/` are neutral instruments. Their use is
the analyst's responsibility.

## Rules that apply to anything produced in this repository

1. **Authorisation first.** Confirm the target is yours or that you have permission before
   touching it.
2. **Disposable environments.** Untrusted targets run in a throwaway VM or container with an
   isolated network — never on a workstation with real credentials.
3. **No live secrets in the repository.** Use `REDACTED` placeholders. If a secret lands in git,
   treat it as compromised: rotate it first, then remove it.
4. **Minimise collected data.** Redact personal data, tokens, cookies, and session identifiers
   from captures, logs, and reports before storing them.
5. **Respect licences.** Third-party tools keep their own licences and terms. Ghidra, IDA, Hopper
   and JEB must be legally obtained; no cracked copies, no stolen keys, no automated activation
   bypass.
6. **Report responsibly.** Prefer vendor disclosure over publication, give the vendor a
   reasonable window, and never publish a working exploit against a live system.

## Handling a leaked secret

```text
1. Rotate the credential first. Removing it from git does not un-leak it.
2. Purge from history (git filter-repo / BFG) if the repository is public.
3. Review access logs for the exposure window.
4. Record the incident in the risk register with the closure evidence.
5. Never paste the value into an issue, a commit message, or a report.
```

## Security of the tooling itself

`scripts/` are read-only analysers by design:

- `scripts/re/triage.sh` and `scripts/re/lib_analyze.py` read bytes; they never execute, unpack,
  or import anything from a target.
- `scripts/sec/secret_scan.py` reads files and redacts the values it reports.
- `scripts/sec/sca_audit.sh` may invoke ecosystem audit tools (`npm audit`, `pip-audit`,
  `cargo audit`, `govulncheck`) when they are already installed. It never installs them.

If you find a path where one of these scripts executes target content, that is a Critical finding
in this repository — please report it privately.
