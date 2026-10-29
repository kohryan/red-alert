# Secrets policy

## 1. What counts as a secret here

Credentials, tokens, keys, certificates, connection strings, and anything that grants access:

| Kind | Examples |
| --- | --- |
| Provider keys | AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe, SendGrid, Twilio, OpenAI, Anthropic |
| Infrastructure | private keys (`.pem`, `.key`, `id_*`), keystores, `.netrc`, `.pypirc`, `.npmrc` tokens |
| Application | session tokens, JWTs, database URLs with a password, API keys, webhook secrets |
| Operational | CI secrets, cloud credentials, kubeconfigs, service-account JSON |

Also treat as sensitive: personal data, internal hostnames, and unredacted capture payloads.

## 2. Rules

1. **Never commit a secret.** Not in code, not in a fixture, not in a screenshot, not in a lab
   note.
2. **Placeholder values must be obviously fake** but must keep the *shape* a scanner needs:
   `sk_live_REDACTED000000000000000000000000` is fine; a real key is not.
3. **Never print a secret in full.** Redact: keep the first 4 and last 2 characters.
4. **Never send a secret to a third-party service** — including a model provider — as part of an
   analysis. Redact before the text enters a prompt.
5. **No secrets in git history.** If it happened, rotate first, then purge.
6. **Environment variables only for local development.** Production secrets live in a secret
   manager.

## 3. Detection

```bash
make secret-scan .                 # whole tree
scripts/sec/secret_scan.py src/ --json
scripts/sec/secret_scan.py . --fail-on high    # CI gate
```

The scanner is **high precision by design**: known provider formats, private-key blocks, and
generic credential assignments with an entropy floor. It skips vendored directories and binary
files, and it reports `files_scanned` vs `files_skipped` so a coverage gap is visible.

Every hit is a **lead**. Triage it:

```text
Is the value a real credential?  → treat as exposed: rotate now.
Is it a placeholder or example?   → record the decision, add a suppression marker if noisy.
Is it a false positive?           → record the decision; improve the pattern if the class is new.
```

Suppression markers (inline, on the offending line): `red-alert:ignore`, `gitleaks:allow`,
`nosec`.

## 4. Rotation

```text
1. Revoke/rotate at the provider first — the credential is burned the moment it lands in a log,
   a commit, a CI run, or a model prompt.
2. Then clean the artefact (git history, artefact file, issue, chat).
3. Review access logs for the exposure window.
4. Record the incident: what leaked, where, for how long, what was rotated, when it was closed.
5. Add a detection for that credential class if it was not covered.
```

Rotation before cleanup. Cleanup without rotation is cosmetic.

## 5. History hygiene

```bash
# inspect before rewriting
git log --all --oneline -S'AKIA' -- .
git log --all --oneline -S'BEGIN RSA PRIVATE KEY' -- .

# purge (rewrites history; coordinate before force-pushing)
git filter-repo --path secrets.txt --invert-paths
```

Rewriting history invalidates clones and open PRs. Coordinate, then rotate anyway — history is a
copy, not a control.

## 6. Review of findings

A secret committed to a **public** repository is Critical. To a private repository it is High.
In a local, untracked artefact it is Medium. Severity also depends on the credential's power and
blast radius — a read-only key is not a deploy key.

## 7. Incident handling

See `incident-response.md`. The credential-handling section there is normative.
