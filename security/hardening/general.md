# Hardening checklist — general

Applies to any repository, service, or workstation used in this workspace. Mark each item or record
why it does not apply.

## Repository

- [ ] `.gitignore` covers `.env*`, keys, certificates, credentials, captures, build output.
- [ ] No secrets in the tree or in history (`git log --all -S`).
- [ ] `LICENSE`, `SECURITY.md`, and `CONTRIBUTING.md` exist.
- [ ] Default branch is protected; review required for changes to `scripts/`, `.kilo/`, `.github/`.
- [ ] CODEOWNERS names real people/teams, not a placeholder.
- [ ] Issue templates ask for authorization context and forbid secrets in reports.

## CI

- [ ] Default `permissions: contents: read` at workflow level; narrower per job.
- [ ] Actions pinned to commit SHAs.
- [ ] No `pull_request_target` running fork code.
- [ ] Secrets scoped per job/environment; never echoed; masked in logs.
- [ ] Untrusted input passed via `env:` and quoted, never interpolated into `run:`.
- [ ] Dependency caching does not leak credentials into cache keys.
- [ ] Self-hosted runners are isolated from production networks.

## Application defaults

- [ ] Debug mode off in production; no stack traces in responses.
- [ ] Security headers: CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`, `frame-ancestors`.
- [ ] Cookies: `HttpOnly`, `Secure`, `SameSite`, minimal `Path`/`Domain`.
- [ ] CORS allowlist explicit; never `*` with credentials.
- [ ] Rate limits on auth, password reset, and expensive endpoints.
- [ ] Request body, upload, and pagination sizes capped.

## Data

- [ ] Sensitive data encrypted at rest; keys outside the data store.
- [ ] Logs contain no secrets, tokens, or personal data.
- [ ] Backups encrypted, access-controlled, and restore-tested.
- [ ] Retention and deletion paths exist and are exercised.

## Identity and access

- [ ] No shared accounts; no long-lived credentials for humans.
- [ ] MFA on every system that offers it.
- [ ] Access reviews on a schedule.
- [ ] Service accounts have the minimum scope and are inventoried.

## Workstation (analyst)

- [ ] Analysis of untrusted targets happens in a disposable VM/container, not the workstation.
- [ ] Full-disk encryption and screen lock enabled.
- [ ] No real credentials in the analysis environment.
- [ ] SSH keys per purpose, hardware-backed where possible, rotated on a schedule.
- [ ] OS and analysis engines updated automatically.

## Verification

Record the date, the checker, and the result. A hardening claim without a check date is a wish.
