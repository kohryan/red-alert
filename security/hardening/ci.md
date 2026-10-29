# Hardening checklist — CI/CD

## Workflow basics

- [ ] Default `permissions: contents: read` at the top of every workflow.
- [ ] Each job narrows permissions further.
- [ ] Third-party actions pinned to a commit SHA.
- [ ] `actions/checkout` pinned; `fetch-depth: 0` only when history is needed.
- [ ] Timeouts on every job (`timeout-minutes`).
- [ ] Concurrency groups for deploy workflows to prevent overlapping runs.

## Untrusted input

- [ ] `pull_request` used for fork code; never `pull_request_target` for code execution.
- [ ] `${{ github.event.* }}` values never interpolated directly into `run:` blocks — pass via
      `env:` and quote.
- [ ] Artefacts downloaded from other jobs are treated as untrusted input.
- [ ] Matrix values that come from user input are validated before use.

## Secrets

- [ ] Secrets scoped per job/environment, not workflow-wide.
- [ ] Fork PRs get no secrets (verify the workflow does not request them).
- [ ] Secrets masked in logs (`::add-mask::`), never `set -x` around their use.
- [ ] Rotation tested; expiry reminders set.
- [ ] No secrets in build args, cache keys, or artefact names.

## Release path

- [ ] Publishing only from protected branches/tags.
- [ ] Release artefacts signed and provenance attached.
- [ ] Secrets used for publishing are available only to the release job.
- [ ] A second person approves releases of high-impact artefacts.
- [ ] The published artefact is verified against the built one (digest comparison).

## In this repository

The security workflow runs the defensive baseline:

```bash
scripts/sec/baseline.sh --path . --format json --fail-on critical
```

It is read-only: it runs `secret_scan.py`, the dependency audit, and the hygiene checks. It never
installs a tool and never executes target content.
