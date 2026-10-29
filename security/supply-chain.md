# Supply chain

## 1. Principles

1. **Pinning** — exact versions in lockfiles; actions pinned to a commit SHA.
2. **Provenance** — where a dependency came from and who published it, recorded.
3. **Least privilege** — CI and publishers get the minimum scope needed.
4. **Reviewability** — a dependency diff is a diff; an install script is not.
5. **Verifiability** — builds produce attestations that can be checked later.

## 2. Dependencies

| Rule | Why |
| --- | --- |
| Commit the lockfile and install from it (`npm ci`, `pip install -r` with hashes) | A lockfile is the only thing that makes an install reproducible |
| No `latest`, `*`, or URL specs in production dependencies | A moving target cannot be audited |
| Review every dependency with a `postinstall`/`setup.py` build step | Install scripts run with your privileges before any code review |
| Pin transitive dependencies that matter (or use a constraints file) | The compromise path usually runs through a transitive dep |
| Check for typosquats before adding a dependency | `reqeusts`, `beautifulsoup` — verify the name and the publisher |
| Prefer a mature package with an active maintainer over a tiny one with a generic name | Abandonment is a security property |
| Audit regularly, not only on install | CVEs appear after the fact |

Tooling in this repo:

```bash
make sca                                  # audit whatever ecosystems are present
scripts/sec/sca_audit.sh .                # same, with coverage-gap reporting
```

When an audit tool is missing, the audit reports a **coverage gap** — it never installs one.

## 3. CI/CD

```yaml
permissions:
  contents: read          # default to the least privilege you can live with

jobs:
  build:
    steps:
      - uses: actions/checkout@v4      # pin to a SHA for real supply-chain control
      - uses: some/action@<full-sha>  # a tag can be moved; a SHA cannot
```

Rules:

- **`pull_request`, never `pull_request_target`,** for workflows that check out and run code.
- Fork PRs get no secrets and a read-only token — do not work around this.
- Never interpolate untrusted values (`github.event.pull_request.title`, branch names, issue
  bodies) into a `run:` block. Pass them as environment variables and quote them.
- Self-hosted runners must not run untrusted PRs.
- Secrets are scoped per job and per environment, never global.
- Artefacts uploaded from CI are untrusted input to any later job that consumes them.

## 4. Build and release integrity

- Build in a clean, pinned environment; record the toolchain versions.
- Produce provenance: SLSA provenance or Sigstore attestations for released artefacts.
- Sign releases (`cosign`, `sigstore`, or the platform's signing key).
- Separate duties: the person who merges is not the only person who can publish.
- Publish only from CI, from a protected branch, after tests and review.
- Keep the signing key out of the repository and out of the build container.

## 5. Containers

- Pin base images by digest.
- Minimal base images; no compilers or package managers in the final layer.
- Run as a non-root user with a read-only filesystem where possible.
- No secrets in build args or layers — build args are visible in the image history.
- Never `ADD` a remote URL; `COPY` a verified artefact instead.
- Generate an SBOM for published images.

## 6. Third-party analysis engines

The engines used for reverse engineering (Ghidra, Hopper, IDA, JADX, Rizin) are themselves
third-party binaries that run with the analyst's privileges:

- Obtain them from the vendor or an official repository; verify signatures/checksums.
- Keep them updated — engine vulnerabilities are real.
- Run them against **untrusted** targets inside the disposable environment, not on the analyst's
  workstation, where a parser bug is a parser bug.
- Record the engine and version used in each investigation: the output is only reproducible with
  the same version.

## 7. Package publishing

- Verify the artefact you publish is the artefact you built (rebuild and compare digests).
- 2FA on the registry account; hardware key if available.
- Rotate publish tokens; scope them to one package.
- Watch for unexpected "yank/unpublish" events and account-level token creation.

## 8. Review checklist

```text
[ ] Lockfile committed and used in CI
[ ] No floating versions in production dependencies
[ ] Install scripts reviewed for new/changed dependencies
[ ] Actions pinned to commit SHAs
[ ] Workflow permissions are minimal and explicit
[ ] Untrusted input never reaches a shell interpolation
[ ] Fork PRs run without secrets
[ ] Releases are signed and have provenance
[ ] Base images pinned by digest, non-root runtime
[ ] Analysis engines verified and up to date
```
