# Red-alert

Agentic reverse-engineering and defensive-security workspace.

## Default branch

`main` — protected. Changes to `scripts/`, `.kilo/`, and `.github/` require review by a maintainer.

## Review requirements

| Path | Required review |
| --- | --- |
| `scripts/**` | 1 maintainer + a second reviewer for parsing/execution changes |
| `.kilo/skills/**` | 1 maintainer (a skill changes agent behaviour) |
| `.github/workflows/**` | 1 maintainer |
| `security/**` | 1 maintainer |
| `docs/**`, `labs/**` | normal review |

## What a review checks

- **Scripts**: no target content is executed, imported, or evaluated; all subprocess calls are
  argument-list based and timeout-bounded; failures are closed, not open; outputs are redacted.
- **Skills and agents**: the epistemics vocabulary is intact; no claim is made without evidence;
  target-derived text is treated as data; the safety rails are not weakened.
- **Workflows**: minimal `permissions`; actions pinned to SHAs; untrusted input never interpolated
  into `run:`; no secrets in fork contexts.
- **Docs**: no live secrets, no personal data, no exploit payloads against live systems.

## Commit and PR conventions

- Conventional Commit subjects: `feat:`, `fix:`, `docs:`, `sec:`, `chore:`, `test:`.
- One logical change per PR. A behaviour change to a skill and its docs belong together.
- Describe behaviour changes, the validation that ran, and the coverage that was *not* verified.
- Never commit binaries, captures, or evidence containing live data.

## Running the checks locally

```bash
make test        # script syntax + tooling self-test + link check
make baseline    # hygiene, secrets, dependencies
```

Both must pass before a PR is ready.

## Responsible use

Contributions must stay within the authorised-testing scope in `SECURITY.md`. Material that
enables bypassing licence enforcement, or attacking systems the contributor does not own, will
not be merged.
