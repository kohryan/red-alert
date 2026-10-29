# Hardening checklist — Python

## Dependencies

- [ ] Fully pinned requirements (`==`) or a lock file with hashes.
- [ ] `pip-audit` (or `safety`) run in CI; findings triaged with reachability analysis.
- [ ] No packages installed from URLs or local paths in production requirements.
- [ ] Packages with `setup.py` build steps reviewed.

## Application

- [ ] `DEBUG = False` and `ALLOWED_HOSTS` set in production settings.
- [ ] `SECRET_KEY` from the environment or a secret manager, never from the repository.
- [ ] `ALLOWED_HOSTS`, secure proxy headers, and session cookie flags configured explicitly.
- [ ] Django: `CSRF_COOKIE_SECURE`, `SESSION_COOKIE_SECURE`, security middleware enabled.
- [ ] Flask: no debug mode; `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SAMESITE`.
- [ ] SQL via the ORM or parameterised queries; no f-string SQL.
- [ ] `pickle`, `yaml.load`, `eval` never applied to untrusted input.
- [ ] `subprocess` calls use argument lists, `shell=False`, and a timeout.
- [ ] File uploads stored outside the served directory with random names and a size cap.
- [ ] `DEBUG` tracebacks never returned to clients.

## Tooling

- [ ] Virtualenvs used; no global installs.
- [ ] `python -m compileall` / a linter (`ruff`, `flake8`) in CI.
- [ ] Bandit or equivalent static security check in CI.
- [ ] Pre-commit hooks installed for the security checks.

## Packaging

- [ ] Wheels signed where the ecosystem supports it.
- [ ] Publishing token scoped to one project; 2FA enabled.
- [ ] No credentials in `setup.cfg`, `pyproject.toml`, or package metadata.

## Checklist commands

```bash
pip-audit
bandit -r src/
python -m compileall -q src
pip list --outdated
```
