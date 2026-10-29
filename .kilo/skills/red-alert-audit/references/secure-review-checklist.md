# Secure review checklist

Concrete checks per layer, with the searches that surface each class. Adapt paths to the repo.
Every hit needs a manual decision.

## L0 — Repository hygiene

```bash
git ls-files | rg -i '(\.env|secret|credential|\.pem$|\.p12$|id_rsa|\.key$)'   # tracked sensitive paths
git log --all --oneline -S'BEGIN RSA PRIVATE KEY' -- .                         # history: keys
git log --all --oneline -S'AKIA' -- .                                          # history: AWS keys
git ls-files -s | rg '^100755'                                                  # executable bits
```

- [ ] `.gitignore` covers `.env*`, keys, credentials, captures, build output.
- [ ] No committed secrets, including in fixtures and test data.
- [ ] File permissions: no world-writable files; scripts that handle secrets are not world-readable.
- [ ] CI logs do not print secrets (`set -x` around secret usage, `::add-mask::`).
- [ ] `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md` present and consistent.

## L1 — Dependencies and supply chain

```bash
npm audit --omit=dev 2>/dev/null || true
pip-audit 2>/dev/null || true
cargo audit 2>/dev/null || true
govulncheck ./... 2>/dev/null || true
```

- [ ] Lockfiles committed and used in CI (`npm ci`, not `npm install`).
- [ ] No unpinned versions in production dependencies (`^`, `~`, `latest`).
- [ ] Install scripts (`postinstall`, `setup.py`) reviewed in every direct dependency.
- [ ] Dependabot/Renovate configured.
- [ ] Known CVEs triaged with reachability analysis — "is the vulnerable function reachable from
      untrusted input?" — not just version matching.
- [ ] Abandoned/unmaintained dependencies replaced or pinned with a documented exception.
- [ ] Internal/private registries have a scope check: a dependency name that typosquats a popular
      package must not resolve.

## L2 — Secrets

```bash
scripts/sec/secret_scan.py .            # high-precision patterns + entropy heuristics
```

- [ ] No secrets in code, config, tests, fixtures, notebooks, docs.
- [ ] Secrets come from the environment or a secret manager, never hardcoded.
- [ ] No secrets in CI logs, error messages, or client-side bundles.
- [ ] Rotation procedure exists and has been exercised.
- [ ] `.env.example` contains only placeholder values.

## L3 — Configuration and headers

- [ ] Debug mode is off in production; stack traces are not returned to clients.
- [ ] CORS is not `*` with credentials; allowed origins are explicit.
- [ ] Security headers present: CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`,
      `frame-ancestors` (via CSP), `Permissions-Policy`.
- [ ] Cookies: `HttpOnly`, `Secure`, `SameSite`, scoped `Path`/`Domain`.
- [ ] Error responses do not leak stack traces, SQL, or internal hostnames.
- [ ] Cloud/storage buckets are not public; default credentials removed.
- [ ] Terraform: no public S3 buckets, no wide IAM, encryption at rest, no hardcoded ARNs for
      privileged roles.

## L4 — Code review hotspots

Use the searches as *starting points*, then read the code path.

### Injection
```bash
rg -n --no-heading "exec\(|execSync|spawn\(|eval\(|new Function\(|child_process" src/
rg -n --no-heading "raw\(|query\(|execute\(|sequelize\.query|\$queryRawUnsafe" src/
rg -n --no-heading "system\(|popen|subprocess\.|os\.system|shell=True" src/
```
- [ ] No string-concatenated SQL; parameterised queries only.
- [ ] No shell interpolation of user input (`shell: true` with a template).
- [ ] No `eval`/`new Function` on untrusted input; template engines escape by default.
- [ ] ORM `raw` queries are parameterised.

### Authentication / authorisation
```bash
rg -n --no-heading "jwt\.sign|jwt\.verify|verify\(|algorithm" src/
rg -n --no-heading "req\.user|request\.user|ctx\.user" src/
rg -n --no-heading "role|permission|isAdmin|authorize|requireAuth" src/
```
- [ ] Passwords hashed with argon2/bcrypt/scrypt (cost tuned), never MD5/SHA1/plain.
- [ ] Session tokens: signed, expiry, rotation on privilege change, invalidated on logout.
- [ ] JWT: algorithm pinned, `aud`/`iss` verified, expiry enforced, `alg: none` rejected.
- [ ] **Object-level authorisation** on every route that takes an identifier — the most common
      real finding. Check for a tenant/user filter inside the query, not just in the middleware.
- [ ] Auth middleware is applied **before** the handler, and cannot be bypassed by route order.
- [ ] Admin endpoints are not merely hidden in the UI.
- [ ] Password reset / MFA / recovery flows are rate-limited and single-use.

### Input, paths, and deserialisation
- [ ] Validation at the boundary with an allowlist where possible (schema validation).
- [ ] Path traversal: user input joined into a path → canonicalise and check the prefix.
- [ ] Deserialisation of untrusted data: `pickle`, `yaml.load`, `ObjectInputStream`, PHP
      `unserialize` — all dangerous.
- [ ] XML: disable external entities (XXE).
- [ ] Archive extraction: zip-slip (entries with `../`), symlink entries, decompression bombs
      (cap total size and entry count).
- [ ] Regexes built from user input → ReDoS (check nested quantifiers).

### Web
- [ ] Output encoded by context (HTML / attribute / JS / URL).
- [ ] No `innerHTML`/`dangerouslySetInnerHTML` with untrusted data.
- [ ] CSRF protection on state-changing routes (or `SameSite` + custom header discipline).
- [ ] Open redirect: validate the post-login redirect target against an allowlist.
- [ ] SSRF: user-supplied URL fetches validated against an allowlist; block link-local and
      metadata addresses (169.254.169.254).
- [ ] File upload: content-type and extension validated, stored outside the web root, served
      with `Content-Disposition: attachment` and a safe content type, size capped.
- [ ] Rate limits on authentication, password reset, and expensive endpoints.

### Crypto
- [ ] Randomness from a CSPRNG (`crypto.randomBytes`, `secrets`), never `Math.random` for tokens.
- [ ] AES-GCM / ChaCha20-Poly1305 for encryption; no ECB; unique nonces.
- [ ] Password hashing: argon2id/bcrypt/scrypt with a calibrated cost.
- [ ] HMAC comparison is constant-time (`crypto.timingSafeEqual`).
- [ ] TLS: certificates verified, no `rejectUnauthorized: false`, modern TLS versions only.
- [ ] No custom crypto.

### Concurrency and resources
- [ ] TOCTOU on files (check-then-use) — use atomic operations.
- [ ] Race conditions in check-then-act logic (idempotency keys, unique constraints).
- [ ] Unbounded reads: request body size, upload size, query result size, pagination limits.
- [ ] Regex/loop denial of service: timeouts, iteration caps.
- [ ] Worker/thread pools bounded; queue depth bounded.

### Data handling
- [ ] PII minimised; logs do not contain secrets or full tokens.
- [ ] Encryption at rest for sensitive stores; keys not co-located with the data.
- [ ] Retention and deletion paths exist.
- [ ] Backups are encrypted and access-controlled.

## L5 — CI/CD and build

- [ ] Actions pinned to a commit SHA (not a mutable tag).
- [ ] `pull_request_target` / `workflow_run` not used to run untrusted code with secrets.
- [ ] Untrusted input (issue titles, PR bodies, fork code) never reaches a shell interpolation.
- [ ] Least-privilege `permissions:` block on each job; no `write-all`.
- [ ] Self-hosted runners are not used for untrusted PRs.
- [ ] Secrets are scoped per job/environment, not global.
- [ ] Releases are signed (Sigstore/cosign or a signed provenance attestation).
- [ ] Package publishing is gated by tests, review, and provenance.
- [ ] Dockerfiles: no secrets in build args, minimal base images, `USER` non-root, no `ADD` of
      remote URLs.

## L6 — Runtime (only with authorisation)

- [ ] The deployed config matches the reviewed config (no drift).
- [ ] Dependencies actually loaded at runtime match the lockfile (no phantom deps).
- [ ] The service runs as a non-root user with a read-only filesystem where possible.
- [ ] Network egress is restricted to the expected endpoints.
- [ ] No debug endpoints or profiling servers exposed.

## Finding quality bar

Before writing a finding, confirm:

```text
[ ] The vulnerable code path was read end to end.
[ ] A framework mitigation was searched for and does not cover this path.
[ ] The precondition is explicit.
[ ] The impact is concrete (what can the attacker do, with what data).
[ ] The fix is specific enough to implement without further research.
[ ] No live secret appears in the finding text.
```
