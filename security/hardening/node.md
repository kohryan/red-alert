# Hardening checklist — Node.js

## Dependencies

- [ ] `package-lock.json` committed; CI uses `npm ci`.
- [ ] `npm audit --omit=dev` clean or triaged in CI.
- [ ] No `latest`/`*`/URL specs in production dependencies.
- [ ] `postinstall`/`prepare` scripts reviewed for every new dependency.
- [ ] Dependabot or Renovate enabled with grouped, low-noise updates.

## Application

- [ ] `node_modules` never committed; `.npmrc` with tokens never committed.
- [ ] No secrets in client bundles — check with `grep` over the built output before release.
- [ ] Server framework in production mode; error pages do not leak stack traces.
- [ ] Input validated at the boundary with a schema (zod/ajv/joi).
- [ ] SQL parameterised; `sequelize.query`/`knex.raw` always parameterised.
- [ ] `child_process` calls use argument arrays, never `shell: true` with interpolated input.
- [ ] `eval`/`new Function` absent from request-handling paths.
- [ ] Output encoding handled by the template engine; no raw HTML injection.
- [ ] CSRF protection on state-changing routes; `SameSite` cookies.
- [ ] Rate limiting on auth and expensive routes.
- [ ] `helmet` (or equivalent) enabled with an explicit CSP.

## Supply chain

- [ ] `npm publish` uses 2FA and a scoped token.
- [ ] Publishing happens from CI on a protected tag, not from a laptop.
- [ ] Provenance attestation enabled (`npm publish --provenance`).
- [ ] `npm ci --ignore-scripts` used anywhere scripts are not needed.

## Runtime

- [ ] Non-root user in the container image.
- [ ] `NODE_ENV=production`.
- [ ] Health/readiness endpoints do not expose internals.
- [ ] Graceful shutdown drains in-flight requests.

## Checklist commands

```bash
npm audit --omit=dev
npm ls --all --json > dependency-tree.json   # review the transitive shape
npm outdated
grep -rIn --exclude-dir=node_modules -E "(sk_live_|AKIA|ghp_)" . | head
```
