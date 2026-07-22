# CertOps cloud overlay verification (P0.5)

Status: verified 2026-06-25 against the cloud working tree.
Owner: overlays. Reviewer: backend.

Purpose: confirm the cloud path and manifest assumptions the CertOps work was
written against, and record corrections so inventory/executor overlay work is
not blocked.

## Verified facts

| Assumption (plan) | Reality | Verdict |
|---|---|---|
| Cloud API at `apps/saas/` | `apps/saas/` exists (overlays core `apps/api/`) | Confirmed |
| Cloud web at `apps/web/` | `apps/web/` exists (overlays core `apps/dashboard/src/`) | Confirmed |
| Marketing surface | `apps/marketing/` (cloud-only) | Confirmed |
| Worker overlay | `apps/worker/` (partial overrides) | Confirmed |
| Override manifest | `overrides.manifest.json` at repo root | Confirmed |
| Compatibility pin | `compatibility.manifest.json` (core `^0.8.1`, artifact SHA-256 digests) | Confirmed |
| Composition manifest | NOT a source file; generated at `.build/stage/cloud/composition.manifest.json` | Corrected |

## Corrections to plan assumptions

1. **No `additiveFile` kind in cloud.** Cloud override `kind` values are:
   `fileOverride`, `derivedDivergence`, `pluginBehaviorOverride`, `saaSOnly`,
   `enterpriseOnly`. (`additiveFile` is an enterprise-manifest kind.) New
   cloud-only CertOps files must be registered as `saaSOnly` (or
   `derivedDivergence` when they diverge from a core counterpart), not
   `additiveFile`.
2. **Override entry fields** are `ownerPath`, `targetCorePath` (or `null`),
   `kind`, `reason`, `confidence`, optional `coreParity`. There is no
   `enterpriseOnly` entry in cloud's manifest today (valid kind, zero entries).
3. **`check:contracts` does not live in cloud.** It runs against tokentimer-core
   via cloud's `test:baseline` (`scripts/run-baseline.js`). Cloud's own manifest
   gates are `check:overrides` and `check:compat`.
4. **Core <-> cloud path mapping**: `apps/saas/*` -> core `apps/api/*`;
   `apps/web/*` -> core `apps/dashboard/src/*`.

## Plan-relevant precedents to reuse

- **Plan gating (402)**: `requireDomainCheckerPlan` in
  `apps/saas/routes/domains.js` returns 402 `PLAN_FEATURE_REQUIRED`. CertOps
  cloud plan gates should mirror this shape. Token-limit gating uses 402
  `PLAN_TOKEN_LIMIT`.
- **Fail-closed freeze**: `apps/saas/services/rbac.js` `loadWorkspace` returns
  403 `WORKSPACE_FROZEN` for frozen workspaces (no try/catch swallowing).
- **Plan limits service**: `apps/saas/services/planLimits.js` (free/pro/team
  ladders; production fail-closed `QUOTA_BACKEND_UNAVAILABLE`).
- **Rate limiting**: authenticated `/api/*` is keyed `user-${id}` via
  `authenticatedBaselineLimiter`; dev/test skips the global limiter on `/api`.

## Manifest checklist for CertOps cloud overlays

- [ ] New cloud-only route file -> `overrides.manifest.json` entry, `kind: saaSOnly`, `targetCorePath: null`.
- [ ] Overriding a core file -> `kind: fileOverride`, set `targetCorePath`.
- [ ] New cloud-only page (`apps/web/pages/*.jsx`) -> `saaSOnly` entry + lazy route in `apps/web/App.jsx`.
- [ ] Pin any new core contract artifact in `compatibility.manifest.json` (`requiredEntries` / `artifactDigests`).
- [ ] Run `pnpm run check:overrides` and `pnpm run check:compat` before PR.
- [ ] Run cloud `test:baseline` (invokes core `check:contracts` + contract tests).

## Test commands (cloud)

- `pnpm run check:overrides` - validate override manifest.
- `pnpm run check:compat` - validate compatibility pin + artifact digests.
- `pnpm run test` - core-aware test entry.
- `pnpm run test:local:full` - full local suite (`scripts/run-local-full.js`).
