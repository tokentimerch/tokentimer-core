# CertOps M1/M2 issue map (P0.6)

Status: ready-for-human (Dev A draft; Dev B to edit owners/estimates)
Drafted: 2026-06-25. Drafted by Dev A; reviewer/editor Dev B.

Scope: M1 (inventory) and M2 (jobs, tokens, executor). Tracer-bullet vertical
slices: each ticket is independently grabbable and lands a thin end-to-end
slice. Threat ids (T#) reference docs/adr/0005-certops-threat-model.md. Routes
and schemas reference the Phase 0 contract freeze.

Legend: [A]=suited to Dev A, [B]=suited to Dev B, dep=depends on.

## M1 - Inventory (public material only)

### CERTOPS-M1-1 Migration: CertOps inventory tables [A]
- dep: none (core migrate.js highest version is 9; use 10+).
- Add `managed_certificates` (+ supporting columns) per `certops-inventory.schema.json`.
- AC: idempotent `CREATE TABLE IF NOT EXISTS`; migration runs clean twice; no
  column intended to hold key material.

### CERTOPS-M1-2 Private-key rejection middleware [B]
- dep: secretMaterial.js (done in Phase 0).
- Express middleware that scans request bodies via `containsPrivateKeyMaterial`
  and returns 422 `PRIVATE_KEY_MATERIAL_REJECTED`; mount on certops write routes.
- AC (T1): nested/base64-wrapped private key in any field -> 422; certificate /
  public key passes. Integration test added.
- AC (T1, detector hardening): extend `secretMaterial.js` with binary PKCS#12/PFX
  (.p12/.pfx) DER sniffing (deferred from Phase 0) plus adversarial fixtures; the
  plan forbids PKCS#12/PFX bundles, so a `.p12` body must be rejected (422).

### CERTOPS-M1-3 GET/POST certificates + GET by id [A]
- dep: M1-1, M1-2.
- Implement `/api/v1/workspaces/{id}/certops/certificates` (GET, POST) and
  `/certificates/{certId}` (GET). Public material only; parse PEM via
  `X509Certificate` (reuse vaultIntegration helpers) for metadata.
- AC: returns inventory matching schema; POST persists; conformance test asserts
  routes documented in OpenAPI.

### CERTOPS-M1-4 Import endpoint [B]
- dep: M1-2, M1-3.
- Implement `/api/v1/workspaces/{id}/certops/imports` (POST). Accept PEM public
  material, dedupe, link to `tokens` where applicable.
- AC (T1): import body with key material -> 422; valid cert chain imported.

### CERTOPS-M1-5 Dashboard inventory view [A]
- dep: M1-3.
- Read-only inventory list + detail in dashboard (core `apps/dashboard`; cloud
  overlays in `apps/web`).
- AC: lists managed certs; never renders key fields (none exist).

### CERTOPS-M1-6 Logger/evidence redaction guard test [B]
- dep: secretMaterial.js.
- AC (T2/T3): log + evidence paths render placeholder, never key material.

## M2 - Jobs, tokens, executor

### CERTOPS-M2-1 Scoped API token system [A]
- dep: M1-1.
- `api_tokens` table; issue/list/revoke scoped tokens; HMAC-protected storage;
  plaintext returned once. Routes `/certops/tokens` (GET, POST).
- AC (T10): token scoped to workspace A cannot act on workspace B; secrets never
  returned after creation.

### CERTOPS-M2-2 certOpsTokenAuth middleware [B]
- dep: M2-1.
- Bearer auth for `/api/v1/certops/executor/*` and `/agent/*`; constant-time
  compare (mirror `internal-worker-auth.js`); CSRF-exempt these paths.
- AC: invalid/expired token -> 401; valid scoped token authorizes only its scope.

### CERTOPS-M2-3 Job model + signing [A]
- dep: M2-1, ADR-0003.
- `certificate_jobs` table; Ed25519 signing of job payloads per
  `job-payload.schema.json`; `signingKeyId` lifecycle.
- AC (T4): unsigned/HMAC/invalid-signature job rejected by verifier; signed job
  verifies against pinned public key.

### CERTOPS-M2-4 Job list endpoint [B]
- dep: M2-3.
- `/api/v1/workspaces/{id}/certops/jobs` (GET).
- AC: lists workspace jobs with state; documented in OpenAPI.

### CERTOPS-M2-5 Executor events endpoint [A]
- dep: M2-2, M1-2.
- `/api/v1/certops/executor/events` (POST). Accept progress + evidence metadata;
  scrub via `redactGenericSecrets`; reject key material 422.
- AC (T3/T5): evidence stored without secrets; replayed event (nonce/jobId)
  rejected.

### CERTOPS-M2-6 Replay protection [B]
- dep: M2-3, M2-5.
- Nonce + jobId replay cache; expiry-window enforcement.
- AC (T5/T6): duplicate nonce rejected; out-of-window job rejected.

### CERTOPS-M2-7 Cloud plan gating for CertOps [B]
- dep: M1-3, cloud overlay verification.
- Mirror `requireDomainCheckerPlan` (402 `PLAN_FEATURE_REQUIRED`) and fail-closed
  freeze (403 `WORKSPACE_FROZEN`) for CertOps cloud routes; register overrides
  (`saaSOnly`).
- AC (T12): frozen workspace -> 403; free plan over CertOps gate -> 402.

### CERTOPS-M2-8 Dedicated machine-token / agent rate limiter [B]
- dep: M2-2, cloud overlay verification.
- Add a limiter keyed by token prefix / agent id / workspace id (clone the shape
  of `createApiLimiter`), mounted before the executor and agent handlers,
  independent of the session-user baseline limiter. Cloud's authenticated `/api`
  limiter is keyed by `user-${id}`, which machine (token/agent) calls do not
  have, so without this they ride the authenticated-user path unbounded.
- AC (T10/abuse): executor and agent traffic is limited per token/agent/workspace,
  not per user; high-volume machine traffic cannot bypass limits via the
  session-user keying. Limiter is enforced even when no session user is present.

## Dependency order (critical path)

M1-1 -> M1-2 -> M1-3 -> {M1-4, M1-5}; M1-6 parallel.
M2-1 -> M2-2 -> M2-3 -> M2-4; M2-5 -> M2-6; M2-7 after M1-3; M2-8 after M2-2.

## Parallelization

- Dev A owns the data/contract spine: M1-1, M1-3, M1-5, M2-1, M2-3.
- Dev B owns the safety boundary and overlays: M1-2, M1-4, M1-6, M2-2, M2-5,
  M2-6, M2-7, M2-8. M2-4 either.
- Overlap is minimized: A defines tables/signing; B owns rejection/auth/redaction
  and cloud gating. Shared touch points (`secretMaterial.js`, contracts) are
  frozen in Phase 0.
