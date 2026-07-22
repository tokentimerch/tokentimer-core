# CertOps inventory/executor issue map (P0.6)

Status: ready-for-human (draft; second reviewer to edit owners/estimates)
Drafted: 2026-06-25.

Scope: certificate inventory and the jobs/tokens/executor surface. Tracer-bullet
vertical slices: each ticket is independently grabbable and lands a thin
end-to-end slice. Threat ids (T#) reference
docs/adr/0005-certops-threat-model.md. Routes and schemas reference the Phase 0
contract freeze.

Legend: [data]=data/contract spine owner, [safety]=safety-boundary/overlays
owner, dep=depends on.

## Inventory (public material only)

### CERTOPS-INV-1 Migration: CertOps inventory tables [data]
- dep: none (core migrate.js highest version is 9; use 10+).
- Add `managed_certificates` (+ supporting columns) per `certops-inventory.schema.json`.
- AC: idempotent `CREATE TABLE IF NOT EXISTS`; migration runs clean twice; no
  column intended to hold key material.

### CERTOPS-INV-2 Private-key rejection middleware [safety]
- dep: secretMaterial.js (done in Phase 0).
- Express middleware that scans request bodies via `containsPrivateKeyMaterial`
  and returns 422 `PRIVATE_KEY_MATERIAL_REJECTED`; mount on certops write routes.
- AC (T1): nested/base64-wrapped private key in any field -> 422; certificate /
  public key passes. Integration test added.
- AC (T1, detector hardening): extend `secretMaterial.js` with binary PKCS#12/PFX
  (.p12/.pfx) DER sniffing (deferred from Phase 0) plus adversarial fixtures;
  PKCS#12/PFX bundles are forbidden, so a `.p12` body must be rejected (422).

### CERTOPS-INV-3 GET/POST certificates + GET by id [data]
- dep: INV-1, INV-2.
- Implement `/api/v1/workspaces/{id}/certops/certificates` (GET, POST) and
  `/certificates/{certId}` (GET). Public material only; parse PEM via
  `X509Certificate` (reuse vaultIntegration helpers) for metadata.
- AC: returns inventory matching schema; POST persists; conformance test asserts
  routes documented in OpenAPI.

### CERTOPS-INV-4 Import endpoint [safety]
- dep: INV-2, INV-3.
- Implement `/api/v1/workspaces/{id}/certops/imports` (POST). Accept PEM public
  material, dedupe, link to `tokens` where applicable.
- AC (T1): import body with key material -> 422; valid cert chain imported.

### CERTOPS-INV-5 Dashboard inventory view [data]
- dep: INV-3.
- Read-only inventory list + detail in dashboard (core `apps/dashboard`; cloud
  overlays in `apps/web`).
- AC: lists managed certs; never renders key fields (none exist).

### CERTOPS-INV-6 Logger/evidence redaction guard test [safety]
- dep: secretMaterial.js.
- AC (T2/T3): log + evidence paths render placeholder, never key material.

## Jobs, tokens, executor

### CERTOPS-EXEC-1 Scoped API token system [data]
- dep: INV-1.
- `api_tokens` table; issue/list/revoke scoped tokens; HMAC-protected storage;
  plaintext returned once. Routes `/certops/tokens` (GET, POST).
- AC (T10): token scoped to workspace A cannot act on workspace B; secrets never
  returned after creation.

### CERTOPS-EXEC-2 certOpsTokenAuth middleware [safety]
- dep: EXEC-1.
- Bearer auth for `/api/v1/certops/executor/*` and `/agent/*`; constant-time
  compare (mirror `internal-worker-auth.js`); CSRF-exempt these paths.
- AC: invalid/expired token -> 401; valid scoped token authorizes only its scope.

### CERTOPS-EXEC-3 Job model + signing [data]
- dep: EXEC-1, ADR-0003.
- `certificate_jobs` table; Ed25519 signing of job payloads per
  `job-payload.schema.json`; `signingKeyId` lifecycle.
- AC (T4): unsigned/HMAC/invalid-signature job rejected by verifier; signed job
  verifies against pinned public key.

### CERTOPS-EXEC-4 Job list endpoint [safety]
- dep: EXEC-3.
- `/api/v1/workspaces/{id}/certops/jobs` (GET).
- AC: lists workspace jobs with state; documented in OpenAPI.

### CERTOPS-EXEC-5 Executor events endpoint [data]
- dep: EXEC-2, INV-2.
- `/api/v1/certops/executor/events` (POST). Accept progress + evidence metadata;
  scrub via `redactGenericSecrets`; reject key material 422.
- AC (T3/T5): evidence stored without secrets; replayed event (nonce/jobId)
  rejected.

### CERTOPS-EXEC-6 Replay protection [safety]
- dep: EXEC-3, EXEC-5.
- Nonce + jobId replay cache; expiry-window enforcement.
- AC (T5/T6): duplicate nonce rejected; out-of-window job rejected.

### CERTOPS-EXEC-7 Cloud plan gating for CertOps [safety]
- dep: INV-3, cloud overlay verification.
- Mirror `requireDomainCheckerPlan` (402 `PLAN_FEATURE_REQUIRED`) and fail-closed
  freeze (403 `WORKSPACE_FROZEN`) for CertOps cloud routes; register overrides
  (`saaSOnly`).
- AC (T12): frozen workspace -> 403; free plan over CertOps gate -> 402.

### CERTOPS-EXEC-8 Dedicated machine-token / agent rate limiter [safety]
- dep: EXEC-2, cloud overlay verification.
- Add a limiter keyed by token prefix / agent id / workspace id (clone the shape
  of `createApiLimiter`), mounted before the executor and agent handlers,
  independent of the session-user baseline limiter. Cloud's authenticated `/api`
  limiter is keyed by `user-${id}`, which machine (token/agent) calls do not
  have, so without this they ride the authenticated-user path unbounded.
- AC (T10/abuse): executor and agent traffic is limited per token/agent/workspace,
  not per user; high-volume machine traffic cannot bypass limits via the
  session-user keying. Limiter is enforced even when no session user is present.

## Dependency order (critical path)

INV-1 -> INV-2 -> INV-3 -> {INV-4, INV-5}; INV-6 parallel.
EXEC-1 -> EXEC-2 -> EXEC-3 -> EXEC-4; EXEC-5 -> EXEC-6; EXEC-7 after INV-3;
EXEC-8 after EXEC-2.

## Parallelization

- The data/contract owner has the spine: INV-1, INV-3, INV-5, EXEC-1, EXEC-3.
- The safety-boundary owner has the boundary and overlays: INV-2, INV-4, INV-6,
  EXEC-2, EXEC-5, EXEC-6, EXEC-7, EXEC-8. EXEC-4 either.
- Overlap is minimized: one owner defines tables/signing; the other owns
  rejection/auth/redaction and cloud gating. Shared touch points
  (`secretMaterial.js`, contracts) are frozen in Phase 0.
