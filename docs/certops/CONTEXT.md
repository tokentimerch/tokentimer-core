# CertOps domain context

Program-scoped domain language for the CertOps milestone track. This file lives
under `docs/certops/` so the whole CertOps doc bundle can be removed or folded
into core-wide docs when the program graduates. Decisions that shape the code
live in `docs/adr/`. When a term here and the code disagree, that is a bug in
one of them.

## Product invariant: zero private-key custody

TokenTimer control planes (Core, Cloud, Enterprise) never store, generate,
export, transmit, or process private key material. This is structural, not a
policy toggle. It is enforced in depth:

- field-name redaction in the logger (`apps/api/utils/logger.js`),
- content-based detection and rejection (`apps/api/utils/secretMaterial.js`),
- schema design (no inventory field is meant to hold key material),
- the API rejection boundary (HTTP 422 `PRIVATE_KEY_MATERIAL_REJECTED`).

Field-name redaction and explicit sanitized logging are wired for the current
M1 boundary paths. A broader logger content-scrub layer for arbitrary log
message content is a follow-up, not something M1 assumes globally.

The one private key the platform does hold is the platform operational signing
key (Ed25519) used to sign jobs. It is never used for certificate issuance and
never holds customer key material. See ADR-0003.

## Control plane vs execution plane

- **Control plane** - Core/Cloud/Enterprise backend and dashboard. Observes,
  plans, signs jobs, records evidence. Holds no private keys.
- **Execution plane** - the TokenTimer **agent** (and Kubernetes controller).
  Generates keys locally, builds CSRs, runs ACME, deploys, reloads. Holds keys
  on the host it runs on; TokenTimer never backs them up.

The agent is **outbound-only**: it polls the control plane. The control plane
never opens connections to agents.

## Ubiquitous language (CertOps)

- **Managed certificate** - a tracked certificate identity in a workspace.
  Inventory stores public material only (see
  `packages/contracts/certops/certops-inventory.schema.json`).
- **Certificate instance** - a deployed copy of a managed certificate on a
  target.
- **Target** - a place a certificate is deployed (host, path, k8s secret ref).
- **Agent** - the execution-plane process that performs key-bearing work.
- **Proxy-agent** - an agent acting on behalf of targets it can reach.
- **Job** - a signed unit of work dispatched to an agent. Carries replay
  protection (jobId, nonce, issuedAt/expiresAt). See
  `packages/contracts/certops/job-payload.schema.json` and ADR-0003.
- **Evidence** - structured, size-limited proof of what happened. Scrubbed of
  private keys and generic secrets before storage.
- **Agent-local policy** - allowlists (commands, paths, CA endpoints, DNS
  zones/providers) the agent enforces locally. Local policy wins over
  control-plane intent; rejections are reported as evidence. See ADR-0002.

## Dashboard certificate visibility (D6)

Certificate inventory stays on existing token surfaces; CertOps enriches them
rather than adding a parallel M1 inventory page. See ADR-0006.

- **Tokens list / Control Center** - cert rows show key locality, managed status,
  and retired filtering when CertOps is enabled.
- **Token detail** - CertOps panel for managed fields and deployment history.
- **Import tokens** - public PEM import card when `certops.enabled` is on.
- **CertOps section (M2+)** - orchestration only (agents, jobs, evidence,
  approvals), not a second certificate list.

## Certificate removal (D7)

Removing a tracked certificate is retire-first, not row delete. See ADR-0007 and
plan section 10.1.

- **Retire** - `POST .../certops/certificates/:certId/retire` with
  `revoked` or `decommissioned`; rows, instances, and evidence preserved;
  linked token lifecycle status mirrors the certificate.
- **Hard purge** - only for manually created cert tokens not backed by a
  `managed_certificate`; managed-backed certs route to Retire from the token
  surface.

## Rollout flag

CertOps ships behind a rollout switch that is separate from edition/plan/license
gating: `certops.enabled`, stored in a `certops_settings` JSONB column, with
`env > DB > default` precedence and **default false**. While false, CertOps
routes and UI are hidden, so milestone code can ship dark, Cloud can run staged
per-workspace previews, and Enterprise enables it deliberately. Edition, plan,
and license gating apply on top once the flag is on.

M1 Core is dark-launched and env-gated: `CERTOPS_ENABLED` is the authoritative
Core rollout control for M1. The optional
`system_settings.certops_settings.enabled` read path is forward-compatible only;
the JSONB column and admin settings persistence are deferred. The resolver must
continue to fall back safely when that column is absent.

## M1 monitor bridge and instance history

Endpoint and domain monitors are **observers**, not deployable endpoints
TokenTimer can write to. They watch a URL or hostname and record what public
certificate is currently served. TokenTimer does not push or patch certificates
to those endpoints; rotation is detected when the next observation shows
different public material at the same monitor.

`certificate_targets` is a broader **certificate location** abstraction: an
observation point or a deployment destination. Monitor-bridge-created target
rows are observation points (`target_type` endpoint/domain); they key instance
history by location and do not imply deploy capability. Future job
orchestration must not treat observation-only locations as deploy targets;
deployability is a future `target_type` / capability policy.

Bridge rules (worker rechecks and admin create paths share `monitorBridge.js`):

- **Token first**: bridge runs only when a linked `token_id` exists (including
  auto-created ssl_cert tokens). No orphan `managed_certificate` rows.
- **Monitor-stable identity**: observations upsert by `source` + `source_ref`
  (the monitor id), not fingerprint alone, so each monitor keeps exactly one
  `managed_certificate` row. A rotation at the same URL updates that one row in
  place (new fingerprint, serial, expiry). The linked token row is updated in the
  same worker pass for alerts.
- **Instance history by fingerprint**: `certificate_instances` are uniquely keyed
  by `(workspace_id, target_id, managed_certificate_id,
  observed_fingerprint_sha256)` (index
  `uq_certificate_instances_target_cert_fingerprint`). Re-observing the same
  fingerprint refreshes the existing instance row (last-seen); a new fingerprint
  at the same monitor appends a new instance row, so rotations accumulate as
  history under the one managed certificate.
- **PEM import** remains the path for certificates without an endpoint monitor
  (no URL to observe).

Recurring endpoint SSL checks call the bridge after updating the linked token.
M1 does not add a historical backfill job or admin UI; existing monitor recheck
flows use this path when `certops.enabled` is on.
- Certificate instance history is available at
  `GET /api/v1/workspaces/:id/certops/certificates/:certId/instances`. It is
  workspace-scoped, gated by `certops.enabled`, and returns public observation
  fields only, such as `observedAt`, `status`, `deploymentReference`,
  `observedSubject`, `observedIssuer`, `observedSerialNumber`,
  `observedFingerprintSha256`, and `source`. It must never expose private key
  material, evidence, or secret fields.

## Editions

- **Core** - source-available (BUSL-1.1), generous free base.
- **Cloud** - production SaaS overlay of core (`apps/saas`, `apps/web`).
- **Enterprise** - licensed overlay; restricted execution and connectors.

## Where things live

- Program docs: `docs/certops/` (this file; purgeable when CertOps graduates).
- ADRs: `docs/adr/` (CertOps ADRs 0001-0007 today).
- API: `apps/api/` (core), `apps/saas/` (cloud), `src/api/` (enterprise).
- Contracts: `packages/contracts/` (registered in `contracts.manifest.json`).
