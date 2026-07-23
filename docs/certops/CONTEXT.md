# CertOps domain context

Program-scoped domain language for the CertOps feature track. This file lives
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
inventory boundary paths. A broader logger content-scrub layer for arbitrary log
message content is a follow-up, not something the inventory assumes globally.

The one private key the platform does hold is the platform operational signing
key (Ed25519) used to sign jobs. It is never used for certificate issuance and
never holds customer key material. See ADR-0003.

## Control plane vs execution plane

- **Control plane** - Core/Cloud/Enterprise backend and dashboard. Observes,
  plans, signs jobs, records evidence. Holds no private keys.
- **Execution plane** - the TokenTimer **agent** (`packages/agent`) and the customer-side
  Kubernetes controller. The agent performs the key-bearing work locally:
  keypair/CSR generation, ACME issuance (native HTTP-01/DNS-01 solvers plus
  certbot/acme.sh exec adapters), atomic deploy/rollback, and service reload.
  Its keys, DNS provider credentials, and ACME account keys never leave the
  agent host. The cert-manager controller never handles a key: it asks cert-manager to reconcile a
  `Certificate`, and cert-manager generates and retains the key in Kubernetes.

Execution-plane components are **outbound-only**: they call the control plane.
The control plane never opens connections to an agent or customer Kubernetes
API, and TokenTimer does not accept uploaded kubeconfigs.

## cert-manager controller boundary

The controller uses two additive controller-specific machine transports, not
the agent protocol:

- `POST /api/v1/certops/executor/observations` for passive public observation;
- `POST /api/v1/certops/executor/provisioning-commands/next` for the narrow,
  cluster-bound cert-manager provisioning command.

The provisioning controller reports its job lifecycle through the existing
executor event/evidence routes. It does not register an agent, claim a general
job, heartbeat, receive a signed command, or use agent attempts, leases, nonces,
or replay windows.

| From | To | Direction and data |
|---|---|---|
| Controller | TokenTimer API/control plane | Outbound-only public observations, narrow commands, events, evidence |
| Controller | Kubernetes API | Outbound list/watch of Certificate/CertificateRequest; optional `tls.crt` Secret get; owned Certificate create/patch |
| cert-manager | Kubernetes API | In-cluster issuance/renewal and TLS Secret management |
| TokenTimer control plane | Kubernetes API | None |

The controller is disabled by default and defaults to `observe`. `provision`
is explicit and additive. Observe RBAC is read-only; provision adds only
Certificate `create`/`patch`. Neither mode writes Secrets or
CertificateRequests or deletes Kubernetes resources. Status is preferred over
the optional `tls.crt` fallback. Because Kubernetes RBAC cannot restrict a
Secret read to one data key, a bounded streaming reader captures only the
public certificate value without object-deserializing other data members, while
the shared detector scans every outbound envelope.

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
- **Sequence** - optional per-agent monotonic message counter stamped on
  protocol envelopes and enforced server-side (compare-and-swap on
  `certops_agents.last_sequence`, 409 on regression, generation reset on
  re-register). Defense in depth over the nonce replay cache.
- **Per-CA cap** - sweep-time limit on in-flight renewal jobs per
  `caEndpoint` (`CERTOPS_RENEWAL_PER_CA_CAP`) so the scheduler cannot flood
  one CA; skipped certificates are reported in the sweep summary and picked
  up by later sweeps.
- **Bulk renew** - `POST .../certops/jobs/bulk-renew`: many certificates
  through the same creation path as single renew (validation, approval
  gates, kill switch identical) with a per-item partial-failure envelope.

## Dashboard certificate visibility (D6)

Certificate inventory stays on existing token surfaces; CertOps enriches them
rather than adding a parallel inventory page. See ADR-0006.

- **Tokens list / Control Center** - cert rows show key locality, managed status,
  and retired filtering when CertOps is enabled.
- **Token detail** - CertOps panel for managed fields and deployment history.
- **Import tokens** - public PEM import card when `certops.enabled` is on.
- **CertOps section** - orchestration only (agents, jobs, evidence,
  approvals), not a second certificate list. It ships
  `/certops/operations` (executor jobs, evidence timelines, machine API
  tokens, the Deploy-an-agent panel with the show-once bootstrap token and
  install command, and the Agent fleet panel with status/heartbeat/retire)
  mounted via the `/certops/*` splat route. No nav entry: it is
  reached from the Control Center certificate-operations panel footer link
  and from a Workspace Preferences entry (last section, shown only when
  `certops.enabled` is on).

## Certificate removal (D7)

Removing a tracked certificate is retire-first, not row delete. See ADR-0007.

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
routes and UI are hidden, so feature code can ship dark, Cloud can run staged
per-workspace previews, and Enterprise enables it deliberately. Edition, plan,
and license gating apply on top once the flag is on.

The explicit exception is the workspace kill-switch settings surface:
`GET` and `PUT /api/v1/workspaces/:id/certops/settings` remain available while
the global rollout is disabled, so incident controls can be inspected and
staged. The stored workspace pause state is independent of the global flag;
effective operational activity remains
`certOpsActive = certOpsEnabled && !certOpsPaused`.
The settings surface is human session-only: internal worker bearer credentials
cannot read, pause, or resume a workspace. Private-key material remains
rejected before the session-user and role checks on its body-bearing `PUT`.

For the controller, pause blocks new provision intent and command delivery but deliberately
does not block passive controller observations or the established executor
event/evidence ingestion. It does not delete queued/running work. The global
rollout flag remains a separate deployment-wide gate.

Manual-job idempotency stores a SHA-256 fingerprint of normalized original
creation inputs. Lifecycle transitions never change it, so an exact original
replay returns the current job state without a second creation audit. Rows
created before the fingerprint migration retain a null hash and use only the
historic immutable-subset comparison; they are never backfilled from mutable
lifecycle state.

Core is dark-launched and env-gated: `CERTOPS_ENABLED` is the authoritative
Core rollout control today. The optional
`system_settings.certops_settings.enabled` read path is forward-compatible only;
the JSONB column and admin settings persistence are deferred. The resolver must
continue to fall back safely when that column is absent.

## Monitor bridge and instance history

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
The bridge does not add a historical backfill job or admin UI; existing monitor recheck
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
