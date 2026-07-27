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
  keypair/CSR generation, ACME issuance via external certbot/acme.sh command
  adapters (no embedded ACME client; native DNS-01 TXT solvers are invoked
  through `certops-dns-hook`), atomic deploy/rollback, and service reload.
  Its keys, DNS provider credentials, and ACME account material (owned by
  the external ACME tool on the host) never leave the
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
- **Renewal profile snapshot** - the immutable renewal configuration frozen
  into a `renew` job's payload at creation time. Optional when a job is
  created manually or via bulk renew, but **required and fully validated at
  approval time** (`validateRenewalProfileOnPayload(..., { required: true })`
  in `jobApprovals.js`), so approving a thin payload fails with
  `400 CERTOPS_RENEWAL_PROFILE_INCOMPLETE` and the job stays at
  `pending_approval`. The gate exists so what an approver signs off on is
  bound by hash to what actually runs, rather than being re-resolved from a
  mutable profile row at dispatch. Scheduler-created renewals always carry a
  complete snapshot, resolved from the certificate's linked
  `certificate_profiles` row; for certificates TokenTimer issued, that row is a
  **derived renewal profile** (below).
- **Issue operation and `provisioning` status** - `issue` is the job operation
  that requests a brand-new certificate when no `managed_certificate` row
  exists yet, unlike `renew`/`deploy`/`reload`/`revoke`/`noop`, which all
  assume the certificate identity already exists. The caller sends no
  `subjectType`/`subjectId` and no `payload.certificateId`, and
  `idempotencyKey` is required: idempotency is what makes a retry safe and
  keeps a duplicate certificate row from being created. The API creates the
  row upfront in the same transaction with `status = 'provisioning'`,
  `source = 'agent_issuance'`, `source_ref = <idempotencyKey>`, and
  `key_mode = 'agent-local'`, then injects the new id as the job's
  `subject_id` and `payload.certificateId`. Execution fields are exactly the
  `renew` set (`commandRef`, `caEndpoint`, `acmeKind`, `keyRotation`,
  `certPath`, `reloadService`, `verifyHost`, `verifyPort`, `dnsZone`,
  `dnsProvider`); a renewal profile snapshot is not valid on an `issue` job.
  `issue` is control-plane-only: at dispatch it is translated to
  `action: "renew"` in the signed payload, so the agent-facing action enum is
  unchanged and no `schemaVersion` bump was needed. Agents do, however, have to
  declare the `evidence-claim-binding-v1` capability to be offered `issue` work
  (see **Evidence claim binding** below). On a successful terminal result the
  control plane reconciles a still-`provisioning` subject to `active`,
  backfilling fingerprint, validity dates, serial, subject, and SANs from that
  job's claim-bound `verify`-step evidence, and derives the certificate's
  renewal profile in the same transaction. The trigger is the subject still
  being `provisioning`, not the operation, so a retry via a plain `renew`
  against the now-known `subjectId` reconciles identically. A failed issuance
  does **not** raise a `cert_renewal_failed` alert (see **Renewal alert
  policy**) and leaves the row `provisioning` for an operator to retry or
  retire; there is no auto-cleanup. `provisioning` is non-terminal: the row can
  be retired to `revoked`/`decommissioned` like any other and counts as active
  for quota purposes.
- **Evidence claim binding** - `certificate_evidence` rows carry the `claim_id`
  of the attempt that produced them plus the server's own `attempt_count`
  (migration 36). The value comes from the job row after ownership is proven,
  never from the agent, and an agent-supplied `claimId` that disagrees with the
  job's current claim is rejected. Reconciliation needs it because a job can be
  attempted more than once and evidence outlives the attempt that produced it,
  so an unbound lookup could promote attempt 2 using attempt 1's fingerprint.
  Agents that can send it declare the capability `evidence-claim-binding-v1`,
  and the claim query offers `issue` jobs, plus `renew` jobs whose subject is
  still `provisioning`, only to those agents. An agent without it keeps claiming
  ordinary renewals of `active` certificates unchanged. See ADR-0002 and
  ADR-0008 A1.2.
- **Reconciliation reason** - `managed_certificates.reconciliation_reason`, why a
  `provisioning` certificate was **not** promoted. Promotion requires evidence
  whose `metadata.step` is `verify`, bound to the job's current claim, carrying
  both a fingerprint and a parseable expiry. Expiry is mandatory because a
  certificate without one cannot be scheduled for renewal or alerted on, so
  activating without it produces a row that looks healthy and is silently
  unmanaged. Values: `no_claim_bound_verify_evidence`,
  `verify_evidence_missing_fingerprint`, `verify_evidence_missing_expiry`.
  Cleared on successful promotion. Distinct from
  `certificate_jobs.reconciliation_reason`, which explains why a **job** needs
  operator reconciliation. See ADR-0008 A1.3.
- **Derived renewal profile** - the `certificate_profiles` row created from an
  `issue` job's payload and the verified certificate at reconciliation, linked
  via `managed_certificates.profile_id`
  (`apps/api/services/certops/renewalProfileDerivation.js`). It exists because
  the renewal scheduler refuses any certificate without a complete profile, and
  nothing else ever wrote one, so nothing TokenTimer issued could auto-renew.
  Named `Derived: <common name>`, `source = 'api'`,
  `source_ref = 'certops-issuance:<certificateId>'`. Required payload fields are
  `caEndpoint`, `commandRef`, `dnsProvider`, `dnsZone`, and `certPath`; a missing
  one fails the derivation by name rather than defaulting. SANs are pinned to
  what the CA issued (`sanPolicy.mode = 'exact'`), not what the job requested.
  Derivation never fails the issuance: it returns no profile, logs
  `certops-renewal-profile-derivation-failed`, and the certificate is still
  promoted. An operator-authored profile already linked to the certificate is
  never overwritten. See ADR-0010.
- **Auto-renewal switch** - `certificate_profiles.status` read as "is automatic
  renewal on for the certificates using this profile"
  (`AUTO_RENEW_DISABLED_PROFILE_STATUSES` in
  `apps/api/services/certops/renewalScheduler.js`, `{disabled, archived}`). The
  scheduler excludes those profiles and counts them as
  `skippedAutoRenewDisabled`; the certificates API reports the certificate's
  renewal state as `disabled`. It lives on the profile, not on
  `managed_certificates`, because derivation already produces one profile per
  issued certificate, so the profile *is* the per-certificate control and a
  second flag would be a second source of truth. `disabled` is settable through
  the API; `archived` is not. See ADR-0010 A1.1.
- **Safe-subset profile edit** - the deliberately narrow write surface on a
  renewal profile (`apps/api/services/certops/renewalProfileAdmin.js`,
  `PATCH /certops/profiles/:profileId`, permission
  `certops.renewal_profile.manage`). `EDITABLE_PROFILE_FIELDS` is the set that
  cannot change what executes on a host; `IMMUTABLE_PROFILE_FIELDS` (`acme`,
  `ca`, `dns`, `target`, `deploymentTargets`, `schemaVersion`, `profileId`) is
  refused with `CERTOPS_PROFILE_FIELD_IMMUTABLE` naming the offending fields.
  Those values are trustworthy because a real ACME order proved them against a
  real host, so changing them is a re-issuance rather than a settings change.
  There is no create and no delete: a profile exists because an issuance produced
  it. Every write revalidates through `validateRenewalProfile`, the same gate the
  scheduler admits on. See ADR-0010 A1.2 and A1.3.
- **Renewal alert policy** - the single source of truth for whether a terminal
  job transition notifies anyone
  (`apps/api/services/certops/renewalAlertPolicy.js`, imported by both
  `agentDispatch.js` and `renewalFailureAlerts.js` so the two cannot disagree).
  `RENEWAL_ALERTING_OPERATIONS` is `{renew}`: a failed `issue` deliberately does
  not alert, because there is no existing certificate at risk of expiring and no
  linked token to route contacts through. Classification is by
  `(operation, status, origin)`, where origin is what caused the transition
  (`agent_result`, `approval_rejection`, `operator_cancel`, `lease_reaper`,
  `stale_agent`, `forced_retirement`) rather than how the job was created:
  agent-reported refusals and human approval rejections share the statuses
  `rejected`/`blocked`, and only the former is actionable. Dry runs never alert.
  `orphaned_unknown_effect` always alerts at high priority. Every decision
  records a reason, skips included. See ADR-0009.
- **CertOps outbox** - `certops_outbox` (migration 35), the transactional outbox
  for side effects that must survive the transaction that decided them. The
  deciding transaction records the intent as a plain local INSERT with no
  savepoint, so a terminal job transition and its alert intent commit together
  or not at all; if the enqueue fails, the transition fails. Delivery moves to
  the `outbox-drain` sweep, which claims due rows under an owner-scoped lease and
  retries with backoff. Idempotent on
  `(workspace_id, event_type, dedupe_key)`. Payloads are allowlisted per event
  type and carry ids and frozen codes only. A structural skip (no linked token,
  no deliverable channel) goes terminal with its reason preserved; a thrown error
  retries until `max_attempts` then parks as `failed`; an event type with no
  handler defers rather than being consumed. Renewal alerting depends on this
  sweep running. See ADR-0009.
- **Per-CA cap** - limit on in-flight renewal jobs per `caEndpoint`
  (`CERTOPS_RENEWAL_PER_CA_CAP`, default 5) so one CA cannot be flooded.
  Enforced on **every** renewal creation path, not just the sweep: the
  scheduler skips over-cap certificates and reports them in the sweep
  summary (picked up by later sweeps), while manual and bulk creation
  reserve against the same per-workspace/per-CA counter inside the creating
  transaction and fail with `409 CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED`.
- **Agent-deployable key custody** - only `key_mode` `agent-local` or
  `proxy-agent-local` can carry an agent-executed
  `issue`/`renew`/`deploy`/`reload`/`revoke` job. A certificate that was
  merely *observed* (endpoint/domain monitor, `key_mode` NULL) has no agent
  holding its key, so creating such a
  job fails at creation time with `409
  CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE` rather than dispatching to an
  agent that must fail. See `AGENT_DEPLOYABLE_KEY_MODES` in
  `apps/api/services/certops/jobs.js`.
- **`key_reference` is a locality pointer, not a key path** - it answers "which
  host or cluster holds this key", not "open this file to find the key". Every
  writer follows the same convention: `agent-local` sources (both
  `agent_filesystem` discovery and `agent_issuance`) record
  `file://<certificate path>`, and `cert_manager` records the Secret's `tls.key`
  coordinate. The certificate path is used for agent sources because it is the
  only coordinate the control plane can honestly know: it never sees the key, so
  a stored key path would be an unverifiable assertion that readers would then
  treat as authoritative. Discovery genuinely cannot learn a key path from
  scanning a certificate, so a "key path" semantic was never achievable for that
  source and is deliberately not faked for the others. See ADR-0008 (custody
  implication) and ADR-0001.
- **Job assignment** - distinct from claim exclusivity. Claiming is
  transactional (`FOR UPDATE SKIP LOCKED`), so two agents never take the
  same job; but a job with neither `assignedAgentId` nor
  `requiredTargetSelector` is claimable by *any* online agent declaring the
  operation, including one unrelated to the certificate. For
  `agent_filesystem`-sourced certificates, `assignedAgentId` therefore
  defaults to the discovering agent at creation time
  (`resolveManagedCertificateJobDefaults`), pinning host-specific work to
  the host that actually holds the files. An explicit `assignedAgentId`
  always wins.
- **Bulk renew** - `POST .../certops/jobs/bulk-renew`: many certificates
  through the same creation path as single renew (validation, approval
  gates, kill switch identical) with a per-item partial-failure envelope.
  Items without an explicit `idempotencyKey` derive a stable one
  (`bulk-renew:auto:<certificateId>`), which is permanent: re-running after
  cancelling the created jobs returns the original terminal jobs instead of
  creating new ones. Pass a fresh key to force a genuine re-run.

## Dashboard certificate visibility

Certificate inventory stays on existing token surfaces; CertOps enriches them
rather than adding a parallel inventory page. See ADR-0006.

- **Tokens list / Control Center** - cert rows show key locality, managed status,
  and retired filtering when CertOps is enabled.
- **Token detail** - CertOps panel for managed fields and deployment history.
- **Import tokens** - public PEM import card when `certops.enabled` is on.
- **CertOps section** - orchestration only (agents, jobs, evidence,
  approvals, kill switch), not a second certificate list. It ships
  `/certops/operations` (the workspace kill switch toggle at the top; the
  executor jobs panel with a manager-only "Create manual job" dialog,
  including a "require approval" checkbox, and inline Approve/Reject
  actions on jobs sitting at `pending_approval`; evidence timelines; machine
  API tokens; the Deploy-an-agent panel with the show-once bootstrap token
  and install command; and the Agent fleet panel with status/heartbeat/retire)
  mounted via the `/certops/*` splat route. No nav entry: it is
  reached from the Control Center certificate-operations panel footer link
  and from a Workspace Preferences entry (last section, shown only when
  `certops.enabled` is on).

## Certificate removal

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
- **Agent filesystem discovery is the one bridge-adjacent exception to
  "Token first"**: an agent host has no pre-existing monitor/token setup step
  the way an endpoint/domain monitor does, so `agentObservations.js` mints or
  reuses an `ssl_cert` token the same way manual PEM import does (by
  fingerprint, then by certificate shape) instead of skipping the write when
  unlinked. Identity still keys by the stable `(source, source_ref)` pair
  (`agentId/targetHost/filePath`), not fingerprint, so a rotation at the same
  file path reuses the same `managed_certificate` row and its already-linked
  token instead of minting a new token per rotation.

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
- ADRs: `docs/adr/` (CertOps ADRs 0001-0011 today; see `docs/adr/README.md` for
  the index and which records carry amendments).
- API: `apps/api/` (core), `apps/saas/` (cloud), `src/api/` (enterprise).
- Contracts: `packages/contracts/` (registered in `contracts.manifest.json`).
