# Agent protocol and job contracts

Advanced reference for agent implementers and operators investigating dispatch. For onboarding, start with [Linux](install-linux.md) or [Windows](install-windows.md) installation.

<a id="3-protocol"></a>

## Protocol

The agent speaks the envelope defined in
`packages/contracts/certops/agent-protocol.schema.json` over four frozen
routes (`src/protocol/index.js` `ROUTES`), plus a plain (non-envelope) lease
renewal POST used during job execution:

| Message | Route |
|---------|-------|
| `register` | `POST /api/v1/certops/agent/register` |
| `heartbeat` | `POST /api/v1/certops/agent/heartbeat` |
| `claim` | `POST /api/v1/certops/agent/jobs/claim` |
| `result`, `evidence` | `POST /api/v1/certops/agent/jobs/results` |
| lease renew | `POST /api/v1/certops/agent/jobs/:jobId/lease` |
| `log` | `POST /api/v1/certops/agent/jobs/:jobId/logs` |

Result and evidence share one route; the envelope's `messageType`
disambiguates server-side. Every envelope carries `schemaVersion` (1),
`protocolVersion`, `messageType`, `agentId`, `sentAt`, and optionally
`workspaceId`, `clockOffsetMs`, and `sequence`. Messages must never carry
private key material (schema-level rule, enforced again by the evidence
builder).

<a id="protocol-validation-parity"></a>

### Protocol validation parity

Register, heartbeat, claim, result, and evidence envelope/body shapes are
validated by AJV compiled directly from the canonical
`packages/contracts/certops/agent-protocol.schema.json` on both sides: the
agent (`packages/agent/src/protocol/schemaValidation.js`, schema vendored
under `packages/agent/vendor/contracts/`) and the API
(`apps/api/services/certops/protocolSchemaValidation.js`). That eliminates
drift between hand-written validators. Semantic and authorization checks
(job `mode` vs result `status`, lease/nonce ownership, claim ownership,
sequence) remain in the service layer (`agentDispatch`), not in the AJV
compile.

Message sequence: the protocol client stamps every outbound envelope with
`sequence`, a per-agent monotonically increasing counter, and the control
plane rejects any message whose sequence does not exceed the last accepted
one for that agent (HTTP 409, code `CERTOPS_AGENT_SEQUENCE_REGRESSION`).
This is defense in depth on top of the single-use nonce replay ledger. The
counter is not persisted: a restart begins at 1 again, which is safe because
a successful `register` starts a new generation (the server resets its
high-water mark to the register envelope's sequence), so regressions are only
rejected within the current registered generation. Envelopes without
`sequence` remain accepted for backward compatibility with already-deployed
agents and never move the high-water mark.

Authentication: `register` uses the bootstrap token as a Bearer token;
everything else uses the stored `ttagent_...` credential as a Bearer token.
The credential is never placed in a request body and never logged
(`redactCredentialForLogging` returns a fixed placeholder unconditionally).

Flow:

- **register**: sends `bootstrapTokenId`, `agentVersion`, `hostname`,
  `platform`, `nodeVersion`, `declaredTargetSelectors`,
  `declaredCommandProfileNames`. Response returns `agentId`, `credential`,
  and optionally `signingKeyId` + `signingPublicKeyPem` for TOFU pinning.
- **heartbeat**: every `heartbeatIntervalMs`, sends `agentVersion`,
  `ntpSynced`, `uptimeSeconds`, `pinnedSigningKeyId`, `declaredCapabilities`
  (this build's fixed capability set, re-sent every heartbeat so
  an in-place binary upgrade can advertise a new one without re-enrollment;
  see `AGENT_DECLARED_CAPABILITIES`), and (on the envelope) `clockOffsetMs`.
  **Rollout order: the server must accept `declaredCapabilities` on
  `heartbeatBody` before any agent build that sends it is deployed.**
  `heartbeatBody` has `additionalProperties: false`, so an older server
  rejects a heartbeat carrying an unrecognized field with a 400 instead of
  ignoring it; upgrading agents ahead of the server turns every heartbeat
  from those agents into a hard failure until the server catches up.
  When execution enabled, `clockOffsetMs` is the clock
  estimator's current median and `pinnedSigningKeyId` is the pinned key id;
  in observe-only mode both stay null. `ntpSynced` is independent of
  execution mode: it comes from `src/ntp` running
  `timedatectl show -p NTPSynchronized --value` (systemd, matching the
  agent's only supported install target) fresh on every heartbeat tick, and
  is `true`/`false` when timedatectl gives a definite answer, or `null`
  when it cannot (missing binary, non-systemd host, timeout, nonzero exit,
  or unparseable output), never a guessed default. An HTTP 410 response
  means the control plane retired this agent: it exits cleanly, no
  respawn loop.
  **Capability freshness window:** `claim` does not dispatch a
  capability-gated job format (currently `signed-payload-b64-v1` -> v2
  signed envelope) off the mere fact that the agent once declared the
  capability. `certops_agents.capabilities_updated_at` is stamped on every
  heartbeat/register that includes `declaredCapabilities`, and dispatch
  only trusts a capability whose `capabilities_updated_at` is within
  `CERTOPS_CAPABILITY_FRESHNESS_MS` (default 600000ms / 10 minutes,
  matching `CERTOPS_AGENT_OFFLINE_AFTER_MS`'s existing liveness threshold
  rather than an independently chosen number) of "now". An agent that
  stops heartbeating for longer than that window is dispatched the legacy
  v1 envelope on its next successful claim, not v2, even though its
  `declaredCapabilities` row still lists `signed-payload-b64-v1` from
  before it went quiet; capability freshness and agent liveness
  (`livenessState`) are two separate signals on separate columns, but they
  share this one threshold value. This means an agent that heartbeats
  again after a gap longer than the freshness window is briefly dispatched
  v1 until that heartbeat lands, then v2 again from the next claim onward
  -- no special recovery step is needed, the agent's own next heartbeat
  is what restores it.
- **claim**: every `pollIntervalMs`, requests up to `maxJobs` (the main loop
  uses 1) and processes each returned job.
- **result/evidence**: terminal job outcome (`succeeded`, `failed`,
  `rejected`, `blocked`, `dry_run_complete`, `orphaned_unknown_effect`,
  plus `rejectionReason`, `keyRotated`, `errorMessage`, `clockOffsetMs`)
  and per-step evidence bodies. See "Dry-run and reconciliation statuses"
  below for mode gating on the two newer terminals.

<a id="execution-console-stream"></a>

### Execution console stream

The job's **Agent output** panel is fed by an optional, best-effort stream.
Job results and evidence stay authoritative: a lost, dropped or refused log
batch never changes a job outcome, and log storage failures never fail a
claim.

- **Negotiation.** The agent declares `job-log-stream-v1`. The claim
  response carries a top-level `logStreams` array, one `{ enabled,
  maxBatchBytes }` entry per job in `jobs`, outside the signed job, so job
  signatures and the job schema are unchanged. Agents that predate it ignore
  the field, and a server that omits it leaves streaming off. A stream is
  enabled only for a fresh capability (same freshness window as above) and
  when `CERTOPS_AGENT_LOG_RETENTION_DAYS` is not `0`.
- **Transport.** `log` envelopes post to the per-job route with the claim's
  `claimId`, `lines` (per-claim `seq` starting at 1) and an optional
  `final: true`. They carry no `sequence` and never share the control-channel
  queue, so a slow log endpoint cannot delay heartbeats, lease renewals or
  results. Bodies are capped at 64 KiB.
- **Acks.** `200` returns `{ ackThroughSeq, newlyStored, duplicateCount,
  serverDroppedCount, streamDisabled, retryAfterMs }`. A retried batch (same
  lines, same `final` flag) gets the stored ack of its first delivery;
  counters and the daily quota never move twice. Lines past the per-claim cap
  (5000 lines or 1 MiB) or the workspace quota (`CERTOPS_AGENT_LOG_DAILY_BYTES`)
  are acknowledged in `serverDroppedCount`, not stored. `streamDisabled: true`
  means stop sending for this claim.
- **Refusals.** `409 CERTOPS_AGENT_LOG_CLOSED` once the stream is final,
  abandoned or past its grace window; `409 CERTOPS_AGENT_LOG_CLAIM_INVALID`
  for an unknown claim or one owned by another agent; `422
  CERTOPS_AGENT_LOG_PRIVATE_MATERIAL` when a batch contains key material (the
  whole batch is refused and audited); `400 CERTOPS_AGENT_LOG_INVALID` for a
  non-contiguous `seq` run; `429 CERTOPS_AGENT_LOG_RATE_LIMITED` with
  `Retry-After`.
- **Agent sender.** Lines are buffered locally (1000 lines and 256 KiB per
  claim, 2 MiB per agent) and flushed every 50 lines or 1 second, at most 200
  lines per batch. It backs off on 408 and 5xx, honors `Retry-After` on 429
  and 503, splits on 413, stops the stream on 401, 403, 404, 409 and 410, and
  drops a batch on any other 4xx. Retries give up after 2 minutes, 60 seconds
  for the final flush. Closing a stream never blocks the claim loop.
  `TT_AGENT_LOG_STREAM=off` turns the stream off on one agent.
- **Lifecycle.** A claim that ends without a final batch (cancel, requeue,
  reaped lease) has its stream closed with a 5-minute grace window for late
  batches, then the maintenance worker marks it abandoned. The read API's
  `logsComplete` becomes true once the job is terminal and every stream is
  closed; clients should stop polling then.

Backoff and jitter: poll loops apply +/-20% jitter to every interval
(`jitteredDelay`) to avoid fleet thundering herd. `withRetry` provides
exponential backoff with full jitter (defaults: 5 attempts, 250 ms base,
30 s cap). A failed tick is logged and never kills the loop.

Clock offset estimation: every successful (2xx) response's HTTP `Date` header
is fed to the clock module (`onServerDate` ->
`createClockOffsetEstimator().estimateFromResponseDate`). Offset is
`serverTime - localTime`; positive means the local clock is behind the
server. The estimator keeps a rolling window of the last 5 samples and
reports the median, because the Date header has 1-second resolution and
individual samples are contaminated by network latency. This is a coarse
drift detector for the signed-job time window, not an NTP replacement.

<a id="which-agent-gets-a-job-exclusivity-vs-assignment"></a>

### Which agent gets a job: exclusivity vs assignment

Two independent mechanisms, routinely conflated, and both matter once a
workspace runs more than one agent.

**Claim exclusivity** is guaranteed by the claim transaction itself
(`FOR UPDATE SKIP LOCKED` in `claimJobs`, `apps/api/services/certops/agentDispatch.js`).
Simultaneous pollers each get different jobs; a claimed job carries a lease
and cannot be claimed again while that lease lives.

**Assignment** decides *which* agent is eligible in the first place, and
exclusivity says nothing about it. The claim matcher is
`assigned_agent_id IS NULL OR assigned_agent_id = $3::uuid`, so a job with
neither `assignedAgentId` nor `requiredTargetSelector` is claimable by **any**
online agent declaring support for the operation, including one with no
relationship to the certificate. Because certificate work is host-specific
(renewing `/etc/nginx/ssl/site.pem` only means anything on the host where
that file exists), `createCertificateJob` defaults `assignedAgentId` from the
certificate's discovering agent for `agent_filesystem`-sourced
`managed_certificates` rows
(`resolveManagedCertificateJobDefaults`, reading
`public_metadata.controllerObservation.agentId`). An explicit
`assignedAgentId` from the caller always wins, which is the supported
re-homing/hand-off path.

Consequences:

- A job pinned to an offline agent **waits at `pending`** rather than failing
  over to a healthy agent, since a different host is not a valid substitute.
  Check the fleet panel first when a job appears stuck.
- Jobs pinned to a retired/rebuilt host never run. Pass an explicit
  `assignedAgentId`, or let the replacement agent rediscover the certificate.
- A job pinned to a live, non-retired agent that cannot currently claim it
  (a version/protocol compatibility block, or a declared-capability mismatch)
  also stays unclaimed. The Certificates inventory shows this as
  `assigned_agent_ineligible` next to the renewal state, rather than the
  generic "no agent is currently associated with this certificate's renewal".
  When the agent declared other operations (for example issue and deploy)
  but not renew, the summary names those operations.
- Certificates with no agent key custody are rejected at creation instead
  (`409 CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE`, see
  `AGENT_DEPLOYABLE_KEY_MODES`), rather than being dispatched to an agent
  that must fail and surface a misleading `cert_renewal_failed` alert.
- Target selectors still apply on top of assignment: they are the coarse
  routing tool (role/environment), assignment is the exact one.

<a id="dry-run-and-reconciliation-statuses"></a>

### Dry-run and reconciliation statuses

Job `mode` is an immutable control-plane field on the claimed job. Result
ingestion (`ingestResult`) enforces:

| Status | Valid when | Control-plane effect |
|--------|------------|----------------------|
| `dry_run_complete` | job `mode` is `dry_run` only (real jobs reporting it are rejected) | Terminal success-equivalent for plan-only work; does **not** set `needs_operator_reconciliation` |
| `orphaned_unknown_effect` | real jobs only (dry-run jobs reporting it are rejected) | Sets `needs_operator_reconciliation=true` and a bounded `reconciliation_reason` (from the agent `errorMessage` markers, or the fallback `agent_reported_orphaned_unknown_effect`) |

`orphaned_unknown_effect` is an operational failure that requires manual
reconciliation, not a policy rejection (`rejectionReason` is not used for
this path). The agent embeds `needsOperatorReconciliation=true` and optional
`reconciliationReason=<slug>` in `errorMessage` when it self-reports
uncertainty (for example multi-target rollback uncertain, or an unresolved
local side-effect journal on restart).

The worker lease reaper also reaches `orphaned_unknown_effect` when a lease
expires after renewal (or while status is already `running`) in the
side-effect-risk window and the agent is no longer expected to report: it
sets `needs_operator_reconciliation` with reason
`lease_expired_after_side_effect_window_agent_unresponsive`. Never-renewed
`claimed` leases may still be requeued; renewed/`running` leases are never
silently requeued.

Dry-run jobs must never terminate as `succeeded`; the agent reports
`dry_run_complete` instead. Local `execution.dryRun: true` is a separate
safety refusal: it **blocks** a `mode:"real"` job outright and never
silently downgrades it to a successful plan-only report.

<a id="7-contract-status-and-forward-compatible-fields"></a>

## Contract status and forward-compatible fields

Earlier bootstrap builds documented a set of deviations against the base job
payload; the executable job-type contract has since landed
(`packages/contracts/certops/job-payload.schema.json` blesses `commandRef`,
`caEndpoint`, `acmeKind`, `keyRotation`, `certPath`, `reloadService`,
`verifyHost`/`verifyPort`, `certificatePem`, `dnsZone`/`dnsProvider`) and the
control plane now dispatches signed jobs, so most deviations are resolved.
Current behavior:

- Unsigned jobs never execute whenever execution is enabled; a payload without
  `signature`/`nonce`/`signingKeyId`/`issuedAt`/`expiresAt` fails signed-field
  validation, and that failure is terminal and silent (no result, lease
  expires). Signed dispatch is what the control plane's claim route produces.
- When `job.sans` is absent: the CSR CN and the ACME `-d` domain come
  from `job.target.reference`. When present, the full SAN list is used.
- `certPath` / `keyPath` / `chainPath` resolution: an explicit
  `job.certPath` (or per-target `certPath`) wins; otherwise
  `target.reference` is used as the deploy destination when it is an
  absolute path (POSIX or Windows form). `job.deploymentTargets` deploys to
  every listed destination with optional per-target `keyPath`, `chainPath`,
  modes, ownership, and backup settings (see [Execution](execution.md)). Neither a
  resolvable cert destination nor a usable target list means the job fails
  with a clear message. `keysDir` never substitutes for a missing
  production `keyPath`.
- `deploy` without `certificatePem` is `blocked`. The contract defines
  `certificatePem` as public leaf-plus-chain material attached by the
  control plane at signed dispatch time, never stored in the job payload
  column.
- `revoke` is always `blocked` (out of scope for this agent build).
- `attemptId` is assigned by the control plane at claim time (it mirrors the
  claim id and is covered by the job signature); the agent falls back to
  `job.claimId`, then a local `local-<jobId>-<timestamp>` id, only when the
  dispatch omits it. Result reports carry `claimId` and the dispatch `nonce`
  back so the control plane can re-prove claim ownership and consume the
  single-use nonce (ADR-0003).
- Execution fields honored when present: `keyRotation` (forces key
  regeneration), `verifyHost`/`verifyPort` (enables the live TLS probe),
  `reloadService` + `reloadCommandRefs` (enables the reload step), `acmeKind`
  (`certbot` or `acme.sh`), and `commandRef`/`caEndpoint`/`dnsZone`/
  `dnsProvider` on the policy descriptor.
- Ed25519 CSR generation is not supported: `generateCsr` throws a clear
  error for ed25519 keys (use `ec-p256` or `rsa-*` when a CSR is needed).

## Related

[Agent overview](../agent.md) · [Configuration](configuration.md) · [Operations](operations.md)
