# ADR-0008: CertOps upfront issuance and provisioning lifecycle

## Status

Accepted (2026-07-26). Design decision D8.

## Context

CertOps job operations are `renew`, `deploy`, `reload`, `revoke`, and `noop`.
Every one of them assumes the certificate identity already exists: the job
carries `subjectType`/`subjectId` pointing at a `managed_certificate`, or
`payload.certificateId`, and inventory, evidence, and alerting all hang off that
row.

There is no operation for "get me a certificate I do not have yet". An operator
can already approximate one by submitting a bare `renew` job with no
`subjectId` and an ACME payload. That job executes correctly: the agent runs the
ACME order, writes the key and chain to `certPath`, deploys, reloads, and
verifies. But nothing in inventory ever references the result. There is no
`managed_certificates` row, so the new certificate is invisible on the
dashboard, has no expiry tracking, no renewal cadence, no linked token, and no
evidence trail an operator can find. The certificate exists on the host and
nowhere in the product. That silent success is the defect this ADR closes.

The gap cannot be closed after the fact from the job result alone. Creating the
inventory row on completion would mean a successful job with an unreachable
subject in the window between dispatch and result, no dashboard trace while
issuance is in flight, and no row at all when issuance fails - exactly the case
where an operator most needs to see what happened.

## Decision

1. **New control-plane operation `issue`.** The existing route
   `POST /api/v1/workspaces/:id/certops/jobs` accepts `operation: "issue"` with
   no `subjectType`/`subjectId`, no `payload.certificateId`, and a **required**
   `idempotencyKey`. Supplying a subject or a `certificateId` is a validation
   error: `issue` exists precisely for the case where neither is known.
2. **Inventory row created upfront, in the same transaction as the job.** Job
   creation inserts the `managed_certificates` row first:
   - `status = 'provisioning'`
   - `source = 'agent_issuance'`, `source_ref = <idempotencyKey>`
   - `name` and `common_name` from `payload.target.reference`
   - `subject_alt_names` from `payload.sans`
   - `key_mode = 'agent-local'`, `key_reference = 'file://<certPath>'`

   The job is then created with `subject_type = 'managed_certificate'`,
   `subject_id = <new cert id>`, and `payload.certificateId` injected as the new
   certificate id. From the moment the request returns, the certificate is a
   normal dashboard-visible asset with a job attached to it.
3. **`idempotencyKey` is mandatory because the operation has a side effect
   beyond the job.** Retrying a create is common (client timeout, proxy retry,
   operator double-click). An idempotent replay returns the existing job and
   creates zero additional `managed_certificates` rows. Without the key, retries
   would silently multiply provisioning rows for one certificate.
4. **Execution fields match `renew`.** Allowed: `commandRef`, `caEndpoint`,
   `acmeKind`, `keyRotation`, `certPath`, `reloadService`, `verifyHost`,
   `verifyPort`, `dnsZone`, `dnsProvider`. A `renewalProfile` snapshot is **not**
   allowed on an `issue` job: there is no renewal cadence to snapshot for a
   certificate that does not exist yet. Renewal configuration is set on the row
   after it becomes `active`.
5. **`issue` never reaches the agent (wire-protocol decision).** The
   agent-facing payload contract
   `packages/contracts/certops/job-payload.schema.json` keeps its `action` enum
   as `renew`/`deploy`/`reload`/`revoke`/`noop`. At dispatch the control plane
   translates `operation: "issue"` into `action: "renew"` in the signed payload.
   Agent-side execution is byte-identical to a renew: same ACME order, same
   deploy, same reload, same verification, same agent-local policy and command
   profile evaluation (ADR-0002). Consequently there is no agent protocol schema
   change, no `schemaVersion` bump, and agents already deployed in the field
   accept `issue` jobs with no upgrade. The `operation` vs `action` asymmetry is
   deliberate: `issue` is a control-plane intent about inventory state, not a new
   thing for an agent to do. It must not be "fixed" later by someone who notices
   the mismatch.
6. **Reconciliation is keyed on subject status, not on operation.** On a
   successful terminal job result, if the job's subject `managed_certificate` is
   still `status = 'provisioning'`, the control plane promotes it to `active` and
   backfills `fingerprint_sha256`, `not_before`, `not_after`, `serial_number`,
   subject, and SANs from that job's `validation.passed` evidence, inside the
   same transaction as the job status transition. The trigger deliberately
   ignores which operation produced the result. A manual retry after a failed
   issuance is a plain `renew` job pointed at the now-known `subjectId`, and it
   reconciles through the identical path with zero special-casing. Keying on the
   operation would have required an `issue`-shaped retry operation, or a second
   reconciliation branch, for no benefit.
7. **Failure leaves the row in place.** If issuance fails, the certificate stays
   `provisioning`, visible on the dashboard with its failed job and evidence
   attached. The operator either retries with a `renew` job against that
   `subjectId` or retires the row (ADR-0007). There is intentionally no
   auto-cleanup: an unexplained disappearing row is worse than a visible
   unfinished one, and the failed attempt is itself the audit record.
8. **Alerting is unchanged.** A failed `issue` job raises the same existing
   `cert_renewal_failed` alert as a failed `renew`, with the same contact-group
   resolution. No new alert type, no new routing configuration for operators.

### Schema implication

Migration v33 is additive:

- `'provisioning'` is added to the `managed_certificates` status CHECK
  constraint.
- `'agent_issuance'` is added to the source CHECK constraint.
- The partial unique indexes that enumerate sources are widened to include
  `agent_issuance`.

### Lifecycle implication

`provisioning` extends the lifecycle model in ADR-0007 with a pre-active status.
It is non-terminal and behaves like every other non-terminal status:

- It can be retired to `revoked` or `decommissioned` through the existing retire
  route, with the same retire-first gating and token status mirroring.
- It counts as active for workspace quota, because active counting is
  `status NOT IN ('revoked', 'decommissioned')`. A provisioning row consumes a
  slot, which is correct: it represents a certificate the workspace is
  committing to.

### Custody implication

Zero private-key custody (ADR-0001) is unaffected. The CSR and the private key
are generated agent-side, exactly as for a renew; nothing about upfront row
creation moves key generation into the control plane. `key_reference` is an
opaque, non-secret pointer to where the agent placed the key on its own host. It
is never key material and remains subject to the ingest detector like any other
inventory field.

## Alternatives considered

- Add `issue` to the agent-facing `action` enum - rejected: a breaking protocol
  change requiring a fleet upgrade for zero behavioural gain. Agent execution
  for `issue` is identical to `renew` in every step; the only difference is what
  the control plane does with inventory before dispatch and after the result.
- Keep the bare `renew` with no subject and rely on the agent's periodic
  filesystem discovery scan to surface the new certificate - rejected: there is
  no linkage between the job and the discovered row, so evidence and the
  operator's request never connect; the delay until the next scan is arbitrary;
  and it only works when the deploy path happens to fall inside a configured
  scan root. Certificates deployed outside a scan root would stay invisible
  forever.
- Create the `managed_certificates` row on successful job completion instead of
  upfront - rejected: no dashboard visibility while issuance is in flight, a
  dispatched job whose subject does not exist, and no row at all on failure,
  which is the case that most needs a visible record.
- Reuse the existing `discovered` status instead of adding `provisioning` -
  rejected: `discovered` means "we observed this certificate on a host". It
  cannot express "we are actively creating this and it does not exist yet".
  Collapsing the two would make dashboard filtering, reconciliation triggers,
  and operator interpretation ambiguous.
- Overload `renew` with an optional "create subject if missing" flag - rejected:
  a mode flag that changes whether a request creates inventory is harder to
  reason about, to authorize, and to audit than a distinct operation name, and
  it would make `idempotencyKey` conditionally required on `renew`.

## Consequences

- Migration v33 must be applied before the `issue` route is enabled; the CHECK
  constraints reject `provisioning` and `agent_issuance` until then.
- Cloud and Enterprise must adopt the same migration and the same job-service
  change when they re-pin core. The reconciliation branch lives in the shared
  job status transition path, so overlays inherit it, but the migration is not
  optional for them.
- Agents require no change and no redeploy. Field fleets accept `issue` jobs
  immediately because they only ever see `action: "renew"`.
- Failed issuances accumulate `provisioning` rows until an operator retries or
  retires them. Dashboard surfaces should make `provisioning` visually distinct
  from `active` so a stalled issuance is obvious, and retire remains the exit
  path (ADR-0007).
- `provisioning` rows consume workspace certificate quota. A workspace that
  repeatedly fails issuance and never retires can exhaust its quota with
  certificates that were never issued; this is intended, and resolved by
  retiring.
- The `operation` (control plane) versus `action` (wire) distinction is now a
  real part of the model. Future operations may also be control-plane-only, and
  reviewers should not assume the two enums must converge.
