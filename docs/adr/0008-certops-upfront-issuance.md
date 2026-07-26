# ADR-0008: CertOps upfront issuance and provisioning lifecycle

## Status

Accepted (2026-07-26). Design decision D9 in the CertOps plan's accepted
architecture choices table.

**Amended (2026-07-26, release 0.11.0).** Decision points 4, 5, 6, and 8 are
revised by [Amendment 1](#amendment-1-2026-07-26-issuance-hardening-and-renewal-enablement-0110)
at the end of this record. Read the amendment before relying on those four
points: two of them (agents need no upgrade, alerting unchanged) no longer hold.

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

   This puts a real constraint on the implementation, learned the hard way:
   the replay must resolve the *same* identity the first attempt assigned and
   present the job layer with the *same* derived request. The job layer decides
   replay-versus-conflict by hashing the creation request, so a replay path that
   reconstructs the request differently (omitting the server-assigned
   `subjectId` and `certificateId`, for example) hashes differently and gets
   reported as a conflicting reuse of the key, which is precisely the failure
   the mandatory key exists to prevent. Identity resolution therefore happens
   before the job table is touched, and both first attempt and replay go through
   one call site.
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

Two migrations, both additive, and the vocabulary lives in **two different
tables**. Migration v33 covers the certificate row:

- `'provisioning'` is added to the `managed_certificates` status CHECK
  constraint.
- `'agent_issuance'` is added to the source CHECK constraint.
- The partial unique indexes that enumerate sources are widened to include
  `agent_issuance`.

Migration v34 covers the job that references it:

- `'issue'` is added to the `certificate_jobs.operation` CHECK constraint.

v34 was missed on first implementation, and the consequence is worth recording
because it is not obvious: with only v33 applied, the certificate row inserts
fine and then the job insert fails, so the whole transaction aborts and *every*
`issue` request returns an opaque HTTP 500 with the real cause visible only in
the API log. Nothing partial is written, so it is safe, but it is
undiagnosable from the response alone. Unit tests could not see it because they
stub the database; it was found by live testing against a running stack. The
regression test therefore asserts the v34 constraint's value list equals the
service layer's `JOB_OPERATIONS` **exactly**, rather than merely containing
`'issue'`, so any future operation added to one side and not the other fails
the suite instead of production.

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

- Migrations v33 **and** v34 must both be applied before the `issue` route is
  enabled. v33's constraints reject `provisioning` and `agent_issuance`; v34's
  rejects the `issue` job itself. Either one missing means every request fails,
  and because the failure is a constraint violation at COMMIT it surfaces as an
  opaque HTTP 500 rather than a useful error.
- Cloud and Enterprise must adopt both migrations and the same job-service
  change when they re-pin core. The reconciliation branch lives in the shared
  job status transition path, so overlays inherit it, but the migrations are not
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

## Amendment 1 (2026-07-26): issuance hardening and renewal enablement (0.11.0)

The original record was written before `issue` had been exercised end to end
against a live stack. First contact produced four corrections. The original
decision text above is kept verbatim; this section is authoritative where the
two disagree.

### A1.1 Renewal configuration is derived, not operator-authored (amends 4)

Decision point 4 ends "Renewal configuration is set on the row after it becomes
`active`", which read as an operator task deferred to later. It was neither
deferred nor a task: nothing in the product wrote `certificate_profiles` and
nothing set `managed_certificates.profile_id`, so the renewal scheduler counted
every issued certificate as `skippedIncompleteProfile` on every sweep, forever.
The result was the exact failure this ADR set out to avoid, one step later in
the lifecycle: a dashboard-visible `active` certificate with a real expiry date
that nothing would ever renew.

The renewal profile is now **derived from the issue job payload that just
succeeded** and persisted during the same reconciliation transaction that
promotes the certificate
(`apps/api/services/certops/renewalProfileDerivation.js`). A successful issuance
is the only moment where every field the profile needs is both known and proven
to work against the real CA. See ADR-0010 for the derivation contract, the SAN
pinning decision, and the failure modes.

Point 4's prohibition on a `renewalProfile` **snapshot in the issue job payload**
stands unchanged. The caller still may not supply one. What changed is who
produces it afterwards, and when.

### A1.2 Agents are no longer upgrade-free for `issue` (amends 5)

Decision point 5 and the third consequence bullet both state that field agents
accept `issue` jobs with no upgrade, on the grounds that they only ever see
`action: "renew"`. That is still true of the wire contract, and no protocol
schema or `schemaVersion` change was needed. It turned out to be insufficient.

Reconciliation (point 6, tightened in A1.3) requires evidence bound to the
specific job claim being executed. An agent that does not bind evidence to its
claim can complete an issuance perfectly and still leave the certificate at
`provisioning` forever, with real material deployed on the host and no way for
the control plane to prove what is there. Dispatching to such an agent produces
the worst available outcome: work done, nothing recorded.

The claim query therefore gates on a declared agent capability,
`evidence-claim-binding-v1`, for both shapes of job that need claim-bound
evidence:

- `operation = 'issue'`, and
- `operation = 'renew'` where the subject certificate is still `provisioning`,
  which is the retry path point 6 deliberately created.

An agent without the capability keeps claiming ordinary renewals of `active`
certificates exactly as before, so this is not a fleet-wide upgrade requirement.
It is a requirement on whichever hosts should run issuance. The operator-visible
symptom of a fleet that is behind is an `issue` job that stays `pending` and is
never claimed, with no error: the capability is a matching predicate, not a
rejection. That is a deliberate trade (no work is better than unreconcilable
work), and it is why the gate is documented on the operator-facing issuance page
rather than only here.

The capability name is a contract surface under the README's change-control
rule. Agents declare it during registration and heartbeat; see ADR-0002.

### A1.3 Promotion requires claim-bound verify-step evidence (tightens 6)

Decision point 6 says promotion backfills from "that job's `validation.passed`
evidence". Two ambiguities in that phrasing were exploitable in practice:

1. **Which `validation.passed`.** The agent emits it twice per run: once when the
   ACME order returns, and once after the deployed file has been read back and
   fingerprinted. Only the second describes what is on the host. Accepting the
   first records the certificate the control plane asked for rather than the one
   that exists.
2. **From which attempt.** A job can be attempted more than once and evidence
   from an earlier attempt outlives it, so an unbound lookup can promote attempt
   2 using attempt 1's fingerprint.

Promotion now requires evidence whose `metadata.step` is `verify`, whose
`claim_id` equals the job's current claim, and which carries **both** a
fingerprint and a parseable expiry. Expiry is mandatory because a certificate
without one cannot be scheduled for renewal or alerted on, so activating without
it produces a row that looks healthy and is silently unmanaged, which is the
same class of defect as the one in A1.1.

When a check fails the row stays `provisioning` and records a
`reconciliation_reason` an operator can read:
`no_claim_bound_verify_evidence`, `verify_evidence_missing_fingerprint`, or
`verify_evidence_missing_expiry`. The reason is cleared on successful promotion.
Point 7's "failure leaves the row in place" therefore now covers a second case:
not only a failed job, but a succeeded job whose evidence was insufficient.

Request validation was tightened for the same reason, one step earlier:
`payload.certPath` must be an absolute file path, rejected at request time
rather than agent-side after the ACME order has been placed. A rejection after
the order burns a real rate-limited order and leaves a stuck `provisioning` row,
which is a needlessly expensive way to learn about a trailing slash. Identity
resolution is additionally serialized on a per-identity advisory lock, so the
concurrent-retry case described in point 3 returns the same job instead of a
constraint violation surfaced as an HTTP 500.

### A1.4 Alerting is not unchanged: a failed issuance does not alert (replaces 8)

Decision point 8 asserted that a failed `issue` job raises the same
`cert_renewal_failed` alert as a failed `renew`. It did not, and the way it
failed to is instructive: the dispatcher's alerting operation set said
`{renew, issue}` while the alert resolver hard-rejected anything but `renew`, so
failed issuances were dispatched into an alert path that silently discarded
them. Point 8 documented an intent that the code never had.

Rather than make the code match point 8, the decision itself is reversed:
**a failed `issue` job deliberately does not raise a renewal-failure alert.**
The reasoning is the one this ADR already relies on elsewhere:

- A failed **renewal** means a certificate that exists, is serving traffic, and
  has a real expiry was not replaced. There is a deadline, and inaction breaks
  something. That is what an alert is for.
- A failed **issuance** means a certificate that was never created. Nothing is
  serving it, nothing is expiring, and there is no deadline. Per point 7 the
  operator already has a visible, non-terminal `provisioning` row with the
  failed job and its evidence attached, which is a better record than a
  notification. There is also nothing to route through: renewal alerts are
  addressed via the certificate's linked token, and per A1.3 the token is only
  linked once a verified expiry exists.

Once an issued certificate reaches `active`, its subsequent renewals alert
normally, so this is a difference in the first attempt only.

The rule now lives in exactly one place,
`apps/api/services/certops/renewalAlertPolicy.js`, imported by both the
dispatcher and the resolver, precisely so the two cannot disagree again. See
ADR-0009, which also covers how the intent to alert is made durable.

**Operator-facing consequence:** watch `provisioning` certificates for issuance
problems and alerts for renewal problems. The dashboard must therefore make
`provisioning` visually distinct (already required by the fourth consequence
bullet above); with A1.4 that requirement is load-bearing rather than cosmetic.

