# ADR-0010: CertOps renewal profiles are derived at issuance

## Status

Accepted (2026-07-26), amended 2026-07-26 (Amendment 1: the control surface for a
derived profile). Amends [ADR-0008](0008-certops-upfront-issuance.md)
decision point 4, revised by
[Amendment 1, section A1.1](0008-certops-upfront-issuance.md#a11-renewal-configuration-is-derived-not-operator-authored-amends-4)
of that record.

## Context

The renewal scheduler creates a `renew` job for a certificate only when that
certificate links to a `certificate_profiles` row carrying a complete,
agent-executable `public_metadata.renewalProfile`. The gate is correct:
dispatching a half-specified renewal hands an agent a job it cannot run against
a real, rate-limited CA, and the failure lands 60 days later at the worst
possible moment.

Nothing populated it. No API route wrote `certificate_profiles`, no code path
set `managed_certificates.profile_id`, and no derivation existed. The scheduler
therefore counted every certificate as `skippedIncompleteProfile` on every
sweep, and automatic renewal could not fire for anything TokenTimer issued.

The failure shape is the expensive part. The operator sees an `active`
certificate with a real expiry date, a complete evidence trail, and no failed
jobs. Nothing in that picture is wrong, and nothing in it indicates that the
certificate will silently expire. This is the same defect class ADR-0008 was
written to close, displaced one step later in the lifecycle: work that succeeded
and was never connected to the system that was supposed to manage it.

Worse, the scheduler's observability actively hid it. Only the `created` count
was exported, so a fleet where every certificate was skipped for an incomplete
profile was indistinguishable from a fleet with nothing due.

Asking the operator to author the profile by hand was the implied plan (ADR-0008
point 4: "Renewal configuration is set on the row after it becomes `active`").
That is worse than it sounds. A hand-entered profile can disagree with what
actually ran, and the disagreement is undetectable until the renewal fails.

## Decision

1. **Derive the renewal profile at reconciliation, from the payload that just
   succeeded.** On promotion of a `provisioning` certificate to `active`
   (ADR-0008 point 6 as tightened by A1.3),
   `apps/api/services/certops/renewalProfileDerivation.js` builds a
   `renewalProfile` from the `issue` job payload plus the certificate the agent
   verified, inserts a `certificate_profiles` row, and sets
   `managed_certificates.profile_id`. All of it runs inside the reconciliation
   transaction: a promoted certificate and its renewal configuration commit
   together.

   A successful issuance is the only moment where every field the profile needs
   is both known and **proven to work**. The agent has just completed a real
   ACME order with exactly this CA endpoint, DNS provider, zone, command
   profile, key parameters, and deployment paths.
2. **Derivation is a mapping, not a guess.** Every field comes from the issue
   payload or from the verified certificate. When a field that determines how the
   certificate is re-issued is genuinely absent, derivation **fails and names the
   missing field** rather than defaulting. Required: `caEndpoint`, `commandRef`,
   `dnsProvider`, `dnsZone`, `certPath`, and a common name on the verified
   certificate. A default here would renew the certificate differently from how
   it was issued, which is a silent divergence, and silent divergence is the
   thing this ADR exists to remove.
3. **Optional deployment fields are carried if present and omitted if not.**
   `keyPath`, `chainPath`, `reloadService`, file modes, owner, group, and backup
   directory are copied when the issuance used them. Absent stays absent, so the
   agent applies its own documented defaults. Inventing different ones here would
   silently change file ownership or permissions at the first renewal.
4. **Job-specific fields are dropped.** Idempotency keys, one-shot reasons, and
   dispatch timestamps do not enter the profile. A profile describes a repeatable
   operation, not the run it came from.
5. **The SAN policy is pinned to what the CA issued, mode `exact`.** Observed
   SANs from the verified certificate win over the ones the job requested,
   because a CA that normalised or dropped a name means renewing against the
   requested set would produce a different certificate than the one deployed.
   `inherit` was rejected: it re-reads inventory at renewal time, so a later
   discovery scan that rewrote `subject_alt_names` would silently change what the
   renewal asks for.
6. **The candidate is validated through the scheduler's own gate.** Derivation
   calls `validateRenewalProfile`, so a profile that would be rejected at renewal
   time is rejected now, while the operator is still looking at the issuance that
   produced it.
7. **A derivation that cannot be computed never fails the issuance.** A
   certificate that exists on a host must be recorded. When the payload cannot be
   mapped to a valid profile, derivation returns `profileId: null` with a reason;
   the promotion still commits. An un-auto-renewable certificate the operator can
   see and fix beats losing the row for a real certificate over missing renewal
   metadata.

   Scoped deliberately: this covers **mapping and validation** failures, not
   persistence. The profile upsert and the certificate link run on the
   reconciliation transaction's client, so a database error there aborts result
   ingestion along with the promotion. That is the right outcome (a half-written
   profile is worse than a retried result) but it means "never fails the
   issuance" is not an unconditional guarantee.

   **Known gap:** the swallow path builds a structured reason and a
   `logger.warn`, but the production call site passes no logger, so a derivation
   decline currently produces no log line, no audit event and no
   `reconciliation_reason`, which the promotion explicitly sets to `NULL`. The
   only durable trace is `profileId: null` in `CERTOPS_CERTIFICATE_ISSUED`.
   ADR-0011 made this asymmetric: success is audited
   (`CERTOPS_RENEWAL_PROFILE_DERIVED`) while failure is silent, so the audit log
   reads as though derivation always succeeds. Closing it belongs with the
   outbox's durable-completion machinery rather than a log line.
8. **An operator's own profile is never overwritten.** If the certificate already
   links to a profile, derivation returns `already_linked` and does nothing. The
   link update is additionally guarded by `profile_id IS NULL`.
9. **Derived profiles are ordinary profiles, and identifiable.** They are named
   `Derived: <common name>`, described as derived, `source = 'api'`,
   `source_ref = 'certops-issuance:<certificateId>'`, and carry
   `public_metadata.derivedFrom`. Re-derivation upserts on the per-workspace
   unique index over `LOWER(name)`, so one issued certificate keeps one profile
   instead of failing reconciliation on a duplicate name. The upsert refreshes
   `renewalProfile` but preserves an existing `renew_before_days`, so an operator
   edit to the renewal lead time survives re-derivation.
10. **Renewal timing stays a two-level model.** The global default is
    `CERTOPS_RENEWAL_THRESHOLD_DAYS` (30). A profile's `renew_before_days`
    overrides it for its own certificates via
    `COALESCE(cp.renew_before_days, <global>)` in the due-certificate query.
    Editing a derived profile is therefore the supported way to give one
    certificate a longer runway than the fleet.
11. **Every scheduler outcome is a metric series.**
    `certops_renewal_scheduler_certificates` is labelled by `outcome`:
    `scanned`, `created`, `replayed`, `skipped_paused`, `skipped_ca_cap`,
    `skipped_incomplete_profile`, `skipped_not_agent_deployable`, `errors`.
    Exporting only `created` was what allowed a fleet that renewed nothing to
    look idle.
12. **An observed-only certificate is its own skip, not an error.** A certificate
    with no agent custody of its key (`key_mode` outside `agent-local` and
    `proxy-agent-local`) can never be renewed by an agent. That is an expected
    steady state, so it counts as `skipped_not_agent_deployable`. Counting it as
    an error would make every sweep look broken and bury real failures.

### Key custody implication

A derived profile always sets `key_mode = 'agent-local'` and
`keyRotationPolicy.rotateOnRenew: true`. An issued certificate is agent-local by
construction (ADR-0001, ADR-0008): the agent generated the key and holds it, so a
renewal both can and should rotate it. Nothing here moves key material into the
control plane; the profile records parameters, never keys.

### Interaction with the outbox

[ADR-0009](0009-certops-durable-side-effects-and-alert-policy.md) reserved a
`profile_derivation_requested` outbox event type on the assumption that
derivation would run asynchronously. It does not, **on the issuance path**.
Derivation there is a pure mapping over data already loaded in the reconciliation
transaction plus two local writes, so it has no external dependency to fail on and
no reason to be deferred; doing it inline means a promoted certificate is never
briefly renewable-in-theory but unlinked in practice.

**Amended 2026-07-27: the event type is no longer unused.** The adoption flow
(`POST .../certificates/:id/renewal-setup`, for a certificate TokenTimer did not
issue) arms a `profile_derivation_requested` intent and the CertOps worker drains
it, because there adoption *must* wait for a real preflight job to produce the
evidence the profile is derived from, which is genuinely asynchronous. So the two
paths differ by necessity rather than by inconsistency: derived-at-reconciliation
when the evidence already exists, derived-via-outbox when it has to be produced
first. The consequences differ too, and the asynchronous path is the better
behaved one - see the derivation-failure note below.

## Alternatives considered

- **Require the operator to author a profile before or after issuance** -
  rejected: it is the status quo that produced the defect, it cannot be enforced
  (nothing blocks an unlinked `active` certificate), and a hand-entered profile
  can disagree with what actually ran, with the disagreement surfacing only at
  the first renewal.
- **Accept a `renewalProfile` snapshot on the `issue` request** - rejected, and
  ADR-0008 point 4 still forbids it. The caller would be asserting renewal
  parameters before anything has proven they work against the CA, and a rejected
  or normalised order would leave the profile describing a certificate that does
  not exist. Deriving after success is strictly better information for no extra
  caller effort.
- **Derive at request time, when the payload is first seen** - rejected: it would
  create a profile for issuances that never succeed, and it cannot pin SANs to
  what the CA issued because the CA has not issued anything yet.
- **Let the scheduler synthesise a profile on the fly from certificate
  metadata** - rejected: inventory does not retain the command profile, DNS
  provider, deployment paths, or key parameters, so the scheduler would be
  guessing at exactly the fields that decide whether a renewal is executable.
  It would also make the scheduler's refusal gate meaningless.
- **Default the missing fields (a house DNS provider, a conventional cert path)**
  - rejected: a renewal that works but deploys somewhere other than the original
  path, or validates through a different provider, is a worse outcome than a
  certificate the operator is told is not auto-renewable.
- **Fail the issuance when derivation fails** - rejected: it discards a real
  certificate that exists on a host over metadata, and ADR-0008 point 7 already
  establishes that a visible imperfect row beats a missing one.
- **Derive asynchronously through the outbox** - rejected: see above. Inline
  keeps promotion and renewability atomic.
- **`sanPolicy.mode: 'inherit'`** - rejected: it makes the renewal request depend
  on whatever last wrote `subject_alt_names`, which includes discovery scans.

## Consequences

- Certificates issued by TokenTimer auto-renew without operator action. This is
  a behaviour change for existing `provisioning` rows only at their next
  reconciliation; certificates already `active` from before this change have no
  profile and will not gain one retroactively. Operators with such certificates
  must author a profile once, or re-issue. *(Amendment 1 resolves this: authoring
  is not offered, so re-issuing is the path. See A1.3.)*
- Profile lists now contain machine-derived entries. The `Derived:` prefix and
  the `derivedFrom` metadata are the operator's signal, and dashboards should not
  present derived profiles as read-only, since editing `renew_before_days` on
  them is the supported per-certificate override. *(Amendment 1 makes this
  precise: the lead time and the on/off switch are editable, the deployment
  details are not. See A1.2.)*
- `skipped_incomplete_profile` becoming non-zero is now an actionable alert
  condition for operators, and it is the series to watch after this change.
- Derivation failures are visible only by the absence of a linked profile. The
  intended log line (`certops-renewal-profile-derivation-failed`) is unreachable
  **on the issuance path** because that caller passes no logger, so there is no
  log, no audit event and no per-certificate reason at all. See decision 7's known
  gap. *(Amended 2026-07-27: this is now true of the issuance path only. The
  adoption path passes the worker logger and converts a decline into a durable,
  retryable outbox failure carrying the reason, so the asymmetry is between the
  two callers rather than inherent to derivation. Note also that
  `CERTOPS_CERTIFICATE_ISSUANCE_UNRECONCILED` does not cover a derivation decline:
  it fires only for missing or incomplete verify evidence and returns before
  derivation is attempted.)*
- `certificate_profiles` gains rows at issuance rate, **one per distinct common
  name per workspace, not one per certificate**. The upsert's conflict target is
  `(workspace_id, LOWER(name))` with `name = 'Derived: <commonName>'`, so two
  certificates issued for the same CN in one workspace share a single profile
  row: the second derivation updates it and links to it. That is legal and
  common (load-balanced pairs, blue/green, edge plus origin), and it has a real
  consequence: `public_metadata` is replaced wholesale on conflict, so a
  same-CN re-derivation overwrites the `renewalProfile` block that `PATCH` also
  writes, while reporting `created: false`, which reads as a benign replay. The
  two fields operators care about most do survive: `status` is not in the update
  set, so an explicit auto-renew off switch holds, and `renew_before_days` is
  `COALESCE`-preserved, so an edited lead time holds. `source_ref`
  (`certops-issuance:<certificateId>`) is in neither the conflict target nor the
  update, so a shared row keeps the first certificate's provenance pointer.

  *(Amended 2026-07-27, two corrections. First, "replaced wholesale" is
  **conditional**: the `DO UPDATE` carries
  `WHERE public_metadata->>'operatorOwned' <> 'true'`, and the first successful
  `PATCH` sets that marker, so an edited profile is never clobbered. Second, and
  less obvious, the guard does not merely protect the edit - when it matches,
  `RETURNING` yields no row and derivation declines with `profile_operator_owned`,
  so the **second same-CN certificate is left with no profile at all** rather than
  sharing an unwanted one. There are therefore two outcomes for a same-CN
  collision, and which one occurs depends on whether the existing profile was ever
  edited: a pristine profile means shared row plus clobbered metadata, an owned
  profile means the new certificate silently does not auto-renew. The second is
  the more surprising and is the one to watch.*

  *A further consequence follows from this that Amendment 1's per-certificate
  framing does not admit: because same-CN certificates share one row, the
  auto-renew off switch and the lead time are **per profile, not per
  certificate**. Switching auto-renew off for one certificate switches it off for
  every certificate sharing that common name in the workspace. The dashboard
  patches the profile and shows a `certificateCount`, so the sharing is visible
  there, but a certificate's own renewal badge does not convey it.)*
  Treat the uniqueness key as the open question here; guarding the write would
  paper over it. They count against nothing today. If profile quotas are
  introduced later, derived profiles must be considered.
- Cloud and Enterprise inherit this through the shared reconciliation path when
  they re-pin core. No migration is required by this ADR: `certificate_profiles`,
  `renew_before_days`, and `profile_id` all predate it.

## Amendment 1 (2026-07-26): the control surface for a derived profile

Derivation made automatic renewal live for everything TokenTimer issues. It also
made it **unconditional**: a profile appeared by itself, the scheduler acted on
it, and nothing in the product could inspect or stop it. The original
consequences section understated this by treating it as a documentation and
dashboard concern. An automation that turns itself on and cannot be turned off is
a defect regardless of how well it is described.

This amendment records the surface added in response. It does not revise any
decision above; it decides what an operator may change about a derived profile,
and what they may not.

### A1.1 The profile is the unit of renewal control, and `status` is the switch

`certificate_profiles.status` is now read by the scheduler as "is automatic
renewal on". `disabled` and `archived` exclude every certificate linked to the
profile, counted as `skipped_auto_renew_disabled` and surfaced per certificate as
the `disabled` renewal state.

The switch lives on the profile rather than on `managed_certificates` because
derivation already produces one profile per issued certificate, so the profile
*is* the per-certificate control in practice. A parallel per-certificate flag
would be a second source of truth for the same question, and the scheduler would
have to reconcile two answers.

`archived` is not settable through the API. It exists for profiles retired by
other means, and overloading the renewal switch to archive things would conflate
"stop renewing this" with "retire this record".

### A1.2 Deployment details are immutable after derivation

The API exposes list, read, and a narrow `PATCH`. `acme`, `ca`, `dns`,
`target`, `deploymentTargets`, `schemaVersion` and `profileId` are refused with
`422 CERTOPS_PROFILE_FIELD_IMMUTABLE`, naming the fields.

The editable subset is exactly the fields that cannot change what executes on a
host: `sanPolicy`, `keyAlgorithm`, `keySize`, `keyRotationPolicy`,
`verification`, `preferredChain`, plus `renew_before_days` and the switch.

The reason is the same one that made derivation right in the first place. Those
fields are trustworthy *because* a real ACME order proved them against a real
host. Letting them be edited would recreate the failure mode derivation removed:
a profile full of values nobody has executed, discovered to be wrong by an
unattended renewal against a rate-limited CA. Repointing where a live
certificate is written is a re-issuance, not a settings change, and re-issuing
re-derives the profile from what actually worked.

Every write still passes `validateRenewalProfile`, the gate the scheduler admits
on, so the API cannot persist a profile the scheduler would later refuse.

### A1.3 There is no create and no delete

A profile exists because an issuance produced it. Consequence 1 above says
operators with pre-existing `active` certificates "must author a profile once, or
re-issue"; **authoring is not offered, so re-issuing is the only path.** That is
the intended reading, and it follows from A1.2: a hand-authored profile is
precisely the untested-values case the immutability boundary exists to prevent.

The cost is real and accepted: a certificate TokenTimer did not issue
(`agent_filesystem` discovery, PEM import) cannot be brought under automatic
renewal without issuing it through CertOps.

### A1.4 Reading the schedule is not gated on a client-side role check

Reads (`GET /certops/profiles`, `GET /certops/renewals/upcoming`) require manager
or above; writes require workspace admin (`certops.renewal_profile.manage`).

Manager rather than viewer, because a profile body is deployment topology, not
expiry metadata: certificate and key paths, the reload unit, file ownership and
modes, the ACME command reference, the CA account reference, the DNS zone. That
puts it with the agent and machine-token routes, which are manager-gated for the
same reason, rather than with `GET /certops/certificates`. A viewer keeps full
visibility of what expires and when, and of whether it auto-renews, through the
inventory and the renewal badge; what they lose is a map of where each key sits
on which host.

The first implementation shipped these reads with no role middleware at all,
which handed any viewer exactly that map. The routing guard on `/certops/*` is
manager-scoped, so the dashboard hid the surface and the gap was invisible
through the UI; it was reachable directly. Two lessons: a client-side route guard
is never the enforcement point, and "same posture as the inventory" is the wrong
default for a payload that is categorically different from the inventory. The
test at `tests/unit/certops-routes-hardening.test.js` now asserts the middleware
on all three reads.

The dashboard deliberately does **not** pre-filter reads on a locally computed
permission. A boolean that starts `false` and collapses lookup failures into
`false` cannot distinguish "resolving" or "denied" from "no data", and rendering
an empty schedule for any of those makes a workspace of expiring certificates
read as all-clear. On this surface a false negative is the worst available
failure, so the server is the only authority and a refusal is rendered as a
refusal. Write affordances are still hidden from non-admins, but only to avoid
offering a button that would 403.

### A1.5 The schedule lists what will not renew, not what will

A certificate with renewal switched off is listed in the upcoming schedule rather
than filtered out of it, with a standing count. A switched-off certificate and an
empty schedule are indistinguishable otherwise, and only one of them is safe.

Switching off asks for confirmation and states how many certificates the profile
covers. Switching on does not: the safe direction should not carry friction.

**Generalised (2026-07-26).** The first implementation applied that reasoning only
to the switch, and built the schedule as an inner join onto
`certificate_profiles` filtered to `status = 'active'` certificates. That
reintroduced the same defect one level down. The population it dropped was
certificates with `profile_id IS NULL`, which is precisely the population that
this ADR's own derivation step produces when it fails (see the Consequences
section: a swallowed derivation leaves the certificate active and unlinked). So
the page whose reason for existing is to expose unattended-renewal risk hid the
certificates most at risk, and a workspace where nothing renewed at all rendered
as an empty schedule with no warning.

The rule is therefore stated positively: **this view is a list of certificates
that could expire, not a list of scheduled work.** It selects every certificate
the sweep would consider (the same `NOT IN (revoked, decommissioned)` filter, via
a LEFT JOIN) and decides coverage per row by calling
`resolveRenewalProfileSnapshot`, the identical function the sweep admits on, so
the two cannot disagree. Anything not covered carries a `blockedReason`.

The reason is not collapsed into a single "will not renew" flag because the
remedies differ. `auto_renew_disabled` is a decision the operator made and can
undo from the same page. `no_profile` and `incomplete_profile` are defects that no
toggle can fix and that require re-issuance. Presenting both as "Off" would point
an operator at a control that cannot help them, which is a worse failure than
saying nothing.

Any future addition to this view inherits the constraint: a filter that can hide
a certificate is a filter that can manufacture a false all-clear, so the default
is to include and label rather than exclude.
