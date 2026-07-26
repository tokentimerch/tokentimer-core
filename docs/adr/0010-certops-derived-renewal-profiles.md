# ADR-0010: CertOps renewal profiles are derived at issuance

## Status

Accepted (2026-07-26). Amends [ADR-0008](0008-certops-upfront-issuance.md)
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
7. **Derivation never fails the issuance.** A certificate that exists on a host
   must be recorded. Derivation returns `profileId: null` with a reason and logs
   `certops-renewal-profile-derivation-failed`; the promotion still commits. An
   un-auto-renewable certificate the operator can see and fix beats losing the
   row for a real certificate over missing renewal metadata.
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
derivation would run asynchronously. It does not. Derivation is a pure mapping
over data already loaded in the reconciliation transaction plus two local
writes, so it has no external dependency to fail on and no reason to be deferred;
doing it inline means a promoted certificate is never briefly renewable-in-theory
but unlinked in practice. The event type remains defined and unused, as recorded
in ADR-0009.

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
  must author a profile once, or re-issue.
- Profile lists now contain machine-derived entries. The `Derived:` prefix and
  the `derivedFrom` metadata are the operator's signal, and dashboards should not
  present derived profiles as read-only, since editing `renew_before_days` on
  them is the supported per-certificate override.
- `skipped_incomplete_profile` becoming non-zero is now an actionable alert
  condition for operators, and it is the series to watch after this change.
- Derivation failures are visible only in API logs
  (`certops-renewal-profile-derivation-failed`) and by the absence of a linked
  profile. A surfaced per-certificate reason, as `reconciliation_reason` does for
  promotion, would be an improvement and is deliberately out of scope here.
- `certificate_profiles` gains rows at issuance rate, one per issued
  certificate, and they count against nothing today. If profile quotas are
  introduced later, derived profiles must be considered.
- Cloud and Enterprise inherit this through the shared reconciliation path when
  they re-pin core. No migration is required by this ADR: `certificate_profiles`,
  `renew_before_days`, and `profile_id` all predate it.
