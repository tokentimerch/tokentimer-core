# Temporary delivery for existing recipients

An operator can give reviewed existing email and WhatsApp destinations a fixed
confirmation period while recipient verification remains `enforce`. This is a
delivery exception, not recipient consent: contacts keep their `pending` status.
There is no automatic enrollment during migration and no production setting is
changed by installing this feature.

## What can receive grace

A grant is bound to one workspace, contact, channel and normalized destination.
It expires at the deadline chosen in the preview, at most 30 days after that
preview. Opt-outs, manager revocations and active suppressions still block
delivery. New contacts and changed destinations require confirmation immediately.
Changing an address or number back does not restore its old grant. Editing an
email does not invalidate a phone grant, or vice versa.

The preview requires an explicit rollout cutoff. Both the contact's creation
and last-update timestamps must be at or before it; creation time alone does not
establish the age of an address. The preview records the exact current
destinations and database row versions. Activation rejects the entire snapshot
if a selected contact was edited, removed or became ineligible after preview.
The cutoff is deliberately conservative: a recent name-only edit can exclude an
otherwise old destination. Review the preview instead of treating every old
contact as proof of a legacy address. No historical `contact_opt_ins` row is
converted into consent.

Each contact/channel can receive grace only once. Deadlines and destinations are
immutable; another snapshot cannot renew an expired or revoked grant. Consent
revocation and destination-edit triggers also cover older API replicas and direct
imports during a rolling upgrade.

## Prepare and review

1. Run the normal migration runner before deploying matching APIs and workers.
   The canonical Core migration is `109 / recipient_legacy_delivery_grace`; the
   runner preserves supported preview ledger identities. Never modify an applied
   migration row or apply this SQL by hand.
2. Use a trusted checkout with dependencies installed. Run the operator script
   with the same `NODE_ENV`, `DB_*`, `PGSSLROOTCERT` and recipient fingerprint secret
   as the API. Production runs must set `NODE_ENV=production` (or `DB_SSL=verify`)
   so `DB_SSL=require` authenticates the database server. Do not place credentials
   in command arguments. The script does not send
   invitations or messages.
3. Choose `ROLLOUT_CUTOFF_UTC` and `GRACE_EXPIRES_UTC` as explicit UTC ISO timestamps
   such as `2026-11-08T12:00:00Z`. The cutoff cannot be in the future. The deadline
   must be in the future and within 30 days of the preview.

```sh
node scripts/recipient-legacy-grace.cjs preview \
  --before "$ROLLOUT_CUTOFF_UTC" \
  --until "$GRACE_EXPIRES_UTC" \
  --output recipient-grace-preview.json
```

Add `--workspace-id <UUID>` to review one workspace. A preview is limited to
10,000 contacts; use workspace scope for larger deployments. Preview runs in a
read-only database transaction. Its local file is created with owner-only
permissions and contains recipient addresses/numbers, so handle it as customer
data. It refuses to overwrite an earlier file.

Review the workspace/contact IDs, exact destinations, cutoff and expiry in the
file. Record the `sha256` printed by the command. Keep the reviewed file unchanged.
An empty eligible set is reported as an error and is not activated.

## Activate and enable delivery

```sh
node scripts/recipient-legacy-grace.cjs activate \
  --input recipient-grace-preview.json \
  --sha256 "$REVIEWED_SNAPSHOT_SHA256" \
  --operator "$ROLLOUT_OPERATOR_LABEL" \
  --apply
```

Activation requires the exact reviewed checksum and rechecks every selected
destination under contact locks. It commits all grants together or none. The
stored snapshot ID, checksum, activation time and operator label record the
decision. Repeating an already activated snapshot does not extend it.

Then explicitly set these values consistently on the API and every notification
worker, including scheduled digests:

```env
RECIPIENT_VERIFICATION_MODE=enforce
RECIPIENT_VERIFICATION_LEGACY_GRACE=1
```

Keep `TT_DEPLOYMENT=cloud` on Cloud. In Compose the new flag defaults to `0`; Helm
operators can put it under `api.env` and `worker.env`. Restart running processes
after changing their environment. A snapshot without the opt-in flag, or the flag
without a live matching snapshot, does not permit unconfirmed delivery.

During grace, alerts, digests and saved-contact tests use the same delivery gate.
The contact API still reports `status: "pending"` and adds
`delivery_basis: "legacy_grace"` plus `grace_expires_at` only for an active eligible
grant. Send confirmation invitations during the window. Once confirmed, ordinary
verified delivery continues beyond the deadline. There is no automatic switch to
shadow when the deadline passes.

## Existing blocked alerts

Enabling grace does not automatically replay alerts already terminally blocked
for `NO_VERIFIED_RECIPIENTS` or `RECIPIENT_NOT_VERIFIED`. Review those alerts and
retry the affected channel using the application's existing retry action. The
worker reads current eligibility again and preserves successful delivery evidence.
Do not bulk reset sent, opted-out, revoked or suppressed outcomes.

## End grace early

Unset `RECIPIENT_VERIFICATION_LEGACY_GRACE` (or set it to `0`) everywhere and restart
the affected processes to stop using all grants. To stop one snapshot immediately:

```sh
node scripts/recipient-legacy-grace.cjs revoke \
  --snapshot-id "$GRACE_SNAPSHOT_ID" \
  --apply
```

Revocation is permanent; confirmation is still available through the ordinary
recipient flow. The deadline is checked at each delivery decision with the
database clock and never renewed on retry. A grace lookup failure fails closed
and remains retryable rather than claiming a recipient refused consent.

`shadow` remains a separate emergency behavior. It permits delivery even when the
evaluated recipient opted out, was revoked or was suppressed. It does not provide
the protections of the bounded legacy grants described here.
