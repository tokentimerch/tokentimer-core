# Recipient verification

Workspace contacts can exist, and can belong to contact groups, before a destination is confirmed. Whether alerts, weekly digests, and workspace notification tests require that confirmation depends on the deployment. Cloud requires it. A standard self-hosted deployment does not, until an operator turns verification on. When verification is enforced, a weekly digest checks consent again after it claims the recipient and does not mark the digest sent when the check fails.

Account verification, password reset, billing, waitlist, workspace invitations, and operator incident email are not recipient-consent messages. They are not blocked by this policy.

## States

Each channel is independent:

| Status | Meaning |
| --- | --- |
| `pending` | No recipient confirmation for the current address or number. |
| `verified` | The recipient confirmed this exact destination for this workspace. |
| `revoked` | A workspace manager stopped notifications. |
| `opted_out` | The recipient declined. |

Changing the email address invalidates email verification only. Changing the phone number invalidates WhatsApp verification only. A confirmation in one workspace does not authorize another workspace. Deleting and recreating a contact does not clear a decline for that destination in the same workspace.

A decline stays in force until the recipient accepts a new confirmation sent to that mailbox. An administrator cannot receive or open that link. The recipient requests it from `/verify/recipient/resubscribe`. Expired, used, revoked, and superseded links do not restore consent.

Historical `contact_opt_ins` rows recorded when a contact was created are not treated as consent. New contacts do not write that row.

## Email

A workspace admin or manager sends a verification invitation. TokenTimer emails a link that expires in 48 hours. Opening the link only shows the confirmation page. The recipient must submit the accept or decline form. The token is stored as an HMAC, is single-use, and is bound to the workspace, contact, channel, and normalized address.

## WhatsApp

TokenTimer does not send an unsolicited verification message to a new number. The admin copies a confirmation link and sends it through a channel they already trust. The recipient opens the page and sends the prefilled `CONFIRM` message from their own WhatsApp to the official TokenTimer number. The inbound Twilio webhook must present a valid signature for the external URL. The sender address must match the saved E.164 number and the unexpired challenge. Delivery success is not consent.

Configure Twilio's incoming message webhook as `POST {PUBLIC_BASE_URL}/webhooks/twilio/whatsapp/inbound`.

## Enforcement

`RECIPIENT_VERIFICATION_MODE` controls delivery. It is an environment setting, not a workspace setting. The API and every notification worker must use the same value. Startup logs `recipient verification mode`.

- Self-hosted default is `off` when `TT_DEPLOYMENT` is unset or `self-hosted`. Alerts, weekly digests, and workspace tests send without recipient confirmation, and they do not require `PUBLIC_BASE_URL`, `RECIPIENT_FINGERPRINT_SECRET`, or the Twilio inbound webhook. Set `RECIPIENT_VERIFICATION_MODE=enforce` to require confirmation. Set `shadow` to evaluate and log eligibility without blocking delivery.
- Cloud default is `enforce` when `TT_DEPLOYMENT=cloud`. `off` is ignored. `shadow` on Cloud requires both `RECIPIENT_VERIFICATION_MODE=shadow` and `RECIPIENT_VERIFICATION_CLOUD_SHADOW=1`. An unrecognized nonempty `TT_DEPLOYMENT` also enforces.

When enforcement blocks every required recipient, the alert is marked `blocked` with `NO_VERIFIED_RECIPIENTS` and is not retried as a provider outage. If another channel succeeded, the alert is `partial` and the successful channel is not sent again. Other eligible recipients in a mixed group are still delivered, including when an earlier duplicate contact for the same address is unverified. A workspace warning is raised for administrators. A permanent webhook response is a provider failure: that endpoint is not retried automatically, earlier successful channels are not sent again, and the warning type is `delivery_webhook_permanent`. An administrator can retry that webhook after fixing it. A later temporary failure stays scheduled on that new retry. A malformed webhook URL is refused when settings are saved. A previously stored malformed URL is a permanent delivery failure for that endpoint, and the other endpoints in the batch still run. Retry returns `409 DELIVERY_IN_PROGRESS` while a worker is delivering the alert. A claim whose lease has expired can still be retried. A recipient who has not confirmed, or who opted out, is not retried by that action.

Workspace WhatsApp tests require `contact_id` for a saved contact, and the number must match that contact. In `enforce` mode the current number must also be verified. An arbitrary `phone_e164` is rejected. In `off` and `shadow`, an unverified saved contact can still receive the test.

## Limits

Defaults, overridable by environment (see [configuration](CONFIGURATION.md#recipient-verification)):

- 1 email invitation per destination per 24 hours, and 3 per 7 days.
- 1 WhatsApp challenge per destination per 24 hours, and 3 per 7 days.
- 50 invitations per workspace per day, and 20 per user per day.
- 3 notification tests per contact per day, with 120 seconds between tests.

A destination that hits the weekly cap from 3 or more workspaces is suppressed for 24 hours. That suppression is saved even though the refused invitation is rolled back. Per-destination, per-workspace, and per-user limits are enforced inside one transaction with advisory locks, so concurrent invitations to different destinations cannot pass a shared workspace or user cap. Public confirmation pages are limited per client address in memory and in Postgres. The Twilio inbound webhook keeps its own limiter and is not part of the page limit. Limits are stored in Postgres and apply across API replicas.

## Rollout

Self-hosted notification delivery works with verification left off. Turn it on only when you want recipients to confirm:

```env
RECIPIENT_VERIFICATION_MODE=enforce
```

`shadow` is the self-hosted observation mode. It logs eligibility and still delivers. Cloud verification is mandatory. Set `TT_DEPLOYMENT=cloud` and `RECIPIENT_VERIFICATION_MODE=enforce` on the API and every notification worker.

1. Apply migration 80 before running the weekly digest worker, including when verification stays off. It adds the digest claim ownership token. Apply migration 79 when you enable verification. It does not mark existing contacts verified. Migration 78 remains CertOps installed-file distribution.
2. Set `RECIPIENT_FINGERPRINT_SECRET` and `PUBLIC_BASE_URL` or `API_URL` before sending invitations.
3. Ask workspace managers to send invitations. Existing alert groups keep their contacts.
4. Switch self-hosted from `off` or `shadow` to `enforce` after recipients confirm.
5. Rollback on self-hosted is `RECIPIENT_VERIFICATION_MODE=off` or `shadow`. That restores delivery. It does not delete consent rows. Cloud has no indefinite fail-open switch.

## Monitoring

- Audit actions: `RECIPIENT_VERIFICATION_INVITED`, `RECIPIENT_VERIFICATION_RATE_LIMITED`, `RECIPIENT_VERIFICATION_REVOKED`, `RECIPIENT_VERIFICATION_RESUBSCRIBE_REQUIRED`, `RECIPIENT_WHATSAPP_CONFIRMED`.
- Worker log `recipient-verification-shadow` while shadow mode is on.
- Operational notification type `delivery_unverified_recipients` when an enforced alert has no eligible recipient.
- Operational notification type `delivery_webhook_permanent` when a webhook endpoint rejects the alert. That warning is not used for an unverified or opted-out recipient.
- Alert status `blocked` and error `NO_VERIFIED_RECIPIENTS` means the failure is eligibility, not SMTP, Twilio, or a webhook response. `PERMANENT_DELIVERY_FAILURE` means a provider rejected the delivery.

## Limitations

- A verification email the provider rejects can be retried without using another destination-day allowance. An uncertain SMTP result is not replaced while that challenge is still pending. If the API stops after creating the challenge and before recording an outcome, another invitation is allowed after the dispatch lease (120 seconds by default), not after the 48-hour challenge lifetime.
- The confirmation token is present on the POST URL. The response redirects to a token-free page and sets `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.
- Invitation pages return the same generic result for unknown, expired, and replayed links.
- Apply the migration on a database before production enforcement. The migration is idempotent.
