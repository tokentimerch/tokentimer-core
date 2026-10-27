# Recipient verification implementation

## 1. Initial findings

- Creating a contact could record `contact_opt_ins` with method `contact_created`. That row is an administrator action, not recipient consent. New creates no longer write it. Old rows are left in place and are not read for delivery.
- Email addresses were checked for syntax only. Phone numbers were normalized, not confirmed.
- Alert delivery and weekly digests resolved contact-group destinations and sent without a verification or consent check.
- `POST /api/test-whatsapp` accepted a caller-supplied `phone_e164`. The cooldown lived in a process-local `Map`, so it did not hold across API replicas.
- Weekly digest claim happened before any recipient check, so an unverified destination could be marked sent.
- Account email verification is a user-login concern. It does not prove that a workspace contact consented to alerts.
- Cloud migration history already has `contact_opt_ins`. Those rows are not reused as the verification record.

## 2. Threat model

An ordinary workspace member, or a workspace manager, must not be able to aim TokenTimer at an arbitrary third party.

Relevant cases:

- Register a contact the person does not control, then send alerts, digests, or test messages.
- Confirm a destination by editing JSON, replaying a link, or relying on a mail-security scanner that only issues GET.
- Confirm a WhatsApp number by typing it, or by receiving a delivery receipt, without a message from that number.
- Reuse one confirmation in another workspace, or keep a confirmation after the address or number changes.
- Bypass a decline by deleting and recreating the contact.
- Burst invitations across accounts, workspaces, and API replicas.
- Treat an SMTP or Twilio failure retry as permission to contact someone who is not eligible.

Account, password, billing, waitlist, workspace-invite, and operator incident mail are out of scope. Blocking those would break sign-in and recovery.

## 3. Architecture

`packages/recipient-verification` is the policy. A standard Core deployment defaults to self-hosted `off`. Cloud defaults to `enforce` when `TT_DEPLOYMENT=cloud`. `RECIPIENT_VERIFICATION_MODE=off` is ignored when the deployment is Cloud. `shadow` still delivers and logs. Workspace tests follow the effective mode: `off` and `shadow` can reach a saved matching destination that is not yet verified, and `enforce` cannot. An arbitrary number that does not match the saved contact is still rejected.

Email: a manager requests an invitation. After the rate-limit transaction commits, the API sends one standard message. The page is GET-only. Accept and decline are POST, then a 303 to a token-free result page. Tokens and WhatsApp codes are HMAC'd at rest. The short WhatsApp code is also sealed with AES-256-GCM so the page can rebuild the `wa.me` link.

WhatsApp: the manager receives a share URL. The recipient sends `CONFIRM <code>` to the official number. `POST /webhooks/twilio/whatsapp/inbound` checks the Twilio signature against `PUBLIC_BASE_URL` or `API_URL` plus the request path and form fields. The sender must match the challenge destination. Retries with the same `MessageSid` are deduped. Invalid challenges return empty TwiML and do not send a reply.

Declines insert a workspace-scoped suppression keyed by an HMAC fingerprint. Abuse across three or more workspaces in a week inserts a 24-hour global suppression. Advisory locks and `recipient_verification_events` make the limits durable across replicas.

Delivery uses `filterDeliveryRecipients` before send and `canDeliverToRecipient` again immediately before the provider call. Eligibility-only failure sets alert status `blocked`, `next_attempt_at` null, and error `NO_VERIFIED_RECIPIENTS`. Mixed groups still send to eligible recipients. Digests skip the claim when enforce mode rejects the destination, so a later confirmation in the same week can still send.

## 4. Files changed

- `packages/recipient-verification/` policy, migration SQL, and a local copy of the email syntax check
- `apps/api/routes/recipientVerification.js`
- `apps/api/routes/contacts.js`, `whatsapp.js`, `alerts.js`, `apps/api/index.js`
- `apps/api/migrations/migrate.js` version 79
- `apps/worker/src/delivery-worker.js`, `weekly-digest.js`, `shared/recipientDeliveryGate.js`
- `apps/dashboard/src/pages/AlertPreferences.jsx` and the small verification controls beside it
- `tests/unit/recipient-verification.test.js`
- `tests/integration/api-test-whatsapp.test.js`
- `docs/recipient-verification.md`, `docs/CONFIGURATION.md`, `CHANGELOG.md`

## 5. Database

Migration name `recipient_channel_verification`, version 79. Tables:

- `contact_channel_verifications`
- `contact_verification_challenges`
- `notification_suppressions`
- `recipient_verification_events`
- `twilio_inbound_messages`

No existing contact is marked verified. Unique pending challenge per workspace, contact, and channel. Suppressions are unique per global destination and per workspace destination.

## 6. API

- `POST /api/v1/workspaces/:id/contacts/:contactId/verifications/email` sends the invitation and returns 202 without the token.
- `POST .../verifications/whatsapp` returns 201 with `share_url`.
- `POST .../verifications/:channel/revoke` sets `revoked`.
- `GET /verify/recipient/:token` renders the page. `POST .../accept` and `POST .../decline` confirm. `GET /verify/recipient/done` is the result page.
- `POST /webhooks/twilio/whatsapp/inbound` is the Twilio inbound webhook.
- `POST /api/test-whatsapp` requires `contact_id` and a verified current number. Arbitrary numbers return `CONTACT_REQUIRED` or `DESTINATION_MISMATCH`.
- Contact list responses include `verification` and `verification_summary`. The client cannot set status.

## 7. Outgoing paths

Gated: expiration email, expiration WhatsApp, endpoint-health WhatsApp, the shared delivery worker path used for renewal and agent alerts, weekly email digest, weekly WhatsApp digest, and workspace WhatsApp tests.

Not gated: account verification, password reset, welcome, billing, waitlist, workspace invite, operator incident email, admin SMTP to the signed-in operator, webhooks.

Self-hosted admin WhatsApp provider probes stay available in shadow mode. In enforce mode they require `RECIPIENT_VERIFICATION_ADMIN_PROVIDER_TEST=1`.

## 8. Tests and results

`node --test tests/unit/recipient-verification.test.js` passed, 15 tests, 0 failures. `node --test tests/postgres/recipient-verification-concurrency.test.js` passed, 9 tests, 0 failures, against PostgreSQL 16. That run applies migration `recipient_channel_verification` twice and covers workspace and user invitation limits under concurrency, abuse suppression that survives the rolled-back invitation, decline after contact recreation, one-winner confirmation, a destination change during confirmation, the public confirmation budget, and an expired challenge.

The suite uses an in-memory query double with serialized transactions. It does not open Postgres, SMTP, or Twilio. `tests/integration/api-test-whatsapp.test.js` was updated to expect `CONTACT_REQUIRED` for an arbitrary number. That file was not executed because no API server was running. The migration SQL was not applied to a live database in this run. No browser session was available on ports 3000, 3001, 4000, 5173, or 8080, so the contacts screen was not clicked through.

## 9. Limitations

- A failed invitation email still consumes the 24-hour destination slot.
- Existing mail logs can include the recipient address. The token is not logged by the new route.
- The accept POST URL contains the token until the redirect. Referrer and cache headers are set to limit leakage.
- Partial unique suppression indexes were created by applying the migration twice on PostgreSQL 16 in `tests/postgres/recipient-verification-concurrency.test.js`.
- Self-hosted verification is off unless an operator sets `shadow` or `enforce`. `shadow` still delivers.
- WhatsApp decline is implemented in the route transaction rather than the shared consume function. Email decline is in the package.

## 10. Deployment and rollback

1. Deploy the API and worker together with migration 79.
2. Set `RECIPIENT_FINGERPRINT_SECRET` and `PUBLIC_BASE_URL` or `API_URL`.
3. Configure the Twilio inbound webhook.
4. Leave self-hosted on `off` until managers are ready to collect confirmation. `shadow` records eligibility without blocking delivery.
5. Set `RECIPIENT_VERIFICATION_MODE=enforce` when ready.
6. Self-hosted rollback is `off` or `shadow`. Consent rows stay. Cloud does not honor `off`.

Do not treat this document as a production enablement on TokenTimer Cloud. Cloud enforcement is a separate deployment of the Cloud branch.
