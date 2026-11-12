# Recipient verification

Self-hosted delivery keeps verification off by default. In `enforce` mode, a contact matching a current workspace member's exact verified mailbox needs no second email confirmation; other email addresses and WhatsApp numbers require their own confirmation. Membership removal or lost mailbox proof ends inherited eligibility. Opt-outs, revocations and suppressions still take precedence. Use `shadow` to evaluate eligibility without blocking delivery during rollout. Run the standard migrations before starting matching API and workers.

## Configuration

- `RECIPIENT_VERIFICATION_MODE`: `off` bypasses verification, `shadow` logs eligibility while delivering, and `enforce` requires eligibility. Configure the same mode on the API and notification workers.
- `RECIPIENT_FINGERPRINT_SECRET`: shared HMAC key for destination fingerprints and verification tokens; falls back to `PHONE_HASH_SALT`, then `SESSION_SECRET`.
- `PUBLIC_BASE_URL`: public API origin for confirmation links and Twilio inbound signature validation; falls back to `API_URL`.

See [configuration variables and limits](CONFIGURATION.md#recipient-verification) for defaults.
