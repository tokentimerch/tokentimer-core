# Recipient verification validation — 2026-11-02

PR: [#461](https://github.com/tokentimerch/tokentimer-core/pull/461). Tested the existing `feat/recipient-verification` branch, based on `bdff06c5`, with the fixes in this PR. No external SMTP or Twilio account was used.

## Security review

All PR review threads and the current code-scanning instances were inspected.

| Finding | Assessment and change |
| --- | --- |
| CodeQL #141, biased cryptographic randomness | Already fixed at the starting HEAD. The alphabet has 32 distinct symbols; masking a uniform byte with 31 gives each symbol exactly eight preimages. The generator is unchanged. A deterministic regression exercises all 256 byte values through invitation creation, checking all ten code characters and eight occurrences per symbol. |
| CodeQL #142, prototype-polluting assignment | Applicable at the starting HEAD. A log channel such as `__proto__` could resolve an inherited object, subsequently modified during folding. Dictionaries now use null prototypes during channel folding, merging, reconciliation and retry planning. Stored JSON and nested recipient/endpoint objects are copied using own entries, recursively excluding `__proto__`, `constructor` and `prototype`. Raw log and attempt keys are checked before assignment; settlement eligibility uses own properties. Public ledger output remains ordinary JSON objects. |
| CodeQL #136, polynomial CSR regex, open on main | Also applicable to this branch. Separate PEM prefix/suffix checks and a single body character check replace overlapping whitespace quantifiers. The 64 KiB limit, base64 canonicalization, signature validation and private-key rejection remain. A subprocess regression rejects long tab bodies with missing, malformed and valid end markers within a bounded timeout. |
| CodeQL #143, raw process-error logging in the new browser runner | The first scan of the runner identified that process errors can carry inherited environment values. The runner now prints fixed failure messages and directs diagnostics to service logs; it does not log raw process errors. |
| Vite GHSA-8g5g-mxqh-grgj; glob GHSA-3g3m-2fjr-6pw4 | The all-dependency audit found two moderate advisories beyond the production-only audit. Vite is pinned to 6.4.5. A scoped override moves affected glob versions to 14.0.2 while preserving older callback-API users on unaffected glob 7/8. The coverage consumer's synchronous glob and a c8 smoke run were exercised. |

Untrusted ledger inputs include serialized and object-form queue channels, `retry`/`required` arrays, `outcomes` channel keys, nested recipient and webhook endpoint keys, history `channel` and `metadata.recipient`/`destination`/`urlHash`, attempt channels and nested outcomes, and configured live channel lists. Both the recipient-verification helpers and the shared alert-eligibility ledger use the same sanitization. Verification display rows additionally allow only email/WhatsApp channels and known statuses. No CodeQL suppression was added.

Regressions cover all three reserved names at channel, recipient, endpoint and nested data levels; JSON and object inputs; inherited outcomes; manual retry and settlement; mixed recipient failures; legacy arrays and serialized arrays; and ordinary extension channel names. Successful recipients and webhook retry history remain intact.

## Reproduce the browser and API tests

Prerequisites: Node 24, the repository's pinned pnpm, Docker Desktop, and the Playwright Chromium browser.

```sh
pnpm install --frozen-lockfile
pnpm exec playwright install chromium
pnpm test:e2e:recipient-verification
```

The runner uses the supported PostgreSQL Compose service through a dedicated test override, and the native `dev:api` and `dev:dashboard` commands. The API runs real migrations and authentication. The browser scenarios run with development CSRF protection enabled. The subsequent existing integration tests use a separate API process with `NODE_ENV=test`, as those fixtures expect.

The disposable Compose project is `tt-recipient-browser`; its database is `recipient_browser_test` on loopback port 54339. API/dashboard ports are 44061/5173; Mailpit uses loopback ports 11025/18025. The runner rejects occupied API/dashboard ports, overrides provider configuration with local test values and removes its own containers and volume on completion. Tests assert the dedicated database identity before modifying fixtures. Screenshots, Playwright traces and service logs are written under the ignored `test-results/recipient-verification/` directory. To run one browser mode, use `pnpm test:e2e:recipient-verification --mode=enforce` (or `off`/`cloud`); API integration checks still follow it.

## Executed browser scenarios

Chromium ran against the actual dashboard, Express API, PostgreSQL 17 and SMTP transport to Mailpit. No component or API responses were mocked. Contact/group fixtures, controlled challenge expiry and signed inbound requests were created only in the disposable database/application.

| Scenario | Result |
| --- | --- |
| Create a contact in the UI; reload and read it through the API | Passed in all three modes. |
| Existing alert queue and contact-group settings; open group editor with a pending contact | Passed in all three modes. Contacts stay in their groups after address/number changes. |
| Email invitation over actual SMTP to Mailpit | Passed in ENFORCE and Cloud. UI remains Pending on invitation and GET; only explicit recipient POST records consent. |
| Verified state, reload, consumed link and replay | Passed. GET of a consumed link is read-only; replayed acceptance is invalid. |
| Expired, declined and forged links | Passed. Expired/forged links expose no acceptance form; decline persists, replay cannot restore consent, manager reinvitation returns opted-out. |
| WhatsApp link generation and clipboard | Passed. Link opens the real public page with the correct official-number `wa.me` link and ten-character CONFIRM code; no verification message is sent. |
| WhatsApp inbound consent | Passed with synthetic signed HTTP requests: invalid signature rejected; wrong sender leaves Pending; matching sender verifies; repeated message SID is idempotent. No Twilio delivery was asserted. |
| Revoke email; edit email and WhatsApp number | Passed. Revoked is visible; editing resets the changed destinations to Pending after reload. |
| Refresh, error, loading and recovery | Passed. A real PostgreSQL lock/cancellation produces a 500; existing contacts remain visible with an error and Retry. Retry displays loading and succeeds after unlock. Stopping Mailpit produces a real API 502 and UI error; restarting it allows a new SMTP invitation without consuming another destination allowance. |
| Viewer versus workspace manager/admin | Passed in all modes. Viewer writes/invites/revokes return 403 and the preferences route is inaccessible; managers can create contacts/invitations and edit contacts. Admin actions are exercised throughout. |
| Self-hosted OFF | Passed. Verification controls are absent, the API reports off and an unverified saved-contact WhatsApp test reaches the configured dry run. |
| Self-hosted ENFORCE and Cloud | Passed. Unverified WhatsApp tests return 403. Cloud still reports enforce with `RECIPIENT_VERIFICATION_MODE=off`. |
| Browser runtime errors | None observed by the admin-page error listener. No browser request to a Twilio provider was made. |
| Vite file-deny bypass regression | Passed in all modes. Requests for a temporary, non-secret `.env.*` canary with `?raw`, `?import&raw` and `?import&url&inline` all return 403 without its contents. The file is removed afterward. |

Total: **31 passed** (12 ENFORCE, 7 OFF, 12 Cloud). Five consent-only scenarios are intentionally skipped in OFF because those controls are absent; those scenarios ran in both enforcement deployments.

## Other validation

- Full backend unit suite: **2,932 passed** (`pnpm run test:unit`).
- PostgreSQL: **24 passed** across verification concurrency, contact atomicity, delivery timeout/retry, digest claim ownership and the real delivery-worker ledger tests. The dedicated migration-upgrade test also passed (**1**), retaining migration history and applying verification/digest migrations at 84/85 on a fresh ledger.
- Running API: **12 integration tests passed**, including `api-test-whatsapp`, contacts CRUD, contact-group settings/RBAC and group reassignment; **8 runtime contract tests passed**. These run as part of the browser command.
- Focused dashboard unit tests: **44 passed** across contact-group creation, assignment and onboarding contact setup (`pnpm --filter @tokentimer/dashboard exec vitest run tests/unit/contactGroupCreation.test.jsx tests/unit/contactGroupAssignment.test.js tests/unit/onboardingContactSetup.test.js --maxWorkers=2 --no-file-parallelism`).
- Dashboard lint, formatting, type check and production build passed; API/worker lint passed with existing warnings. Contract manifest/integrity, lockfile override and secret-logging checks passed. Offline contract tests: **47 passed**.
- Production and all-dependency audits passed the moderate threshold after the Vite/glob updates; **one low** advisory remains: deepmerge GHSA-gcqx-w48m-w2h4 through react-joyride/react-floater, with no patched release listed. The latest main Docker Build & Security Scan was successful: [run 41199587659](https://github.com/tokentimerch/tokentimer-core/actions/runs/41199587659/job/124534535866). Images were not rebuilt locally because Dockerfiles did not change.
- All four standard Compose configurations and the Helm template verification script passed locally.

## Limits

The full dashboard Vitest run stalled locally with repeated jsdom XMLHttpRequest connection errors, both with default parallelism and serialized file execution. Those runs were stopped; the 44 focused dashboard tests above passed. Full Core CI, full coverage and the complete Docker integration suite are not claimed.

SMTP acceptance was demonstrated only by the local Mailpit sink. WhatsApp tests used synthetic signed inbound requests and an outbound dry run. External SMTP deliverability, Twilio acceptance and confirmation through an actual WhatsApp client remain untested because no external provider credentials were configured for this validation.
