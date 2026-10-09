# Executed user/API lab — 9 October 2026

**Historical r4 result: all 17 journey checks passed.** This installation was subsequently stopped with volumes/evidence retained. The latest replay after merging main is documented in `MERGE-VALIDATION.md`. The harness uses public HTTP APIs, normal session/CSRF authentication, separate owner/approver actions, real enrolled agents and customer-host controls. No database fixtures or direct SQL injection were used.

- Core source: base commit `63a8aa37909b71ab5086fe50ea6839eeb79735f5`, plus the local renewal fixes and lab files.
- Project: `tt-wildcard-ux-20261009-r4`.
- Workspace: `ebc3703c-17de-444c-9a74-4bd4dc547131` (`Wildcard API UX Lab 2f2926f1`).
- Certificate: `9d30041e-7f7e-422a-a8cb-fbf0085261f8`.
- Distribution group: `98660df5-ac06-486a-b460-eef9cfeda7ef`.
- Initial issuance: `ba65d017-6d3e-4f40-8e30-654f2dcfe542`.
- Rotated renewal/recovery: `f0233d1b-0cb6-4b94-b297-42fe4037abdf`.
- Renewal reusing the recovered key: `298292f2-1264-4bdc-8965-4f8c6ae6be23`.

## Fixed behavior and executed evidence

A SAN-only certificate now derives its renewal profile from the originally approved domain, only when that name is present in the issued SANs. Vault publication custody is renewable through its validated publication destination; it does not enable generic filesystem deployment. Manual renewal defaults to the distribution group's pinned issuer. Separate manual requests receive separate immutable version IDs, while an idempotent replay retains its original ID.

The newly issued SAN-only wildcard immediately exposed a profile and automatic renewal state. Empty-body repair replay kept that profile; the separate approver received 403, and execution-setting input received 422. After the owner changed the rotation policy to reuse the key, another repair call preserved that setting.

The formerly failing r3 certificate, issued before the fix with no profile, was repaired through the new administrator API. Replay returned the same profile and public detail reported automatic renewal. Evidence is retained in `.scratch/tt-wildcard-ux-20261009-r3/journey-state.json`. That stack was then stopped; its volumes and evidence were retained.

The fresh r4 journey exercised normal invitation/email verification, three enrolled agents, approved real DNS-01 issuance, publication to Vault and real nginx/HAProxy deployment. Concurrent unchanged PUTs preserved binding revisions and proof. Rollout retries before approval, after completion and after membership changes retained their original approval identity. Changed parameters returned 409. A genuine binding change invalidated old proof and a reviewed rollout restored convergence. A cross-workspace request was denied.

An approver rejected a never-claimed renewal. Its failed version retained history with the allocation released. A corrected request allocated another version in the same group. The customer proxy then dropped a committed Vault write response and blocked readback, including versioned GET requests. The agent retained the old canonical key, and a new issuance request remained fenced.

That fence initially surfaced as HTTP 500 despite the service's correct conflict code. The route mapping was fixed and the same lab resumed from its failed original renewal; no certificate/order or database state was manufactured. The API now returned 409 `CERTOPS_PUBLICATION_UNRESOLVED`. Clearing the customer fault and retrying the original job recovered the committed Vault version, promoted the rotated key into the custom directory with mode 0600 and created no extra ACME order.

The next real ACME CSR reused that recovered key. With the HAProxy agent stopped, nginx moved to the renewed certificate while HAProxy continued serving its old certificate and remained stale in the matrix. Restarting HAProxy converged through a signed pinned deployment. The issuer recorded exactly three certbot/ACME invocations: initial issuance, rotation, then key reuse; recovery and consumer catch-up added none.

## Verification and limits

All 2,278 unit tests and 42 contract tests passed, along with contract checks, API/worker/dashboard lint, dashboard formatting/type-check/build, lockfile overrides, secret-logging guard and production dependency audit. API lint retains existing warnings; the dashboard build retains its existing bundle-size warning. The latest main CI Docker Build & Security Scan inspected was successful (run `37931620474`); that is separate from validation of these local changes.

This is source-mounted Core functional testing with a lab-only experimental agent artifact, Pebble CA and development Vault token. It does not qualify real appliance adapters, production images, Cloud billing or Enterprise licensing, and is not full release CI parity. Never-claimed cancellation and historical migration backfill are not fabricated through this journey; they require separate regression evidence.

Browser sign-in and navigation confirmed the issued certificate shows auto-renew **On**, last attempt **Succeeded**, and its derived profile. Both live consumers showed **Verified and current**, generation 3. Screenshots are saved as `renewals-ui.png` and `automatic-renewal-ui.png` in the run evidence directory. The second certificate with **No expiry** belongs to the intentionally rejected issuance; the extra unassigned consumer row is retained history from the membership replay test.

The machine-readable result is `validation-2026-10-09.json`. Full transcripts, state and logs are retained in `.scratch/tt-wildcard-ux-20261009-r4/`. Original failure evidence is preserved in `VALIDATION-before-renewal-fix.md` and `validation-before-renewal-fix-2026-10-09.json`. The original manual audit PostgreSQL remains healthy with unchanged start time `2026-10-07T08:43:12.063869281Z`.
