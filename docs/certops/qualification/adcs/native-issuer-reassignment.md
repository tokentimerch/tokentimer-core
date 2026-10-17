# Native AD CS issuer reassignment

This source is the confirmed AD CS issuer switch followed by one real renewal migration.
The six public API cases in the issuer-switch qualification remain integration evidence.
This journey has not executed against a disposable forest. Pure proof refusals establish
the report contract only. The native cell remains pending.

`tests/e2e/helpers/certops-native-issuer-reassignment.js` confirms two issuers through
the public API. Each confirmation is a real preflight, confirmation of the observed
CA key, and a fresh post-confirmation preflight. The two observed CA keys must differ.
A same-CA confirmation cannot pass. All four dispatches must be counted in the parent
workspace preflight budget.

The helper then issues and installs one `TTQualificationRSAShort` certificate on the
origin issuer. The public profile update moves only `issuerId` to the destination.
Renewal policy, target, and key mode stay as stored, and the update writes one
`CERTOPS_RENEWAL_PROFILE_UPDATED` audit. The manual renew route must return HTTP 409
`CERTOPS_ADCS_RENEWAL_NOT_MANUAL` and create no renew job.

The migration itself is one production scheduler sweep. Due selection uses the stored
expiry and the default SQL clock. The six-day certificate is already inside the stored
30-day renewal window, so the helper does not change clocks, journals, or job results.
The renewal enrollment must freeze the destination issuer, CA config, and confirmed CA
key. Its leaf must verify against that CA key and must not verify against the origin CA
key. The successor replaces the same IIS and HTTP.sys SNI coordinate. The predecessor
certificate and non-exportable machine key remain in the parent-owned store.

The helper sets `nativeCell` to `pending` on both the closed report and a completed
proof. A completed host report is not catalog qualification.

## What a missing forest does

`node tests/e2e/helpers/certops-native-issuer-reassignment.js` writes
`qualification-results/native-issuer-reassignment.json` with status `failed`, cleanup
`failed`, and `nativeCell` `pending`, then exits 1. Lab markers alone do not call
`qualifyNativeIssuerReassignment`. The manual workflow is `workflow_dispatch` only and
does not provision a forest. Its always step rejects any report that is not a completed
strict qualification. Until `native-adcs-issuer-reassignment` is registered, the strict
verifier also reports that the suite has no committed scenario specification.

## Parent integration contract

Call `qualifyNativeIssuerReassignment` from the disposable forest harness before any
other native cleanup. The gate must already be preflighted with suite
`native-adcs-issuer-reassignment`, evidence level `real-host`, and fixture source
`tests/e2e/helpers/certops-native-issuer-reassignment.js`. The context supplies two
distinct CA configs, the authenticated fixture, `jobFinished`, the trusted TLS
authority resolver, and the native command oracles.

`reservePrimaryPreflights(4)` accounts for both issuers' preflight and
post-confirmation preflight. Skipping a preflight is not allowed.

Declare `domain(run)` on the agent before the service starts. `run` is ten lowercase
hex digits. `registerOwnedStoreCertificate({store: "My", domain, certificateId})` is
mandatory before the enrollment POST. Append each enrollment id before waiting for
native completion. Unresolved native ownership must fail the run and stay with the
parent. This helper does not remove the forest.

The background scheduler interval is not qualified. Reverse migration back to ACME,
failure rollback, and a second renewal generation are outside this source.
