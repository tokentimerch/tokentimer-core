# Main merge validation — 9 October 2026

The PR branch now includes main through `fdb92438ce3de345e14520a845858b3dd7797b1a`. Merge commits `4acbda28` and `3e670b8e` preserve the existing PR history.

## Why the conflicts happened

The feature branch began from Core v0.17.3. Main subsequently added the AD CS wire contracts, dispatch-only enrollment fields, and an issuer interface that moved ACME order/output handling out of the agent's main execution module. Both branches changed the same execution and schema sections.

Git reported seven conflicted files: API job validation, agent execution, the protocol source schema, its vendored copy and generated validator, the certificate job schema, and OpenAPI. Three of those files represent one protocol contract. The later main commits adding the CMC reference helper and CODEOWNERS merged without conflicts.

## Resolution

- Preserve main's issuer interface. Vault stages the public certificate returned by the issuer alongside the protected staged key, then follows the existing publication/recovery path.
- Preserve the control-plane-only issuer/enrollment input guard before validating Vault execution fields.
- Retain both Vault distribution and AD CS actions/result fields. Route `deploy-from-store` through the certificate job schema and reject Vault publication/deployment fields on AD CS enrollment jobs.
- Regenerate the vendored protocol schema and standalone validator from the canonical contract.
- Keep the SAN-only renewal profile fix, administrator repair endpoint, immutable manual version identity, issuer pinning, and previous allocation/binding/rollout review fixes.

## Executed checks

- 2,307 unit tests passed, including a mixed Vault/AD CS contract regression.
- Native Windows agent suite: 1,554 passed, 15 skipped, zero failures (1,569 total). It includes real package creation, self-contained source checks, Windows ACL/CNG regressions and issuer tests. The cached Go 1.26.6 compiler was supplied on the test process's PATH.
- The newly merged AD CS CMC reference helper passed `go test ./...` in both packages.
- 42 contract tests passed; contract/OpenAPI coverage and integrity, lockfile overrides, secret-logging guard, API/agent/worker lint, shipped source/installer parsing, production dependency audit and dashboard build passed. Existing lint/build warnings remain.
- All 17 user/API lab checks passed in fresh project `tt-wildcard-ux-20261009-merge2`, workspace `5daaf885-b0db-414e-8fa0-1910a6d53f32`, with three ACME invocations and no database injection.

The lab verifies SAN-only issuance, renewal profile preservation and authorization, concurrent unchanged bindings, approval identity replay, rejection/allocation release, real binding revision changes, cross-tenant denial, lost Vault responses, retry of the original publication, recovered-key reuse and offline HAProxy catch-up. nginx and HAProxy serve the renewed certificate with trusted probe evidence.

The first merged replay caught a lab reload race: nginx accepted the signal before its replacement worker served TLS. The agent correctly returned uncertain deployment and did not mark that consumer current. The customer reload hook now waits for a trusted handshake serving the installed certificate before returning; the agent still performs its own independent probe. A fresh complete replay passed.

The Windows agent suite also exposed a fixture connection race: synchronous ACL work could outlast the local HTTP server's default idle timeout. The protocol fixture now keeps that connection valid and uses a suitable test transport deadline. Production transport failures remain fenced. Earlier failed attempts and logs were retained.

Machine-readable replay evidence: `validation-merge-2026-10-09.json`. Local logs are in `.scratch/tt-wildcard-ux-20261009-merge2/` and `.scratch/merge-*.log`. The final lab remains running at <http://127.0.0.1:58801>; previous UX lab volumes/evidence were retained. The original manual audit database was untouched and remained healthy with start time `2026-10-07T08:43:12.063869281Z`.

This is source-mounted Core functional validation, not full release CI parity or customer qualification. The three distribution capabilities remain experimental. Real appliance/HA adapters, Cloud billing, Enterprise licensing, historical migration backfill and never-claimed cancellation are outside this API journey.
