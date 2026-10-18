# API, browser and worker qualification

Run these scopes only against their disposable fixtures. Use the committed suite and case inventories for exact assertions; missing prerequisites, skipped mandatory cases, stale fingerprints and failed cleanup cannot qualify. Supporting API/browser evidence does not replace native host evidence. Catalog statuses and pending native work remain authoritative. Local worktree reports cannot fill hosted release slots; report evidence levels and native qualification remain separate from source implementation.

The standard API runner is `node scripts/certops-api-qualification.js`; browser, scheduler, retention, signing and alert scopes use their named manual workflows. Global worker sweeps require exclusive disposable stacks. Start with the [qualification overview](../../e2e-qualification.md).

## Issuance admission and workspace pause qualification

Authenticated API/PostgreSQL fixtures verify signed issuance admission, pause/resume, passive discovery during pause and refusal to derive incomplete renewal profiles. Pausing blocks new claims and issuance while preserving heartbeats, existing results and factual observations. These are supporting integration scopes; no issuer or native certificate store executes.

Scopes: `first-issuance-admission-api`, `pause-ingestion-api`, `derivation-failure-api`.

## Certificate audit history qualification

`certificate-audit-api` runs eight strict named scenarios through actual authenticated API routes and PostgreSQL. The central API qualification runner includes it automatically; `CERTOPS_AUDIT_REPORT` selects its sanitized report.

## Browser certificate audit qualification

Chromium exercises real public retirement audits, literal percent/underscore search, action filters, stable pagination and foreign-workspace refusal against PostgreSQL. Browser results must match independently queried event identities. Cleanup removes only the owned fixture; reports exclude cookies, private keys and raw audit rows.

Runner and report settings: `node scripts/certops-browser-audit.js`, `CERTOPS_CSR_API_URL`, `CERTOPS_BROWSER_URL`, `CERTOPS_BROWSER_AUDIT_REPORT`.

Run prerequisites: `CERTOPS_CSR_DISPOSABLE_STACK=1`.

Scopes: `browser-certificate-audit`.

## Completed console authorization

The `browser-agent-console` suite verifies that stream finalization leaves a noop claimed until its real result arrives. Completed consoles revalidate authorization every 15 seconds; status-only or HTTP 401/403 responses clear cached text and cursor. Restored permission reloads retained history once, and unmounting cancels polling. Foreground qualification permits a 30-second observation bound, not instantaneous revocation.

## Browser execution-console qualification

The `browser-agent-console` suite runs Chromium against the real dashboard, API and PostgreSQL using registered protocol agents and signed noop claims. It checks live console authorization, reconnect behavior and secret-sentinel exclusion. It does not execute an installed certificate operation.

Runner and report settings: `CERTOPS_BROWSER_CONSOLE_REPORT`.

## Retired certificate visibility in the dashboard

The `browser-retirement-visibility` suite runs actual Chromium against a disposable dashboard, API and PostgreSQL stack. Two owned TLS endpoints provide independently trusted public certificate fingerprints. Public monitoring and retirement requests establish revoked and decommissioned identities; no observation rows or successful jobs are seeded.

Runner and report settings: `CERTOPS_CSR_API_URL`, `CERTOPS_BROWSER_URL`, `CERTOPS_BROWSER_RETIREMENT_REPORT`, `node scripts/certops-browser-retirement.js`.

Run prerequisites: `CERTOPS_CSR_DISPOSABLE_STACK=1`.

## Mixed eligible bulk renewal admission

The central API qualification runner executes six mandatory `bulk-eligible-api` scenarios against a disposable API/PostgreSQL fixture with OpenSSL. Genuine public certificate imports have complete linked renewal profiles and agent-local admission metadata seeded as explicit prerequisites. No CA or native agent executes these jobs.

## Public CA capacity admission qualification

`ca-capacity-api` covers concurrent public issuance admission. Six simultaneous public issuance requests admit exactly five pending approval jobs under the default per-CA cap; the sixth receives the documented capacity conflict. Idempotency still resolves the existing job at capacity. Canonical endpoint variations cannot split one bucket, a different CA remains independently eligible, and an actual requester rejection releases capacity for another request. Failed reservations preserve job, certificate and outbox counts.

## Certificate transfer qualification

The central `scripts/certops-api-qualification.js` runner executes `tests/e2e/certops-certificate-transfer-e2e.test.js` against the explicitly disposable API/PostgreSQL stack. The `certificate-transfer-api` report requires every committed named scenario and the current test source digest. It is supporting control-plane integration evidence.

## CSR observation qualification

The authenticated API runner requires `csr-observation-api` and `csr-bound-observation-api`, using real TLS endpoints and OpenSSL certificates. A matching observed leaf can complete a reviewed CSR; a replacement observed during pending name review must preserve the selected identity and token expiry until acknowledgement. Replay retains observation provenance; observation does not become manual installation attestation.

## Shared CSR ownership and truthful installation evidence

`csr-provisional-api` exercises shared provisional ownership, last-reference cancellation races, manual confirmation without invented physical instances, and real TLS observation. A sibling cancellation must preserve an active or observed identity. Conflicting ownership cannot transfer identity, expiry or audit provenance. OpenSSL keys stay in the owned fixture; these controls do not qualify native key custody.

Scopes: `csr-provisional-api`.

Runner and report settings: `CERTOPS_CSR_PROVISIONAL_REPORT`, `CERTOPS_CSR_API_URL`, `GITHUB_SHA`.

```powershell
$env:CERTOPS_CSR_PROVISIONAL_REPORT = "qualification-results/csr-provisional.json"
node --test tests/e2e/certops-csr-provisional-e2e.test.js
node scripts/certops-qualification-report.js $env:CERTOPS_CSR_PROVISIONAL_REPORT
```

Run prerequisites: `CERTOPS_CSR_DISPOSABLE_STACK=1`, `CERTOPS_E2E_REQUIRED=1`, `CERTOPS_QUALIFICATION_STRICT=1`.

## Decommission acknowledgement and factual rediscovery

`decommission-lifecycle-api` requires explicit uncertainty acknowledgement (`428 CERTOPS_VISIBILITY_ACK_REQUIRED`) before terminal decommissioning. Registered filesystem observations and later real TLS rescans remain factual evidence without reactivation, duplicate identities or additional retirement audits. No installed agent removal is claimed.

Runner and report settings: `node --test tests/e2e/certops-decommission-e2e.test.js`, `CERTOPS_DECOMMISSION_REPORT`.

Run prerequisites: `CERTOPS_E2E_REQUIRED=1`, `CERTOPS_CSR_DISPOSABLE_STACK=1`.

## Fleet execution-log quota qualification

`agent-log-quota-api` uses registered noop claims and production PostgreSQL log ingestion with a fixture 1000-byte daily budget. Racing streams share one budget; replay does not charge again, workspaces remain independent, disabled storage does not charge, and telemetry finalization preserves job state. Native fleet load and elapsed retention remain separate.

Runner and report settings: `CERTOPS_LOG_QUOTA_REPORT`.

## Certificate import metadata preservation

`import-metadata-api` checks that repeated and concurrent public reimports preserve certificate/token identity, provenance, operator name, contacts, description and group memberships. Invalid group/contact edits fail atomically. OpenSSL and real API/PostgreSQL persistence support these controls; provider delivery and native host concurrency are not qualified.

## Certificate-producing integration source qualification

The [source inventory](../../integration-source-inventory.json) covers AWS ACM, Azure Key Vault, Google Certificate Manager/Compute SSL and Vault KV/PKI. Production scanners use SDK/HTTP fixtures; real API/PostgreSQL tests enforce persisted source provenance, authorization, incomplete-scan preservation and newer-observation fences. This does not contact live providers or establish issuance, deployment or custody. Run `node scripts/certops-integration-source-inventory.js` to check mappings.

Runner and report settings: `CERTOPS_CSR_API_URL`, `CERTOPS_API_WORKER_FIXTURE_KEY`, `CERTOPS_INTEGRATION_SOURCES_REPORT`, `node --test tests/e2e/certops-integration-sources-e2e.test.js`, `node scripts/certops-qualification-report.js <report.json>`.

Run prerequisites: `CERTOPS_CSR_DISPOSABLE_STACK=1`, `DB_*`, `CERTOPS_E2E_REQUIRED=1`.

## Public renewal issuer switch policy

The `profile-issuer-switch-api` suite contains six mandatory cases executed through the real authenticated API and PostgreSQL database. A valid confirmed AD CS issuer reassignment preserves the immutable deployment/key policy and writes its audit event. Unconfirmed, foreign-workspace and incomplete reverse-to-ACME switches atomically preserve every profile field and audit count. Repeating the same issuer produces the documented no-change response without jobs or additional audit writes.

## Actual elapsed log abandonment and production worker retention

The manual `certops-log-maintenance-qualification.yml` workflow requires an exclusive disposable API/PostgreSQL stack because purge is global. A real registered noop result starts the production 300,000-millisecond grace. The unchanged maintenance sweep must observe the actual deadline, refuse foreign fixture data, and preserve owned cleanup; database dates are not rewritten. No push starts the five-minute wait.

Runner and report settings: `CERTOPS_LOG_MAINTENANCE_REPORT`.

Run prerequisites: `CERTOPS_AGENT_LOG_RETENTION_DAYS=0`, `CERTOPS_LOG_MAINTENANCE_EXCLUSIVE_STACK=1`, `CERTOPS_CSR_DISPOSABLE_STACK=1`.

Scopes: `agent-log-maintenance-worker`.

## Multi-target filesystem deployment qualification

`multi-target-deploy-api` runs the production deployment coordinator against actual temporary filesystem destinations and independently generated end-entity certificates and keys. A registered protocol agent owns a genuine noop claim. The coordinator's step evidence travels through authenticated API ingestion under that claim; the fixture adapter assigns evidence identifiers and does not replace filesystem operations or return fabricated API responses.

## Native Linux certificate dry-run

The `native-agent-api` suite includes four certificate-operation scenarios in addition to its existing signed noop dry-run. The fixture runs the unmodified Linux Node agent against the actual API/PostgreSQL stack. Owned CA-signed certificates, restrictive custody files, a real TLS listener and independent command/gateway counters distinguish a useful dry-run from an unconfigured path that could never mutate anything.

The generic public job route intentionally does not expose a selectable execution mode. These scenarios explicitly call the production `createCertificateJob` service with `mode: "dry_run"`; the normal public certificate import, real signing, native claim/lease/result handling and persisted evidence remain in use. Jobs, dispatches, nonces, successful outcomes and evidence rows are not fabricated.

## Public certificate import and private container refusal

`tests/e2e/certops-public-import-e2e.test.js` runs twelve mandatory supporting scenarios against an authenticated disposable API and PostgreSQL stack. It verifies public PEM identity facts against OpenSSL and Node's independent X509 parser, repeated and concurrent identity conservation, PEM bundles, malformed/oversized input, source-reference restrictions and private material refusal. Exact DER parsing is explicitly classified as supporting unit evidence rather than a binary HTTP upload.

Scopes: `public-import-api`.

Runner and report settings: `CERTOPS_PUBLIC_IMPORT_REPORT`.

## Queued renewal profile snapshot qualification

Six mandatory supporting integration cases exercise real public manual-renew admission, operator profile editing, independent approval and authenticated signed dispatch. The initial request waits for approval with its original RSA 2048 profile. Editing the live profile to RSA 4096 must preserve every queued payload field. Approval binds the original canonical payload hash, and the actual signed claim must cryptographically verify against the registration public key while retaining the original profile digest. A subsequent request uses the edited RSA 4096 policy without changing the first job.

## Renewal outbox and SMTP qualification

The separate manual `certops-renewal-alert-qualification.yml` workflow executes eight mandatory supporting integration scenarios against only an isolated API, PostgreSQL and MailHog. The source admits a renewal through the production job service, claims it using a genuinely registered protocol client, reports a fixture failure through the real authenticated result endpoint, drains the production outbox resolver and starts the actual delivery-worker process. An independent MailHog receipt must match the run-owned recipient and MIME-decoded renewal subject. Terminal replay, public first-issuance failure, requester approval rejection and a completed dry run must leave one owned renewal alert.

### Native proxy refusal

The Ubuntu certbot bulk-scope journey can extend the same outbox and delivery path after a certificate is already serving. It admits one public renewal, then refuses `new-order` on the owned qualification proxy. The refusal is counted only for requests the proxy recorded and did not forward. The current claim fails, one nonce is consumed, and the serving certificate, private key and trusted TLS fingerprint stay in place. No additional issuance response is counted. This composition is a controlled proxy fault. It is not evidence of a native CA run.

Runner and report settings: `CERTOPS_NATIVE_RENEWAL_MAILHOG_URL`, `CERTOPS_NATIVE_RENEWAL_SMTP_PORT`.

## Renewal path topology qualification

The mandatory `renewal-health` supporting integration group executes fifteen existing production resolver cases against actual PostgreSQL. It covers pinned and open-claim execution paths, redundant executors, partial/all-location outage forecasts, retired agents, missing target/profile/custody, disabled profiles, retired certificates and dependency counts. No SQL query or resolver is mocked.

## Renewal public-key metadata correctness

The `renewal-key-facts-api` suite exercises seven mandatory named scenarios against a disposable authenticated API/PostgreSQL fixture and actual OpenSSL RSA/EC public certificates. Signed agent claims, evidence and result requests exercise the production renewal completion path. Complete execution-profile and key-mode rows are explicit fixture prerequisites.

## Retirement and fresh observation qualification

The seven mandatory `retired-observation-lifecycle` cases run through the actual authenticated API and PostgreSQL with an owned HTTPS endpoint. OpenSSL generates two public leaves and their local private keys. An independent TLS client trusts only those fixture certificates and verifies the exact served fingerprint before each rotation.

## Automatic renewal after identity retirement

The trusted manual `certops-scheduler-capacity-qualification.yml` workflow runs
`certops-retired-scheduler-e2e.test.js` sequentially after the existing capacity
and toggle fixtures have removed their resources. It requires an exclusive
API/PostgreSQL database, OpenSSL and `CERTOPS_SCHEDULER_EXCLUSIVE_STACK=1`.

Expected refusal: `CERTOPS_CERTIFICATE_NOT_RENEWABLE`.

## Retirement, approval and dispatch races

`retirement-approval-api` exercises public renewal approval against operator retirement with real PostgreSQL and authenticated registered-agent claims. Complete linked agent-local renewal profiles/key mode are explicitly seeded prerequisites. Public OpenSSL certificate imports create identities; public endpoints create every job, approval and retirement. No job, observation, expiry or claim timestamp is seeded.

## Scheduler and public admission capacity

The separate manual `certops-scheduler-capacity-qualification.yml` workflow creates a fresh API/PostgreSQL stack, runs six mandatory supporting integration scenarios, verifies the report and destroys the stack even after failure. It is deliberately separate from concurrent API suites: the production scheduler scans globally. The test requires `CERTOPS_SCHEDULER_EXCLUSIVE_STACK=1` and refuses any foreign active automation period before creating its own.

Scopes: `renewal-toggle-scheduler-api`.

### Automatic renewal toggle boundaries

The same exclusive workflow runs `renewal-toggle-scheduler-api` after the capacity suite has cleaned its fixture. Seven mandatory supporting integration scenarios use actual public certificate imports, public profile edits, real PostgreSQL and production SQL-NOW scheduler/admission code:

## Native signing key rotation qualification

The manual `certops-signing-rotation-qualification.yml` workflow runs nine mandatory scenarios against a fresh disposable API and PostgreSQL stack on Ubuntu 24.04. It starts two unmodified native Node agents, observes actual signed public noop jobs, and invokes the production operator CLI for status, begin and completion. A stopped agent prevents completion until its actual heartbeat adopts and acknowledges the new pin. Restarted agents must retain credentials and execute a new-key signed job exactly once.

## Terminal certificate renewal admission

`terminal-renewal-admission-api` verifies that public manual and bulk renewal cannot revive an operator-retired identity. Seven mandatory scenarios use real authenticated API requests, PostgreSQL, public certificate imports and independently trusted loopback TLS. Complete linked agent-local renewal profiles/key mode are explicit SQL prerequisites. No jobs, certificate expiry or observations are seeded.

## Unmanaged discovery qualification

`unmanaged-discovery-api` invokes the production filesystem collector against an actual temporary public certificate file, then sends its observations through a registered protocol agent to the real API and PostgreSQL database. OpenSSL generates the certificate; its public fingerprint is independently calculated before collection. The private key lives outside the scanned directory, and the fixture never advertises Windows CNG or machine-store custody.
