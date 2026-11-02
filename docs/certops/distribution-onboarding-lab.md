# Material-store and consumer onboarding lab

The existing `/onboarding` wizard's **Share one certificate across servers** goal
now uses **Configure material store** and **Connect and validate consumers** in
place of the single long Vault setup screen. Its goal/session identity remains
`certops_vault`; configuration, agent installation, execution, recipients and
final verification remain in the existing planner. There is no second wizard.

## Fast reproducible checks

Use Node 24, pnpm 11.28.8 and the existing PR branch checkout:

```powershell
pnpm install --frozen-lockfile
pnpm --filter @tokentimer/dashboard exec vitest run tests/unit/materialSetupModel.test.js tests/unit/onboardingMaterialStore.test.jsx tests/unit/onboardingMaterialConsumers.test.jsx
node --test tests/unit/onboarding-material-setup.test.js
node tests/e2e/onboarding-material-browser.cjs
```

The browser command needs the repository's Playwright dependency and installed
Chromium (`pnpm exec playwright install chromium` if missing). It runs the real
components at desktop and mobile widths against **synthetic HTTP fixtures**,
checks public-reference persistence, binding requests, verification-only intent,
independent approval, persisted completion/reopening and Windows gating, and
checks for document overflow and browser exceptions. It creates an ephemeral
loopback-only Vite harness, removes it on exit, and leaves screenshots and
`report.json` in `.scratch/onboarding-material-browser-evidence/`. This is UI
evidence, not live provider/IIS or release-artifact qualification.

## Real Vault/OpenBao lab: reuse a verified publication

Use the existing [customer/API lab](../../tests/wildcard-vault/ux-lab/README.md).
It owns separate Docker containers, PostgreSQL, mail capture, a real KV v2
service, Pebble CA, full agents and real nginx/HAProxy listeners. Docker Desktop
and available image-build space are required. Use a new project name each time;
never attach this lab to a production or audit database.

```powershell
$project = 'tt-wildcard-ux-onboarding-openbao-20261102-a'
./tests/wildcard-vault/ux-lab/run.ps1 -Action Up -Project $project -BasePort 60800 -MaterialProvider openbao-kv2 -BuildImages
./tests/wildcard-vault/ux-lab/run.ps1 -Action Test -Project $project -Phase functional
./tests/wildcard-vault/ux-lab/run.ps1 -Action Status -Project $project
```

Repeat with a fresh project, free port range and `-MaterialProvider vault-kv2`
for Vault. `functional` retains the workspace for review; do not run the final
workspace-transfer phase in a lab you intend to keep. These are source-mounted
functional checks, not production-package qualification.

1. Open `http://127.0.0.1:60801`. Sign in using the lab-only owner credentials
   documented in the lab README, and select its generated workspace. Keep the
   separate approver account/session available; do not share session cookies.
2. Open `/onboarding`, choose **Share one certificate across servers**, choose
   the existing Linux issuer and complete/review the preceding configuration,
   installation and signed execution-check steps. Reuse the issuer's actual
   existing settings; do not overwrite its identity or local state.
3. In **Configure material store**, select **Use an existing publication**.
   Choose the lab group and save its public references. Provider, issuer, store
   reference, issuance profile and revision come from persisted backend metadata.
   Confirm **Agent publication verified** only appears for that exact group.
   No store address or credential needs to be entered for evidence reuse.
4. Continue to **Connect and validate consumers**. The backend's current
   consumer matrix and real rollout evidence can satisfy this step. Installed
   files and live TLS verification remain distinct. Inspect the same group's
   Deployments view and independent TLS evidence in the lab report.
5. Use **Check installed material (no deployment)** on the already configured
   group. Inspect the request's `verificationOnly: true`, exact material version,
   pending approval and signed consumer jobs. Approve as the other manager.
   A verification-only request never installs, rebinds, reloads or imports keys,
   and does not itself satisfy the guide's real-deployment completion predicate.
6. Refresh, reload the browser, navigate back/forward and return to the guide.
   Check that public choices/job references resume, while host-local address/CA
   inputs must be entered again. Do not reissue a certificate to recover a lost
   HTTP response. Publication/verification retries retain their original request
   key and exact intent.
7. Revoke a fixture consumer's read permission or introduce drift using the
   lab's documented customer controls. Refresh and inspect failure, stale or
   uncertain evidence. Completion must reopen. Preserve journals/checkpoints,
   reconcile on the customer host, use the existing original-job retry and
   resume controls, and obtain a fresh approval when authorization changed.

The fixture lab's internal KV listener uses its existing explicit test HTTP
transport. The wizard deliberately does **not** relax production HTTPS
validation to generate new host configurations for that listener. The preceding
walkthrough reuses its existing protected configurations and accepted evidence.
For a new publication through the wizard, use the HTTPS setup below.

## Fresh publication and Linux destination walkthrough

Prerequisites: a customer-owned HTTPS Vault/OpenBao KV v2 listener, a Linux issuer
with the registered `certbot` profile and DNS-01 credentials, a separate consumer,
the existing protected agent configuration, and a staging/private CA test domain.
Follow the [Vault Agent authentication runbook](vault-agent-authentication.md)
for narrow AppRoles and renewable protected token sinks. Use OpenBao Agent/`bao`
equivalents for OpenBao; namespaces and KV v1/PKI are unsupported there.

1. Choose provider, issuer, public store reference, issuance profile reference
   and revision. Missing/stale capabilities and unsupported platforms are shown
   per agent. Save references; never paste a token, key or credential into any
   wizard field.
2. Run the signed agent check. Its top-level `mode: dry_run`, `operation: noop`
   proves dispatch only. It does not prove KV connectivity or deploy material.
3. Stop the issuer and acknowledge this before **Request real publication**.
   This button explicitly requests real issuance/publication. Approval follows
   the existing workspace policy; when approval is disabled, leave the issuer
   stopped until its group policy is ready. Read the returned group ID, scoped
   HCL and generated configuration. Apply/merge these locally with owner-only
   permissions, keeping existing identity and protected state intact. Enter an
   optional local store CA-file path for a private TLS CA; no credential contents
   are accepted or transmitted. Restart deliberately with real execution enabled
   only after local policy and any required independent approval are complete.
4. Wait for an accepted exact-version publication receipt. A submitted/successful
   job or a saved form alone cannot finish the material-store step.
5. Select Linux consumers and installed, served or trust assurance. Installed
   mode has no TLS probes or reload command; it reads back leaf/key/fingerprint
   and the full chain. Served and trust require listener evidence; trust also
   checks chain/hostname. For a staging/private CA supply the issuer CA's local
   file path on each consumer. Select nginx, Apache or HAProxy only as applicable.
6. Authorize each binding through the existing API. Copy the exact returned
   profile and authorization revision into its protected local configuration,
   run its signed no-op and confirm the applied configuration. Confirmation
   enables requesting work; it is never deployment evidence.
   A registered discovery-only consumer can prepare binding metadata to obtain
   this configuration. Real deployment stays disabled until its current check-in
   reports all required execution operations, capabilities and signed evidence.
7. Optionally request verification-only first. An uninstalled destination must
   fail without installing anything. For an intentional installation use
   **Deploy the selected version**, review/approve the frozen rollout and enable
   real execution locally. Continue only after every active consumer converges
   on the current version/generation and meets its assurance policy.

## Negative checks and qualification limits

- A viewer, including a system administrator without the workspace role, cannot
  submit jobs or authorize bindings. Test missing agents, missing capabilities,
  stale declarations, invalid references and inaccessible status reads.
- Start over and switch workspace/goal. Old UI flags and unrelated groups must
  not satisfy the new setup. The selected group remains included in the bounded
  summary even when it predates the latest twenty groups.
- Azure Secrets configuration and Windows/IIS guidance are visible as implemented
  candidates. Their production capability facts remain false; advertised agent
  capabilities do not enable actions. Do not alter qualification manifests or
  override gates just to finish this guide. No Azure subscription is required
  for these UI/gating checks; they are not live Azure evidence.
- IIS guidance requires the typed `windows-material-iis-v1` connector,
  non-exportable machine CNG custody, exact ACL/signing association, exact
  IIS/HTTP.sys binding and served/trusted TLS evidence. File-only assurance and
  generic endpoint installation are not offered for IIS. Native qualification
  still requires an authorized Windows Server runner and the release artifact.
- Rollback remains separately authorized in Certificate Management. Uncertainty
  is not permission to delete a checkpoint, bypass approval, republish blindly
  or overwrite a retained pinned version.

Stop only the owned lab after collecting sanitized evidence:

```powershell
./tests/wildcard-vault/ux-lab/run.ps1 -Action Stop -Project $project
```

Retain private keys and credential files only in the protected lab volumes.
Never publish them with screenshots, transcripts or the report.
