# Shared certificate user/API lab

Run from the implementation checkout, with Docker Desktop, Node 24, pnpm, and the checkout's dependencies installed. This is a separate Core installation with its own PostgreSQL, mail capture, Vault, Pebble DNS-01 CA, maintenance worker, dashboard, and customer hosts. All published ports bind to `127.0.0.1`; PostgreSQL and Vault have no host port.

The journey uses public HTTP routes with session cookies and CSRF tokens. It creates a workspace, invites a second user through captured email, verifies that account, enrolls real agents with bootstrap tokens, submits work, and approves/rejects it as a different user. The customer host runs the full agent CLI, including signing, replay protection, live leases, evidence, and result outbox. Real nginx and HAProxy processes load the certificate and receive TLS probes. There are no SQL commands, direct database connections, inserted receipts, service-layer calls, or database fixture injection in the harness. Ordinary API startup migrations/admin bootstrap and the ordinary worker retain their normal database access.

## Start and test

```powershell
# Use the SAME project for every action; choose a fresh name for a fresh run.
$project = 'tt-wildcard-ux-my-run'
# Current workstation has the dependency images cached:
./tests/wildcard-vault/ux-lab/run.ps1 -Action Up -Project $project -BasePort 60800
./tests/wildcard-vault/ux-lab/run.ps1 -Action Test -Project $project
./tests/wildcard-vault/ux-lab/run.ps1 -Action Status -Project $project

# Elsewhere, build isolated lab image tags first:
./tests/wildcard-vault/ux-lab/run.ps1 -Action Up -Project $project -BasePort 60800 -BuildImages

# Stop ONLY this named lab; retains volumes and evidence:
./tests/wildcard-vault/ux-lab/run.ps1 -Action Stop -Project $project
```

Use a fresh `-Project tt-wildcard-ux-your-run` consistently for Up/Test/Status/Stop. The script default identifies a historical run; choose a new name for your test. `Up` refuses existing containers or journey evidence. Do not use global Docker cleanup or attach this stack to the manual audit database. Vault dev mode and Pebble are volatile: retaining the database volume does **not** preserve Vault objects after restart. A fresh project is required for a fresh replay.

`Up` builds the current dashboard. API, worker, and package source are mounted read-only from this checkout; cached images supply dependencies. Cached defaults are `tt-wildcard-core-api:20261008`, `localhost:58600/core-worker:20261008`, and `tt-wildcard-vault-fixture:20261008`. `-BuildImages` uses dedicated project-specific tags instead. This is source-mounted functional testing, not validation of newly built production images.

`Test` leaves the lab running on success or failure and returns failure when an assertion/API fails. Evidence is in `.scratch/<Project>/`: `report.json`, `journey-state.json`, `http-transcript.jsonl`, and build/journey logs. HTTP transcripts omit bodies, cookies, tokens, and verification links. Customer-side credentials/keys stay in the lab volume with protected file modes. State contains synthetic identities and public certificate/key hashes only. Completed phases can be resumed with `-Action Test -Phase <phase>`; do not run phases concurrently. A partially executed phase may require a fresh project.

The default certificate contains the ordinary SANs `nginx.wildcard.test` and `haproxy.wildcard.test`, with no wildcard. Both services must serve the same leaf fingerprint. Use `-CertificateMode wildcard` on Up to test the wildcard variant instead. BasePort and certificate mode are retained in local runtime-options.json for subsequent actions. With BasePort 60800, the web/API/mail/control/nginx/HAProxy ports are 60801/60800/60803/60805/60843/60943.

For a real browser approval, run `Test -Phase setup`, then `Test -Phase prepare-publication`. Sign in as the separate approver, select the lab workspace, open CertOps → Jobs and approve the pending issuance. Run `Test -Phase all` to resume the remaining checks; the harness recognizes the existing approval and does not create another issuance.

## Manual user experience

- Dashboard with BasePort 60800: <http://127.0.0.1:60801>
- Email inbox with BasePort 60800: <http://127.0.0.1:60803>
- Owner: `owner@wildcard.test` / `LabOwner-2026!Only`
- Approver: `approver-<first 8 characters of runId>@wildcard.test` / `LabApprover-2026!Only` (exact email in journey-state.json).
- nginx TLS with BasePort 60800: `127.0.0.1:60843`, SNI `nginx.wildcard.test`.
- HAProxy TLS with BasePort 60800: `127.0.0.1:60943`, SNI `haproxy.wildcard.test`.

1. Sign in as owner and select **Shared Certificate UX Lab <runId prefix>**.
2. Open **CertOps → Jobs**. Inspect issuance, approval, and the two `deploy-from-store` jobs, their evidence and errors. Approvals are visible and attributable to the separate approver.
3. Open **CertOps → Renewals** and inspect the distribution group's material versions and consumer convergence. Compare source publication with each consumer's served/trusted evidence.
4. In a separate browser session, sign in as the approver. Use **Approve** or **Reject** on a new pending manual job; the automated transcript performs the same public actions.
5. Inspect the shared certificate from **Certificates** and its automatic renewal profile in **Renewals**. For a previously published certificate missing its profile, an administrator can use **Repair renewal profile** in the CertOps certificate actions. It restores settings from the accepted publication; existing profiles and operator edits are preserved. The generic asset-inventory **Renew** button edits metadata dates; use CertOps jobs for real ACME renewal.

The localhost-only customer control endpoint at BasePort + 5 (`60805` in the example) models customer-owned installation/configuration, agent start/stop, and a network failure. It is intentionally unauthenticated with synthetic lab credentials and has no database client/access configuration. The journey uses it for actions that an operator performs on a customer host. Do not expose it beyond loopback or reuse real credentials.

## Scenarios and limits

| Phase | User/API behavior |
|---|---|
| setup | Normal startup, invite/register/verify/login, bootstrap and full agent enrollment |
| publish | Approval, SAN-only DNS-01 issuance, Vault write, automatic renewal profile, custom canonical key directory and permissions; repair replay/admin/input checks |
| bindings | Two real TLS consumers, concurrent identical PUTs, unchanged proof, idempotent retries before approval and after completion, changed parameters rejected, changed membership replay |
| validation | Nine malformed distribution requests return 422 and create no jobs |
| scanner | Scan actual published Vault bundle prefixes with five raw/encoded forms; customer-side HTTP observations prove no private object request occurs |
| rejection | Reject a never-claimed publication; version history remains with `rejected_before_execution` |
| authorization | Genuine binding change increments once, invalidates old proof; matching request still replays its original identity; a new reviewed rollout uses updated local policy; cross-workspace route denied |
| recovery | Rejected renewal/corrected allocation; lose actual successful Vault write response and block recovery reads; verify old canonical key/fresh issuance fence; clear network fault and retry original job; no extra order; next CSR reuses rotated key; offline consumer remains stale then catches up |
| transfer | While Vault effects are uncertain, inventory transfer returns actionable 409. After recovery, transfer succeeds without a destination Vault integration, retains source material/job history, and leaves destination management unconfigured without offering an unavailable profile repair. `transfer-status` rechecks the transferred inventory through the API |

The recovery sequence expects three ACME invocations total: initial issuance, rotated renewal, then renewal reusing the recovered key. The fault proxy drops a committed Vault write response and blocks readback, including versioned GETs, until the operator clears the fault and retries the original job. The accepted publication receipt must clear that job's reconciliation flag before the final transfer can succeed. The customer reload hook waits for a trusted TLS handshake serving the installed certificate before it returns; the agent independently verifies that listener afterward. The lab does not fabricate a historical pre-migration row or never-claimed cancellation. There is no standalone public job-cancel API; retirement fences claimed/running leases, which cannot satisfy the never-claimed predicate. Those migration/cancellation regression cases require separate test evidence and are outside this public user journey.

The supported repair endpoint is `POST /api/v1/workspaces/:id/certops/certificates/:certId/renewal-profile/repair`, with an empty JSON body, workspace-admin session and CSRF token. It validates the current management period, live issuer and accepted publication proof. It accepts no new execution settings and never reads private keys or contacts Vault. `Test -Phase repair` exercises that endpoint on the journey's certificate.

To exercise a genuinely missing profile without database injection, pause between the bindings and recovery phases. Sign in as owner, use the certificate's **Detach** action, then **Repair renewal profile**. Run `Test -Phase repair` and then `Test -Phase all` to verify renewal and continue. Perform this before the final inventory transfer, which intentionally removes source management authority.

Session cookies are reused between phases like a browser session, so repeated phases do not repeatedly log in. The ignored, mode-600 `session-owner.json` and `session-approver.json` contain synthetic lab cookies/CSRF tokens; do not publish them. They are separate from the sanitized transcript and public journey state.

Pebble uses [its documented NONCEREJECT setting](https://github.com/letsencrypt/pebble#invalid-anti-replay-nonce-errors) to disable random rejection of otherwise valid nonces. This keeps the Vault recovery scenario deterministic with the cached fixture Certbot. Actual DNS-01 checks and nonce validation remain enabled; ACME bad-nonce retry qualification is outside this lab.

The disposable agent artifact in `/lab/experimental-agent` enables the three experimental distribution capabilities solely for this lab. Shipped capability manifests remain unchanged. Pebble certificates, development Vault token, local self-signed transport CA, and lab-only TLS bootstrap settings are not customer qualification. Cloud billing, Enterprise licensing, real appliance adapters, and release CI parity are not tested here.
