# Wildcard Vault user/API lab

Run from the implementation checkout, with Docker Desktop, Node 24, pnpm, and the checkout's dependencies installed. This is a separate Core installation with its own PostgreSQL, mail capture, Vault, Pebble DNS-01 CA, maintenance worker, dashboard, and customer hosts. All published ports bind to `127.0.0.1`; PostgreSQL and Vault have no host port.

The journey uses public HTTP routes with session cookies and CSRF tokens. It creates a workspace, invites a second user through captured email, verifies that account, enrolls real agents with bootstrap tokens, submits work, and approves/rejects it as a different user. The customer host runs the full agent CLI, including signing, replay protection, live leases, evidence, and result outbox. Real nginx and HAProxy processes load the certificate and receive TLS probes. There are no SQL commands, direct database connections, inserted receipts, service-layer calls, or database fixture injection in the harness. Ordinary API startup migrations/admin bootstrap and the ordinary worker retain their normal database access.

## Start and test

```powershell
# Current workstation has the dependency images cached:
./tests/wildcard-vault/ux-lab/run.ps1 -Action Up
./tests/wildcard-vault/ux-lab/run.ps1 -Action Test
./tests/wildcard-vault/ux-lab/run.ps1 -Action Status

# Elsewhere, build isolated lab image tags first:
./tests/wildcard-vault/ux-lab/run.ps1 -Action Up -BuildImages

# Stop ONLY this named lab; retains volumes and evidence:
./tests/wildcard-vault/ux-lab/run.ps1 -Action Stop
```

Default project: `tt-wildcard-ux-20261009-merge2`. This is the replay after merging current main; earlier r4 and merge runs were stopped with volumes/evidence retained. To replay, stop the previous UX lab and use a new `-Project tt-wildcard-ux-your-run` consistently for Up/Test/Status/Stop. `Up` refuses existing containers or journey evidence. Do not use global Docker cleanup or attach this stack to the manual audit database. Vault dev mode and Pebble are volatile: retaining the database volume does **not** preserve Vault objects after restart. A fresh project is required for a fresh replay.

`Up` builds the current dashboard. API, worker, and package source are mounted read-only from this checkout; cached images supply dependencies. Cached defaults are `tt-wildcard-core-api:20261008`, `localhost:58600/core-worker:20261008`, and `tt-wildcard-vault-fixture:20261008`. `-BuildImages` uses dedicated project-specific tags instead. This is source-mounted functional testing, not validation of newly built production images.

`Test` leaves the lab running on success or failure and returns failure when an assertion/API fails. Evidence is in `.scratch/<Project>/`: `report.json`, `journey-state.json`, `http-transcript.jsonl`, and build/journey logs. HTTP transcripts omit bodies, cookies, tokens, and verification links. Customer-side credentials/keys stay in the lab volume with protected file modes. State contains synthetic identities and public certificate/key hashes only. Completed phases can be resumed with `-Action Test -Phase <phase>`; do not run phases concurrently. A partially executed phase may require a fresh project.

## Manual user experience

- Dashboard: <http://127.0.0.1:58801>
- Email inbox: <http://127.0.0.1:58803>
- Owner: `owner@wildcard.test` / `LabOwner-2026!Only`
- Approver: `approver-<first 8 characters of runId>@wildcard.test` / `LabApprover-2026!Only` (exact email in journey-state.json).
- nginx TLS: `127.0.0.1:58843`, SNI `nginx.wildcard.test`.
- HAProxy TLS: `127.0.0.1:58943`, SNI `haproxy.wildcard.test`.

1. Sign in as owner and select **Wildcard API UX Lab <runId prefix>**.
2. Open **CertOps → Jobs**. Inspect issuance, approval, and the two `deploy-from-store` jobs, their evidence and errors. Approvals are visible and attributable to the separate approver.
3. Open **CertOps → Renewals** and inspect the distribution group's material versions and consumer convergence. Compare source publication with each consumer's served/trusted evidence.
4. In a separate browser session, sign in as the approver. Use **Approve** or **Reject** on a new pending manual job; the automated transcript performs the same public actions.
5. Inspect the wildcard certificate from **Certificates** and its automatic renewal profile in **Renewals**. For a previously published certificate missing its profile, an administrator can use **Repair renewal profile** in the CertOps certificate actions. It restores settings from the accepted publication; existing profiles and operator edits are preserved. The generic asset-inventory **Renew** button edits metadata dates; use CertOps jobs for real ACME renewal.

The localhost-only customer control endpoint at `58805` models customer-owned installation/configuration, agent start/stop, and a network failure. It is intentionally unauthenticated with synthetic lab credentials and has no database client/access configuration. The journey uses it for actions that an operator performs on a customer host. Do not expose it beyond loopback or reuse real credentials.

## Scenarios and limits

| Phase | User/API behavior |
|---|---|
| setup | Normal startup, invite/register/verify/login, bootstrap and full agent enrollment |
| publish | Approval, SAN-only DNS-01 issuance, Vault write, automatic renewal profile, custom canonical key directory and permissions; repair replay/admin/input checks |
| bindings | Two real TLS consumers, concurrent identical PUTs, unchanged proof, idempotent retries before approval and after completion, changed parameters rejected, changed membership replay |
| rejection | Reject a never-claimed publication; version history remains with `rejected_before_execution` |
| authorization | Genuine binding change increments once, invalidates old proof; matching request still replays its original identity; a new reviewed rollout uses updated local policy; cross-workspace route denied |
| recovery | Rejected renewal/corrected allocation; lose actual successful Vault write response and block recovery reads; verify old canonical key/fresh issuance fence; clear network fault and retry original job; no extra order; next CSR reuses rotated key; offline consumer remains stale then catches up |

The recovery sequence passed with three ACME invocations total: initial issuance, rotated renewal, then renewal reusing the recovered key. The fault proxy drops a committed Vault write response and blocks readback, including versioned GETs, until the operator clears the fault and retries the original job. The customer reload hook waits for a trusted TLS handshake serving the installed certificate before it returns; the agent independently verifies that listener afterward. The lab does not fabricate a historical pre-migration row or never-claimed cancellation. There is no standalone public job-cancel API; retirement fences claimed/running leases, which cannot satisfy the never-claimed predicate. Those migration/cancellation regression cases require separate test evidence and are outside this public user journey.

The supported repair endpoint is `POST /api/v1/workspaces/:id/certops/certificates/:certId/renewal-profile/repair`, with an empty JSON body, workspace-admin session and CSRF token. It validates the current management period, live issuer and accepted publication proof. It accepts no new execution settings and never reads private keys or contacts Vault. `Test -Phase repair` exercises that endpoint on the journey's certificate; the formerly failing r3 installation was repaired through this API before being stopped, without database writes from the harness.

The disposable agent artifact in `/lab/experimental-agent` enables the three experimental distribution capabilities solely for this lab. Shipped capability manifests remain unchanged. Pebble certificates, development Vault token, local self-signed transport CA, and lab-only TLS bootstrap settings are not customer qualification. Cloud billing, Enterprise licensing, real appliance adapters, and release CI parity are not tested here.
