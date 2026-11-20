# Interactive AD CS orchestration lab

This lab runs the actual TokenTimer API, dashboard, CertOps maintenance worker,
notification delivery worker and PostgreSQL migrations. A separate **SIMULATED**
Windows/CA client registers, heartbeats, claims signed jobs, checks the signature,
identity and validity window, and reports controlled verdicts and claim-bound
verification evidence through the existing agent protocol. There are no public
test endpoints in the application and no production authentication exceptions.

It validates orchestration, admission, retries, identity history and notification
delivery. Simulated `installed` states and verification evidence are explicitly
labelled: they do **not** prove Windows, Kerberos/DCOM, CNG custody, actual CA
issuance, certificate installation or a TLS handshake. **NATIVE AD CS
QUALIFICATION PENDING.** Protected native workflows remain unchanged.

## Start and inspect

Use a clean checkout/worktree of PR #714 with Node 24, pnpm, Docker Compose v2
and Docker Desktop (or Docker Engine on Linux). No Windows domain is required.
The CLI refuses production mode or ambient `.env` files at the root/API/worker.
It creates random disposable credentials in an ignored private state file.

```powershell
pnpm install --frozen-lockfile
pnpm exec playwright install chromium
pnpm adcs:lab up --simulated
pnpm adcs:lab credentials
```

`up` starts PostgreSQL and MailHog, applies migrations, starts the real API and
Vite dashboard, registers protocol identities, seeds all scenarios and starts
automatic worker cycles every 15 seconds. It returns after startup. Native
Node services run in hidden background processes; the same commands work on
Windows and Linux. Linux CI installs Chromium system dependencies with
`pnpm exec playwright install --with-deps chromium`.

- Dashboard: **http://localhost:55174**. Sign in with the email/password returned
  by `credentials`; select **SIMULATED AD CS — developer lab**.
- API: **http://localhost:55471**.
- SMTP mailbox: **http://localhost:18025**; SMTP submission is loopback port
  **11025**. All recipients use reserved `example.test` identities.
- PostgreSQL: loopback **55479**, database/user `tt_adcs_simulated`.
- The private controller binds only `127.0.0.1:55474`, requires a random bearer
  token and accepts a fixed set of test commands. Use the CLI to access it.

Open **Certificate Management → Renewals → AD CS issuers**. The issuer names
match the scenario names below. Certificates and jobs also appear in their
normal tabs. Bell incidents and the mailbox link to the correct workspace and
issuer. Click **Check again**, choose that scenario's simulated agent, then
**Run check** to exercise the normal manual API flow. Initial key approval is
separate from readiness; only an explicit operator confirmation pins the key.

Credentials live in `.tmp/adcs-local-lab/private-state.json` with restrictive
creation permissions. Never commit/share that file, browser storage state or
the credential command's output. No customer keys or protected lab credentials
are read. Public CA facts and renewed certificate metadata are synthetic.

## Controls

```powershell
pnpm adcs:lab pause
pnpm adcs:lab status
pnpm adcs:lab tick
pnpm adcs:lab scheduler
pnpm adcs:lab agent
pnpm adcs:lab scenario unavailable safe
pnpm adcs:lab advance unavailable 16
pnpm adcs:lab manual unavailable
pnpm adcs:lab expire success
pnpm adcs:lab scenario success timeout
pnpm adcs:lab manual success
pnpm adcs:lab agent
pnpm adcs:lab expire-lease success
pnpm adcs:lab scenario success safe
pnpm adcs:lab tick
pnpm adcs:lab resume
```

`pause` stops automatic cycles after any current cycle finishes. `tick` runs the
real maintenance worker, simulated agents, then the real delivery worker.
`scheduler` runs the production scheduler once; `agent` only polls/reports.
Concurrent controller cycles are rejected; the automated verifier uses separate
scheduler processes to challenge PostgreSQL coordination.

`scenario <name> <mode>` accepts `safe`, `unavailable`, `changed-key`, `unsafe`,
`offline`, `timeout`, `hold`, or `exhausted`. These settings affect only the
separate simulator. `hold` does not poll; `timeout` claims but deliberately never
reports a result. `offline` also marks that fixture's identity offline.
Reconnecting heartbeats restore its normal state.

`advance <name> <minutes>` ages only completion/update timestamps of that
scenario's persisted preflight fixtures to exercise the actual backoff. It does
not change job creation order or the confirmation episode. `expire` ages that
scenario's confirmation/final preflight fixture to create a stale-evidence
boundary. `expire-lease` ages only claimed/running read-only preflight leases.
Production clocks, TTL constants, timeouts, signing, pinning and retry limits
are unchanged. These are deterministic fixture operations, not elapsed native
24-hour qualification.

The client respects server `429 Retry-After`; the 100-certificate scenario can
take several minutes with normal machine rate limits. No limiter is disabled.
The API still handles signed nonce replay and result idempotency normally.

## Scenario catalog

All 12 scenarios are seeded together; activate a mode with the controls above.
Reset returns every scenario to this initial catalog.

| Name | Initial state and visible expectation |
|---|---|
| `initial` | One unconfirmed issuer, mock CA key, allowed template, agent, managed certificate and profile. Safe simulated preflight exists; no CA approval or automatic enrollment. Confirm explicitly in the UI. |
| `expired` | Approved key, old preflight, one due certificate. The next sweeps create one automatic refresh and then one enrollment. |
| `success` | Same renewal flow with simulated verification evidence; normal reconciliation advances expiry/fingerprint and retains predecessor/successor identity history. |
| `unavailable` | Transient failure with recorded `ADCS_CA_UNREACHABLE` text and terminal job code. Actual backoff prevents floods. Set `safe`, advance the backoff or request a manual check, then tick to recover. |
| `changed-key` | Simulator returns another CA digest. Original approved key stays pinned; renewal remains blocked pending explicit approval. |
| `unsafe` | Unsafe template verdict. Policy stops automatic progress; no enrollment or policy retry flood. |
| `offline` | Assigned simulated agent is offline. No other scenario's agent declares this target. Set `safe` and tick to reconnect and recover. |
| `shared` | Five due certificates share one issuer, CA/template/version and agent. One automatic preflight supports five individual enrollment lifecycles. |
| `critical` | Three certificates expire in 1/5/25 days. One incident retains count 3, earliest expiry and critical severity; actual SMTP message links to this issuer. |
| `exhausted` | Transient failures. Repeat advance/scheduler/agent four times after the first failure to reach five; another sweep must not create a sixth. A normal manual check resets the episode. |
| `large` | 125 actual registered protocol identities and 100 certificates. First 100 declarations lack enrollment capability; eligible agent 101 is found. Multiple later eligible agents remain available; normal priority ordering applies after heartbeats. |
| `concurrent` | Five certificates; run independent scheduler processes against this database. PostgreSQL single-flight and idempotency prevent duplicate jobs/enrollments. |

The `large` fixture deliberately has 50 distinct declared targets shared by 100
certificates, respecting the production protocol's 64-selector maximum. There
are **136 registered identities and 121 managed certificates** in the full seed.
The simulator never contacts the named Windows targets or CA.

## Automated verification and evidence

Run the verifier on a clean seed, before changing scenario state:

```powershell
pnpm adcs:lab reset
pnpm adcs:lab verify
pnpm adcs:lab browser
```

The verifier pauses background cycles, then checks services/migrations, real
login and issuer API reads, automatic refresh, reconciled simulated renewal,
lineage, the agent-101 boundary, policy failures, backoff, shared incident and
actual SMTP contents, five-attempt exhaustion, manual recovery and independent
concurrent schedulers. It leaves cycles paused for inspection. Browser checks
follow the link extracted from an actual received message, inspect the issuer,
queue a manual check and capture renewed-state/mailbox screenshots.
They also inspect successful Jobs history, the reconciled certificate expiry,
and navigation from an actual bell incident.

The **AD CS simulated integration lab** CI job runs startup, verification,
browser validation, ownership-checked cleanup and sanitized artifact upload.
The existing mandatory PostgreSQL suite also tests actual SMTP crashes/races,
authorization changes, pagination/ownership/capability boundaries, and a separate
100-issuer / 1,000-certificate / 30,000-job scale fixture. Its scale regression
compares the batched response with the unbatched reference projection.

```powershell
node --test --test-force-exit tests/postgres/certops-adcs-preflight-incidents.test.js
pnpm adcs:lab logs
pnpm adcs:lab status
```

Evidence is under `.tmp/adcs-local-lab/`: `verification.json`,
`browser-verification.json`, `smtp-evidence.json`, `browser-*.png`, `api.log`,
`dashboard.log`, `worker.log`, `supervisor.log`. Worker and API logs include job,
issuer, workspace and correlation identifiers. The status command exposes
persisted jobs, enrollments and incident state without printing credentials.
The private state and raw cookie material are excluded from CI artifacts.

## Stop, reset and cleanup

```powershell
pnpm adcs:lab stop
pnpm adcs:lab up --simulated
pnpm adcs:lab reset
pnpm adcs:lab clean
```

`stop` terminates the owned supervisor/services and removes only this Compose
project's containers/network; its database volume and credentials persist.
`up` resumes that session. `reset` performs owned cleanup and a fresh start/seed.
MailHog's mailbox is in memory: `stop` clears captured messages while database
delivery receipts persist. Use `reset` followed by `verify` for a fresh capture;
already acknowledged messages are not resent merely to refill the catcher.
`clean` stops services, removes this project's database volume, then deletes the
private state file. Logs/screenshots remain for review. Before any Docker
teardown, container and volume labels must match this lab and checkout's owner
digest; resources belonging to another checkout are refused. No Docker prune,
broad certificate/store cleanup or production operation is performed.

If startup fails after partial seeding, inspect logs and run `reset`. Stop other
services occupying the documented ports; the lab does not kill unrelated
listeners. An existing `.env` requires a clean worktree instead of borrowing
ambient credentials.
