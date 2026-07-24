# TokenTimer Agent (bootstrap + execution runtime)

Reference for operators installing and running the TokenTimer Agent, the
outbound-only execution-plane process under `packages/agent`. See
`docs/certops/CONTEXT.md` for domain language, ADR-0001 (zero private-key
custody), ADR-0002 (outbound-only protocol, agent-local policy wins), and
ADR-0003 (job signing and replay protection).

## 1. What the agent is

The agent is a Node.js daemon that runs on customer infrastructure and is the
only CertOps component that ever touches private keys. The TokenTimer control
plane plans and audits certificate lifecycle work; the agent executes it. Keys
are generated, stored, and used exclusively on the host the agent runs on. The
control plane never receives or stores private key material, and the agent
enforces that invariant locally as well: every module is written to stay safe
against an untrusted or compromised control plane.

The agent is outbound-only. It opens HTTPS connections to the control plane
and never accepts inbound connections. No listening port, no firewall holes.

Two milestone scopes ship in this package:

- **Observe-only bootstrap**: config and credential storage, agent-local policy engine
  (default deny), the register/heartbeat/claim/result/evidence protocol
  client, schema-safe evidence construction, and observe-only filesystem
  certificate discovery. In observe-only mode the agent never executes jobs: every
  policy-allowed job is reported back as `blocked` with an explanatory
  message, and every policy-rejected job is reported as `rejected` with
  evidence.
- **signed-job dispatch** (opt-in via `execution.enabled`): claimed jobs
  run through the full trust chain (Ed25519 signature verification against a
  pinned key, replay cache, clock window check, agent-local policy) before
  any execution. Execution modules cover key generation and CSR building
  (`src/keys`), ACME renewal via certbot/acme.sh (`src/acme`), atomic
  certificate deployment (`src/deploy`), validate-then-reload service helpers
  (`src/reload`), and post-deploy fingerprint verification (`src/verify`).

When `execution` is absent from config or `enabled` is `false`, the observe-only
bootstrap behavior is preserved exactly.

## 2. Install and run

Requirements: Node >= 22 (`packages/agent/package.json` `engines`; the
protocol client uses the built-in global `fetch`). The package has zero
runtime dependencies.

Entry point: `packages/agent/bin/tokentimer-agent.js` (also exposed as the
`tokentimer-agent` bin). Start it with:

```
node packages/agent/bin/tokentimer-agent.js
```

or `pnpm start` from `packages/agent`. There are no CLI flags; configuration
is via `config.json` and `TOKENTIMER_AGENT_*` environment variables.

### Installer script (Linux, systemd)

`packages/agent/scripts/install-agent.sh` automates the production install
that the dashboard's Deploy-an-agent panel generates a command for. It:

- verifies OS/arch and a Node >= 22 runtime;
- creates a dedicated system user and install directory;
- writes a `config.json` skeleton and stores the bootstrap token in a
  0600-mode file consumed once at first start;
- installs, enables, and starts the hardened systemd unit
  (`packages/agent/scripts/tokentimer-agent.service`, `ProtectSystem=strict`
  among other directives).

`--dry-run` prints every action without touching the system; `--uninstall`
removes the unit, user, and install directory. The script is POSIX shell and
requires root (or sudo) for the real install. The recommended flow is:
create a bootstrap token in the dashboard (shown exactly once), copy the
generated install command, run it on the target host, and watch the
dashboard's agent fleet panel flip the agent to registered on first
heartbeat.

### Supported platform / tool version matrix

This is the tested support matrix for this release. Versions outside this
matrix may work but are not covered by CI or release sign-off.

| Component | Supported range | Notes |
|---|---|---|
| Node.js | `>= 22.0.0, < 25.0.0` | Even-numbered Active LTS lines only (22, 24); odd/Current releases are not release-tested. |
| Certbot | `2.x` (tested against the latest `2.x` release at release time) | `--manual` + `--csr` mode only; snap and pip installs both exercised in CI. |
| acme.sh | Latest tagged release at release time (pinned commit recorded in CI config) | Uses the shipped `dns_certops` dnsapi hook; requires acme.sh's own `dnsapi` loading support (stable across acme.sh releases). |
| Operating system | Linux with systemd (Debian/Ubuntu LTS, RHEL/Rocky 9+) | The installer and hardened unit (`ProtectSystem=strict`) assume systemd; other init systems are not supported by `install-agent.sh`. |
| DNS provider APIs | See `src/dns/providers/*.js`; each provider module documents the API version/date it was implemented against | Re-verified when a provider's upstream API has a breaking change. |

### Config directory

Resolution order (`resolveConfigDir`): explicit argument >
`TOKENTIMER_AGENT_CONFIG_DIR` env var > OS default. OS defaults:

- Linux/macOS: `~/.config/tokentimer-agent`
- Windows: `%APPDATA%\tokentimer-agent`

The directory is created with mode 0700 and the mode is re-asserted on every
write (best-effort on Windows, where POSIX modes are not meaningful). Files
inside it:

| File | Contents | Mode |
|------|----------|------|
| `config.json` | Non-secret runtime config (below) | inherited |
| `credential` | Registration credential `ttagent_<id>_<secret>` | 0600 |
| `signing-key-pin.json` | Pinned control-plane job-signing public key (`signingKeyId`, `publicKeyPem`) | 0600 |
| `replay-store.json` | Consumed-nonce replay cache (default location) | 0600 |
| `keys/` | Agent-generated private keys, `<certificateId>.key.pem` (default location) | dir 0700, keys 0600 |

### First-run registration

With no stored credential, the agent requires `TOKENTIMER_AGENT_BOOTSTRAP_TOKEN`
(and optionally `TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID`) in the environment.
The bootstrap token is single-use and never persisted. Registration stores
the assigned `agentId` in `config.json`, the issued credential in
`credential`, and, when the register response carries one, pins the control
plane's job-signing public key in `signing-key-pin.json` (trust-on-first-use,
ADR-0003). A stored credential with no `agentId` in `config.json` is an
inconsistent config directory and aborts startup.

#### Encrypted registration recovery

A lost register response can be replayed within a short window by presenting
the same authenticated bootstrap token plus the original `registrationId`.
The control plane stores that replay credential as an AES-256-GCM encrypted
envelope in `certops_agent_registration_replays` (never plaintext). Decrypt
happens only on that authenticated replay path
(`apps/api/services/certops/registrationCredentialCrypto.js`). The API process
requires `CERTOPS_REGISTRATION_ENCRYPTION_KEY` (64 hex chars = 32 bytes) and
fails closed if it is missing or malformed. Replay TTL defaults to 15 minutes
and is overridable via `CERTOPS_REGISTRATION_REPLAY_TTL_MS` (positive
milliseconds). Expired replay rows are deleted by the CertOps maintenance
worker's `registration-replay-sweep`.

### Config reference (`config.json`)

Validation is fail-loud: a malformed value aborts startup with a descriptive
error instead of being silently normalized. Field names and defaults below
come from `packages/agent/src/config/index.js`.

Top level:

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `serverUrl` | string | required | Control plane base URL. Env override: `TOKENTIMER_AGENT_SERVER_URL`. |
| `agentId` | string or null | null | Assigned at registration; matches `^[A-Za-z0-9_.:-]{1,128}$`. |
| `protocolVersion` | string | `"1.0.0"` | Semver `x.y.z`. |
| `heartbeatIntervalMs` | positive int | 30000 | Env override: `TOKENTIMER_AGENT_HEARTBEAT_MS`. |
| `pollIntervalMs` | positive int | 15000 | Claim loop interval. Env override: `TOKENTIMER_AGENT_POLL_MS`. |
| `declaredTargetSelectors` | string[] | `[]` | Target scope this agent declares; exact match at policy time. |
| `declaredCommandProfileNames` | string[] | `[]` | Reported at registration. |
| `policy` | object or null | null | Agent-local allowlists (below). Null means every allowlist is empty: default deny. |
| `discovery` | object or null | null | Null disables discovery entirely. |
| `execution` | object or null | null | Null is treated as `{ enabled: false }` (observe-only mode). |
| `caBundlePath` | string or null | null | Path to a PEM CA bundle trusted for the agent-to-control-plane HTTPS channel (private-CA control planes). Env override: `TOKENTIMER_AGENT_CA_BUNDLE`. Fail-loud at startup: a missing/unreadable file, a file without a `BEGIN CERTIFICATE` block, or a file containing private key material aborts before any network call. When set, the bundle replaces the default trust store for control-plane requests (it does not extend it); plain `http` URLs are unaffected. When unset, the OS trust store applies (`NODE_EXTRA_CA_CERTS` remains a coarser process-wide alternative). |
| `dnsProviders` | object or null | null | Native DNS-01 solver configuration (see "DNS-01 providers" in section 5). Maps provider id to `{ credentialsFile: <absolute path>, ...non-secret options }`, plus a reserved `zoneProviderMap` key (zone to provider id). Credentials never live in `config.json`, only the path to a 0600 credentials file does. Fail-loud validation: unknown provider ids, relative paths, and `zoneProviderMap` entries naming unconfigured providers abort startup. |
| `dnsPropagation` | object or null | defaults | Post-mutation DNS wait: `{ timeoutMs` (default 120000), `intervalMs` (default 2000), `resolvers` (optional recursive resolver IPs), `checkAuthoritative` (default true) `}`. Used by `certops-dns-hook` after present/cleanup. |

`policy` block (deep validation in `src/policy/loadPolicyConfig`, fail-loud):

| Field | Type | Notes |
|-------|------|-------|
| `allowedCommands` | object | Maps profile name to `{ argv: string[] }`. Every argv element is rejected at load time if it contains a shell metacharacter (`; \| & $ ` > <` or CR/LF). |
| `allowedPaths` | string[] | Normalized to absolute paths; containment is segment-aware (no sibling-prefix collisions). |
| `allowedCaEndpoints` | string[] | Full-URL exact match after trailing-slash normalization. |
| `allowedDnsZones` | string[] | Suffix match with dot boundary (`sub.example.com` covered by `example.com`, `evilexample.com` is not). |
| `allowedDnsProviders` | string[] | Exact match. |

`discovery` block:

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `directories` | string[] | required | Directories to scan for certificates. |
| `intervalMs` | positive int | 3600000 | Hourly by default. |

`execution` block (signed-job execution):

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | boolean | false | Opt-in; an upgraded agent never starts executing without it. |
| `dryRun` | boolean | true | Plan-only execution with zero side effects (see section 5). |
| `keysDir` | string | `<configDir>/keys` | Private keys, 0600 in 0700 dir. |
| `replayStorePath` | string | `<configDir>/replay-store.json` | Persisted replay cache. |
| `clockDriftToleranceMs` | positive int | 30000 | Slack applied to the signed-job validity window. |

## 3. Protocol

The agent speaks the envelope defined in
`packages/contracts/certops/agent-protocol.schema.json` over four frozen
routes (`src/protocol/index.js` `ROUTES`), plus a plain (non-envelope) lease
renewal POST used during job execution:

| Message | Route |
|---------|-------|
| `register` | `POST /api/v1/certops/agent/register` |
| `heartbeat` | `POST /api/v1/certops/agent/heartbeat` |
| `claim` | `POST /api/v1/certops/agent/jobs/claim` |
| `result`, `evidence` | `POST /api/v1/certops/agent/jobs/results` |
| lease renew (B6) | `POST /api/v1/certops/agent/jobs/:jobId/lease` |

Result and evidence share one route; the envelope's `messageType`
disambiguates server-side. Every envelope carries `schemaVersion` (1),
`protocolVersion`, `messageType`, `agentId`, `sentAt`, and optionally
`workspaceId`, `clockOffsetMs`, and `sequence`. Messages must never carry
private key material (schema-level rule, enforced again by the evidence
builder).

### Protocol validation parity

Register, heartbeat, claim, result, and evidence envelope/body shapes are
validated by AJV compiled directly from the canonical
`packages/contracts/certops/agent-protocol.schema.json` on both sides: the
agent (`packages/agent/src/protocol/schemaValidation.js`, schema vendored
under `packages/agent/vendor/contracts/`) and the API
(`apps/api/services/certops/protocolSchemaValidation.js`). That eliminates
drift between hand-written validators. Semantic and authorization checks
(job `mode` vs result `status`, lease/nonce ownership, claim ownership,
sequence) remain in the service layer (`agentDispatch`), not in the AJV
compile.

Message sequence: the protocol client stamps every outbound envelope with
`sequence`, a per-agent monotonically increasing counter, and the control
plane rejects any message whose sequence does not exceed the last accepted
one for that agent (HTTP 409, code `CERTOPS_AGENT_SEQUENCE_REGRESSION`).
This is defense in depth on top of the single-use nonce replay ledger. The
counter is not persisted: a restart begins at 1 again, which is safe because
a successful `register` starts a new generation (the server resets its
high-water mark to the register envelope's sequence), so regressions are only
rejected within the current registered generation. Envelopes without
`sequence` remain accepted for backward compatibility with already-deployed
agents and never move the high-water mark.

Authentication: `register` uses the bootstrap token as a Bearer token;
everything else uses the stored `ttagent_...` credential as a Bearer token.
The credential is never placed in a request body and never logged
(`redactCredentialForLogging` returns a fixed placeholder unconditionally).

Flow:

- **register**: sends `bootstrapTokenId`, `agentVersion`, `hostname`,
  `platform`, `nodeVersion`, `declaredTargetSelectors`,
  `declaredCommandProfileNames`. Response returns `agentId`, `credential`,
  and optionally `signingKeyId` + `signingPublicKeyPem` for TOFU pinning.
- **heartbeat**: every `heartbeatIntervalMs`, sends `agentVersion`,
  `ntpSynced`, `uptimeSeconds`, `pinnedSigningKeyId`, and (on the envelope)
  `clockOffsetMs`. With execution enabled, `clockOffsetMs` is the clock
  estimator's current median and `pinnedSigningKeyId` is the pinned key id;
  in observe-only mode both stay null. An HTTP 410 response means the control plane
  retired this agent: it exits cleanly, no respawn loop.
- **claim**: every `pollIntervalMs`, requests up to `maxJobs` (the main loop
  uses 1) and processes each returned job.
- **result/evidence**: terminal job outcome (`succeeded`, `failed`,
  `rejected`, `blocked`, `dry_run_complete`, `orphaned_unknown_effect`,
  plus `rejectionReason`, `keyRotated`, `errorMessage`, `clockOffsetMs`)
  and per-step evidence bodies. See "Dry-run and reconciliation statuses"
  below for mode gating on the two newer terminals.

Backoff and jitter: poll loops apply +/-20% jitter to every interval
(`jitteredDelay`) to avoid fleet thundering herd. `withRetry` provides
exponential backoff with full jitter (defaults: 5 attempts, 250 ms base,
30 s cap). A failed tick is logged and never kills the loop.

Clock offset estimation: every successful (2xx) response's HTTP `Date` header
is fed to the clock module (`onServerDate` ->
`createClockOffsetEstimator().estimateFromResponseDate`). Offset is
`serverTime - localTime`; positive means the local clock is behind the
server. The estimator keeps a rolling window of the last 5 samples and
reports the median, because the Date header has 1-second resolution and
individual samples are contaminated by network latency. This is a coarse
drift detector for the signed-job time window, not an NTP replacement.

### Dry-run and reconciliation statuses

Job `mode` is an immutable control-plane field on the claimed job. Result
ingestion (`ingestResult`) enforces:

| Status | Valid when | Control-plane effect |
|--------|------------|----------------------|
| `dry_run_complete` | job `mode` is `dry_run` only (real jobs reporting it are rejected) | Terminal success-equivalent for plan-only work; does **not** set `needs_operator_reconciliation` |
| `orphaned_unknown_effect` | real jobs only (dry-run jobs reporting it are rejected) | Sets `needs_operator_reconciliation=true` and a bounded `reconciliation_reason` (from the agent `errorMessage` markers, or the fallback `agent_reported_orphaned_unknown_effect`) |

`orphaned_unknown_effect` is an operational failure that requires manual
reconciliation, not a policy rejection (`rejectionReason` is not used for
this path). The agent embeds `needsOperatorReconciliation=true` and optional
`reconciliationReason=<slug>` in `errorMessage` when it self-reports
uncertainty (for example multi-target rollback uncertain, or an unresolved
local side-effect journal on restart).

The worker lease reaper also reaches `orphaned_unknown_effect` when a lease
expires after renewal (or while status is already `running`) in the
side-effect-risk window and the agent is no longer expected to report: it
sets `needs_operator_reconciliation` with reason
`lease_expired_after_side_effect_window_agent_unresponsive`. Never-renewed
`claimed` leases may still be requeued; renewed/`running` leases are never
silently requeued.

Dry-run jobs must never terminate as `succeeded`; the agent reports
`dry_run_complete` instead. Local `execution.dryRun: true` is a separate
safety refusal: it **blocks** a `mode:"real"` job outright and never
silently downgrades it to a successful plan-only report.

## 4. Job security model

With execution enabled, no job runs without passing every gate below. All
gates produce the same rejection shape
`{ allowed: false, rejectionReason, detail }` so evidence and result
reporting handle them uniformly.

### Ed25519 signature verification with TOFU pinning

Jobs are signed by a control-plane Ed25519 operational key (HMAC is
explicitly rejected by ADR-0003: a shared symmetric secret would let any
agent forge jobs for any other agent). The agent pins the public key at
registration (`signing-key-pin.json`: `signingKeyId` + `publicKeyPem`) and
verifies every job against it (`verifyJobSignature`):

1. Structural checks on `signature` (base64, 64-1024 chars), `signingKeyId`,
   `nonce` (16-128 chars, `[A-Za-z0-9_.:-]`), `issuedAt`, `expiresAt`. A job
   missing any of these (e.g. a plain unsigned payload) is rejected with
   `job_integrity_failed`: unsigned jobs never execute.
2. `job.signingKeyId` must equal the pinned key id. A mismatch (rotation lag
   or forgery) rejects with `job_integrity_failed`.
3. `crypto.verify` over the canonical payload bytes.

A present-but-corrupted pin file fails startup loudly (never silently
unpinned). If execution is enabled but no key is pinned yet, jobs are
reported `blocked` (not rejected): an agent-side precondition failure, not a
verdict about the job.

### Canonical payload

The signature covers a deterministic canonical JSON serialization of the job
excluding the top-level `signature` field (`canonicalizeJobPayload`): keys
sorted lexicographically at every level, arrays in original order, no
whitespace, standard JSON string escaping, UTF-8 bytes. Non-finite numbers
and `undefined` anywhere in the tree are rejected. The control plane must
implement the identical algorithm byte for byte; `signJobPayload` in the same
module is the reference implementation used by the test harness.

### Replay cache

`src/replay` keeps a persisted cache of consumed `nonce + jobId` pairs
(JSON file, 0600, default 5000 entries). Persistence matters because a job's
validity window can outlive an agent process; without it, a restart would
reopen the replay window. Semantics:

- `check` is read-only and runs early in the chain; `consume` records the
  pair and runs only after all other gates pass, immediately before
  execution. A rejected job therefore does not burn its nonce, but a crash
  mid-execution can never allow a replay.
- A corrupted or unreadable store throws at startup. A tampered replay store
  is treated as a security signal, not a recoverable glitch.
- When the cache is full after sweeping expired entries, new jobs are
  rejected with `job_replay_rejected` rather than evicting unexpired nonces
  (eviction would reopen the replay window for exactly the evicted job).

### Clock drift window checks

`checkJobTimeWindow` validates `now + clockOffsetMs` against
`[issuedAt - tolerance, expiresAt + tolerance]` with
`execution.clockDriftToleranceMs` (default 30000 ms) slack. `expiresAt`
before `issuedAt` is malformed regardless of any clock and rejects with
`job_integrity_failed`; a future-dated or expired job rejects with
`clock_drift_suspected` (both are plausibly clock-related, and a genuinely
replayed job is independently caught by the replay cache).

### Agent-local policy

The policy engine (`src/policy`) is the sole authority on whether a job's
command, path, CA endpoint, DNS zone/provider, and target selector are
allowed on this host. Local policy always wins over control-plane intent
(ADR-0002); the control plane only ever sends opaque references that are
looked up against agent-local config. With no `policy` block every allowlist
is empty and everything is denied; the agent still runs so operators see
policy rejections as evidence instead of silent failures.

`evaluateJob` check order: `checkNoKeyExport` (always first, never
overridable by any config; any custody-shaped intent rejects with
`key_export_requested`), then `checkTargetScope`, `checkCommandRef`,
`checkPath`, `checkCaEndpoint`, `checkDnsZone`, `checkDnsProvider`. Each
dimension is only checked when present on the job.

Policy path checks are lexical only; the deploy module re-checks the
realpath-resolved destination immediately before write so a symlink cannot
escape the allowlisted roots.

## 5. Renewal execution chain

`handleSignedJob` in `src/index.js` runs the fixed order:

```
signature verify -> replay check -> clock window -> policy -> replay consume
  -> unresolved-journal check -> mandatory lease start (claimed→running)
  -> execute (with periodic lease renew + per-mutation renew)
```

Any `{ allowed: false }` verdict reports `policy.checked` evidence plus a
`rejected` result with that `rejectionReason` and stops the chain.

### Fail-closed lease start

The first lease renew after accept is mandatory and fail-closed: it is the
`claimed` → `running` confirmation. No external side effect begins until the
server confirms ownership. During execution the agent:

- runs a periodic lease heartbeat while the job is active;
- renews the lease immediately before each side-effecting stage (key
  generation/rotation, ACME including DNS-01 challenge work driven by the
  ACME adapter, deploy, reload).

On HTTP `409` (ownership/lease conflict), `410` (agent retired), confirmed
lease loss, or a mandatory confirmation failure, execution aborts. A lost
mandatory start is reported as a terminal `blocked`/`failed` outcome rather
than proceeding optimistically.

### Side-effect journal and crash recovery

Before the first external mutation of a job attempt, the agent persists a
claim-scoped side-effect journal entry under
`<configDir>/job-journal/<jobId>-<attemptId>.json` (dir 0700, file 0600;
ids and stage names only — never private keys). Stages recorded include
`keygen`, `acme`, `deploy`, and `reload`. On restart, if an unresolved
journal entry exists for the job id, the agent refuses automatic
re-execution and reports `orphaned_unknown_effect` with
`needsOperatorReconciliation=true` so an operator can reconcile host state.
Terminal outcomes clear the journal entry when reporting completes.

Supported actions: `renew`, `deploy`, `reload`, `noop`. `revoke` is always
`blocked` (out of scope for this agent build). `deploy` without a `certificatePem` field
is `blocked` (see section 7).

For `renew` (`executeRenewJob`):

1. **Keys** (`src/keys`): the private key lives at
   `<keysDir>/<certificateId>.key.pem`. An existing key is reused; one is
   generated only when absent, or when `job.keyRotation` is truthy
   (forward-compatible field). `keyRotated` in the result reports whether a
   new key was generated. Supported algorithms: `ec-p256` (default),
   `ec-p384`, `rsa-2048`, `rsa-3072`, `rsa-4096`, `ed25519`. When the job
   carries `keyAlgorithm`/`keySize` from the renewal profile, those map onto
   the matching algorithm id; unrecognized combinations fail the job.
   Keys are written 0600 in 0700 dirs and
   the exported PEM buffer is zeroized after the write; no exported function
   ever returns private key material.
2. **CSR** (`generateCsr`): PKCS#10. When `job.sans` (or nested
   `renewalProfile.sanPolicy.sans`) is present, the full approved SAN list is
   used for CSR altNames and ACME `-d` domains (CN prefers
   `target.reference` when it is in that list). Otherwise CN and a single SAN
   come from `target.reference`. The CSR is written to a job-scoped temp path
   `<keysDir>/<jobId>.csr.pem` (0600) and removed after the ACME step.
3. **ACME** (`src/acme`): `job.commandRef` must resolve through
   `policyEngine.checkCommandRef` to an allowlisted `{ argv }` profile;
   `job.caEndpoint` is required and re-checked against the CA allowlist
   inside the adapter as defense in depth. Optional `preferredChain` and
   External Account Binding (`eabRef` / `accountRef` resolved via local
   `config.acmeAccounts` credentials files — never transmitted by the control
   plane) are passed through when present. The adapter (`certbot` by
   default, or `acme.sh` when `job.acmeKind` says so) shells out via
   `child_process.execFile` without a shell, in CSR mode (`certbot certonly
   --csr` / `acme.sh --signcsr`), staging the certificate to
   `<keysDir>/<jobId>.cert.pem`. **Scope (current):** external command
   adapters only — there is no embedded ACME client, no step-ca
   integration, and no CA/profile model beyond the allowlisted `caEndpoint`
   URL, optional EAB refs, and the tool's own on-host account state. DNS-01 is wired through the shipped
   `certops-dns-hook` (certbot `--manual-auth-hook` /
   `--manual-cleanup-hook`, acme.sh `--dns` pointing at `dns_certops.sh`).
   No private key and no DNS/EAB credentials ever appear in argv; credentials
   stay in agent-local 0600 files referenced by path in `config.json`.
   Default exec timeout is 10 minutes.
4. **Deploy** (`src/deploy` + multi-target coordinator in `src/index.js`):
   installs public certificate material (and, when configured, the matching
   private key) to explicit destinations. Destination fields on each
   `deploymentTargets[]` entry (and job-level fallbacks) include `certPath`,
   optional `keyPath`, optional `chainPath` (intermediate PEM split from a
   fullchain-style blob; leaf stays at `certPath`), per-file POSIX modes
   (`certMode` / `keyMode` / `chainMode`), optional `owner`/`group`, and
   optional `backupDir` plus validated `backupRetentionCount` (integer
   1–64). `execution.keysDir` is staging/custody state for agent-generated
   keys, **not** an implicit production destination — a deploy that needs a
   live key without an explicit `keyPath` fails preflight. Private-key
   bytes never traverse protocol envelopes, evidence, results, logs, audit,
   or control-plane storage (paths and modes only).

   When `job.deploymentTargets` has more than one entry, deploy is
   transactional:

   1. Preflight every target with no writes (path/policy/mode/ownership
      shape, cert/SAN/key-match validation, lease renew).
   2. Apply+verify each target in turn, renewing the lease before each
      mutation and retaining all backups until commit.
   3. On any failure: stop; roll back previously changed targets in reverse
      order (restore backups or remove first-deploy files); reload restored
      targets when configured. Every restored target → `failed`. Any
      uncertain live state after a failed rollback →
      `orphaned_unknown_effect` with reconciliation markers in
      `errorMessage`.
   4. Commit only after every target succeeds: discard retained backups,
      then return `succeeded`.

   A single target (or legacy single `certPath` / absolute
   `target.reference`) keeps the same atomic write, timestamped backup,
   realpath containment re-check, per-destination mutex, and
   first-deploy-orphan promotion semantics. The module throws if any
   payload contains a PEM private-key marker.
5. **Reload** (`src/reload`, only when the job carries `reloadService`):
   validate-then-reload for `nginx`, `apache`, or `haproxy`. The job must
   name `reloadCommandRefs.validate` and `.reload`, both resolved through
   the command allowlist; commands run via `execFile` with `shell: false`
   and a 30 s default timeout. A failing validate command means the reload
   command never runs.
6. **Verify** (`src/verify`): the deployed PEM's leaf certificate is
   fingerprinted (sha256, lowercase hex, no colons). A live TLS probe
   against the endpoint runs only when the job provides `verifyHost`
   (port from `verifyPort`, default 443); the probe compares the served
   certificate's DER sha256 against the deployed fingerprint. The probe
   deliberately uses `rejectUnauthorized: false`: fingerprint byte-identity
   is the verification, and chain trust would wrongly fail private CAs and
   staging CAs.

`deploy` jobs run steps 4-6 with the job-supplied `certificatePem`; `reload`
jobs run step 5 only; `noop` reports a `validation.passed` evidence item and
succeeds.

Dry-run mode is driven by the signed job's immutable `mode` field (see
"Dry-run and reconciliation statuses" in section 3). When `mode` is
`dry_run`, all trust gates still run, then instead of executing the agent
reports one `policy.checked` evidence item per step the action would run
(with `dryRun: true` metadata) and returns `dry_run_complete` with
`keyRotated` null. Zero filesystem or exec side effects; the
keys/acme/deploy/reload/verify modules are never called. Local
`execution.dryRun` (default true) remains a safety refusal for
`mode:"real"` jobs only — it reports `blocked`, never a silent success.

### DNS-01 providers

`src/dns` implements native TXT-record solvers so DNS-01 challenges no
longer require the ACME tool's own DNS plugins. certbot/acme.sh still drive
the ACME conversation; the ACME adapter always wires them to the
`certops-dns-hook` executable (`packages/agent/bin/certops-dns-hook.js`)
and, for acme.sh, the shipped `dns_certops.sh` dnsapi wrapper. The hook
resolves the managed zone (longest `zoneProviderMap` match, else DNS NS
walk refined by the provider zone list when available), presents/cleans
the TXT value under a cross-process file lock, then polls authoritative
nameservers (and optional configured recursive resolvers) until the value
is visible — or gone on cleanup — before returning success to the ACME
tool. Zero npm dependencies: HTTP providers use global `fetch`, Route 53
SigV4, the GCP JWT, the OVH request signature, and the Exoscale
EXO2-HMAC-SHA256 signature are computed with `node:crypto`, and RFC 2136
speaks the DNS wire format over `node:net` with a TSIG HMAC (RFC 8945,
`hmac-sha1/224/256/384/512`).

Wave-1 provider ids (exact-match against `policy.allowedDnsProviders`):
`cloudflare`, `route53`, `azure-dns`, `google-cloud-dns`, `rfc2136`,
`acme-dns`. Wave-2 provider ids: `ovhcloud`, `hetzner`, `infomaniak`,
`exoscale`, `powerdns`. **Not supported yet:** DigitalOcean DNS (the
`acme-dns` provider is the sixth wave-1 id; do not confuse the two).

Config (`config.json`): each configured provider maps to an object holding
the absolute path of its agent-local credentials file plus optional
non-secret options; the reserved `zoneProviderMap` key routes zones to
providers on multi-provider hosts (longest matching zone wins, dot-boundary
rule; with a single provider and no map entry, that provider is selected
and the zone is discovered via DNS NS / provider zone list — the challenge
hostname is never assumed to be the zone). Optional top-level
`dnsPropagation` controls the post-present / post-cleanup wait:

```json
{
  "dnsPropagation": {
    "timeoutMs": 120000,
    "intervalMs": 2000,
    "resolvers": ["1.1.1.1", "8.8.8.8"],
    "checkAuthoritative": true,
    "verificationMode": "all",
    "quorumCount": null
  }
}
```

`verificationMode` defaults to `all`, requiring every configured resolver
(and the authoritative check, when enabled) to independently confirm the
TXT record before the hook proceeds. Set it to `quorum` with a
`quorumCount` (positive integer, required in quorum mode) to instead
proceed once that many independent server checks confirm — useful when one
of several public resolvers is flaky or slow to pick up the record.

```json
{
  "dnsProviders": {
    "cloudflare": { "credentialsFile": "/etc/tokentimer-agent/dns/cloudflare.json" },
    "rfc2136": { "credentialsFile": "/etc/tokentimer-agent/dns/rfc2136.json" },
    "zoneProviderMap": {
      "example.com": "cloudflare",
      "internal.example.net": "rfc2136"
    }
  }
}
```

Credentials files are JSON objects, must be `0600` (the agent refuses
group/other-readable files on POSIX), and never leave the host:

| Provider | Credentials file fields |
|----------|-------------------------|
| `cloudflare` | `apiToken` (scoped token, Zone.DNS:Edit); optional `zoneId` (looked up by zone name when absent) |
| `route53` | `accessKeyId`, `secretAccessKey`; optional `sessionToken`, `hostedZoneId` (else `ListHostedZonesByName`), `region` (default `us-east-1`) |
| `azure-dns` | `tenantId`, `clientId`, `clientSecret`, `subscriptionId`, `resourceGroup` (client-credentials flow, DNS Zone Contributor role) |
| `google-cloud-dns` | `client_email`, `private_key`, `project_id` (standard SA JSON fields); optional `managedZone` (else looked up by `dnsName`). The SA key is a DNS credential: it signs the OAuth JWT locally and never leaves the host |
| `rfc2136` | `server`, `keyName`, `keySecretBase64`; optional `port` (default 53), `keyAlgorithm` (default `hmac-sha256`) |
| `acme-dns` | `baseUrl`, `username`, `password`, `subdomain` (from `/register`). Cleanup is a documented no-op: acme-dns rotates its two TXT slots automatically. The provider declares `capabilities.cleanupVerifiable: false`, so the hook skips the generic wait-for-TXT-absence poll after cleanup and reports evidence `status: "cleanup_not_applicable"` instead of failing/timing out |
| `ovhcloud` | `applicationKey`, `applicationSecret`, `consumerKey`; optional `endpoint` (default `https://eu.api.ovh.com/1.0`; other regions `https://ca.api.ovh.com/1.0`, `https://us.api.ovhcloud.com/1.0`). Requests are OVH-signed (`$1$` + SHA1) with the LOCAL unix time as `X-Ovh-Timestamp` (no `/auth/time` skew correction); a `POST /domain/zone/<zone>/refresh` follows every mutation so the change actually serves |
| `hetzner` | `apiToken` — **Hetzner Console / Cloud project API token** (`Authorization: Bearer`), not a legacy DNS Console token. Optional `zoneId` (looked up by zone name when absent). Uses `https://api.hetzner.cloud/v1` rrset `add_records` / `remove_records` actions (value-specific; concurrent challenges do not clobber each other). Legacy `dns.hetzner.com` Auth-API-Token credentials are not supported |
| `infomaniak` | `apiToken` (Bearer, "domain" scope). Every response is wrapped in a `{ result: "success"\|"error", data }` envelope; a non-`success` result is treated as failure even on HTTP 200 |
| `exoscale` | `apiKey`, `apiSecret`; optional `apiEndpoint` (default `https://api-ch-gva-2.exoscale.com/v2`; DNS is global, any zone endpoint works). Requests are EXO2-HMAC-SHA256 signed. Mutations are async on Exoscale's side: the accepted operation response is treated as success; the hook's propagation wait covers the apply window |
| `powerdns` | `apiUrl` (e.g. `http://127.0.0.1:8081`), `apiKey` (X-API-Key header); optional `serverId` (default `localhost`). Zone and record names carry a trailing dot and TXT content is double-quoted, per PowerDNS API rules. Present merges with existing TXT values at the name and `REPLACE`s the union (parallel challenges never clobber each other); cleanup `REPLACE`s the remainder or sends `changetype: DELETE` when none remain |

Hook usage. The ACME adapter builds these flags automatically; operators
debugging by hand can use the same contract. certbot manual hooks (the hook
derives the TXT name `_acme-challenge.$CERTBOT_DOMAIN` and reads
`CERTBOT_DOMAIN` + `CERTBOT_VALIDATION` from the environment certbot sets):

```
certbot certonly --csr <csr.pem> --preferred-challenges dns --manual \
  --manual-auth-hook    "/path/to/certops-dns-hook.js present" \
  --manual-cleanup-hook "/path/to/certops-dns-hook.js cleanup" \
  --config-dir <stateDir>/acme/certbot/config \
  --work-dir   <stateDir>/acme/certbot/work \
  --logs-dir   <stateDir>/acme/certbot/logs
```

For acme.sh, `--dns` takes the shipped dnsapi hook **name** (`dns_certops`),
not an absolute path — acme.sh sources `dnsapi/dns_certops.sh` from its own
config home and calls the `dns_certops_add` / `dns_certops_rm` shell
functions it defines. The installer symlinks the shipped script into
`<stateDir>/acme/acme.sh/dnsapi/dns_certops.sh`:

```
CERTOPS_DNS_HOOK=/path/to/certops-dns-hook.js \
LE_CONFIG_HOME=<stateDir>/acme/acme.sh \
  acme.sh --signcsr --csr <csr.pem> --dns dns_certops \
  --home <stateDir>/acme/acme.sh --config-home <stateDir>/acme/acme.sh ...
```

`dns_certops.sh` strips one leading `_acme-challenge.` from the complete TXT
name acme.sh calls it with and exports `ACME_DOMAIN` (base domain) /
`ACME_TXT_VALUE` into `certops-dns-hook present|cleanup`, which prepends
`_acme-challenge.` itself (same convention as certbot's `CERTBOT_DOMAIN`).
Credentials never appear on argv or in the ACME tool environment. Both
tools' working state (config/work/log dirs, or acme.sh's home) lives under
the agent's own state directory so they stay writable under the hardened
systemd unit's `ProtectSystem=strict`. See `COORDINATION-ACME-ADAPTER.md` at
the repo root for the full typed adapter-options contract (`preferredChain`,
`eabKid`/`eabHmacKey`); the adapter no longer accepts a generic `extraArgs`
passthrough.

Policy gate: the hook resolves the provider and zone for the domain, then
requires BOTH `checkDnsProvider` and `checkDnsZone` to pass against the
agent-local policy engine before reading any credentials file or making any
network call. A rejection prints the `{ allowed: false, rejectionReason,
detail }` JSON to stderr and exits nonzero, so the provider id must be in
`policy.allowedDnsProviders` and the zone covered by
`policy.allowedDnsZones` (suffix match with dot boundary). Solver failures
never carry secrets: every provider response excerpt is bounded to 1024
chars and replaced wholesale with `[redacted]` if it contains a
`PRIVATE KEY` marker or any of the credential strings themselves.

## 6. Zero-custody guarantees

Layers, from outermost in:

- **Config**: `writeSigningKeyPin` refuses to pin anything that does not look
  like PEM public key material and rejects any input containing a private-key
  marker. The credential is a bearer secret (not key material) but gets the
  same 0600 discipline and is never logged; `redactCredentialForLogging`
  returns a fixed placeholder for any input.
- **Discovery**: never reads private key bytes. Key presence detection is
  filename heuristics plus a bounded content peek (first 4096 bytes checked
  for a PEM private-key header); results carry only the boolean
  `coLocatedKeyDetected`.
- **Keys**: exported functions return only paths, public key PEM, CSR PEM,
  and fingerprints; every return value is deep-scanned by the shared
  detector (`apps/api/utils/secretMaterial.js`) before it leaves the module.
  Private key PEM buffers are zeroized after writes (documented JS limit:
  KeyObject/OpenSSL internal memory cannot be zeroized from JS).
- **Evidence**: `buildEvidenceItem`/`buildEvidenceBody` reject values
  containing private key material and defensively redact generic secret
  patterns; metadata names must match the schema's deny-pattern (no
  `private-key`, `password`, `secret`, `credential`, ... fragments).
  `assertEvidencePayloadSafe` is a final deep scan run immediately before
  every evidence POST.
- **ACME and reload output**: stdout/stderr excerpts are bounded (1024/512
  chars) and replaced wholesale with `[redacted]` if they contain a
  `PRIVATE KEY` marker; never partially scrubbed.
- **Deploy**: throws on any payload containing a PEM private-key header.
- **Policy**: `checkNoKeyExport` rejects any key-export intent
  unconditionally; there is no config knob that permits it.

## 7. Contract status and forward-compatible fields

Earlier bootstrap builds documented a set of deviations against the base job
payload; the executable job-type contract has since landed
(`packages/contracts/certops/job-payload.schema.json` blesses `commandRef`,
`caEndpoint`, `acmeKind`, `keyRotation`, `certPath`, `reloadService`,
`verifyHost`/`verifyPort`, `certificatePem`, `dnsZone`/`dnsProvider`) and the
control plane now dispatches signed jobs, so most deviations are resolved.
Current behavior:

- Unsigned jobs are rejected with `job_integrity_failed` whenever execution
  is enabled; a payload without `signature`/`nonce`/`signingKeyId`/
  `issuedAt`/`expiresAt` fails signed-field validation. Signed dispatch is
  what the control plane's claim route produces.
- When `job.sans` is absent: the CSR CN and the ACME `-d` domain come
  from `job.target.reference`. When present, the full SAN list is used.
- `certPath` / `keyPath` / `chainPath` resolution: an explicit
  `job.certPath` (or per-target `certPath`) wins; otherwise
  `target.reference` is used as the deploy destination when it is an
  absolute path (POSIX or Windows form). `job.deploymentTargets` deploys to
  every listed destination with optional per-target `keyPath`, `chainPath`,
  modes, ownership, and backup settings (see section 5). Neither a
  resolvable cert destination nor a usable target list means the job fails
  with a clear message. `keysDir` never substitutes for a missing
  production `keyPath`.
- `deploy` without `certificatePem` is `blocked`. The contract defines
  `certificatePem` as public leaf-plus-chain material attached by the
  control plane at signed dispatch time, never stored in the job payload
  column.
- `revoke` is always `blocked` (out of scope for this agent build).
- `attemptId` is assigned by the control plane at claim time (it mirrors the
  claim id and is covered by the job signature); the agent falls back to
  `job.claimId`, then a local `local-<jobId>-<timestamp>` id, only when the
  dispatch omits it. Result reports carry `claimId` and the dispatch `nonce`
  back so the control plane can re-prove claim ownership and consume the
  single-use nonce (ADR-0003).
- Execution fields honored when present: `keyRotation` (forces key
  regeneration), `verifyHost`/`verifyPort` (enables the live TLS probe),
  `reloadService` + `reloadCommandRefs` (enables the reload step), `acmeKind`
  (`certbot` or `acme.sh`), and `commandRef`/`caEndpoint`/`dnsZone`/
  `dnsProvider` on the policy descriptor.
- Ed25519 CSR generation is not supported: `generateCsr` throws a clear
  error for ed25519 keys (use `ec-p256` or `rsa-*` when a CSR is needed).

## 8. Windows notes

The agent primarily targets POSIX hosts, but it runs (and its tests run) on
Windows:

- POSIX file modes (0600/0700) are asserted best-effort: `chmod` calls are
  wrapped and failures ignored on win32, where the POSIX mode model does not
  apply. Tests asserting modes are skipped on win32.
- Directory fsync after the deploy rename is skipped on win32 (opening a
  directory for fsync fails there); the file-content fsync before rename
  still runs on every platform.
- Symlink-dependent tests are skipped where symlink creation requires
  privileges; the realpath containment check itself still runs.
- The default config directory is `%APPDATA%\tokentimer-agent`.
- Absolute-path detection accepts POSIX (`/...`), Windows drive (`C:\...`),
  and UNC (`\\...`) forms.

## 9. Troubleshooting

Common terminal states and what to look for:

- **`orphaned_unknown_effect` / `needsOperatorReconciliation`**: live host
  state is uncertain (failed multi-target rollback, first-ever deploy with
  no prior backup after a post-deploy failure, unresolved local side-effect
  journal on restart, or lease reaper expiry after renewal in the
  side-effect-risk window). Inspect the host paths and the job's
  `reconciliation_reason`, reconcile manually, then clear the operator
  reconciliation flag before re-dispatching work for the same
  certificate/target. This is not a policy rejection.
- **`dry_run_complete`**: expected terminal for `mode:"dry_run"` jobs. If a
  real job somehow reports it, the control plane rejects the result
  (`CERTOPS_AGENT_RESULT_STATUS_INVALID`).
- **Job `blocked`, "no control-plane signing key is pinned yet"**: execution
  is enabled but `signing-key-pin.json` is absent (the register response did
  not carry `signingKeyId`/`signingPublicKeyPem`). Re-register the agent
  against a control plane that dispatches signing key info. The heartbeat's
  `pinnedSigningKeyId` will be null until then.
- **Job `blocked`, "does not execute jobs yet" message**: `execution.enabled` is not
  true. This is the expected observe-only behavior, not an error.
- **`rejected` with `job_integrity_failed`**: missing/malformed signed
  fields, a signing key id mismatch (rotation lag or forgery), a signature
  that does not verify against the canonical payload, or a malformed
  validity window (`expiresAt` before `issuedAt`). The `policy.checked`
  evidence item's summary carries the specific detail. If it persists after
  a control-plane key rotation, re-register to re-pin.
- **`rejected` with `clock_drift_suspected`**: the adjusted time fell
  outside `[issuedAt - tolerance, expiresAt + tolerance]`. Check NTP sync on
  the agent host, and compare the heartbeat's `clockOffsetMs` against
  `execution.clockDriftToleranceMs`. Stale dispatches (jobs queued longer
  than their validity window) produce the same reason.
- **`rejected` with `job_replay_rejected`**: the nonce+jobId pair was
  already consumed, or the replay cache is full of unexpired entries (the
  detail string distinguishes the two). A full cache means the control plane
  is dispatching faster than nonces expire; it never silently evicts.
- **`rejected` with a policy reason** (`target_out_of_scope`,
  `command_not_allowlisted`, `path_not_allowlisted`,
  `ca_endpoint_not_allowlisted`, `dns_zone_not_allowlisted`,
  `dns_provider_not_allowlisted`, `key_export_requested`): the agent-local
  allowlist does not cover the job's reference. Fix the agent's `policy`
  block (or `declaredTargetSelectors`); the control plane cannot override
  this.
- **Startup failure mentioning the replay store**: the store file exists but
  is corrupted or unreadable. This is treated as a tamper signal; inspect
  the file before deleting it manually.
- **Startup failure mentioning the signing key pin**: `signing-key-pin.json`
  is corrupted. Re-register the agent to re-pin.
- **Heartbeat stops and the process exits with a "retired" log line**: the
  control plane returned HTTP 410; this is a clean, intentional shutdown.

### Fleet compatibility and clock drift (control plane)

The control plane computes per-agent compatibility on register/heartbeat and
surfaces it on fleet status APIs (`compatibilityState`, `clockDriftState`,
`clockDriftMs`):

| Field | Values | Meaning |
| --- | --- | --- |
| `compatibilityState` | `compatible` / `outdated` / `blocked` | Protocol and agent version vs env-configured min/max |
| `clockDriftState` | `ok` / `warn` / `alert` / `null` | Absolute drift vs warn/alert thresholds |
| `clockDriftMs` | number or `null` | Absolute clock offset in milliseconds |

Env knobs (API process):

- `CERTOPS_AGENT_MIN_PROTOCOL_VERSION` / `CERTOPS_AGENT_MAX_PROTOCOL_VERSION`
- `CERTOPS_AGENT_MIN_AGENT_VERSION` / `CERTOPS_AGENT_MAX_AGENT_VERSION`
- `CERTOPS_AGENT_CLOCK_DRIFT_WARN_MS` / `CERTOPS_AGENT_CLOCK_DRIFT_ALERT_MS`

`blocked` agents are outside the supported protocol/agent version window.
`outdated` means below the preferred minimum but still accepted. Full alert
delivery wiring for `clockDriftState: alert` is a follow-up; the fleet API
flag is the operator-visible signal today.

### Forced agent retirement and in-flight work

When an operator force-retires an agent (`POST .../agents/:id/retire` with
`force: true`), the control plane does **not** wait for the lease reaper:

1. Jobs still in `claimed` (no execution start reported) are immediately
   `cancelled`.
2. Jobs in `running` are moved to `orphaned_unknown_effect` with
   `needsOperatorReconciliation: true`, because a side effect (for example a
   deploy) may already have happened without a reported result.
3. Subsequent result/evidence submissions from that agent are rejected with
   HTTP 410.

Operators must review the jobs list for `needsOperatorReconciliation` (or
status `orphaned_unknown_effect`) and reconcile hosts manually before
re-dispatching work for the same certificate/target.

Log lines are prefixed `tokentimer-agent:` on stderr. Evidence for rejected
jobs arrives as `policy.checked` items; execution steps report
`validation.passed`/`validation.failed`/`deployment.updated` items with a
`step` metadata entry (`acme`, `deploy`, `reload`, `verify`).
