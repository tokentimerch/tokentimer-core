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
routes (`src/protocol/index.js` `ROUTES`):

| Message | Route |
|---------|-------|
| `register` | `POST /api/v1/certops/agent/register` |
| `heartbeat` | `POST /api/v1/certops/agent/heartbeat` |
| `claim` | `POST /api/v1/certops/agent/jobs/claim` |
| `result`, `evidence` | `POST /api/v1/certops/agent/jobs/results` |

Result and evidence share one route; the envelope's `messageType`
disambiguates server-side. Every envelope carries `schemaVersion` (1),
`protocolVersion`, `messageType`, `agentId`, `sentAt`, and optionally
`workspaceId` and `clockOffsetMs`. Messages must never carry private key
material (schema-level rule, enforced again by the evidence builder).

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
  `rejected`, `blocked`, plus `rejectionReason`, `keyRotated`,
  `errorMessage`, `clockOffsetMs`) and per-step evidence bodies.

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
signature verify -> replay check -> clock window -> policy -> replay consume -> execute
```

Any `{ allowed: false }` verdict reports `policy.checked` evidence plus a
`rejected` result with that `rejectionReason` and stops the chain.

Supported actions: `renew`, `deploy`, `reload`, `noop`. `revoke` is always
`blocked` (out of scope for this agent build). `deploy` without a `certificatePem` field
is `blocked` (see section 7).

For `renew` (`executeRenewJob`):

1. **Keys** (`src/keys`): the private key lives at
   `<keysDir>/<certificateId>.key.pem`. An existing key is reused; one is
   generated only when absent, or when `job.keyRotation` is truthy
   (forward-compatible field). `keyRotated` in the result reports whether a
   new key was generated. Supported algorithms: `ec-p256` (default),
   `rsa-2048`, `rsa-3072`, `ed25519`. Keys are written 0600 in 0700 dirs and
   the exported PEM buffer is zeroized after the write; no exported function
   ever returns private key material.
2. **CSR** (`generateCsr`): PKCS#10, CN and single SAN from
   `target.reference`, written to a job-scoped temp path
   `<keysDir>/<jobId>.csr.pem` (0600) and removed after the ACME step.
3. **ACME** (`src/acme`): `job.commandRef` must resolve through
   `policyEngine.checkCommandRef` to an allowlisted `{ argv }` profile;
   `job.caEndpoint` is required and re-checked against the CA allowlist
   inside the adapter as defense in depth. The adapter (`certbot` by
   default, or `acme.sh` when `job.acmeKind` says so) shells out via
   `child_process.execFile` without a shell, in CSR mode (`certbot certonly
   --csr` / `acme.sh --signcsr`), staging the certificate to
   `<keysDir>/<jobId>.cert.pem`. No private key and no DNS credentials ever
   appear in argv; DNS credentials live in the ACME tool's own host-side
   config files. Default exec timeout is 10 minutes.
4. **Deploy** (`src/deploy`): atomic install to the resolved `certPath` with
   target-config re-validation, realpath containment re-check via the policy
   `checkPath` callback, idempotent skip for byte-identical content,
   timestamped backup before overwrite, temp-file-plus-rename atomic write
   with fsync, automatic rollback on failure, and a per-destination async
   mutex. Deployed files get mode 0600. The module throws if the payload
   contains a PEM private-key marker, regardless of what the caller claims.
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

Dry-run mode (`execution.dryRun`, default true): all trust gates still run,
then instead of executing, the agent reports one `policy.checked` evidence
item per step the action would run (with `dryRun: true` metadata) and
returns `succeeded` with `keyRotated` null. Zero filesystem or exec side
effects; the keys/acme/deploy/reload/verify modules are never called.

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
- No domains list in the schema: the CSR CN and the ACME `-d` domain come
  from `job.target.reference`.
- `certPath` resolution: an explicit `job.certPath` wins; otherwise
  `target.reference` is used as the deploy destination when it is an
  absolute path (POSIX or Windows form); neither present means the job fails
  with a clear message.
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

Log lines are prefixed `tokentimer-agent:` on stderr. Evidence for rejected
jobs arrives as `policy.checked` items; execution steps report
`validation.passed`/`validation.failed`/`deployment.updated` items with a
`step` metadata entry (`acme`, `deploy`, `reload`, `verify`).
