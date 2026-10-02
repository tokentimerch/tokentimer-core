# Agent configuration reference

Prepare the local allowlists before enrolling an agent for certificate work. These settings control the host; control-plane requests cannot broaden them. Start with execution disabled, test a signed dry-run, and opt into real work only after checking the intended destinations.

<a id="config-directory"></a>

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
| `outbox/` | Durable queue of terminal results/evidence awaiting control-plane acknowledgement (default location); drained on restart before new claims. Retention-capped at 5000 entries / 7 days; a transient (unclassified) delivery failure is quarantined into `outbox/dead-letter/` once it has both been retrying for 48 hours **and** made at least 8 delivery attempts, so a long control-plane outage cannot discard an entry the agent has barely tried to deliver | dir 0700, files 0600 |
| `outbox/dead-letter/` | Quarantined outbox entries that kept failing transiently past the 48-hour age ceiling and the 8-attempt floor, or failed with a permanent error immediately, plus entries whose file became unreadable and stayed that way past the 7-day cap. Pruned on the same cadence as `outbox/`: entries whose quarantine time (not the original job's completion time) is more than 30 days ago, or beyond 5000 entries, are deleted. Not drained automatically; inspect and clear manually if control-plane acknowledgement is truly unrecoverable for an entry | dir 0700, files 0600 |
| `job-journal/` | Side-effect journal, `<jobId>-<attemptId>.json`, written before the first external mutation; an unresolved entry blocks automatic re-execution (see [Execution](execution.md)) | dir 0700, files 0600 |
| `trust-receipts/` | Agent-local ownership receipt for `distribute-trust`/`revoke-trust`, one file per `(store, fingerprintSha256)`; proves this agent installed a given anchor before a later `revoke-trust` is allowed to remove it (see ADR-0012 decision (d)) | dir 0700, files 0600 |
| `trust-work/` | Scratch working directory for the trust-store executor (e.g. staging a PEM before `certutil`/`update-ca-certificates`/`update-ca-trust`); not durable state, safe to clear when the agent is stopped | dir 0700 |
| `registration-id.json` | Client-generated `registrationId` for encrypted registration recovery; cleared once the credential is durably stored | 0600 |
| `bootstrap.env` | Bootstrap token, written by the installer and **deleted by the agent** after its first successful registration (best-effort; delete it yourself if it survives) | 0600 |
| `acme/` | certbot (`config`/`work`/`logs`) and acme.sh (`home`/`config-home`, incl. the `dnsapi/dns_certops.sh` symlink) working state, kept here so both stay writable under `ProtectSystem=strict` | dir 0700 |

<a id="first-run-registration"></a>

### First-run registration

With no stored credential, the agent requires `TOKENTIMER_AGENT_BOOTSTRAP_TOKEN`
(and optionally `TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID`) in the environment.
The bootstrap token is single-use and never persisted. Registration stores
the assigned `agentId` in `config.json`, the issued credential in
`credential`, and, when the register response carries one, pins the control
plane's job-signing public key in `signing-key-pin.json` (trust-on-first-use,
ADR-0003). A stored credential with no `agentId` in `config.json` is an
inconsistent config directory and aborts startup.

<a id="encrypted-registration-recovery"></a>

#### Encrypted registration recovery

A lost register response can be replayed within a short window by presenting
the same authenticated bootstrap token plus the original `registrationId`.
`registrationId` is a client-generated identifier (string, 1-128 chars,
pattern `^[A-Za-z0-9_.:-]+$`; UUID v4 recommended) sent on every register
attempt (`registerBody.registrationId`, agent-protocol envelope
`messageType: "register"`). The agent persists it under the config dir
(`registration-id.json`, 0600) before sending register and clears it only
after the credential is durably written locally, so a crash between
receiving the credential response and persisting it locally is recoverable:
restart reuses the same `registrationId` and the server replays the
identical `{ agentId, credential, protocolVersion, signingKeyId?,
signingPublicKeyPem? }` response rather than rejecting the bootstrap token as
already spent. A retry with a *different* `registrationId` against an
already-spent token remains a hard rejection, so a single token can only
ever mint one agent identity. The control plane stores that replay credential
as an AES-256-GCM encrypted
envelope in `certops_agent_registration_replays` (never plaintext). Decrypt
happens only on that authenticated replay path
(`apps/api/services/certops/registrationCredentialCrypto.js`). The API process
requires `CERTOPS_REGISTRATION_ENCRYPTION_KEY` (64 hex chars = 32 bytes) and
fails closed if it is missing or malformed. Replay TTL defaults to 15 minutes
and is overridable via `CERTOPS_REGISTRATION_REPLAY_TTL_MS` (positive
milliseconds). Expired replay rows are deleted by the CertOps maintenance
worker's `registration-replay-sweep`.

<a id="config-reference-configjson"></a>

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
| `dnsProviders` | object or null | null | Native DNS-01 solver configuration (see "DNS-01 providers" in [DNS and ACME](dns-and-acme.md)). Maps provider id to `{ credentialsFile: <absolute path>, ...non-secret options }`, plus a reserved `zoneProviderMap` key (zone to provider id). Credentials never live in `config.json`, only the path to a 0600 credentials file does. Fail-loud validation: unknown provider ids, relative paths, and `zoneProviderMap` entries naming unconfigured providers abort startup. |
| `dnsPropagation` | object or null | defaults | Post-mutation DNS wait: `{ timeoutMs` (default 120000), `intervalMs` (default 2000), `resolvers` (optional recursive resolver IPs), `checkAuthoritative` (default true), `verificationMode` (`all` default, or `quorum`), `quorumCount` (required positive integer in quorum mode, else null) `}`. Used by `certops-dns-hook` after present/cleanup. See "DNS-01 providers" in [DNS and ACME](dns-and-acme.md) for the verification-mode semantics. |
| `allowInsecureLocalHttp` | boolean | false | Permits a plain `http://` `serverUrl`, and only for loopback hosts (`localhost` / `127/8` / `::1` / `*.localhost`). Development only; the installer's `--allow-insecure-local-http` writes it. |
| `acmeAccounts` | object or null | null | Maps an opaque account/EAB reference to `{ credentialsFile: <absolute path> }` for ACME External Account Binding. Like `dnsProviders`, only the path lives in config; the credentials stay in an agent-local 0600 file and are never transmitted by the control plane. |
| `pinnedSigningKey` | object or null | null | **Derived, not hand-written.** Read back from `signing-key-pin.json` (`{ signingKeyId, publicKeyPem }`) and surfaced on the loaded config. Set by trust-on-first-use at registration and by rotation adoption; editing it by hand is not a supported way to change the trusted key. |

`policy` block (deep validation in `src/policy/loadPolicyConfig`, fail-loud):

| Field | Type | Notes |
|-------|------|-------|
| `allowedCommands` | object | Maps profile name to `{ argv: string[] }`. `argv` is the allowlisted **executable plus any fixed leading flags you want to require**, not the whole command line: for the built-in certbot/acme.sh CSR flows the adapter appends the subcommand and its own flags (`certonly`/`--signcsr`, `--csr <path>`, the DNS hook flags, `--server <caEndpoint>`, output paths) itself, so repeating them in `argv` duplicates them and the tool fails to parse. See the argv table in `src/acme/index.js`. Every argv element is rejected at load time if it contains a shell metacharacter (`; \| & $ ` > <` or CR/LF). |
| `allowedPaths` | string[] | Normalized to absolute paths; containment is segment-aware (no sibling-prefix collisions). |
| `allowedCaEndpoints` | string[] | Full-URL exact match after trailing-slash normalization. |
| `allowedDnsZones` | string[] | Suffix match with dot boundary (`sub.example.com` covered by `example.com`, `evilexample.com` is not). |
| `allowedDnsProviders` | string[] | Exact match. |

Trust-anchor distribution (`trust-anchor-deploy-v1`) resolves its platform-native
update command through this same `allowedCommands` map, under dedicated
profile names that no other job family uses:

| Profile name | Platform | Typical `argv` |
|--------------|----------|----------------|
| `trust-store:update-ca-certificates` | Debian/Ubuntu | `["/usr/sbin/update-ca-certificates"]` |
| `trust-store:update-ca-trust` | RHEL/Fedora | `["/usr/bin/update-ca-trust", "extract"]` |
| `trust-store:certutil` | Windows | `["certutil.exe"]` |
| `trust-store:update-ca-certificates-fresh` | Debian/Ubuntu, `revoke-trust` only | `["/usr/sbin/update-ca-certificates", "--fresh"]` |

The `-fresh` profile is optional and only consulted on the Debian
`revoke-trust` path: `update-ca-certificates` without `--fresh` does not
prune a just-removed anchor's dangling `/etc/ssl/certs` symlink, so
configuring this profile lets revoke self-heal that symlink instead of only
warning about it (`debian_fresh_command_ref_missing` in the result's
`metadata`). It is never consulted for `distribute-trust`, and RHEL has no
equivalent flag.

Because these names are distinct from every ACME/reload profile, a renewal-only
agent grants no trust-store command execution, and a trust-only agent grants no
renewal command execution. An agent whose policy omits the profile for its own
platform rejects a trust job with `command_not_allowlisted` before attempting
any mutation, on every platform including Windows: a "renew-only" agent (no
`allowedCommands` profiles configured at all) refuses `distribute-trust`/
`revoke-trust` the same way regardless of which platform it runs on.

`discovery` block:

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `directories` | string[] | required | Directories to scan for certificates. |
| `intervalMs` | positive int | 3600000 | Hourly by default. |

`execution` block (signed-job execution):

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | boolean | false | Opt-in; an upgraded agent never starts executing without it. |
| `dryRun` | boolean | true | Plan-only execution with zero side effects (see [Execution](execution.md)). |
| `keysDir` | string | `<configDir>/keys` | Private keys, 0600 in 0700 dir. |
| `replayStorePath` | string | `<configDir>/replay-store.json` | Persisted replay cache. |
| `outboxDir` | string | `<configDir>/outbox` | Durable queue for terminal results/evidence that could not be delivered yet, so an outage does not lose a completed job's outcome. Retention-capped (5000 entries / 7 days); see the [state-directory table](configuration.md#config-directory) for the `dead-letter/` quarantine subdirectory and its own retention. |
| `clockDriftToleranceMs` | positive int | 30000 | Slack applied to the signed-job validity window. |

## Related

[Agent overview](../agent.md) · [Configuration](configuration.md) · [Operations](operations.md)
