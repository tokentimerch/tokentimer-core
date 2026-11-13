# Agent operations and troubleshooting

Use this guide after installation for upgrades, compatibility, logs, failed jobs, and retirement. Preserve the state directory: it contains the agent credential, pinned signing key, custody state, and recovery journals.

## Registration replacement and declaration refresh

A registered agent reuses its stored credential and `agentId` on restart. Supplying a fresh bootstrap token to that same state directory does not replace its identity or signing-key pin; the agent scrubs the unnecessary token. Preserve the original protected state directory, including recovery journals and key-custody receipts.

Configuration changes do not require a replacement registration. After restart, authenticated heartbeats publish the configured command-profile names, including an explicit empty list to remove stale profiles. Observe-only agents publish no supported execution operations and never claim jobs. Setting `TT_AGENT_LOG_STREAM=off` withdraws the log-stream capability while retaining the registered identity and credential.

A retired identity cannot register again with a new bootstrap token: the control plane returns `CERTOPS_AGENT_REGISTRATION_CONFLICT` without consuming that token or overwriting working state. A replacement needs a new `agentId` and separate protected state. Coordinate any installed Windows service handoff and custody migration separately; registering an independent replacement process does not transfer the predecessor's jobs, journals, or keys.

<a id="9-troubleshooting"></a>

## Troubleshooting

Common terminal states and what to look for:

- **`orphaned_unknown_effect` / `needsOperatorReconciliation`**: live host
  state is uncertain (failed multi-target rollback, first-ever deploy with
  no prior backup after a post-deploy failure, unresolved local side-effect
  journal on restart, or lease reaper expiry after renewal in the
  side-effect-risk window). Inspect the host paths and the job's
  `reconciliation_reason`, and reconcile the actual host state before
  requesting replacement work for the same certificate/target. There is no
  general dashboard action to clear this flag. Preserve the job evidence and
  obtain support for the affected recovery path rather than editing database
  flags or deleting local journals. This is not a policy rejection.
- **`dry_run_complete`**: expected terminal for `mode:"dry_run"` jobs. If a
  real job somehow reports it, the control plane rejects the result
  (`CERTOPS_AGENT_RESULT_STATUS_INVALID`).
- **Job `blocked`, "no control-plane signing key is pinned yet"**: execution
  is enabled but `signing-key-pin.json` is absent (the register response did
  not carry `signingKeyId`/`signingPublicKeyPem`). Restore the verified pin or
  replace registration using separate protected state against a control plane
  that dispatches signing key info. A new bootstrap token alone does not
  re-pin an existing registration. The heartbeat's
  `pinnedSigningKeyId` will be null until then.
- **Agent registers and heartbeats, but never claims a pending job**: check
  `execution.enabled`. When it is not true, the agent is observe-only and
  never polls for jobs, so no job result is expected from it. Enable claims
  with `execution.enabled: true` while retaining `execution.dryRun: true`
  to test signed dry-run jobs before allowing real work.
- **No result at all, lease expired, `job_integrity_failed` in the agent log**:
  missing/malformed signed fields, a signing key id mismatch (rotation lag or
  forgery), a signature that does not verify against the canonical payload, or
  a malformed validity window (`expiresAt` before `issuedAt`). This is
  deliberate: an integrity verdict is terminal and silent, so there is no
  `rejected` result and no `policy.checked` evidence item to read. Look for the
  detail in the agent's own log. If it persists after a control-plane key
  rotation, inspect the verified pin and supported signing-key rotation path;
  a fresh bootstrap token does not re-pin an existing credential.
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
- **The agent ran a job to completion but the control plane never shows a
  result**: the result is most likely still sitting in the local outbox
  (`<configDir>/outbox/`), retrying delivery with backoff and jitter. Check
  the agent log for outbox-transmission-failure lines. A transient
  (unclassified) failure keeps retrying for up to 48 hours from when the
  entry was created before being quarantined into `outbox/dead-letter/`; a
  permanent failure (e.g. the job or workspace no longer exists) is
  quarantined immediately. Once in `outbox/dead-letter/`, an entry is not
  retried automatically; inspect it and re-submit the underlying work
  manually if the outcome still needs to reach the control plane.
- **`distribute-trust`/`revoke-trust` settles, but a later `revoke-trust` on
  the same target fails with the agent's own `receipt_pending_install`**:
  the prior job's OS mutation actually succeeded, but the agent's local
  receipt-finalize write failed afterward (`receipt_finalize_conflict`,
  recorded in the installation row's `last_error` on the control plane
  rather than unwinding the row). Re-run `distribute-trust` for that same
  target; this retries the finalize write and clears the stale receipt
  state, after which `revoke-trust` will proceed normally.
- **Startup failure mentioning the replay store**: the store file exists but
  is corrupted or unreadable. This is treated as a tamper signal; inspect
  the file before deleting it manually.
- **Startup failure mentioning the signing key pin**: `signing-key-pin.json`
  is corrupted. Re-register the agent to re-pin.
- **Heartbeat stops and the process exits with a "retired" log line**: the
  control plane returned HTTP 410; this is a clean, intentional shutdown.
  The exit status is **86**, paired with `RestartPreventExitStatus=86` in the
  unit; `systemctl status` shows `inactive (dead)` with `status=86`. Do not
  confuse this with `activating (auto-restart)` + `status=1/FAILURE`, which
  *is* a real startup/registration failure and needs
  `journalctl -u tokentimer-agent -n 50 --no-pager`.
- **A job stays `pending` and this agent never claims it**: the job is pinned
  to a different agent (normally the one that discovered the certificate) or
  requires a target selector this agent does not declare. See [job assignment](../../../.github/maintainers/certops/agent/protocol.md#which-agent-gets-a-job-exclusivity-vs-assignment); this is routing, not an agent fault.
- **Renew job creation refused for a certificate visible in inventory**:
  `409 CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE`. The certificate was only
  observed (endpoint/domain monitor), so no agent holds its key. Install an
  agent on the host that actually serves it.
- **Agent healthy but automatic renewals never happen**: a control-plane
  problem, not an agent one. The `certops` worker target
  (`worker-certops` / `cronjob-certops`) creates renewal jobs; without it,
  or with `CERTOPS_ENABLED` out of sync between API and worker, the
  scheduler counts every certificate as skipped and nothing renews.

<a id="fleet-compatibility-clock-drift-and-liveness-control-plane"></a>

### Fleet compatibility, clock drift, and liveness (control plane)

The control plane computes per-agent compatibility on register/heartbeat and
surfaces it on fleet status APIs (`compatibilityState`, `clockDriftState`,
`clockDriftMs`, `livenessState`):

| Field | Values | Meaning |
| --- | --- | --- |
| `compatibilityState` | `compatible` / `outdated` / `blocked` | Protocol and agent version vs env-configured min/max |
| `clockDriftState` | `ok` / `warn` / `alert` / `null` | Absolute drift vs warn/alert thresholds |
| `clockDriftMs` | number or `null` | Absolute clock offset in milliseconds |
| `livenessState` | `live` / `stale` / `retired` / `null` | Computed in real time from `lastSeenAt` (or `createdAt` if never heartbeated) vs `CERTOPS_AGENT_OFFLINE_AFTER_MS` |

Env knobs (API process):

- `CERTOPS_AGENT_MIN_PROTOCOL_VERSION` / `CERTOPS_AGENT_MAX_PROTOCOL_VERSION`
- `CERTOPS_AGENT_MIN_AGENT_VERSION` / `CERTOPS_AGENT_MAX_AGENT_VERSION` (the
  `MAX` is an unbounded reject-ceiling, not the "outdated" reference; see
  `CERTOPS_AGENT_LATEST_KNOWN_VERSION` below)
- `CERTOPS_AGENT_LATEST_KNOWN_VERSION` (defaults to the shipped agent
  package's own version; only this drives the `outdated` label)
- `CERTOPS_AGENT_CLOCK_DRIFT_WARN_MS` / `CERTOPS_AGENT_CLOCK_DRIFT_ALERT_MS`
- `CERTOPS_AGENT_OFFLINE_AFTER_MS` (default `600000`, 10 minutes; also read by
  the worker sweep below, so keep both in sync if overridden)

`blocked` agents are outside the supported protocol/agent version window.
`outdated` means more than one minor behind `CERTOPS_AGENT_LATEST_KNOWN_VERSION`
but still accepted. Full alert delivery wiring for `clockDriftState: alert` is
a follow-up; the fleet API flag is the operator-visible signal today.

The persisted `certops_agents.status` column (`active` / `offline` /
`retired`) only ever moves *toward* `active` on the agent's own
register/heartbeat/claim calls; it is demoted to `offline` exclusively by the
periodic stale-agent sweep (`sweepStaleAgents` in
`apps/worker/src/certops-worker.js`, the `certops` worker/CronJob target;
Compose schedules it with `WORKER_CERTOPS_CRON`, Kubernetes with
`worker.cronjobs.certops.schedule`, both defaulting to `*/1 * * * *`).
`livenessState` is derived from
the same `CERTOPS_AGENT_OFFLINE_AFTER_MS` threshold on every list/read call,
so the fleet panel shows `stale` immediately even in the window between
sweeps, or if the `certops` worker/CronJob is not deployed at all. The
`certops` worker target must be running (Compose: `worker-certops` service;
Kubernetes: `cronjob-certops`, `worker.cronjobs.certops.enabled`) for
`status` itself to ever converge to `offline`; without it, `status` stays
`active` forever regardless of `livenessState`.

<a id="forced-agent-retirement-and-in-flight-work"></a>

### Forced agent retirement and in-flight work

A retire without `force` is **refused** while the agent still holds actively
leased jobs (`countActivelyLeasedJobs` in `agentRegistry.js`):
`409 CERTOPS_AGENT_RETIRE_BLOCKED` with a `dependencies.leasedJobs` count.
Waiting for the job to finish is the normal path.

`force: true` requires an attributable `reason`, enforced server-side
(`400 CERTOPS_AGENT_RETIRE_REASON_INVALID`), not merely in the dashboard
form: a forced retire can abandon real work, so the audit trail must say
why. When an operator force-retires an agent (`POST .../agents/:id/retire`
with `force: true`), the control plane does **not** wait for the lease
reaper:

1. Jobs still in `claimed` (no execution start reported) are immediately
   `cancelled` with `error_code: CERTOPS_AGENT_FORCE_RETIRED`.
2. Jobs in `running` are moved to `orphaned_unknown_effect` with
   `needsOperatorReconciliation: true`, because a side effect (for example a
   deploy) may already have happened without a reported result.
3. Subsequent result/evidence submissions from that agent are rejected with
   HTTP 410.

The response reports both id lists (`fenced.cancelledJobIds`,
`fenced.orphanedJobIds`) and the `CERTOPS_AGENT_RETIRED` audit event records
`force`, `reason`, `leasedJobs`, and both lists. Retirement is idempotent:
retiring an already-retired agent returns 200 with the original `retiredAt`
and fences nothing a second time.

Operators must review the jobs list for `needsOperatorReconciliation` (or
status `orphaned_unknown_effect`) and reconcile hosts manually before
re-dispatching work for the same certificate/target.

<a id="clean-exit-on-retirement-exit-code-86"></a>

### Clean exit on retirement (exit code 86)

A retired agent that learns of its own retirement (heartbeat/claim answered
410) exits with **`AGENT_RETIRED_EXIT_CODE = 86`**
(`packages/agent/src/index.js`), matched by `RestartPreventExitStatus=86` in
`packages/agent/scripts/tokentimer-agent.service`. The unit is
`Restart=always`, so without that pairing systemd would respawn a
decommissioned agent into an endless heartbeat-410 loop (ADR-0002 clean
retirement).

Operational consequence worth stating for support: a unit sitting
`inactive (dead)` with `status=86` is **not** a crash. It is the designed
terminal state of a retired agent, and it is visually easy to confuse with
the `activating (auto-restart)` / `status=1/FAILURE` loop that a genuine
startup or registration failure produces. Only the latter needs
`journalctl -u tokentimer-agent` triage.

Log lines are prefixed `tokentimer-agent:` on stderr. Evidence for rejected
jobs arrives as `policy.checked` items; execution steps report
`validation.passed`/`validation.failed`/`deployment.updated` items with a
`step` metadata entry (`acme`, `deploy`, `reload`, `verify`).

<a id="supported-platform--tool-version-matrix"></a>

### Supported platform / tool version matrix

This is the tested support matrix for this release. Versions outside this
matrix may work but are not covered by CI or release sign-off.

| Component | Supported range | Notes |
|---|---|---|
| Node.js | `>= 22.0.0, < 25.0.0` | Even-numbered Active LTS lines only (22, 24); odd/Current releases are not release-tested. |
| Certbot | `2.x` (tested against the latest `2.x` release at release time) | `--manual` + `--csr` mode only; snap and pip installs both exercised in CI. |
| acme.sh | Latest tagged release at release time (pinned commit recorded in CI config) | Uses the shipped `dns_certops` dnsapi hook; requires acme.sh's own `dnsapi` loading support (stable across acme.sh releases). |
| Operating system | Linux with systemd (Debian/Ubuntu LTS, RHEL/Rocky 9+) | `install-agent.sh` requires systemd; for other init systems use the documented self-supervised process. Use `install-agent.sh --dry-run` to preview changes. Ubuntu 22.04, 24.04 and 26.04 LTS and AlmaLinux 9 are verified; other distributions require independent verification. |
| Operating system (Windows) | Windows Server, build >= 14393 (2016) or later | `install-agent.ps1` refuses older builds; see the [Windows build-number floor](windows-runtime.md). Server 2019, 2022 and 2025 are verified. Other eligible builds and Windows desktop editions require independent verification. |
| DNS provider APIs | See `src/dns/providers/*.js`; each provider module documents the API version/date it was implemented against | Re-verified when a provider's upstream API has a breaking change. |
| PostgreSQL (control plane) | `15+` | Several CertOps migrations use `ON DELETE SET NULL (column_list)` on composite foreign keys, native since PostgreSQL 15; `gen_random_uuid()` alone would only require 13+. The bundled local-dev compose (`deploy/compose/docker-compose.postgres.yml`) runs `postgres:17-alpine`. |

<a id="wire-contract-compatibility-upgrade-ordering"></a>

### Wire-contract compatibility (upgrade ordering)

Use matching supported control-plane and agent packages. Upgrade the control
plane first, confirm agent registration and fresh heartbeats, then upgrade
agents and verify a signed dry run. Check the deployment compatibility manifest
and fleet compatibility result before dispatching real work.

Agents require a matching signed agent ID by default. They reject jobs if the
control plane does not send it; if rollback is necessary,
CERTOPS_AGENT_REQUIRE_SIGNED_AGENT_ID=false is a temporary agent-side override.
Capability-gated dispatch requires a fresh declaration according to
CERTOPS_CAPABILITY_FRESHNESS_MS.
## Upgrade and uninstall

Upgrade the control plane before agents. Download and verify the new package, then re-run the platform installer using the same settings. The installer still asks for a bootstrap token on an upgrade: a registered agent keeps its credential and does not use it, so paste any value that starts with `ttboot_` (or set `TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=ttboot_unused`). Preserve config, credentials, signing pins, keys, and journals. Confirm a fresh heartbeat and compatibility before dispatching real work.

Retire the agent in the fleet panel after its jobs finish. `install-agent.sh --uninstall` or `install-agent.ps1 --uninstall` removes the service and app while preserving state. Review and back up custody and recovery state before any manual deletion.

### Linux removal behavior

`install-agent.sh --uninstall` stops and disables the service, then removes the app directory, unit file, drop-in override, and polkit rule. It preserves the state directory and system user. Retire the agent in the dashboard too; otherwise the fleet continues to list it until the stale-agent sweep marks it offline. Manually delete state only after preserving required credentials, custody keys, and recovery journals.

## Unusable custody key

A renewal can stop with `agent custody key does not match the deployed certificate` or `agent custody key is quarantined after a failed promotion`, and no staging key remains. The agent refuses to reuse a key it cannot prove belongs to the deployed certificate.

A rotation that is rolled back after a failed reload or verify restores the previous key into custody automatically. A promotion whose outcome is unknown stays quarantined, and so does a host affected before that fix. To recover, stop renewals for the certificate, delete the custody key named in the error (`<state>/keys/<certificate id>.key.pem`) and, when present, its `.custody-quarantine` marker. The next renewal issues a new key and installs it with the new certificate.

## Related

[Agent overview](../agent.md) · [Configuration](configuration.md) · [Linux installation](install-linux.md) · [Windows installation](install-windows.md)
