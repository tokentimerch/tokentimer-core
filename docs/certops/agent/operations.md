# Agent operations and troubleshooting

Use this guide after installation for upgrades, compatibility, logs, failed jobs, and retirement. Preserve the state directory: it contains the agent credential, pinned signing key, custody state, and recovery journals.

<a id="9-troubleshooting"></a>

## Troubleshooting

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
- **No result at all, lease expired, `job_integrity_failed` in the agent log**:
  missing/malformed signed fields, a signing key id mismatch (rotation lag or
  forgery), a signature that does not verify against the canonical payload, or
  a malformed validity window (`expiresAt` before `issuedAt`). This is
  deliberate: an integrity verdict is terminal and silent, so there is no
  `rejected` result and no `policy.checked` evidence item to read. Look for the
  detail in the agent's own log. If it persists after a control-plane key
  rotation, re-register to re-pin.
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
  requires a target selector this agent does not declare. See [job assignment](protocol.md#which-agent-gets-a-job-exclusivity-vs-assignment); this is routing, not an agent fault.
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
| Operating system | Linux with systemd (Debian/Ubuntu LTS, RHEL/Rocky 9+) | The installer and hardened unit (`ProtectSystem=strict`) assume systemd; other init systems (e.g. Alpine/OpenRC) are not supported by `install-agent.sh` (confirmed: it fails at the `/etc/systemd/system` unit-install step, since that directory does not exist without systemd), though the agent binary itself runs fine on musl libc, and a manually-run, self-supervised process is a documented fallback for systemd-less hosts (see the self-hosted install runbook's systemd-less note). Real end-to-end verified on **Ubuntu 22.04, 24.04, and 26.04 LTS** and **AlmaLinux 9** (fresh WSL2 installs, full agent install -> issue -> auto-renew cycle against a real DNS-01 provider, `certbot` on Ubuntu and `acme.sh` on AlmaLinux). `install-agent.sh` itself has no CI dry-run (unlike `install-agent.ps1`'s Windows dry-run above), so a real host run is the only verification path for the Linux installer today. Other systemd-based Debian/Ubuntu LTS and RHEL/Rocky 9+ releases are expected to work (same systemd unit/`ReadWritePaths` model, and AlmaLinux 9's pass confirms the RHEL/Rocky family generally, not just Ubuntu) but are not independently verified. Ubuntu 22.04 is being phased out as a GitHub-hosted CI runner (deprecation announced 2026-09-17, unsupported from 2027-04-17). |
| Operating system (Windows) | Windows Server, build >= 14393 (2016) or later | `install-agent.ps1` fails closed below build 14393, the first widely-deployed release with both WDAC and CNG non-exportable key custody generally available (see the [Windows build-number floor](windows-runtime.md)). Real end-to-end verified on **Windows Server 2025** (build 26100), **Windows Server 2022** (build 20348), and **Windows Server 2019**: full agent install, CNG-native issue with real IIS binding, unattended auto-renew, and the CNG/IIS/retention/discovery module-level real-host checks all produced identical results on all three, with no code path found to differ between them. Other Windows Server releases from build 14393 onward are expected to work the same way but are not independently verified; Windows 10/11 desktop SKUs are not verified as agent hosts at all. |
| DNS provider APIs | See `src/dns/providers/*.js`; each provider module documents the API version/date it was implemented against | Re-verified when a provider's upstream API has a breaking change. |
| PostgreSQL (control plane) | `15+` | Several CertOps migrations use `ON DELETE SET NULL (column_list)` on composite foreign keys, native since PostgreSQL 15; `gen_random_uuid()` alone would only require 13+. The bundled local-dev compose (`deploy/compose/docker-compose.postgres.yml`) runs `postgres:17-alpine`. |

<a id="wire-contract-compatibility-upgrade-ordering"></a>

### Wire-contract compatibility (upgrade ordering)

This stack changes the agent<->control-plane wire contract several times.
Each change is additive and capability-gated, but the *order* you upgrade
components in still matters:

| Change | Minimum server version | Upgrade order | What happens if you get it backwards |
| --- | --- | --- | --- |
| `declaredCapabilities` on heartbeat (not just register) | the release that admits `declaredCapabilities` in `heartbeatBody` | Upgrade the server first. An older server's `heartbeatBody` schema is `additionalProperties: false` with no `declaredCapabilities`, so it rejects the field outright rather than ignoring it. | A heartbeat carrying capabilities fails schema validation against an un-upgraded server. |
| Envelope v2 (`signed-payload-b64-v1`) | the release that ships dual-format dispatch | Either order; this is dispatch-time, not connection-time. An agent advertising the capability gets v2 once its capability declaration is fresh (`CERTOPS_CAPABILITY_FRESHNESS_MS`); every other agent gets v1. | None: an agent that never advertises the capability, or whose declaration goes stale, simply keeps getting v1. |
| Required `agentId` in the signed payload | the release that starts emitting `agentId` unconditionally | Upgrade the server first, let it run until every agent you operate has re-registered or heartbeated at least once, *then* upgrade the agent (`CERTOPS_AGENT_REQUIRE_SIGNED_AGENT_ID` now defaults to `true`, enforcing this automatically). If any agent still talks to a control plane that has not finished emitting `agentId`, set `CERTOPS_AGENT_REQUIRE_SIGNED_AGENT_ID=false` on that agent first as a temporary rollback. | Upgrading the agent before the server emits `agentId` on every dispatch turns every not-yet-upgraded control plane's dispatch into a hard failure for that agent, unless the rollback override is set. |
| `agent-id-binding-v1` capability (reference clients) | same release as required `agentId` above | Reference clients advertise this capability only once their local `agentId` enforcement is actually the effective behavior, not merely because the shipped code supports it. | A client advertising the capability while its own enforcement flag is still off would falsely promise a guarantee it is not enforcing. |
| Enterprise pin | `tokentimer-enterprise` at the matching core version | Bump and pin core and enterprise together; do not let one lag. | Enterprise CI can silently stop skipping edition-gated core tests it must skip if the cross-repo marker it depends on drifts from core. |

## Upgrade and uninstall

Upgrade the control plane before agents when the compatibility table requires it. Download and verify the new package, then re-run the platform installer using the same settings. Preserve config, credentials, signing pins, keys, and journals. Confirm a fresh heartbeat and compatibility before dispatching real work.

Retire the agent in the fleet panel after its jobs finish. `install-agent.sh --uninstall` or `install-agent.ps1 --uninstall` removes the service and app while preserving state. Review and back up custody and recovery state before any manual deletion.

### Linux removal behavior

`install-agent.sh --uninstall` stops and disables the service, then removes the app directory, unit file, drop-in override, and polkit rule. It preserves the state directory and system user. Retire the agent in the dashboard too; otherwise the fleet continues to list it until the stale-agent sweep marks it offline. Manually delete state only after preserving required credentials, custody keys, and recovery journals.

## Related

[Agent overview](../agent.md) · [Configuration](configuration.md) · [Linux installation](install-linux.md) · [Windows installation](install-windows.md)
