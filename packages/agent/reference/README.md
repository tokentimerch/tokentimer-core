# TokenTimer CertOps protocol reference clients

Two standalone, dependency-light reference implementations of the CertOps
agent protocol (see [`docs/adr/0002-certops-agent-protocol.md`](../../../docs/adr/0002-certops-agent-protocol.md)
and [`docs/certops/agent.md`](../../../docs/certops/agent.md) for the wire
contract itself):

* `tokentimer-protocol.sh` - Bash + `curl` + OpenSSL 3.
* `tokentimer-protocol.ps1` - PowerShell 7+.

They exist so the protocol is demonstrably implementable from the published
contract alone, without reading the production agent's source. They are
**not** a production agent replacement: no retry policy, no persistent
claim/lease loop, and by default no real work at all (see "Dry run by
default" below). The PowerShell script is also the reference a Windows
integrator reaches for before onboarding the real Windows agent.

Both scripts share one flag contract so they can be read side by side:

```
--mode <executor|agent>   (-Mode)          required, no default
--step <STEP>             (-Step)          required, no default
--execute                 (-Execute)       opt out of dry run; never default
--json                    (-Json)          machine-readable output
```

## Modes

* **executor** - the external-executor observation surface
  (`apps/api/routes/certops-executor.js`). Only `register` (which posts an
  observation) is documented here; the executor protocol otherwise lives
  in its own contract (`packages/contracts/certops/executor-event.schema.json`).
* **agent** - the outbound machine-protocol surface
  (`apps/api/routes/certops-agent.js`), i.e. what a real CertOps agent
  speaks after enrollment. This is the primary subject of these scripts.

## Steps

| Step | Mode | Network call | Notes |
|---|---|---|---|
| `register` | executor or agent | yes | Bootstrap-token authenticated. Agent mode generates an `agentId`/`registrationId` if `--agent-id`/`-AgentId` is omitted. |
| `heartbeat` | agent | yes | Credential authenticated. Requires `--agent-id`/`-AgentId`. |
| `claim` | agent | yes | Credential authenticated. Requires `--agent-id`/`-AgentId`. |
| `result` | agent | yes | Credential authenticated. Reports a job attempt's terminal outcome (`--result-status succeeded\|failed\|rejected\|dry_run_complete\|orphaned_unknown_effect`, plus `--job-id`/`--attempt-id`). |
| `verify` | agent | no | Local-only: verifies a signed job payload's Ed25519 signature and (unless `--skip-time-window` is added upstream) its validity window. Requires `--job-file`, `--pubkey-file`, `--signing-key-id`. |
| `all` | agent | yes (except the `verify` sub-step) | Walks `register` -> `heartbeat` -> `claim` -> (`verify`, if `--job-file`/`--pubkey-file`/`--signing-key-id` are all given) -> `result` in one run, generating an `--agent-id` and job/attempt ids as needed. |

## Mandatory Ed25519 signature verification

Both scripts verify every signed job payload's Ed25519 signature and never
ship an `--insecure`/`-Insecure` switch to skip that check. If the pinned
verification tool is missing or too old, they fail closed with a clear,
named error rather than silently accepting an unverified job:

* **Bash**: requires OpenSSL 3.x (`openssl pkeyutl -verify -rawin`, i.e.
  PureEdDSA / raw Ed25519, matching `crypto.verify(null, ...)` in
  `packages/agent/src/signing/index.js` bit for bit). Canonical-JSON
  handling (`canonicalize`/`extract-field`) is delegated to the pinned
  Node helper below; the actual signature math is pure OpenSSL.
* **PowerShell**: shells out entirely to `reference/lib/canonicalize.cjs`
  (a thin CLI wrapper around `packages/agent/src/signing/index.js`, itself
  built on `packages/contracts/certops/canonical-json.cjs`, the same
  canonicalization module the control-plane signer and the production
  agent both use). PowerShell's native crypto surface does not yet
  reliably expose Ed25519 across every supported Windows PowerShell 7
  runtime, so this script deliberately does not attempt a from-scratch
  .NET implementation. Requires a pinned Node 22+ on `PATH` (see
  `packages/agent/package.json`'s `engines.node`).

## Dry run by default

Every step except `verify` (which never makes a network call) prints the
HTTP request it *would* send - method, URL, and body, with the
`Authorization` header redacted - and exits `0` without contacting the
control plane, unless `--execute`/`-Execute` is passed. This mirrors
`install-agent.sh`'s `--dry-run` convention. `--execute`/`-Execute` is
never the default and there is no environment variable that silently
implies it.

Real work is limited to the protocol dry run itself: these scripts never
invoke an ACME client, never perform a certificate deployment or rollback,
never generate a key pair for real use, and never read a private key file
off disk.

## Credentials

Credentials are read from environment variables, or from a file passed on
the command line - **never** as a plain `--bootstrap-token`/`--credential`
(or `-BootstrapToken`/`-Credential`) argument value, since argv is visible
in process listings (`ps`, Task Manager, etc.) on shared hosts:

| Credential | Env var | File flag |
|---|---|---|
| Bootstrap token (register) | `TOKENTIMER_AGENT_BOOTSTRAP_TOKEN` | `--bootstrap-token-file` / `-BootstrapTokenFile` |
| Agent credential (heartbeat/claim/result) | `TOKENTIMER_AGENT_CREDENTIAL` | `--credential-file` / `-CredentialFile` |

Credential files must be readable only by their owner (Bash: `chmod 600`,
enforced; PowerShell: a best-effort ACL check that warns if additional
principals beyond the owner/Administrators/SYSTEM have access). Neither
script ever writes a credential to its own log output; the
`Authorization` header is always printed as `Bearer <redacted>` in
dry-run/verbose output.

When running with `--execute`/`-Execute` and no credential is configured,
both scripts fail closed with a clear error instead of sending an empty or
placeholder credential to a real control plane. Without `--execute`, a
missing credential only produces a warning (dry-run preview), since no
request is actually sent.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Step succeeded (dry-run preview shown, or `--execute` request returned 2xx, or `verify` returned `{"allowed":true}`). |
| `1` | Step failed: `--execute` request returned a non-2xx status, `verify` returned `{"allowed":false,...}`, or a usage/validation error (missing required flag, bad `--api-url`, etc.). |
| `2` (Bash `canonicalize.cjs` helper only) | Programmer/usage error inside the Node helper itself (unreadable file, malformed JSON) - never used for an untrusted-job rejection, which is always exit `1` with a JSON body. |

## Determinism and testing

Two live runs against a real control plane never produce byte-identical
`--json`/`-Json` output: `registrationId`, generated `agentId`/`jobId`/
`attemptId` values, and `sentAt` timestamps differ every run by design.
The test suite (`reference-client.test.js`) does not assert byte-identical
output; it normalizes those fields away before comparing against the
recorded fixtures in `fixtures/` (generated by `generate-fixtures.js`,
which is a dev-only tool, not shipped in the npm package).

## Examples

```bash
# Bash: full walkthrough against a local dev control plane, dry run.
./tokentimer-protocol.sh --mode agent --step all --api-url https://localhost:8443

# Bash: verify a signed job payload against a pinned public key.
./tokentimer-protocol.sh --mode agent --step verify \
  --job-file job.json --pubkey-file pinned-key.pem --signing-key-id signing-key-1
```

```powershell
# PowerShell: same full walkthrough.
./tokentimer-protocol.ps1 -Mode agent -Step all -ApiUrl https://localhost:8443

# PowerShell: verify a signed job payload against a pinned public key.
./tokentimer-protocol.ps1 -Mode agent -Step verify `
  -JobFile job.json -PubKeyFile pinned-key.pem -SigningKeyId signing-key-1
```
