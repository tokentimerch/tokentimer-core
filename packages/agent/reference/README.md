# TokenTimer CertOps protocol reference clients

Two standalone, dependency-light reference implementations of the CertOps
agent protocol (see [docs/adr/0002-certops-agent-protocol.md](../../../docs/adr/0002-certops-agent-protocol.md)
and [docs/certops/agent.md](../../../docs/certops/agent.md) for the wire
contract itself):

* `tokentimer-protocol.sh` — Bash + `curl` + OpenSSL 3
* `tokentimer-protocol.ps1` — PowerShell 7+

They exist so the protocol is demonstrably implementable from the published
contract alone, without reading the production agent's source. They are
**not** a production agent replacement: no retry policy, no persistent
claim/lease loop, and by default no real work at all (see "Dry run by
default" below). The PowerShell script is also the reference a Windows
integrator reaches for before onboarding the real Windows agent.

### Runtime dependencies

| Client | Requires |
|---|---|
| `tokentimer-protocol.sh` | Bash, `curl`, OpenSSL 3.x, **and** Node `>=22 <25` |
| `tokentimer-protocol.ps1` | PowerShell 7+ **and** Node `>=22 <25` |

Both clients need Node, not only the PowerShell one. The signed-job
canonicalization contract (ADR-0003) is defined in terms of JavaScript's
key-ordering and number-formatting behavior, so reimplementing it in pure
Bash could not be proven byte-identical to what the control plane signs. The
Bash client therefore delegates canonical-JSON handling (and only that) to
`reference/lib/canonicalize.cjs`, and does the Ed25519 signature math itself
with `openssl pkeyutl -verify -rawin`. `canonicalize.cjs` is self-contained
against the published contracts and imports no production agent runtime.

Both scripts share one flag contract so they can be read side by side:

```
--mode / -Mode agent              required (agent protocol only)
--step / -Step <STEP>             required, no default
--execute / -Execute              opt into real HTTP; never default
--json / -Json                    machine-readable output
```

## Mode

* **agent** — the outbound machine-protocol surface
  (`apps/api/routes/certops-agent.js`), i.e. what a real CertOps agent
  speaks after enrollment. This is the only mode these scripts implement.

## Steps

| Step | Network call | Notes |
|---|---|---|
| `register` | yes | Bootstrap-token authenticated. Generates an `agentId`/`registrationId` if omitted. |
| `heartbeat` | yes | Credential authenticated. Requires `--agent-id` / `-AgentId`. |
| `claim` | yes | Credential authenticated. Requires `--agent-id` / `-AgentId`. Response shape is `{ jobs: [ signedJob, ... ] }`. |
| `result` | yes | Credential authenticated. Reports a job attempt's terminal outcome. |
| `verify` | no | Local-only: verifies a signed job payload's Ed25519 signature and (unless `--skip-time-window` / `-SkipTimeWindow`) its validity window. |
| `all` | yes (except the verify sub-step) | Walks `register → heartbeat → claim → (verify) → result`. With `--execute` / `-Execute`, claimed jobs are parsed and verified before any result is submitted; a verification failure aborts the flow. |

## Mandatory Ed25519 signature verification

Both scripts verify every signed job payload's Ed25519 signature and never
ship an `--insecure` / `-Insecure` switch. If the pinned verification tool
is missing or too old, they fail closed with a clear, named error:

* **Bash**: OpenSSL 3.x (`openssl pkeyutl -verify -rawin`, PureEdDSA / raw
  Ed25519). Canonical-JSON handling is delegated to the pinned Node helper
  below; the actual signature math is pure OpenSSL.
* **PowerShell**: shells out entirely to `reference/lib/canonicalize.cjs`,
  a self-contained helper that reimplements the published canonicalization
  rules from `packages/contracts/certops/canonical-json.cjs` and verifies
  with Node's `crypto.verify(null, ...)`. It does **not** import production
  agent runtime code. Requires pinned Node `>=22 <25` on `PATH`.

The same helper also exposes `result-fields <job.json>`, which reports the
`jobId` / `attemptId` / `claimId` / `nonce` / `mode` a client must echo into
its result envelope, and fails closed when a required id is missing.

## Dry run by default

Every step except `verify` prints the HTTP request it *would* send —
method, URL, and body, with the `Authorization` header redacted — and exits
`0` without contacting the control plane, unless `--execute` / `-Execute`
is passed. Real work is limited to the protocol dry run itself: these
scripts never invoke an ACME client, never perform a certificate deployment
or rollback, never generate a key pair for real use, and never read a
private key file off disk.

## Credentials

Credentials are read from environment variables, or from a file passed on
the command line — **never** as a plain `--bootstrap-token` /
`--credential` (or `-BootstrapToken` / `-Credential`) argument value:

| Credential | Env var | File flag |
|---|---|---|
| Bootstrap token (register) | `TOKENTIMER_AGENT_BOOTSTRAP_TOKEN` | `--bootstrap-token-file` / `-BootstrapTokenFile` |
| Agent credential (heartbeat/claim/result) | `TOKENTIMER_AGENT_CREDENTIAL` | `--credential-file` / `-CredentialFile` |

Credential files must be readable only by their owner (Bash: mode `0600`,
enforced; PowerShell: best-effort ACL check that fails closed if additional
principals beyond the owner/Administrators/SYSTEM have access, or if the
ACL check cannot be performed). Neither script ever writes a credential to
its own log output.

## HTTP and CA hardening

* `https://` is always accepted.
* Plain `http://` is accepted only for loopback hosts (`localhost`,
  `127.0.0.1`, `::1`). Any other plain-HTTP URL fails closed.
* Bash accepts `--ca-bundle` and passes it to `curl --cacert`.
* PowerShell rejects `-CaBundle` (custom CA bundles are not supported by
  this client's HTTP stack); use the system trust store or the Bash client.

## Verified `all --execute` pipeline

```
register → adopt returned identity → heartbeat → claim
        → parse jobs[] → validate contract → verify signature/key/window
        → result (echoing nonce + claimId)
```

Each stage fails closed:

- **Registration identity is consumed, not assumed.** `all --execute` reads
  `{ agentId, credential }` out of the register response and speaks as that
  identity for heartbeat, claim, and result. The credential is held in process
  memory only: never logged, never written to disk, never passed as a child
  process argument. A register response without a usable pair aborts the run
  rather than continuing under a locally generated id.
- **Incoming jobs are contract-validated first.** Every claimed job is checked
  against the published `job-payload.schema.json` *before* any signature work,
  so a correctly signed payload that violates the contract (unknown action,
  missing required field, unexpected extra property) never reaches an
  execution path. If the compiled validator is unavailable, the client rejects
  the job rather than skipping the check.
- **Then signature, pinned key id, and validity window** are verified. A
  failed verification stops the flow before any result is submitted.
- **The result echoes the signed `nonce` and `claimId`.** The control plane
  consumes that nonce in its replay ledger at result ingestion, so a real
  submission that omits it is rejected.
- **Terminal status follows the job's immutable `mode`.** `dry_run_complete`
  is reported only for `mode: "dry_run"` jobs. Because this client performs no
  certificate operations at all, a `mode: "real"` job is **refused** rather
  than reported as complete: it is left for an agent that can actually execute
  it. Pass `--result-status` / `-ResultStatus` explicitly only when reporting
  on work performed elsewhere.

Until `--pubkey-file` / `-PubKeyFile` and `--signing-key-id` /
`-SigningKeyId` are supplied, `all --execute` refuses to run.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Step succeeded (dry-run preview shown, or `--execute` request returned 2xx, or `verify` returned `{"allowed":true}`). |
| `1` | Step failed: `--execute` request returned a non-2xx status, `verify` returned `{"allowed":false,...}`, or a usage/validation error. |
| `2` | (Bash `canonicalize.cjs` helper only) Parameter/usage error inside the Node helper itself. |

## Examples

```bash
# Bash: full walkthrough against a local control plane, dry run.
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