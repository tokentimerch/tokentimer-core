# Job execution and crash recovery

Advanced reference for lease ownership, side effects, and interrupted jobs. For an uncertain result, use [Operations](operations.md) before submitting replacement work.

<a id="5-renewal-execution-chain"></a>

## Renewal execution chain

`handleSignedJob` in `src/index.js` runs the fixed order:

```
signature verify -> replay check -> clock window -> policy -> replay consume
  -> unresolved-journal check -> mandatory lease start (claimed→running)
  -> execute (with periodic lease renew + per-mutation renew)
```

Any `{ allowed: false }` verdict reports `policy.checked` evidence plus a
`rejected` result with that `rejectionReason` and stops the chain.

<a id="fail-closed-lease-start"></a>

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

<a id="lease-renew-endpoint"></a>

#### Lease renew endpoint

```
POST /api/v1/certops/agent/jobs/:jobId/lease
Authorization: Bearer <agent credential>
Content-Type: application/json

{ "claimId": "<uuid from the signed dispatch payload>", "sequence": 12 }
```

This route does not use the agent-protocol message envelope
(`messageType`): the job id is in the path, auth is the agent credential,
and ownership is `agent_id + claimId`. `sequence` is optional until the
agent has sent any sequenced message, after which omitting it is rejected.
Success (`200`) returns `{ ok, jobId, status, claimId, leaseExpiresAt,
leaseRenewedAt, nonceExpiresAt }`; the first successful call transitions
`claimed` → `running`, and every successful call extends both
`lease_expires_at` (by `CERTOPS_JOB_LEASE_SECONDS`, default 900) and the
still-open dispatch nonce.

| Status | Code | When |
| --- | --- | --- |
| 400 | `CERTOPS_AGENT_MESSAGE_INVALID` | Malformed body / jobId |
| 400 | `CERTOPS_AGENT_LEASE_INVALID` | Job not in claimed/running, or missing claimId |
| 409 | `CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH` | claimId / agent does not own the job |
| 409 | `CERTOPS_AGENT_SEQUENCE_REGRESSION` | Sequence not strictly increasing |
| 410 | `CERTOPS_AGENT_RETIRED` | Agent is retired |
| 404 | `CERTOPS_AGENT_JOB_NOT_FOUND` | Unknown job in this workspace |

Do not renew after a terminal result has been submitted.

<a id="side-effect-journal-and-crash-recovery"></a>

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

Supported actions: `renew`, `deploy`, `reload`, `noop`, `distribute-trust`,
`revoke-trust`. `revoke` (managed-certificate revocation, distinct from
`revoke-trust`) is always `blocked` (out of scope for this agent build).
`deploy` without a `certificatePem` field is `blocked` (see [Job contracts](protocol.md)).

The control plane additionally has an `issue` job operation, used for
first-time issuance of a certificate that has no inventory row yet. It is a
control-plane-only concept: at dispatch the control plane translates it to
`action: "renew"` in the signed payload, so an agent never receives the value
`issue`, the wire-level action list above is unchanged, and there is no
protocol `schemaVersion` bump. Agents already deployed in the field execute
`issue` jobs with no upgrade, byte-identically to a renew.

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
   Default exec timeout is 10 minutes. `--cert-path`, `--chain-path`, and
   `--fullchain-path` (the latter two derived as siblings of the resolved
   `--cert-path`, e.g. `<name>.chain.pem` / `<name>.fullchain.pem`) are all
   passed explicitly to certbot for exactly this reason: left unset,
   certbot's own chain/fullchain path defaults resolve relative to the
   process's working directory, which under the hardened systemd unit's
   `ProtectSystem=strict` is typically read-only. Without the explicit
   flags, a certbot run can complete a real ACME order successfully and
   then crash while saving the chain (`OSError: [Errno 30] Read-only file
   system: '/0000_chain.pem'`), losing an already-issued certificate. See
   the argv/flags table in `src/acme/index.js`'s module docblock for the
   exact contract, and the worked Cloudflare DNS-01 example in
   `tokentimer-cloud`'s docs for a real reproduction and fix confirmation.
   A separate, unrelated operator pitfall: certbot also needs an ACME
   account to run non-interactively, so `policy.allowedCommands.<profile>
   .argv` must include `--agree-tos` plus either `--email <address>` or
   `--register-unsafely-without-email` — without one of these, the job
   fails at the ACME step with an account-registration error that is easy
   to misdiagnose as a DNS-01 problem.
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
   or control-plane storage (paths and modes only). `certPath` (and the
   other path fields) must be the exact destination **file**, not the
   containing directory — `policy.allowedPaths` allows a directory tree,
   but `certPath` must resolve to one concrete file under it. Pointing
   `certPath` at a directory gets past every policy check (the directory
   itself is allowlisted) and only fails at deploy time with `deploy:
   could not read existing destination: EISDIR: illegal operation on a
   directory, read`.

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
"Dry-run and reconciliation statuses" in [Protocol](protocol.md)). When `mode` is
`dry_run`, all trust gates still run, then instead of executing the agent
reports one `policy.checked` evidence item per step the action would run
(with `dryRun: true` metadata) and returns `dry_run_complete` with
`keyRotated` null. Zero filesystem or exec side effects; the
keys/acme/deploy/reload/verify modules are never called. Local
`execution.dryRun` (default true) remains a safety refusal for
`mode:"real"` jobs only — it reports `blocked`, never a silent success.

## Related

[Agent overview](../agent.md) · [Configuration](configuration.md) · [Operations](operations.md)
