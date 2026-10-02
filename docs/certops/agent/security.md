# Agent security model

Advanced reference for signatures, replay protection, clock checks, local policy, and private-key custody. For policy setup, begin with [Configuration](configuration.md).

<a id="4-job-security-model"></a>

## Job security model

With execution enabled, no job runs without passing every gate below. All
gates produce the same rejection shape
`{ allowed: false, rejectionReason, detail }` so evidence and result
reporting handle them uniformly.

<a id="ed25519-signature-verification-with-tofu-pinning"></a>

### Ed25519 signature verification with TOFU pinning

Jobs are signed by a control-plane Ed25519 operational key (HMAC is
explicitly rejected by ADR-0003: a shared symmetric secret would let any
agent forge jobs for any other agent). The agent pins the public key at
registration (`signing-key-pin.json`: `signingKeyId` + `publicKeyPem`) and
verifies every job against it (`verifyJobSignature`):

1. Structural checks on `signature` (base64, 64-1024 chars), `signingKeyId`,
   `nonce` (16-128 chars, `[A-Za-z0-9_.:-]`), `issuedAt`, `expiresAt`. A job
   missing any of these (e.g. a plain unsigned payload) fails integrity:
   unsigned jobs never execute.
2. `job.signingKeyId` must equal the pinned key id. A mismatch (rotation lag
   or forgery) fails integrity.
3. `crypto.verify` over the canonical payload bytes.

An integrity failure at any of those three steps is **terminal and silent**:
the agent submits **no** result and lets the lease expire. `claimId` and
`nonce` live inside the signed payload and the claim response carries no
unsigned handle, so a report would have to be built from the very fields the
verdict just declared untrustworthy. Operators therefore see such a job as an
expired lease plus a local agent log line, not as a `rejected` result. A
*semantic* rejection decided after verification (target out of scope, command
not allowlisted, and so on) does travel the result path, bound to the verified
`claimId`/`nonce`.

A present-but-corrupted pin file fails startup loudly (never silently
unpinned). If execution is enabled but no key is pinned yet, jobs are
reported `blocked` (not rejected): an agent-side precondition failure, not a
verdict about the job.

<a id="canonical-payload"></a>

### Canonical payload

The signature covers a deterministic canonical JSON serialization of the job
excluding the top-level `signature` field (`canonicalizeJobPayload`): keys
sorted lexicographically at every level, arrays in original order, no
whitespace, standard JSON string escaping, UTF-8 bytes. Non-finite numbers
and `undefined` anywhere in the tree are rejected. The control plane must
implement the identical algorithm byte for byte; `signJobPayload` in the same
module is the reference implementation used by the test harness.

<a id="replay-cache"></a>

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

<a id="clock-drift-window-checks"></a>

### Clock drift window checks

`checkJobTimeWindow` validates `now + clockOffsetMs` against
`[issuedAt - tolerance, expiresAt + tolerance]` with
`execution.clockDriftToleranceMs` (default 30000 ms) slack. `expiresAt`
before `issuedAt` is malformed regardless of any clock and fails integrity
(terminal and silent, no result submitted); a future-dated or expired job
rejects with `clock_drift_suspected`, which is a below-the-gate rejection and
therefore IS reported (both are plausibly clock-related, and a genuinely
replayed job is independently caught by the replay cache).

<a id="agent-local-policy"></a>

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

<a id="6-zero-custody-guarantees"></a>

## Zero-custody guarantees

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
- **Memory residency**: the agent does not call `mlock`/`VirtualLock` and
  makes no locked-memory guarantee anywhere in this document; pinning one
  Node `Buffer` would be false assurance against the copies the runtime,
  OpenSSL, and the OS itself make elsewhere in the path. Key bytes can still
  reach the OS swap file/pagefile for as long as the process holds them
  before zeroization. Operators handling private keys on this host should
  enable OS-level swap/pagefile encryption (for example, an encrypted swap
  partition on Linux or BitLocker-protected pagefile on Windows) to cover
  this residual risk.
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

## Related

[Agent overview](../agent.md) · [Configuration](configuration.md) · [Operations](operations.md)
