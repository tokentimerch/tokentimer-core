# ADR-0003: CertOps job signing and replay protection

## Status

Proposed (2026-06-25). Skeleton record; details land with the executor API and
agent protocol phases.

**Addendum (2026-08-03, release 0.12.0): dual-format v1/v2 signed dispatch.**
The canonicalization TODO in Consequences is now resolved (see below), and a
second wire format was added. Read the addendum before relying on "signature"
being the only wire shape: a dispatched job may instead arrive as a
`payloadB64`/`signatureB64` wrapper with no top-level `signature` at all.

## Context

Jobs instruct an agent to perform key-bearing actions. A job must be provably
issued by the control plane, must not be replayable, and must not be executable
outside a bounded time window. Symmetric secrets (HMAC) shared with agents would
let any agent forge jobs for any other; they are not acceptable.

## Decision

- **Asymmetric signing**: the control plane holds an Ed25519 **platform
  operational signing key** and signs every job. Agents pin the corresponding
  public key (`signingKeyId`) and verify the signature before execution. HMAC is
  rejected.
- This signing key is a platform operational key only. It is never used for
  certificate issuance and never holds customer PKI/TLS key material.
- **Replay protection** envelope frozen in
  `packages/contracts/certops/job-payload.schema.json`: `jobId`, `attemptId`,
  `issuedAt`, `expiresAt`, `workspaceId`, `agentId`/selector, `nonce`,
  `signingKeyId`, `signature`. Agents keep a bounded replay cache keyed by
  `nonce` + `jobId` and reject jobs outside `[issuedAt, expiresAt]`
  (clock-drift aware via reported `clockOffsetMs`).

## Alternatives considered

- HMAC with per-agent secrets - rejected: key distribution and forgery surface.
- No expiry, rely on nonce only - rejected: unbounded replay cache and no time
  bound on captured jobs.

## Consequences

- The signature must cover a canonical serialization excluding the `signature`
  field; canonicalization must be defined precisely to avoid verification drift.
- TODO (ratification): signing key rotation policy and `signingKeyId` lifecycle; canonical
  serialization; replay-cache size/TTL; clock-drift thresholds.

## Addendum (2026-08-03, release 0.12.0): dual-format v1/v2 signed dispatch

Both open TODOs above are resolved by this addendum: canonical serialization is
defined precisely (below), and signing-key rotation/lifecycle is covered by
ADR-0012's key-rotation decision, which this record defers to rather than
duplicating.

- **Canonical serialization, defined once, shared by both sides.**
  `packages/contracts/certops/canonical-json.cjs` is the single source of
  truth: object keys sorted lexicographically by UTF-16 code unit at every
  nesting level, arrays keep original order, no whitespace, `undefined`
  anywhere throws rather than being dropped silently, and the top-level
  `signature` property (only at depth 0) is excluded from what gets signed.
  Both `apps/api/services/certops/jobSigning.js` (signer) and
  `packages/agent/src/signing/index.js` (verifier) require this exact module,
  so the signed byte contract cannot drift between implementations by
  construction rather than by convention.
- **v1 (original wire shape, still the default): one flat signed object.**
  The job's own fields plus `nonce`/`issuedAt`/`expiresAt`/`signingKeyId` and a
  top-level `signature`, which is the base64 Ed25519 signature over the
  canonical serialization of every other field. This is the shape the original
  decision text above describes; nothing about it changed.
- **v2 (added 0.12.0): the "exact-byte signed envelope".** v1 requires every
  client to implement the same field-sorting canonicalization algorithm
  bit-for-bit, which is a real burden for a dependency-light client (a
  Bash+jq+OpenSSL or standalone Go verifier, see ADR-0012 decision 1). v2
  sidesteps canonicalization on the client: the control plane still
  canonicalizes the job exactly once (the identical `canonicalizeJobPayload`
  call v1 uses, so v1 and v2 sign byte-identical input for the same signed
  job, never two independent serializations of the same job with the same
  nonce), signs those exact bytes, and ships them as `payloadB64` (their
  base64) alongside `signatureB64` (the Ed25519 signature over the *decoded*
  bytes, not over the base64 text) and `signingKeyId`. The wire object is
  `{ envelopeVersion: 2, payloadB64, signatureB64, signingKeyId }` and nothing
  else: no sibling unsigned job object, so anything not inside `payloadB64` is
  simply not part of the dispatch. Full wire-format details (base64
  canonicality rules, exact-length signature check, size bounds) live in
  ADR-0012 decision 1 and 2, which this record defers to rather than
  duplicating; this addendum states the replay-protection-relevant part only,
  that v2 carries the identical replay-protection fields (`nonce`, `issuedAt`,
  `expiresAt`, `signingKeyId`) as v1, just inside the encoded payload instead
  of beside it.
- **The two-decode gate (verify-before-parse) is a replay-protection
  requirement, not just a parsing nicety.** A v2 verifier MUST check
  `payloadB64`'s decoded bytes against `signatureB64` first, and only a
  verified byte sequence is ever `JSON.parse`'d. Parsing first and verifying
  the resulting object second would let a malformed or hostile
  `payloadB64` reach a JSON parser (and whatever downstream code trusts its
  shape) before any signature has been checked at all, which defeats the
  entire point of signing: the replay/expiry/nonce fields this ADR requires
  are exactly the fields a forged, unverified payload could also carry. Both
  decode steps (canonical-base64 check, then Ed25519 verification of the
  decoded bytes) must complete before the second decode (JSON parsing the
  now-verified bytes) is attempted.
- **Dual-format dispatch is selected per job, not per fleet.** The control
  plane picks v1 or v2 per dispatched job based on whether the polling
  agent has a *fresh* declaration of the `signed-payload-b64-v1` capability,
  not merely whether it ever declared it. `certops_agents.capabilities_updated_at`
  must be within `CERTOPS_CAPABILITY_FRESHNESS_MS` (default 600000ms / 10
  minutes, matching the pre-existing `CERTOPS_AGENT_OFFLINE_AFTER_MS` agent
  liveness threshold rather than a second, independently chosen number) of
  "now" for the capability to count. An agent that stops heartbeating for
  longer than that window is dispatched v1 on its next claim even though its
  stored `declaredCapabilities` still lists `signed-payload-b64-v1`; the
  next successful heartbeat refreshes `capabilities_updated_at` and dispatch
  reverts to v2 from the following claim onward. No special recovery step
  exists or is needed: the agent's own heartbeat is what restores it. This
  keeps capability freshness and agent liveness as two separate signals on
  separate columns while deliberately sharing one threshold value, on the
  reasoning that an agent whose capability assertion is stale enough to
  already be liveness-stale has no business being offered a
  capability-gated job format either.

