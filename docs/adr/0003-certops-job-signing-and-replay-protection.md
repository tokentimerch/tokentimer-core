# ADR-0003: CertOps job signing and replay protection

## Status

Proposed (2026-06-25). Phase 0 skeleton; finalize in M0, detail in M2/M4.

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
- TODO (M0): signing key rotation policy and `signingKeyId` lifecycle; canonical
  serialization; replay-cache size/TTL; clock-drift thresholds.
