# ADR-0002: CertOps agent protocol and agent-local policy

## Status

Proposed (2026-06-25). Phase 0 skeleton; finalize in M0, detail in M4.

## Context

The agent is the only component that touches private keys. It must be safe by
construction: a compromised or misconfigured control plane must not be able to
make an agent do arbitrary things.

## Decision

- **Outbound-only**: the agent polls the control plane (`/api/v1/certops/agent/*`).
  The control plane never connects to agents.
- **Message envelope** frozen in `packages/contracts/certops/agent-protocol.schema.json`
  (stub): `register`, `heartbeat`, `claim`, `result`, `evidence`. Bodies defined
  in M4.
- **Agent-local policy wins**: the agent executes only preconfigured/allowlisted
  command profiles, paths, CA endpoints, and DNS zones/providers. When
  control-plane intent exceeds local policy, the agent refuses and reports the
  refusal as evidence.
- **DNS-01 credential locality**: DNS provider API tokens are provisioned
  agent-side only. The control plane stores references and allowlists
  (`allowedDnsZones`, `allowedDnsProviders`), never the credentials.
- **No key material in any message** (enforced by the detector at ingest).

## Alternatives considered

- Control-plane push to agents - rejected: widens attack surface and requires
  inbound connectivity to execution hosts.
- Control-plane-defined commands without local allowlists - rejected: removes
  the agent's ability to be the final authority over what runs on its host.

## Consequences

- The agent is testable in isolation against the frozen envelope.
- TODO (M4): per-message body schemas, registration/enrollment trust, agent
  credential storage (0700/0600, rotation), supply-chain integrity.
