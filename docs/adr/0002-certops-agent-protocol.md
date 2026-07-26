# ADR-0002: CertOps agent protocol and agent-local policy

## Status

Proposed (2026-06-25). Phase 0 skeleton; details land with the agent protocol
phase.

## Context

The agent is the only component that touches private keys. It must be safe by
construction: a compromised or misconfigured control plane must not be able to
make an agent do arbitrary things.

## Decision

- **Outbound-only**: the agent polls the control plane (`/api/v1/certops/agent/*`).
  The control plane never connects to agents.
- **Message envelope** frozen in `packages/contracts/certops/agent-protocol.schema.json`
  (stub): `register`, `heartbeat`, `claim`, `result`, `evidence`. Bodies defined
  with the agent protocol phase.
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
- TODO (agent protocol phase): per-message body schemas, registration/enrollment trust, agent
  credential storage (0700/0600, rotation), supply-chain integrity.
- Addendum (2026-07-26, release 0.11.0): declared capabilities became a
  dispatch-time gate, and evidence gained a claim binding. Both are additive to
  the envelope and neither is a `schemaVersion` change.
  - Agents declare capability strings at `register` and `heartbeat`. The control
    plane matches on them when offering work, so a capability an agent does not
    declare simply means it is not offered those jobs. This is a matching
    predicate, not a rejection: the operator-visible symptom of an out-of-date
    agent is an unclaimed `pending` job rather than an error. Capability names are
    contract surfaces under the README's change-control rule.
  - The first such capability is `evidence-claim-binding-v1`, required to claim
    `issue` jobs and `renew` jobs whose subject certificate is still
    `provisioning`. See
    [ADR-0008 A1.2](0008-certops-upfront-issuance.md#a12-agents-are-no-longer-upgrade-free-for-issue-amends-5).
  - Evidence envelopes carry the `claimId` of the attempt that produced them, and
    `certificate_evidence` persists it alongside the server's own attempt
    counter. The value written is taken from the job row **after** ownership is
    proven, never from the agent, and an agent-supplied `claimId` that disagrees
    with the job's current claim is rejected outright. This preserves the
    agent-local authority principle above while making evidence attributable to a
    single attempt, which reconciliation now depends on.
