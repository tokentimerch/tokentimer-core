# ADR-0002: CertOps agent protocol and agent-local policy

## Status

Proposed (2026-06-25). Skeleton record; details land with the agent protocol
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
  - Agents declare capability strings at `register`. The control
    plane matches on them when offering work, so a capability an agent does not
    declare simply means it is not offered those jobs. This is a matching
    predicate, not a rejection: the operator-visible symptom of an out-of-date
    agent is an unclaimed `pending` job rather than an error. Capability names are
    contract surfaces under the README's change-control rule.
  - **Registration was the only declaration point until 0.12.0.**
    `heartbeatBody` now also admits `declaredCapabilities` (three-valued: omitted preserves, `[]` clears, non-empty replaces)
    (`packages/contracts/certops/agent-protocol.schema.json`), so an in-place
    agent binary upgrade can advertise a newly-supported capability without
    re-enrollment. Before this, `heartbeatBody` was `additionalProperties: false`
    and defined no `declaredCapabilities`, so a heartbeat carrying capabilities
    was schema-invalid; the server-side write existed (guarded so an empty
    array preserves the stored value) but was unreachable until the contract
    admitted the field. Re-enrollment (which loses the agent's identity and
    key pin) is no longer the only remedy for a capability gap; it remains the
    remedy only for an agent build old enough to predate this addendum.
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
- Addendum (2026-08-03, release 0.12.0): `agentId` binding and diagnostic-agent
  isolation (ADR-0012 decisions 2, 3, and 7; wire shapes in ADR-0003's own
  addendum).
  - **`agentId` becomes a signed field, staged.** `agentId` is now part of
    `signed-dispatch-payload.schema.json` and is stamped into every dispatch
    the server produces, but it is enforced additively behind
    `CERTOPS_AGENT_REQUIRE_SIGNED_AGENT_ID` (server) and a matching
    agent-side gate, `checkAgentIdBinding`, which runs after signature
    verification and payload parsing but rejects a job whose signed
    `agentId` disagrees with the agent's own bound ID (ADR-0012 decision 3's
    trusted-identity boundary). While the effective flag is false the gate is
    absence-tolerant: a payload with no `agentId` at all still passes, so
    agents built before this addendum keep working through the rollout. The
    agent advertises `agent-id-binding-v1` only once the *effective* flag
    value is true for it, not merely once the release default is true,
    keeping the capability an honest signal of enforced behavior rather than
    shipped-code-version.
  - **Diagnostic agents are a distinct, immutable kind.** `certops_agents`
    gained `agent_kind` (`normal` | `diagnostic`), assigned exactly once by
    the server at row creation with no update path afterward: an agent
    cannot be reclassified post-registration by either side. Diagnostic
    agents exist to let an operator verify the signed-dispatch pipeline
    end-to-end without a diagnostic run ever being able to claim, or be
    mistaken for, real certificate work.
  - **`protocol_smoke` is its own job operation**, disjoint from `issue` /
    `renew` / `revoke`. `createCertificateJob` refuses to create a
    `protocol_smoke` job outside the dedicated bootstrap path below, so
    these jobs are excluded by construction, not by a downstream filter,
    from certificate quotas, per-CA limits, approval flows, renewal alerts,
    and fleet-health metrics.
  - **`POST .../certops/agents/diagnostic-bootstrap`** is session-authenticated
    (an operator action, not an agent-facing route) and single-use: it mints
    a diagnostic agent, its credential, and its one `protocol_smoke` job in
    one transaction, keyed non-replayably on `(workspace_id, request_id)`. A
    retried request against an already-consumed key fails closed with
    `diagnostic_bootstrap_already_consumed` rather than minting a second
    agent or replaying the first credential.
  - **Orphan retirement.** A diagnostic agent that never heartbeats again
    (registration lost in transit, or the operator abandoning the flow) is
    retired by a worker sweep: its credential is revoked and its bootstrap
    record's agent/job references are cleared, so it does not linger as a
    stale row an operator has to notice and clean up manually.
  - Issuing a diagnostic-bootstrap credential requires the
    `certops.agents.diagnose` permission, held at the `admin` role tier
    (alongside the kill switch and renewal-profile management), and the
    route is rate-limited like other credential-minting routes.
