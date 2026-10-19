# ADR-0015: MCP operator interface

## Status

Proposed (2026-10-19). Not yet reviewed. The credential and authorization
foundation described below is implemented on a feature branch behind a rollout
flag that is off by default: operator connections, the early route guard, the
shared credential primitives, session-only connection management and one
operator route (`whoami`). Nothing that reads certificate data for a connection,
no enrollment flow, and no write execution exists. The contracts under
`packages/contracts/mcp/` describe the full first read-only release and are
ahead of the implementation; the catalog marks each route `implemented` or
`planned`, and a test keeps that honest.

Each decision below carries one of two labels:

- **Settled direction**: reached in design review and expected to survive
  review of this ADR. Changing it later is a new or amended ADR.
- **Open proposal**: a recommended position with its alternative. It needs an
  explicit reviewer decision before the work it governs starts, and the
  contracts that depend on it are marked draft until then.

Verified repository behavior (what the code does today) is kept apart from the
authorization model this ADR proposes. The reuse inventory at the end cites the
code for each fact.

## Context

Operators want to query TokenTimer in natural language and start supported
certificate-management workflows from an MCP client such as an AI assistant.
Model Context Protocol (MCP) is the integration surface. The risk is that an
assistant, or text it reads, talks the system into an action nobody approved,
or reads data nobody meant to disclose.

Today there is no operator-facing programmatic credential:

- The user-facing CertOps routes are session-only (a signed-in human, CSRF for
  cookies).
- The bearer credentials that exist authenticate machines. Executor and
  controller API tokens are workspace-bound and scoped to executor routes. Agent
  bootstrap and runtime credentials authenticate a row in the agent registry.
  None of them represents "this user, in this workspace, with at most this much
  authority".

An MCP server therefore needs a new, explicitly bounded principal. It should
borrow the proven enrollment and credential mechanics rather than invent a
second security subsystem, and it must not pose as an agent or an executor.

## Decision

### 1. The MCP adapter is an interface, not an automation engine (settled direction)

Lifecycle rules, permissions, jobs, approvals and audit stay in the REST API.
The MCP adapter (`packages/mcp`, a later step) calls the public `/api/v1`
surface only. It has no database access and owns no durable workflow state.
Authoritative previews, requests, approvals and jobs live in the API; the
adapter's local credential configuration is persisted separately.

Anything that must remain true when the adapter is bypassed is enforced in the
API. A credential that works against REST will be used against REST directly by
someone, so the adapter cannot be the place where limits live. Cloud and
Enterprise inherit the feature by pointing the adapter at their own API.

### 2. A new principal: the operator connection (settled direction)

A **connection** is the delegated principal. It represents one user in one
workspace. A **credential** is a secret that authenticates a connection and can
be rotated without changing the connection.

- New persistence for connections (and, in the onboarding step, enrollment
  grants). The agent, executor and bootstrap tables are not changed.
- Distinct formats and prefixes for the enrollment grant and the runtime
  credential, so an older API instance running against a newer schema cannot
  accept them as an agent bootstrap or agent runtime credential. Adding a
  `purpose` column to the existing bootstrap table is rejected for that reason.
  Tests prove every credential family is accepted only on its own routes.
- Rejected: using a bootstrap token as a standing API credential; registering
  the adapter as an agent or diagnostic agent (it would appear in the fleet and
  inherit agent protocol responsibilities); reading `api_tokens.created_by` as
  live delegated authority; making `api_tokens` a general principal table as a
  prerequisite for the first release.
- A connection always represents the user who authorized it. Provisioning a
  connection for a different user is deferred.
- Shared mechanics (secret generation, prefix parsing, hashing, timing-safe
  comparison, expiry validation, safe metadata projection, rate-limit identity)
  are extracted into neutral modules. They are not copied, and `_test` exports
  are not used. Existing agent and executor behavior must remain byte-for-byte
  unchanged and is covered by regression tests.

### 3. Authority is evaluated per request in the API (settled direction)

```text
effective authority =
    approved connection scopes
  AND role ceiling delegated at enrollment
  AND current workspace role of the represented user
  AND current operation policy
```

- Demotion and removal take effect on the next request. Promotion never widens
  a connection beyond its scopes and ceiling.
- A shared effective-role resolver is extracted from `loadWorkspace`. It keeps
  the existing implicit workspace-owner behavior until the planned role-model
  cleanup replaces it. System admin confers no workspace role.
- The connection credential never sets `req.user`, `req.isWorkerCall`, or a
  fabricated session. MCP-enabled routes opt in through one guard that names a
  scope and an action. A global check rejects connection credentials on every
  route that is not on the allowlist. A request presenting both a connection
  credential and session cookies is rejected.
- "Operator origin" is derived from the authenticated principal, never from a
  header or body field. Forced approval, the allowed operation set, scope
  checks, the write-enable flags and the workspace pause are all enforced in the
  API, so turning the adapter off does not leave direct writes available and
  removing a header does not enable ordinary execution.
- A connection can never approve or reject, change settings (pause, approval
  policy, write flags), create or revoke connections or machine tokens, or alter
  its own scopes. A route-inventory test generated from the router fails if a
  non-allowlisted route accepts a connection credential.
- A workspace in the path that differs from the connection's workspace returns
  404, matching the existing hide-existence behavior.
- **Amended during implementation.** Operator routes cannot live under
  `/api/v1/workspaces/:id/...`, because every route under that prefix sits behind
  the session authentication stack. They live in their own namespace,
  `/api/v1/operator/*`, which accepts only a connection credential and takes the
  workspace from the connection, never from the path. A workspace in a path
  therefore cannot be used to reach another workspace at all. Management of
  connections stays under the workspace prefix and is session-only.
- The early guard refuses a connection credential on every route outside the
  namespace, and the path check allows plain segments only, so a path with dot
  segments, percent-encoding or empty segments cannot pass as being inside it.
  Connection credentials are CSRF-exempt only when the request carries no cookie.
- The interface is dark by default behind `MCP_OPERATOR_INTERFACE_ENABLED`, like
  CertOps. Scopes for operations that do not exist yet (extended reads, requests,
  configuration and CA revocation) are rejected at creation rather than stored,
  so a premature grant cannot become live authority later.

### 4. Disclosure policy (settled direction)

Authorization is the primary control. The operator projection governs what may
be disclosed after authorization. The adapter's schemas and the outbound secret
scrubber are additional layers, with the scrubber as the last line.

- The API serves connections an operator-safe projection that omits
  authority-bearing and location-bearing fields, even when the represented user
  is an admin: job lease data, signed payloads and nonces, dispatch secrets,
  key references, certificate and deployment filesystem paths, notes and other
  free-form operator text, and certificate bodies.
- The policy applies to search, filters, sorting, counts, pagination, errors and
  resource reads, not only serialized fields. A caller must not be able to infer
  an excluded field through query behavior.
- Text that originates from certificates, assets, agents or operators is
  returned wrapped as untrusted data. Page sizes and response bytes are bounded
  and every list reports completeness (`truncated`, `nextCursor`, whether the
  total is known) so "no matches" is distinguishable from "first page only".
- No tool accepts a certificate signing request, key or key-bearing PEM, and
  none reads secret values. Inputs still pass the existing private-key
  rejection.
- A connection never gets looser access than the session route it is built on.
  Each tool records the role that route requires (`sessionRouteMinRole` in the
  catalog) and a contract test fails if a tool's minimum role is lower. This
  already mattered once: the agent list is manager-only today because fleet
  metadata is treated as sensitive, so `tt_get_agent_health` requires a manager.
- Free-text search is an allowlist. The existing certificate search matches
  certificate bodies, lifecycle reasons, and, for managers and above, key
  references, deployed paths and source references. The operator search matches
  only subject, SANs, issuer and fingerprint, and the topology-reading switch is
  forced off for every connection regardless of the represented user's role. The
  job search is not exposed.
- The operator projection is built from the fields named in the contracts, not by
  deleting fields from the existing responses. Existing job detail includes the
  job payload and result metadata, and existing identity records include key
  references, token and certificate snapshots and location references; none of
  those are reachable from a connection.

### 5. First read-only release (settled direction)

The first release is deliberately small: `tt_whoami`, `tt_list_certificates`,
`tt_get_certificate`, `tt_get_certificate_observations`, `tt_get_agent_health`,
`tt_get_job`, `tt_list_jobs` and `tt_explain_certificate_state`. Their input and
output contracts are in `packages/contracts/mcp/mcp-read-tools.schema.json`,
with scopes, minimum roles and advisory annotations in
`mcp-tool-catalog.json`.

Token and secret metadata search, expiring-asset listing, renewal profiles, job
evidence, job logs, audit events and alert-eligibility explanation follow only
after the security and protocol qualification gate passes. They are outlined in
the catalog and have no schema yet.

`tt_explain_certificate_state` is deterministic and server-side. It composes the
existing reasoning (`renewalPathHealth`, `jobPendingReason`,
`explainAgentJobEligibility`, reconciliation reasons, lifecycle) into stable
reason codes and returns `unknown` when evidence is insufficient. The assistant
narrates the codes and never infers them. A field-to-source inventory precedes
the endpoint; it freezes the reason-code enumerations that the contract
currently constrains by format only.

MCP tool annotations (`readOnlyHint`, `destructiveHint`, and so on) support
client behavior and are never an authorization control.

### 6. Approval model (settled direction, with one open proposal in section 9)

- **No certificate lifecycle mutation executes without a human approval made
  outside the assistant.** Approval is a session-only action in the dashboard.
- **The existing non-requester rule is preserved.** MCP-created jobs and
  requests record the connection's user as the requester plus the connection id.
  They are never recorded with a null requester or as anonymous machine work.
  The user a connection represents therefore cannot approve its own request,
  including through another connection. A same-user confirmation mode is
  deferred and would need its own ADR amendment, interface and tests.
- **Enrollment consent is capability access, not approval** of any later
  operation.
- **Approval covers the full resolved effect** of an operation, including
  derived renewal configuration and future scheduled activity. An issuance
  request must not implicitly grant standing renewal authority.
- **Documented exception for low-risk operational tools.**
  `tt_request_discovery` and `tt_request_verification` may run without
  per-request approval because they change no lifecycle state, do no key-bearing
  or CA work, act only on registered workspace objects referenced by id (never a
  hostname typed by the model), are idempotent, are rate limited per connection
  and workspace, honor the workspace pause, per-CA caps and the shared outbound
  policy, are fully audited, and remain subject to the workspace's always-require
  approval policy. "Verification" is never arbitrary network probing. These are
  described as low-risk operational tools, not as non-destructive: they can start
  real work and update observations.
- Issue and renew reuse the existing job, approval and dispatch path (canonical
  execution intent, approval ledger, dispatch-time invalidation). There is no
  parallel job status and no extra generic queue. Database-only lifecycle or
  configuration changes use action requests whose approval, mutation, audit and
  final state commit atomically. Genuinely deferred work uses a typed outbox
  event, which must be added deliberately to the event vocabulary with an
  allowlisted payload.
- Previews never create a job, allocate inventory, contact an issuer or touch
  agent state. An expiring preview record is the only persisted effect. A
  pending issuance does create the provisioning certificate row with its job
  (existing behavior). That is unapproved request bookkeeping that counts toward
  quota; it is documented and bounded by a per-connection pending-request cap.
  The ADR does not claim "no database changes before approval".

### 7. Lifecycle vocabulary (settled direction)

Three operations are kept distinct in tool names, responses, explanations and
approval screens:

- **Mark revoked** and **decommission** change the exact certificate
  fingerprint's lifecycle. Neither contacts a CA. Neither closes management
  periods or releases quota. Decommission is an operator declaration, not proof
  of absence.
- **Stop managing** ends a selected management period. It is a separate
  operation and is outside the initial tool set.
- **CA-backed revocation** is an issuer-side effect through a supported
  workflow. It has its own tool, scope and flag, is admin only, and cannot ship
  before issuer connectors and revocation jobs exist (issue 246) and the shared
  outbound policy is wired (issue 233).

Responses to mark revoked and decommission always carry `issuerEffect: "none"`
and `caNotified: false`. There is no `revoke` boolean on any tool.

### 8. Revalidation, lineage and revocation (settled direction)

Revalidate at approval and again at execution. The comparison rejects changes to
**what was authorized**, not ordinary progress or temporary unavailability, and
preconditions are specific to each operation, not a row timestamp or a
whole-object hash.

- Invalidate the approval and require a new preview (`stale`) when the target
  identity, authorized names, issuer or execution configuration materially
  changes.
- Block or defer with a stable reason, without discarding a valid approval, when
  an agent is temporarily offline, CA capacity is exhausted, or the workspace is
  paused.
- Cancel or invalidate according to connection policy when the originating
  connection is revoked or expired, or the requester loses required authority.
- Continue when the change is expected progress inside the approved operation,
  such as AD CS pending issuance, polling, deferred validation or installation
  recovery.
- Issuance binds the approved issuer, target, requested names, key parameters
  and renewal settings; the resulting fingerprint is bound afterwards as
  verified evidence. Retirement keeps the exact existing fingerprint
  precondition. Renewal keeps the frozen renewal-profile snapshot, payload hash
  and canonical-intent hash.
- Continuations, polling, retries and distribution rollouts keep a
  server-controlled association with the originating request and connection. A
  continuation must not degrade into anonymous scheduler work that no longer
  checks the connection. Reconciliation and key cleanup use an explicit
  system-authorized path so revocation cannot strand sensitive state; that path
  can clean up and reconcile and cannot resume issuance or deployment.
- Ordering guarantee: once connection revocation commits, no new execution
  authorization may commit for that connection. Work whose authorization
  committed earlier is in flight. This is implemented by locking the connection
  row inside each authorization transaction and is tested on PostgreSQL. It does
  not promise that no previously authorized network activity occurs afterwards.
  Read routes authenticate outside any transaction and do not take the lock,
  which is acceptable because a read has no effect to order. Any route that
  creates a request, approves, or authorizes execution must authenticate the
  connection inside its own transaction with the lock held. A write route that
  reuses the read-route guard would silently lose this guarantee, so the
  write-stage tests must include a concurrent revoke-versus-authorize case on
  the HTTP path, not only at the service layer.
- Revoking a connection invalidates its unapproved requests and blocks dispatch
  of approved but undispatched jobs. Running jobs follow existing cancellation
  and reconciliation. The revoke screen says that revocation does not reverse
  side effects.
- Credential rotation replaces the secret without changing the connection id,
  owner, scopes or in-flight work, and never cancels anything.

### 9. Standing renewal authority after a connection ends (open proposal)

Verified behavior: after a successful issuance, derivation creates a renewal
profile with `status = 'active'` and the scheduler then generates renewals with
no further request (ADR-0010, which already calls the profile the unit of
standing renewal authority). Treating that as authority an administrator
grants, and deciding how long it lives, is the authorization model this ADR
proposes. It is not something the code states today.

Two classes of future work need an explicit governing authority:

- **Continuing an already-requested operation**: AD CS polling, installation
  recovery, retries, distribution tied to that operation.
- **Starting a future operation under standing authority**: a scheduled renewal
  weeks or months after issuance finished.

Recommended position:

> Operation continuations remain bound to the originating request and
> connection. Future scheduled renewals run under the administrator-approved,
> profile-bound standing authorization, subject to the workspace's current
> approval and execution policies at the time.

- The originating request and connection are kept as audit provenance. An
  expired or revoked connection must not silently disable previously approved
  long-term certificate management.
- Revoking a connection therefore means "stop this connection and its
  outstanding work", not "disable every renewal profile created through it".
  Stopping standing renewal stays a separate authorized management action
  (switching the profile off, admin only, which exists today).
- The issuance preview and approval screen state "issuance followed by automatic
  renewal" and the issuer, target, names, key parameters and renewal settings
  that define the permitted recurring activity. The connection-revocation screen
  lists the renewal profiles that originated from the connection and says they
  keep running until separately disabled.
- Required approval authority follows the complete resolved effect, not the tool
  name. An issuance that creates standing renewal needs an approver with
  authority at the level of renewal-profile management (admin) in addition to
  the non-requester rule. A request that does not create standing renewal does
  not.
- The first write release preserves the existing derivation behavior and
  classifies issuance as issuance with standing renewal. Exposing a genuinely
  one-time issuance waits until a supported one-time path exists. This ADR does
  not assume one exists today and does not disable automatic renewal globally.
- A regression test proves that approving an issuance cannot bypass the stronger
  policy for automatic renewal.

Alternative: bind future renewals to the connection and block them when it
expires or is revoked. That is valid, but the approval screen, expiry warnings
and renewal-health explanations must then communicate the dependency, and a
lapsed connection becomes an outage path for certificate renewal.

### 10. Request identity and replay (open proposal)

Four identifiers are kept separate:

- `planId`: server-generated, names one immutable preview.
- `requestId`: client-generated business identifier for one deliberate
  submission, reused across retries, unique within the originating connection.
- `requestRecordId`: server-generated, names the persisted request.
- JSON-RPC `id`: transport correlation only, never a business idempotency key.
  The selected protocol revision requires a new transport request id when a
  client retries after a broken response stream; the business `requestId` stays
  the same for that retry.

The CertOps job idempotency key is derived from the persisted `requestRecordId`.
The API enforces uniqueness of `requestId` within its originating connection.
Submission input is exactly `{planId, planHash, requestId}`. No execution
parameters are accepted at submission; they belong to the approved preview.

Processing order for a submission:

1. Authenticate, check scope and the caller's right to inspect requests.
2. Look up an existing request by `(connection, requestId)`. An identical
   accepted request returns its existing outcome, whatever its state, for the
   retention period (proposed default 30 days). Replay never re-executes work
   and never resurrects cancelled work. The same `requestId` with different
   content returns `409 MCP_IDEMPOTENCY_CONFLICT`.
3. Only a new submission must satisfy the preview's submission deadline
   (proposed 10 minutes), the plan hash and the authority checks.

A successful submission therefore stays replayable after its preview expired: a
lost response is never answered with "preview expired". A new deliberate
operation needs a new `requestId`.

- Replay is scoped to the originating connection. A conflicting operation from
  another connection gets an authorized conflict response. It never adopts that
  connection's request or requester identity, and the response does not reveal
  another request's id unless the caller may inspect it.
- Duplicate-work prevention is separate from retry identity. Conflict keys are
  derived from existing operation semantics (for example per managed source,
  per target, per CA cap) and enforced in the common service path, so dashboard
  and scheduler work obeys the same rules. This ADR deliberately commits to
  neither "one active operation per fingerprint" nor "different parameter hashes
  always run in parallel": two management sources that share a fingerprint can
  legitimately need different work.

### 11. Withdrawal while new work is disabled (open proposal)

`tt_cancel_request` is cataloged as a write tool, but workspace pause and the
MCP write flags must not remove the ability to withdraw a request. Proposed
narrow exception:

> An authenticated and authorized connection may withdraw its own request while
> it is still `pending_approval`, even when new operational requests are
> disabled by workspace pause or the MCP write flags.

- Authentication, scope, workspace and ownership checks still apply. The
  exception does not permit cancelling another connection's request, changing
  execution parameters, or starting work.
- "Pending" means exactly `pending_approval`, not a claimable job.
- Withdrawal and approval race atomically. If approval wins, withdrawal returns a
  conflict and does not claim that execution was prevented.
- A revoked or expired connection cannot authenticate through this exception.
  The dashboard remains the human recovery path.

This refines the kill-switch semantics: disable new operational work, keep
narrowly scoped safety and recovery actions.

### 12. Enrollment (settled; strict one-time delivery, decided at implementation)

Onboarding ("Connect an assistant") reuses the bootstrap pattern without reusing
the agent identity. It is a later step and is not required for the first
read-only release, which can use a directly provisioned credential shown once.

- A signed-in human creates a short-lived (proposed 10 to 15 minutes),
  single-use enrollment grant that fixes the user, workspace, scopes, role
  ceiling and purpose. A local setup command redeems it, receives the runtime
  credential, stores it securely (operating-system keychain or a permissioned
  file; the secret is entered through stdin or a prompt, never argv) and
  discards the grant. Enrollment is not a model-callable tool.
- Redemption cannot change the user, workspace or scopes, and re-checks that the
  authorizing user still has access.
- The redemption service follows the registration transaction pattern without
  calling the agent registration function: lock the grant, validate current
  authority, create the connection, consume the grant, audit, commit. No
  recovery data is recorded (see the decision below).
- **Decision: strict one-time delivery.** This reverses the earlier
  recommendation of recoverable enrollment, after reading what recovery costs in
  agent registration. That mechanism needs a dedicated 32-byte encryption key
  that every deployment must provision and rotate, a sweeper job, a runbook for
  unreadable records, and a plaintext-equivalent secret held in the database for
  days. Agents need it because they install unattended on servers. Here a person
  is at the terminal and a new grant is one click, so the cost is not justified.
  If the response to a redemption is lost, nothing about the credential was
  kept: the unused connection is revoked and a new grant is created. The setup
  command never retries a spent code, says plainly when the outcome is unknown,
  and explains that recovery. The credential stays hash-only in the database at
  all times. Revisit only if real use shows lost responses are common.
- The grant is a separate credential family (`ttopg_`), stored as a hash in its
  own table, valid for 10 minutes by default and at most 15 (a database
  constraint, so a manual insert cannot lengthen it). It fixes the connection's
  name and lifetime as well as user, workspace, scopes and ceiling, so the person
  redeeming it chooses nothing. It is accepted at exactly one route,
  `POST /api/v1/operator/enroll/redeem`, and refused on every other route
  including the rest of the operator namespace; a connection credential is in
  turn refused there. A cookie or session beside it is refused.
- Failures before the secret is proven (unknown, malformed, wrong) look
  identical and cost the same to compute. After it is proven, the reason is
  specific (used, expired, revoked, issuer lost access), since the caller already
  holds the secret and needs to know what to do. Redemption is rate limited per
  client address. A refused redemption does not consume the grant, so an issuer
  who regains access within the grant's life can still use it.
- The setup command reads the code from standard input or a hidden prompt and
  refuses it anywhere on the command line, including as a flag value. It checks
  the destination before spending the code, writes the credential to a private
  file (mode 0600 in a 0700 directory; on Windows the inherited permissions are
  removed and the file is deleted if that fails) and never prints either secret.
  The server refuses a credential file other users can read. An operating-system
  keychain is not implemented; the file is the supported store.
- Credentials are never transmitted through MCP tool arguments, results,
  resources or logs. The local host, credential store and MCP runtime are
  trusted components. This design does not protect against compromise of that
  environment.

### 13. Approval surface (settled direction)

The dashboard renders only server-resolved facts, never assistant text: target
certificate, exact operation, expected effect including renewal effect,
affected locations, uncertainty warnings, whether an issuer or CA is contacted,
requester and connection, advisory client label, and both expiries.

- Mark revoked, decommission and revoke at CA appear as distinct actions with
  plain consequences (section 7).
- Untrusted strings are escaped, truncated and shown as quoted data, with no
  markdown or HTML rendering.
- Session-only approval stops a connection from approving. It does not prove a
  human was present. Approvers enter a reason, and sensitive actions (decommission,
  mark revoked, revocation at the CA, configuration change, issuance with
  standing renewal) require re-authentication or a user-presence confirmation
  within a short freshness window.

### 14. Audit attribution (settled direction)

Requester, approver, connection, request and job attribution stay distinct. A
delegated request records the connection's user as actor with `via`, the
connection id and the request id in metadata. An approval records the approver
as actor, as the approval service already does. Denials of unauthenticated
calls and background execution never fabricate the connection's user as actor.
Audit metadata stores an argument hash, not the arguments. Successful reads go
to structured logs correlated by request id, not to the audit table. Every write
request and every denial is audited.

Write tools require three gates enforced in the API: an instance flag (default
off), a workspace setting (default off, admin, session-only) and the scope.
Workspace pause blocks new write requests, subject to section 11.

### 15. Protocol and transport (settled direction; version pin open)

- The protocol revision targeted is `2026-07-28`. The official versioning page
  lists it as the current version, and its changelog documents the removal of
  protocol-level sessions and the session header from the Streamable HTTP
  transport (checked against the official documentation on 2026-10-19). That
  establishes the specification, not compatibility of any particular SDK or
  client.
- Pin the exact SDK version before the read-only implementation starts. Checked
  against the npm registry on 2026-10-19: the v1.x line (`@modelcontextprotocol/sdk`
  1.32.1, the npm `latest` tag) implements the specification only up to
  `2025-11-25`, and its README states that `2026-07-28` support is not planned
  for v1.x. The v2 packages (`@modelcontextprotocol/server` and
  `@modelcontextprotocol/client`, both 2.3.1 on that date) export a modern
  revision server with a stdio entry point and need Node 20 or later, which this
  repository's Node range satisfies. The proposal is to pin
  `@modelcontextprotocol/server` exactly (2.3.1 today) and use the matching
  client package in conformance tests.
- **Verified by test on 2026-10-19** against the pinned packages, over real
  stdio with the real client (`packages/mcp/src/stdio.test.js`): a client pinned
  to `2026-07-28` is served; a client using the `2025-11-25` handshake is served
  when the adapter runs with `legacy: serve` (the default) and refused with an
  unsupported-version error under `legacy: reject`; schema enforcement (unknown
  fields, over-long values) is identical in both eras. The client defaults to
  the older handshake, so a modern connection is an explicit client opt-in. The
  package's own `LATEST_PROTOCOL_VERSION` constant still reports `2025-11-25`;
  the modern revision is selected through the client's version-negotiation
  option, not that constant.
- **Dependency review.** The server package adds only its core package and
  `zod` 4.6.7 at runtime (Apache-2.0, Node 20 or later). The larger set (`jose`,
  `eventsource`, `pkce-challenge`, `cross-spawn`) arrives only with the client
  package, which is a development dependency used by the conformance tests and
  is not shipped. The lockfile change is purely additive (81 lines, none
  removed) and passes pnpm's supply-chain policy check. A full license audit of
  the transitive set is still to be run before release.
- State the compatibility policy for older clients (negotiate the pinned
  revision plus a stated fallback, refuse the rest with a clear error). Validate
  inputs and outputs on both sides. Conformance tests per supported transport are
  release gates.
- stdio and remote HTTP are separate authentication designs. Enrollment supports
  local setup only. A hosted HTTP endpoint is not launched without standards-based
  OAuth: tokens issued for the MCP server, no passthrough of an upstream token,
  TLS, Origin and DNS-rebinding protection, and protected-resource metadata.
  Permanent bearer credentials are for stdio and localhost self-hosting only.

## Open decisions and proposed defaults

These are product-policy settings, not protocol requirements. The values are
proposals with the rationale given in the section cited.

- Standing renewal lifetime and approver authority: section 9.
- Request identity and replay ordering: section 10. Replay retention 30 days;
  preview submission deadline 10 minutes; pending-approval expiry 24 hours with
  a 72 hour maximum.
- Withdrawal exception: section 11.
- Enrollment recovery: decided in favour of strict one-time delivery (section 12).
- Connection lifetime: default 30 days, maximum 90. Connection expiry behaves
  like revocation for new requests, pending approvals and undispatched jobs
  (recommended). Credential rotation inside a live connection does not.
- Re-authentication freshness window for sensitive approvals: 5 minutes.
- Whether any same-user confirmation mode ever exists: deferred.
- The backing route and projection for token and secret metadata search: decided
  when the extended read set is scoped.

## Alternatives considered

- **Use bootstrap tokens as a standing API credential.** They are enrollment
  credentials with a consume-once lifecycle, not an ongoing delegated grant.
- **Register the adapter as an agent or diagnostic agent.** Wrong identity: it
  would appear in the fleet and inherit agent protocol duties, and declared
  capabilities describe what an executor can do, not what a human delegated.
- **Extend `api_tokens` with a principal kind.** Possible, but every creator,
  validator, list route and revocation route would have to honor the
  discriminator, and machine-token administration could gain authority over user
  delegation. Not a prerequisite for the first release.
- **Enforce policy in the adapter.** Rejected: a REST-capable credential bypasses
  the adapter.
- **Let the connection's user approve their own request.** Rejected for the first
  write release; it would change the non-requester rule.
- **Remote HTTP with permanent bearer keys.** Rejected for a hosted endpoint in
  favor of OAuth.
- **Give the adapter database access or its own workflow state.** Rejected: it
  would duplicate approvals, jobs and audit.

## Consequences

- A new credential family and principal type to secure, test and operate, with
  strict mutual-rejection tests against the existing families.
- The API gains an operator-safe projection and disclosure policy that other
  consumers could later reuse.
- Asking an assistant to start issuance means a second person (an admin when it
  creates automatic renewal) must approve it. Single-operator installs must add a
  second member until a same-user mode is decided separately.
- Standing renewal authority is made visible and reviewable rather than implied.
- Cloud and Enterprise inherit the feature only after their principal handling,
  plan gates, hide-existence behavior and projections are verified there; this is
  an adoption task, not an API URL change.
- Contracts under `packages/contracts/mcp/` are change-controlled once accepted.
  Draft contracts are explicitly not final.

## Delivery sequence

1. This ADR, the read-only tool contracts and fixtures, the draft write envelope,
   and the public roadmap entry (this change).
2. Shared credential primitives, connection persistence, REST authorization,
   operator projection, connection management and audit. Gate: route-inventory
   deny test, credential-family isolation and scope-matrix tests green on Core,
   Cloud and Enterprise.
3. Read-only stdio adapter with a directly provisioned credential.
4. Qualification gate: tenant isolation, role checks, query-level disclosure,
   secret exposure, prompt-injection fixtures, protocol conformance per transport
   and an independent security review. The extended read set is enabled only after
   it.
5. Bootstrap-assisted onboarding.
6. Approval-controlled operations: low-risk discovery and verification, then
   issue, renew, decommission, mark revoked and withdrawal. Every restriction is
   enforced against direct REST calls. Flags default off in every edition.
7. Remote HTTP with OAuth and higher-risk actions (configuration change,
   CA-backed revocation), each under its own release gate.

## Appendix: reuse inventory (verified 2026-10-19)

Each entry states what the code does, whether this design reuses it, and what
must not be inferred from it.

- **Bootstrap tokens** (`apps/api/services/certops/agentCredentials.js`):
  prefixes `ttboot_` and `ttagent_`, SHA-256 storage, timing-safe comparison,
  workspace binding, creator attribution, required expiry with a 30 day maximum,
  and separate validate and consume steps (registration consumes inside its
  transaction). Reused: the primitives and the validate-then-consume transaction
  pattern. Not reused: the tables and the registration operation, which create
  agent state. A runtime agent credential deliberately still authenticates a
  retired agent so the route can answer with the retirement response; that is
  wrong for a revoked operator connection.
- **Registration replay** (`agentDispatch.js`, `registrationCredentialCrypto.js`):
  an encrypted replay record (AES-256-GCM, dedicated key) lets an authenticated
  retry with the same registration id recover the original credential; the
  default window is 15 minutes (`CERTOPS_REGISTRATION_REPLAY_TTL_MS`) and the
  consumed token is accepted only on register (`allowUsed`). Not reused: the
  replay record, because enrollment uses strict one-time delivery (section 12).
  Agents need it for unattended installs; a person at a terminal does not. The
  long-term connection credential therefore stays hash-only at all times.
- **Diagnostic bootstrap** (`diagnosticBootstrap.js`): a session-authorized,
  user-attributed bootstrap transaction that refuses replay of a consumed
  request (`diagnostic_bootstrap_already_consumed`). Reused: precedent for the
  strict one-time delivery that enrollment now follows. Not reused: its restricted agent identity.
- **Executor and controller API tokens**
  (`services/certops/apiTokens.js`, `middleware/api-token-auth.js`): `ttx_`
  credentials, workspace-bound, scopes limited to executor and controller
  routes, creator recorded as provenance, last-used updates, and a middleware
  that rejects session identity. Reused: mechanics. Not reused as a principal:
  `created_by` is not live delegated authority and validation never checks the
  creator's current role.
- **Workspace authorization** (`services/rbac.js`): `actionPolicy` and `can`,
  `loadWorkspace` deriving the role from a session user or trusted worker, and
  the implicit workspace-owner rule. Reused: the role query and policy table.
  A shared resolver is extracted so the credential family stays explicit.
- **Route guards** (`routes/certops.js`): session-only guards, manager write
  guard, and role-based redaction of the job lease id below admin. Reused:
  the redaction principle, applied by the operator projection to every
  connection regardless of the represented user's role.
- **Approvals** (`services/certops/jobApprovals.js`): the non-requester rule,
  jobs requested through an API token carrying a null requester, a canonical
  execution intent, payload hash binding, an append-only ledger, dispatch-time
  invalidation, and audit that records the approver as actor. Reused in full.
  `certificate_jobs.requested_by_api_token_id` already exists; operator
  connections add their own column rather than reusing it.
- **Jobs and idempotency** (`services/certops/jobs.js`): job statuses and
  operations used by the contracts, fingerprinted manual-job idempotency,
  upfront issuance creating a provisioning certificate with the job.
- **Renewal profiles** (`renewalProfileDerivation.js`, `renewalProfileAdmin.js`,
  ADR-0010): derivation inserts an active profile; profile status can be set to
  `active` or `disabled`; profile management is an admin action
  (`certops.renewal_profile.manage`).
- **Explanations** (`renewalPathHealth.js`, `jobPendingReason.js`,
  `agentJobEligibility.js`): `explainAgentJobEligibility` is already shared by
  the renewal-path and pending-reason logic; renewal path states are `healthy`,
  `degraded`, `unavailable` and `unknown`. The explain endpoint composes these
  and does not duplicate them.
- **Durable side effects** (`certops_outbox`, ADR-0009): a typed event
  vocabulary with allowlisted payloads. Reusing it requires adding and handling
  a new event type deliberately.
- **Zero custody** (ADR-0001, `reject-key-material.js`, `packages/log-scrub`):
  private-key rejection and secret-material detection reused for MCP inputs and
  as the last-line outbound scan.
- **Hide-existence behavior** (`middleware/workspace-access-policy.js`): reused
  for cross-workspace paths.
- **Lifecycle semantics** (`docs/certops/CONTEXT.md`, ADR-0007): retirement is
  fingerprint lifecycle, separate from management periods; recording revocation
  does not contact the CA; provisioning rows count toward quota.
- **Issuer-side revocation**: not available. Issuer connectors and revocation
  jobs are open work (issue 246), and the shared outbound policy is issue 233.
