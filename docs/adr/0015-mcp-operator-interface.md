# ADR-0015: MCP operator interface

## Status

Proposed, updated 2026-10-30 against Core 0.18.2. Implemented on the development
branch; both production MCP flags remain off. This ADR records the current
design and separates deferred capabilities from implemented behavior.
[Configuration](../CONFIGURATION.md#mcp-operator-interface) contains operator
instructions; the source adapter has its own development README.

## Context

Assistants need bounded access to certificate state and supported renewal
workflows. A machine executor credential cannot safely represent delegated
human authority. Policy must remain effective when a caller bypasses MCP and
uses REST directly.

## Decision

### API authority and identity

The stdio adapter calls REST and has no database access or durable workflow
state. An operator connection represents one user in one workspace. Its
effective authority is the intersection of granted scopes, its role ceiling,
the user's current workspace role and current operation policy. Promotion
never expands the grant; demotion or removal takes effect on subsequent
authorization. System admin status supplies no workspace role.

Connection credentials and one-time enrollment grants use distinct credential
families. Neither is an agent, executor token or session. Operator credentials
work only under `/api/v1/operator/*`; the workspace comes from the connection.
Management remains session-only under the workspace namespace. Mixed session
cookies and operator credentials are refused. Connections cannot approve jobs,
change settings, administer credentials or expand their own authority.

### Disclosure

Responses are constructed from allowlisted contract fields. They exclude
private keys, certificate bodies, credential values, execution leases, signed
payloads, key references, filesystem paths and free-form operator notes.
Search, filters and counts obey the same disclosure boundary. Certificate
names and client labels remain untrusted data. Bounded pagination reports
completeness; lack of evidence is represented as unknown.

API authorization is the primary control. Input validation, private-key
rejection and outbound secret scrubbing provide additional protection.
Tool annotations describe behavior and never grant permission.

### Implemented scope and deployment

The catalog contains eight read tools and five renewal preview, request,
status, list and withdrawal tools. The supported mutation is manual ACME
renewal of an existing managed certificate. It does not orchestrate AD CS
enrollment, issuance, consumer rollout, CA-backed revocation or general token
writes. Reserved scopes cannot be enrolled before their tools exist.

The API requires `MCP_OPERATOR_INTERFACE_ENABLED`; operational reads also
require CertOps. New renewal work additionally requires
`MCP_OPERATOR_WRITES_ENABLED`, workspace admin enablement, the connection's
`mcp:renew:request` scope and current delegated authority. The adapter lists
write tools only with `TOKENTIMER_MCP_ENABLE_WRITES=true`. All server MCP
deployment defaults are false. Cloud retains hosted plan/freeze/tenant/quota
admission; Enterprise retains licensing and session/SSO isolation.

### Renewal previews and approval

A preview records the resolved renewal/publication effect, executor routing and
workspace Job approval policy. It creates no job, contacts no issuer and
expires after ten minutes. Submission accepts only
`{planId, planHash, requestId}`; it locks the relevant source/profile and rejects
changed intent or policy. An accepted preview is spent once.

MCP renewals follow workspace CertOps **Job approval**. On creates
`pending_approval`, requiring a different workspace manager or admin within
24 hours. Off creates claimable `pending` work without recording approval or
exposing an approval deadline. Existing jobs retain their original gate when
the setting changes. V1 admin-only decisions and grantable admin/manager roles
remain separately scoped in public issues #239 and #243.

For required approval, the dashboard shows requester and connection provenance,
deadlines, destinations, routing and the complete public renewal/publication
snapshot. Secondary settings can be expanded. The reviewer acknowledges that
effect; the API requires its exact `reviewHash`, rechecks authority and source
intent, and atomically refuses concurrent changes. Self-approval is refused.
Ordinary jobs retain their existing approval flow. Preview expiry limits
submission and does not shorten an accepted request's approval window.

### Replay, capacity and containment

`planId` identifies a preview; connection-scoped client `requestId` identifies
one deliberate submission; `requestRecordId` identifies its persisted result.
JSON-RPC ids are transport correlation only. Identical replay returns the
original outcome before checking preview expiry and never re-executes work.
Different content for the same request id returns
`OPERATOR_IDEMPOTENCY_CONFLICT`. A lost response must not become a new order.

Requests use ordinary CertOps jobs, shared per-CA capacity, lifecycle and
dispatch guards. Waiting assistant requests are bounded per connection and
across the workspace to preserve human/scheduler capacity. Expired approvals
are ended during admission and by the maintenance sweep; cleanup never grants
execution authority.

An authenticated connection may withdraw its own waiting approval or queued
job without human approval even while new writes are disabled, paused, frozen
or downgraded. Authentication, scope and ownership still apply. Withdrawal
races approval/claim atomically and cannot undo work already authorized.

Revocation cancels outstanding unclaimed jobs, including human-approved queued
work. Expiry and loss of delegated authority prevent fresh execution.
Disabling workspace MCP writes cancels waiting approvals and unapproved queued
jobs; human-approved work retains its gate. Unapproved jobs also require live
instance/workspace write flags at claim. Authority locks order revocation
against approval and dispatch; claim skips busy rows rather than reversing
that order. Already claimed work uses existing reconciliation. Credential
rotation changes the secret without cancelling work.

Unknown execution effects return `unknown_effect` and
`reconciliation_required`. Publication, consumer installation and live TLS
verification are separate outcomes; one must not be presented as proof of
another. File-only delivery makes no live-TLS claim.

### Enrollment, audit and transport

Enrollment uses normal session/CSRF consent and a short-lived, single-use grant.
Only its hash is stored. Redemption returns the runtime credential once; a lost
response requires revocation and a new enrollment. Credential files and their
ancestor directories must be private to the operating-system user. Windows
enforces this with native ACL checks before consuming the grant.

Audit attributes requests to the represented user and connection and decisions
to the independent approver. Free-form labels remain advisory.

The adapter pins the MCP SDK and validates input/output schemas. Modern and
legacy stdio handshakes have conformance coverage. Codex CLI
`0.165.0-alpha.1.2` was qualified with revision `2025-06-18` and
`TOKENTIMER_MCP_LEGACY=serve`; other clients remain unqualified. Client tool
permission authorizes sending a request, not TokenTimer approval.
A future hosted HTTP transport needs a separate OAuth design: server-audience
tokens, protected-resource metadata, TLS and Origin/DNS-rebinding protection.
Local enrollment is not that design.

## Deferred decisions

- **Issuance and standing renewal:** issuance may derive an active renewal
  profile. Before exposing it, define and display the complete recurring
  authority, its lifetime and approver role. Proposed direction: operation
  continuations remain connection-bound; separately approved profile authority
  governs future scheduled renewals. Revoking a connection must clearly explain
  any standing management that survives it. One-time issuance requires a
  supported one-time path.
- **Other mutations:** discovery/verification requests need a registered-object
  workflow; retirement needs an atomic action-request approval path. CA-backed
  revocation depends on issuer connectors and shared outbound policy. None is
  implied by renewal permission.
- **Retention and stronger consent:** expired preview/request retention,
  sensitive-action reauthentication and any same-user confirmation mode need
  separate decisions. The current preview store has no purge policy.

## Alternatives considered

Reusing bootstrap/executor credentials would conflate machines with delegated
users. Enforcing policy in the adapter would leave REST unprotected. Allowing
connections to approve themselves would defeat independent review. Binding all
future scheduled renewals to a short-lived connection would create an outage
dependency and remains an alternative for the deferred issuance design.

## Consequences and validation

Core owns the contracts, authority and lifecycle implementation; Cloud and
Enterprise compose it with edition admission. Additive migrations preserve
released history. A new tool requires an explicit scope, projection, route
allowlist entry and tests; an existing grant never inherits reserved powers.

Regression coverage includes credential-family isolation, session/CSRF guards,
tenant boundaries, projection secrecy, real stdio negotiation, replay,
PostgreSQL approval/claim/revocation races and both Job approval modes. Local
browser qualification covers independent decisions and refusals. These checks
do not establish native CA/installation, external SSO/payment, production
deployment or release acceptance. PR test plans record actual validation.
