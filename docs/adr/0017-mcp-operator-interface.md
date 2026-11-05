# ADR-0017: MCP operator interface

## Status

Proposed, updated 2026-11-05 against Core 0.18.2. This ADR records the design and
separates deferred capabilities from implemented behavior.
[Configuration](../CONFIGURATION.md#mcp-operator-interface) contains operator
instructions; the optional source adapter has its own README.

## Context

Assistants need bounded access to workspace inventory, certificate state and
supported operator workflows. A machine executor credential cannot safely represent delegated
human authority. Policy must remain effective when a caller bypasses MCP and
uses REST directly.

## Decision

### API authority and identity

Both the optional stdio adapter and remote Streamable HTTP transport call the
same REST authority boundary. The remote transport uses its own API listener,
never a client-supplied upstream. An operator connection represents one user in one workspace. Its
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

The catalog covers inventory, contacts, webhooks, groups, viewer invitations,
certificate/job state and agent health. Reviewed writes include metadata import
and updates, management actions, and file-based ACME issuance and renewal.
Token values, deletes, provider scans, AD CS enrollment, consumer rollout and
CA-backed revocation keep their existing workflows. Reserved scopes cannot be
enrolled before their tools exist.

The API requires `MCP_OPERATOR_INTERFACE_ENABLED`; certificate operations also
require CertOps. New renewal work additionally requires
`MCP_OPERATOR_WRITES_ENABLED`, owner or workspace manager enablement, the connection's
`mcp:renew:request` scope and current delegated authority. The adapter lists
write tools only with `TOKENTIMER_MCP_ENABLE_WRITES=true`. All server MCP
deployment defaults are false. Cloud retains hosted plan/freeze/tenant/quota
admission; Enterprise retains licensing and session/SSO isolation.

### Inventory import

An explicit manager grant of `mcp:inventory:import` and the instance write flag
permit create-only metadata imports. The assistant normalizes input before a
15-minute preview; submission binds its exact plan, hash and request id to the
connection. Unknown fields, secret values and provider-owned identifiers are
refused. Existing records stay intact, and normal Cloud quota admission still
applies. This permission is separate from renewal access and CertOps Job approval.

### Certificate previews and approval

Issuance uses a separate connection permission and workspace switch. Its preview
binds the requested certificate, issuer, agent and installation destination;
successful issuance can establish a renewal profile. Submission rechecks that
effect and the current Job approval policy. The assistant must resubmit the exact
issuance input; sensitive destination details are not returned in the preview.

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
rotation changes the secret without cancelling work. It also invalidates any
OAuth grant on that connection; a remote client must sign in again.

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
legacy stdio handshakes have conformance coverage. The
[adapter README](../../packages/mcp/README.md) records the qualified client and
its required revision setting. Client tool permission authorizes sending a
request, not TokenTimer approval.
Remote access requires an additional disabled-by-default flag and an exact
public HTTPS resource URL. OAuth authorization code with S256 PKCE uses normal
sign-in/SSO, session/CSRF-protected explicit consent, a workspace, scope ceiling
and expiry. Browser nonce and account/session binding prevent consent swapping.
Public clients use dynamic registration;
metadata fetches reject private addresses, pin DNS, and bound time, size and
concurrency. Isolated deployments can disable metadata fetching.

Consent defaults to 30 days; longer durations and explicitly acknowledged
non-expiring connections are supported. Opaque access tokens expire after
15 minutes. Codes are single-use for two minutes; refresh tokens rotate within
the consent lifetime and expire after 90 days of inactivity even for a
non-expiring connection. Hashes alone are stored. Matching code or refresh reuse revokes the connection and unclaimed
work. Audience-bound access also works directly under the same operator REST
namespace, so its existing plan, role, write, quota and approval gates remain
authoritative. It never works as an account/session credential. Host/Origin
checks and isolated MCP CORS protect the remote endpoint. A process-local
forwarding proof changes only rate-limit attribution, never authentication.

## Deferred decisions

- **Standing renewal:** issuance can establish a renewal profile. Further
  changes to the lifetime or authority of scheduled renewals require a separate
  decision; connection revocation does not remove an established profile.
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
dependency.

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
