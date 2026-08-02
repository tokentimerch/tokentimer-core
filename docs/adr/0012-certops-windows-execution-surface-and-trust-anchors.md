# ADR-0012: Windows execution surface, trust-anchor operations, and CNG-vs-PFX custody

## Status

Proposed (2026-08-02). This record must be accepted before the Windows
execution-surface and trust-anchor work described below can begin; the PRs
that implement this feature set follow this decision rather than
re-deciding it.

## Context

This phase of work adds three things the agent protocol and job model did
not previously need to express:

1. A **Windows** agent platform (IIS binding, the Windows machine certificate
   store, Windows service installation), alongside the existing Linux/agent
   filesystem model.
2. **Trust-anchor distribution and revocation** as first-class lifecycle
   operations, distinct from certificate `renew`/`deploy`/`reload`/`revoke`.
3. A **protocol-level reference client** (bash and PowerShell) that exercises
   the agent protocol without owning product behavior.

Three concrete questions blocked this work from starting:

- Does a trust job reuse `certificate_jobs`/the existing job payload schema,
  or does it need its own shape?
- On Windows, does the agent create keys directly in the CNG machine key
  store, or does it import PFX bundles built off-host?
- What privilege does the Windows agent service run with, given it must
  write `LocalMachine\My`, bind certificates to IIS, and write
  `LocalMachine\Root`/`LocalMachine\CA`, all of which are conventionally
  administrator-level operations on Windows?

This ADR decides all three, plus the smaller surface (evidence, audit,
approval, capability gating) that follows from them.

## Decision

### 1. Trust jobs get their own contract file, not a discriminated union on the certificate job schema

`packages/contracts/certops/job-payload.schema.json` requires `certificateId`
and `keyMode` (both `required`, both about certificate custody) and is
`additionalProperties: false`. A distribute/revoke-trust job has neither a
certificate nor key custody; forcing it through that schema means either
making `certificateId`/`keyMode` conditionally required via `if`/`then` (which
makes every future certificate-job field ask "does this apply under the trust
branch too?") or relaxing the `required` array (which weakens validation for
every existing certificate job).

Decision: a new file, `packages/contracts/certops/trust-job-payload.schema.json`,
`schemaVersion: 1`, sibling to the certificate job schema and independently
versioned. It carries only what a trust operation needs:
`schemaVersion, jobId, workspaceId, trustAnchorId, action (enum:
distribute-trust | revoke-trust), anchorType (enum: root | intermediate),
fingerprintSha256, pem`, `requestedAt`, `requestedBy`, `metadata`.

`anchorType` is **required and part of the signed payload**, because it is the
routing decision: a root belongs in `LocalMachine\Root` and an intermediate in
`LocalMachine\CA`, and placing an intermediate into `Root` would silently
promote it to a trust anchor. That decision must not be inferred at execution
time from the certificate's own `basicConstraints`/issuer fields, because the
PEM is untrusted input and inference would make the destination store a
property of the material rather than of the approved intent. The control plane
decides `anchorType` at job creation, signs it, and the agent routes on the
signed value only.

The Windows store name is **derived from `anchorType` by the agent**, not
carried in the payload: `root` maps to `Root`, `intermediate` maps to `CA`. A
payload-supplied store name would be a second source of truth that could
disagree with `anchorType`, and would let a caller name an arbitrary store.
Non-Windows platforms map the same `anchorType` onto their own trust stores
(for example an anchor directory plus a CA-bundle rebuild), so `anchorType`
stays platform-neutral in the contract and platform-specific in the executor.

`additionalProperties: false` alone does **not** keep `pem` off a revoke
request: `pem` is a declared property, so `additionalProperties` never applies
to it. The mutual exclusion is enforced explicitly with a conditional:

```json
"allOf": [
  {
    "if": { "required": ["action"],
            "properties": { "action": { "const": "distribute-trust" } } },
    "then": { "required": ["pem"] }
  },
  {
    "if": { "required": ["action"],
            "properties": { "action": { "const": "revoke-trust" } } },
    "then": { "not": { "required": ["pem"] } }
  }
]
```

so `distribute-trust` must carry `pem` and `revoke-trust` is rejected if it
carries one. Revocation is identified by `trustAnchorId` plus
`fingerprintSha256`, which is all the agent needs to find and remove the
anchor; accepting a PEM there would invite a "revoke this, but here is
different material" ambiguity.

The public-metadata redaction pattern (`publicMetadataEntry`) is **not**
currently a shared definitions file: it is defined inline under
`#/definitions/publicMetadataEntry` in `job-payload.schema.json`, and again in
`executor-event.schema.json` and `evidence.schema.json`. The trust schema
therefore either repeats that same inline definition (consistent with how the
existing schemas already relate to each other) or a preparatory change first
extracts it into a shared file and repoints the existing schemas at it. This
ADR does not require the extraction; it records only that a cross-file `$ref`
cannot be assumed to exist today, and that whichever route is taken the
redaction pattern must stay byte-identical across the schemas that use it (the
contract-integrity digests catch drift).

The two schemas are siblings, not a union, because nothing in the codebase
needs to validate "a job payload of either shape" against one Ajv compile
target. Every call site that loads a job already knows the job's `operation`
before it looks at `payload`, so it can pick the matching validator. A union
would only pay for itself if some caller genuinely needed shape-polymorphic
validation, and none does.

### 2. Persistence reuses `certificate_jobs` and `certificate_evidence`, additively

Both tables are already generic:

```
-- apps/api/migrations/migrate.js, certificate_jobs
subject_type TEXT NULL CHECK (subject_type IS NULL OR subject_type IN
  ('managed_certificate', 'certificate_instance', 'certificate_target',
   'token', 'domain', 'endpoint', 'external')),
subject_id TEXT NULL ...
payload JSONB NOT NULL DEFAULT '{}'::jsonb,
```

There is no `certificate_id` column and no `NOT NULL` constraint that assumes
a certificate subject; `certificate_jobs` is already a generic job table
scoped by `(subject_type, subject_id)` and a JSONB `payload`. The same is true
of `certificate_evidence`. A trust job is therefore not a new table; it is a
new `subject_type = 'trust_anchor'` value and a new pair of `operation`
values, both additive `ALTER TABLE ... DROP CONSTRAINT ... ADD CONSTRAINT`
migrations that widen an existing `CHECK`, never a column addition and never a
backfill. `certificate_jobs.operation` gains `'distribute-trust'` and
`'revoke-trust'`; `certificate_jobs.subject_type` and
`certificate_evidence.subject_type` both gain `'trust_anchor'`.

This is also why `jobApprovals.js` needs no code change: `buildCanonicalExecutionIntent`
already hashes `{operation, subjectType, subjectId, payload}` off the generic
columns, so the existing approve/reject/canonical-intent-hash machinery covers
trust jobs the moment the `CHECK` constraints admit the new values. Approval
is a property of "a job", not of "a certificate job".

### 3. A trust anchor is a new row type: `certops_trust_anchors`

A trust anchor (a root/intermediate CA bundle to be distributed to or revoked
from Windows machine trust stores) is not a certificate: it has no private
key, no renewal, no `managed_certificates` row. New table:

```sql
CREATE TABLE certops_trust_anchors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  pem TEXT NOT NULL,
  fingerprint_sha256 TEXT NOT NULL CHECK (fingerprint_sha256 ~ '^[a-f0-9]{64}$'),
  anchor_type TEXT NOT NULL CHECK (anchor_type IN ('root', 'intermediate')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  source TEXT NOT NULL DEFAULT 'api' CHECK (source IN ('api', 'system')),
  public_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ NULL,
  CONSTRAINT uq_certops_trust_anchors_workspace_id UNIQUE (workspace_id, id)
);
```

`certificate_jobs.subject_id` for a trust job is the trust anchor's `id`
(text-cast, matching the existing `subject_id TEXT` convention for every other
subject type). `fingerprintSha256` is carried on both the anchor row and the
job payload so the agent can verify the anchor it is about to install/remove
against the fingerprint the control plane signed, the same integrity pattern
`certificatePemSha256` already establishes for certificate deploy jobs.

`anchor_type` is stored on the anchor row as well as being signed into each
trust job payload, so the intended destination store is auditable independently
of any single job, and a disagreement between the anchor row and a signed job
payload is a detectable inconsistency rather than a silent reroute. Evidence
records the concrete store the agent actually wrote, so an audit can confirm
the routing end to end rather than trusting the request alone.

Trust anchor writes are additive-only at the row level: `revoke-trust` sets
`status = 'revoked'` and `revoked_at`, it does not delete the row. A revoked
anchor stays queryable for audit ("this host trusted this CA between these
two dates"), which a hard delete would destroy.

### 4. CNG-native key custody is the default; PFX import is the disciplined fallback

Windows offers two paths to get a certificate into `LocalMachine\My`:

- **CNG-native**: `certreq -new` against an INF request descriptor generates
  the key pair directly inside the CNG machine key store (backed by the
  Microsoft Software KSP unless a hardware KSP is configured) and
  `certreq -accept` binds the CA's response to it. The private key never
  exists as a file; it is a CNG key handle, non-exportable by default.
- **PFX import**: a key pair is generated off-host (or by the same agent
  using OpenSSL/Node crypto) and imported as a PFX/PKCS#12 bundle via
  `Import-PfxCertificate`. The private key exists as bytes, however briefly,
  before import.

Decision: CNG-native is the default and required path for any certificate the
Windows agent itself requests (i.e., a `renew` or `issue` job targeting a
Windows target whose custody is the OS certificate store). Such jobs carry
`keyMode: os-store-managed`, not `agent-local`.

The distinction is semantic, not cosmetic. `agent-local` in
`job-payload.schema.json` means the agent holds the key as agent-managed
material on the filesystem (the `openssl genrsa`/`certbot` shape), which is why
`jobs.js`'s `AGENT_DEPLOYABLE_KEY_MODES` admits `agent-local` and
`proxy-agent-local` for file-deploy paths. A CNG-native key is categorically
different: it is a non-exportable handle owned by the OS store, the agent
cannot read its bytes, and any code path that assumes it can write the key to a
`keyPath` is wrong for it. `os-store-managed` already exists in the `keyMode`
enum for exactly this custody model, so the Windows cert-store work extends the
deployable set with `os-store-managed` rather than overloading `agent-local`
with a second, incompatible meaning.

PFX import is supported only for `deploy` jobs where the certificate material
already exists off-host and is being placed onto a Windows target, the same
shape ADR-0001's zero-custody model already permits for other platforms, since
the control plane never holds the private key either way and the PFX bytes are
agent-side, ephemeral, and immediately wrapped by the CNG store on import.

This mirrors ADR-0001's zero-custody invariant precisely: CNG-native gives
Windows the same "the agent generates it, the agent holds it, nothing else
ever sees it" property that Linux `agent-local` key generation already has via
`openssl genrsa`/`certbot`, while keeping the custody *mode* honest about who
can actually read the key. Defaulting to PFX would mean every Windows issuance
briefly materializes a private key as file bytes, in exchange for no benefit
over CNG for the case that matters most (agent-originated keys).

### 5. The Windows agent service runs as `LocalSystem`

Three operations the Windows agent must perform are administrator-level by
Windows design, not by choice: writing `LocalMachine\My` for a CNG-native
enrollment tied to the machine (not the user) context, binding a certificate
to an IIS site (`netsh http add sslcert` / the IIS `Microsoft.Web.Administration`
binding APIs), and writing `LocalMachine\Root`/`LocalMachine\CA` for trust
anchor distribution. There is no supported Windows API to delegate exactly
these three rights to an unprivileged service account without also granting
it enough to reach the same operations by other means (e.g. `WebHosting`
store write access effectively also permits binding certificates other
services rely on).

Decision: the Windows agent Windows Service runs as `LocalSystem`. This
matches established prior art for this exact problem (win-acme, Certify The
Web, and other IIS-certificate-lifecycle tools all run their service as
`LocalSystem` or an equivalently privileged account for the same reason), and
it is honest about the actual privilege boundary rather than presenting a
narrower one that does not hold up: a service that can rewrite IIS bindings
and the machine trust store already has host-administrator-equivalent blast
radius regardless of the account name.

The compensating controls are the ones already established elsewhere in the
protocol, not a narrower account:

- **Agent-local policy wins** (ADR-0002): the agent still refuses any
  `certPath`/`reloadService`/site-binding target outside its own configured
  allowlist, `LocalSystem` or not. Running as `LocalSystem` does not bypass
  agent-local policy; it only means the OS would *let* the agent do more than
  policy allows, which is exactly why agent-local policy, not OS ACLs, is the
  enforcement point per ADR-0002.
- **Config/credential file ACLs**: the agent's own config and
  credential files are still ACL'd to deny access to *other* principals; a
  `LocalSystem` service reading its own config is not a new exposure, since
  `LocalSystem` already has ambient access to the entire machine. `SYSTEM`
  is added to the allowed-principal list for these files precisely because
  the service that must read them runs as `SYSTEM`; the ACL's job is
  excluding everyone else, not excluding the service that owns the file.
- **Evidence and audit** (below): every distribute-trust, revoke-trust, and
  IIS-binding action produces evidence and an audit event, so `LocalSystem`
  breadth is paired with a durable trail of what it actually did, which is
  the control the account name cannot provide by itself.

### 6. Rejected privilege models

- **Delegated ACLs on the machine cert store for a low-privilege service
  account.** Windows does not expose a supported public API to grant
  `LocalMachine\My`/`LocalMachine\Root` write to an arbitrary account short of
  administrator-group membership or `LocalSystem`; the closest primitives
  (`certutil -importPFX`'s ACL flags, `CertSetStoreProperty`) operate on a
  store already opened by a caller who already has store-level access, so
  they do not solve the initial-access problem. Rejected as unsupported for
  the exact rights needed.
- **A dedicated `BUILTIN\Administrators`-member service account** instead of
  `LocalSystem`. This trades nothing meaningful: an account in
  `Administrators` has a strict superset of what the three operations need,
  it still cannot be scoped down to just those three operations, and it adds
  an extra credential (the account's own logon secret) to protect that
  `LocalSystem` does not have, since `LocalSystem` has no logon secret to
  steal. Rejected as added attack surface for no added safety.
- **A group-managed service account (gMSA).** gMSAs solve cross-machine
  Kerberos delegation and automatic password rotation for a *domain*
  identity; they do not by themselves grant machine-cert-store or IIS-binding
  rights, and a large fraction of target hosts (standalone IIS boxes, non-
  domain-joined servers) cannot use a gMSA at all. Rejected as solving a
  different problem than the one blocking this ADR, and as unavailable on a
  meaningful fraction of the fleet this feature targets.
- **A split design: a low-privilege long-running service plus a
  short-lived, separately-launched privileged helper process for the three
  operations.** This is the standard pattern for minimizing standing
  privilege, and it was seriously considered. Rejected for this decision
  specifically because the helper would still need to run as `LocalSystem`
  (or Administrator) to do its three jobs, so the split does not lower the
  ceiling of what an attacker who compromises the agent can reach; it only
  adds an IPC boundary and a second process to keep patched, in exchange for
  a privilege-duration reduction that does not apply here anyway (the service
  is long-running and heartbeats continuously; there is no idle low-privilege
  majority of its lifetime to protect). This is a legitimate design for a
  service that is privileged rarely and unprivileged most of the time; it is
  not this service.

### 7. New operations, actions, and the capability gate

Control-plane `operation` values: `distribute-trust`, `revoke-trust` (added to
`certificate_jobs.operation`'s `CHECK`, per decision 2). Agent-facing `action`
in the trust job payload mirrors them 1:1 (no separate `operation`/`action`
naming split is needed here the way ADR-0008 needed one for `issue`, because
a trust job's control-plane intent and agent-side action are the same
concept: there is no multi-step lifecycle to distinguish).

Per ADR-0002's addendum pattern, a new capability string
`trust-anchor-deploy-v1` is required to claim either operation. This is a
matching predicate, not a rejection: an agent that has not declared it simply
never gets offered `distribute-trust`/`revoke-trust` jobs, which surface to
the operator as an unclaimed `pending` job, consistent with how
`evidence-claim-binding-v1` already behaves. Wiring this gate into
`agentDispatch.js`'s claim path is a follow-up change: the capability string
and schema land first, and the gate itself lands in a subsequent PR.

### 8. Evidence and audit

`certificate_evidence.evidence_type` gains `'trust.distributed'` and
`'trust.revoked'`, following the existing `<domain>.<verb>` naming convention
(`certificate.observed`, `deployment.updated`). `certificate_evidence.subject_type`
gains `'trust_anchor'` (decision 2).

New audit events, following ADR-0011's naming convention
(`CERTOPS_<NOUN>_<VERB>`): `CERTOPS_TRUST_ANCHOR_DISTRIBUTED`,
`CERTOPS_TRUST_ANCHOR_REVOKED`. Per ADR-0011's asymmetric-audit rule (success
is audited, routine non-events are not), a claim or an in-flight attempt does
not itself produce an event; only a terminal `succeeded`/`failed` transition
does, matching how certificate job completion is audited today.

## Alternatives considered

(Trust-job shape and persistence alternatives are covered inline in decisions
1-3 above, alongside the specific reasons each was rejected, since they are
mechanically inseparable from the decision they inform.)

- **Model a trust anchor as a `managed_certificates` row with a sentinel
  `key_mode`.** Rejected: a trust anchor has no key, no expiry-driven renewal,
  and no deployment-target list in the certificate sense; forcing it into
  `managed_certificates` would mean every certificate-shaped query
  (`skipped_incomplete_profile`, renewal scheduling, key-mode-based
  deployability) needs a trust-anchor exclusion clause added defensively,
  forever. A dedicated table has none of that risk.
- **Give trust jobs their own status/audit vocabulary instead of reusing
  `certificate_jobs`'s.** Rejected: the status machine (`pending` -> `claimed`
  -> `running` -> `succeeded`/`failed`, plus `pending_approval`/`approved`/
  `rejected`/`blocked`/`cancelled`) is already subject-agnostic; duplicating
  it for trust jobs would duplicate every consumer that walks job status
  (dashboards, the scheduler's own job-status queries, `agentDispatch.js`'s
  claim loop) for no behavioral difference.

## Consequences

- A shared contract-foundation change owns: the new trust-job schema
  file, the `certops_trust_anchors` migration, the `operation`/`subject_type`
  `CHECK`-constraint widenings on `certificate_jobs` and
  `certificate_evidence`, and the `trust-anchor-deploy-v1` capability string
  constant. Nothing in this list is exclusive to the Windows execution work
  or the trust-anchor distribution work, which is why it lands before both.
- Windows target/IIS/CNG execution and trust-anchor distribution/revocation
  execution, approval, and capability-gate wiring build on this contract
  without needing to touch each other's files for the contract-level pieces;
  a separate internal ownership table covers the remaining execution-logic
  files (`agentDispatch.js`, `jobs.js`, `routes/certops.js`) that both lanes
  still add endpoints/logic to.
- `LocalSystem` is a documented, operator-visible fact of the Windows install
  (the install script and the operator runbook must both say so plainly),
  not an implementation detail. An operator who cannot accept a
  `LocalSystem` service on a given host should not install the Windows agent
  on that host; there is no lower-privilege mode for the IIS/trust-anchor
  feature set. A future "observe-only, no IIS binding, no trust anchors"
  Windows agent profile could run less privileged, but that is a new,
  narrower agent capability set, not a configuration flag on this one.
- Because CNG-native keys are non-exportable CNG handles rather than files, a
  Windows agent uninstall/host decommission does not leave a private key file
  behind to shred; the key is destroyed with the CNG key container, which the
  uninstall path must explicitly delete (`certutil -delkey` semantics) rather
  than assume filesystem cleanup covers it.
- The two new `CHECK` widenings and the new table are all additive; no
  existing row, query, or Cloud/Enterprise consumer that re-pins core changes
  behavior. Cloud and Enterprise inherit trust-anchor and Windows-target
  support through the shared migration and contract path the same way they
  inherit every other CertOps change, with their own follow-up scope
  tracked separately and explicitly deferred past this
  ADR's boundary.
