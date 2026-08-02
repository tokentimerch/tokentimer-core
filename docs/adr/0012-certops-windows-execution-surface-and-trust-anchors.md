# ADR-0012: Windows execution surface, trust-anchor operations, signed-dispatch envelope, and CNG-vs-PFX custody

## Status

Proposed (2026-08-02). This record must be accepted before the Windows
execution-surface, signed-envelope and trust-anchor work described below can
begin; the PRs that implement this feature set follow this decision rather than
re-deciding it.

## Context

This phase of work adds four things the agent protocol and job model did not
previously need to express:

1. A **Windows** agent platform (IIS binding, the Windows machine certificate
   store, Windows service installation), alongside the existing Linux/agent
   filesystem model.
2. **Trust-anchor distribution and revocation** as first-class lifecycle
   operations, distinct from certificate `renew`/`deploy`/`reload`/`revoke`.
3. A **protocol-level reference client** (bash and PowerShell) that exercises
   the agent protocol without owning product behavior, on hosts that will not
   accept a new application runtime.
4. A **signed-dispatch envelope** that a non-JavaScript client can verify
   without reconstructing JavaScript canonical JSON.

Five concrete questions blocked this work from starting:

- How does a client that is not the Node agent verify a signed job, given that
  canonicalization is specified in JavaScript terms?
- Does a trust job reuse `certificate_jobs`/the existing job payload schema,
  or does it need its own shape?
- On Windows, does the agent create keys directly in the CNG machine key
  store, or does it import PFX bundles built off-host?
- What privilege does the Windows agent service run with, given it must
  write `LocalMachine\My`, bind certificates to IIS, and write
  `LocalMachine\Root`/`LocalMachine\CA`, all of which are conventionally
  administrator-level operations on Windows?
- What stops a diagnostic tool that speaks the agent protocol from claiming
  real certificate work?

This ADR decides all five, plus the smaller surface (evidence, audit,
approval, capability gating, RBAC) that follows from them.

## Decision

### 1. Dispatch signs exact bytes: the v2 envelope, capability-gated

A client must not be asked to reconstruct the canonical JSON the control plane
signed. Canonicalization is specified in JavaScript terms, so a non-JavaScript
client cannot be *proven* byte-identical to the signer, and a
merely-probably-identical canonicalizer is a silent verification bypass, not a
compatibility detail. Requiring a JavaScript runtime on every host that needs
to verify a job is the same problem wearing a different hat: it makes an
application runtime a protocol requirement.

Decision: a capability-gated **v2 envelope** carries the exact signed bytes:

```json
{
  "envelopeVersion": 2,
  "payloadB64": "<base64 of the exact UTF-8 JSON bytes that were signed>",
  "signatureB64": "<base64 of the 64-byte Ed25519 signature>",
  "signingKeyId": "<selection hint; must equal the signed value>"
}
```

A client verifies the decoded bytes and only then parses JSON. `envelopeVersion:
2` fixes the algorithm at Ed25519: there is no unsigned `algorithm` field, so
nothing on the wire can select a verifier. The outer `signingKeyId` is a
selection hint only, and must equal the signed one after verification.

**The envelope replaces the job object rather than sitting beside it, and the
reason is measured rather than argued.** The additive-sibling shape (a
`payloadB64` field added next to the existing job object) was considered first
and rejected: `canonicalizeJobPayload` excludes only the top-level `signature`,
so adding any sibling field changes the canonical bytes and **every**
already-deployed v1 agent would reject **every** job. That is a fleet-wide
dispatch outage, not a compatibility wrinkle. Therefore capable clients receive
v2 **only**, legacy clients v1 **only**, never a mixed envelope, and a v2
envelope carries no sibling job object.

Gating is the capability string `signed-payload-b64-v1`. Capabilities are
declared at registration *and* re-advertisable on the heartbeat, which is why
the heartbeat `declaredCapabilities` contract change is a hard prerequisite:
without it, upgrading an agent binary in place could not grant the capability,
and the only remedy would be re-enrollment, costing the agent its identity and
its signing-key pin.

Dispatch is **dual-format, not dual-write**. The control plane constructs the
payload once, canonicalizes once, signs once, and then serializes those same
signed bytes as either the v1 object or the v2 wrapper. Two independently
constructed payloads would reintroduce exactly the divergence the envelope
exists to remove. Carrying both serializations for as long as legacy agents
exist is an accepted cost.

Encoding rules are pinned identically for `payloadB64` and `signatureB64`,
because a field touched only by the signature path is exactly where a
validation gap survives review: standard base64 (not base64url), required
padding, no embedded whitespace, canonicality proven by re-encode-and-compare
after decoding, and a fixed 64-byte decoded signature length. Numeric limits,
stated so two implementations cannot disagree:

```text
claim response body    1 MiB, enforced WHILE READING, not after buffering
encoded payload        65,536 characters
decoded payload        49,152 bytes
signature             64 bytes decoded, exactly
clock skew            heartbeat-derived clockOffsetMs, 300s default tolerance
```

Rejecting an oversized body after buffering it still performs the allocation
the bound exists to prevent, hence "while reading".

The public-key contract is **unchanged**: PEM SubjectPublicKeyInfo on the wire
and in storage (`{ signingKeyId, signingPublicKeyPem }`, requiring
`BEGIN PUBLIC KEY` and rejecting `PRIVATE KEY`), parsed to a required Ed25519
key. The 32-byte raw key length is internal to the verification step, not a
wire limit; neither reference client unwraps ASN.1, because OpenSSL and the
bundled verifier both consume PEM directly. Moving to raw keys would be a
separate contract change and must not ride inside the envelope.

### 2. One normative verification order, with an explicit trusted-identity gate

Every implementation, the production agent and both reference clients alike,
follows one order:

```text
 1. parse and structurally validate the UNSIGNED outer wrapper
 2. bound the encoded length; reject alphabet/whitespace/padding violations
 3. decode payloadB64 and signatureB64
 4. re-encode and compare, to enforce canonical base64
 5. verify the exact decoded bytes against the pinned public key
 6. decode UTF-8 strictly, rejecting invalid sequences and a BOM
 7. parse exactly one JSON value from those same bytes
 8. require end-of-input immediately after that value
 9. extract and validate jobId / claimId / nonce / workspaceId
10. confirm the workspace binding           <-- TRUSTED-IDENTITY GATE
11. validate agentId against the client's own bound identity
12. check remaining required fields, types and enums
13. require the signed signingKeyId to equal the pinned key id
14. check the time window using the heartbeat-derived clock offset
15. act
```

"Verify before parsing" applies to the **signed payload**, not to the envelope
around it: the wrapper must be parsed first because it carries the fields
verification needs. Validating the payload against a JSON schema before
signature verification would be self-contradictory and is not done. Enforcing
canonical base64 *before* decoding is not literally implementable either, hence
the re-encode-and-compare at step 4.

Strict UTF-8 decoding cannot detect trailing content, because whitespace or a
second JSON document are both valid UTF-8. Steps 6-8 are therefore three
separate checks: decode, parse exactly one value, require end-of-input.
Canonical control-plane output carries no leading or trailing whitespace, so
the framing check is defense in depth against a tolerant parser.

**Nothing above the gate may produce a result of any kind.** `jobId`, `claimId`
and `nonce` live inside the signed payload, and the claim response is
`{ jobs: [signedJob] }` with no unsigned handle, so a failure at or before step
10 must fail locally and let the lease expire. A signature mismatch therefore
produces **no** result, `job_integrity_failed` included: in that failure mode
the fields a report would be built from are exactly what an attacker controls.
Integrity-failure telemetry would require a separate opaque claim handle in the
claim response, which is a protocol addition and is deliberately not part of
this record. Below the gate, a replay-bound `rejected` result may be built for
a semantic problem (unsupported action, invalid mode, stale window).

The gate is drawn between identity and intent on purpose. An earlier draft put
one "validate required fields" step here, covering both the identifiers a
rejection is built from and the fields describing what the job wants; that is
wrong precisely when the identifier validation itself fails, because then there
is nothing trusted to report with.

### 3. The signed payload shape: a shared envelope definition plus per-action schemas

`agentId` is a **required field of the signed payload**. Without it a client
cannot self-check that a job was meant for it the way it checks `workspaceId`;
agent-level binding would rest entirely on server-side enforcement (the claim
query returning only jobs stamped to the calling agent, and result ingestion
re-validating the nonce against `(jobId, workspaceId, agentRowId)`), with no
client-side gate at all.

This is a change to what dispatch signs: today's signed `basePayload` is
`{ ...payload, jobId, workspaceId, action, mode, claimId, attemptId,
leaseExpiresAt, attemptCount }`, and `agentId` is passed into signing only to
scope the server-side nonce ledger (`certops_consumed_nonces.issued_to_agent_id`),
never spread into the signed object. It is added to the one shared payload that
dual-format dispatch builds, so it appears identically in the v1 object and in
the v2 `payloadB64` decode. It is not a v2-only field.

**The schema change is not a bare required-key edit.**
`job-payload.schema.json` already requires certificate-specific fields
(`certificateId`, `target`, `keyMode`) that a diagnostic smoke job deliberately
has none of, so adding a bare required key would either weaken certificate
validation to admit smoke jobs or leave smoke jobs unable to validate at all.
Both are unacceptable. The shape is:

- a shared `signedDispatchEnvelope` definition carrying every field a signed
  job has regardless of action: `schemaVersion`, `jobId`, `workspaceId`,
  `agentId` (required), `action`, `mode`, `requestedAt`, plus the
  signed-dispatch fields `nonce`, `signingKeyId`, `signature`, `claimId`,
  `attemptId`, `leaseExpiresAt`, `attemptCount`, `issuedAt`, `expiresAt`;
- composed into `job-payload.schema.json` alongside today's certificate
  requirements, which stay unchanged;
- composed into a new `protocol-smoke-payload.schema.json` with its own minimal
  `additionalProperties: false` shape (`action: "protocol_smoke"`, a typed
  `{ mode: "dry_run", echo }` payload, and no certificate, target, key, DNS or
  PEM fields);
- selected by a discriminated union (`oneOf`, keyed on `action`) at the
  validation entry point, so a smoke job is never validated against the
  certificate schema and vice versa.

Gate step 11 validates `agentId` identically for both branches.

**Two distinct tests, which must never be collapsed into one.** It is true
that a job carrying `agentId` still verifies against already-deployed v1 code,
because `canonicalizeJobPayload` canonicalizes whatever keys are present and
none of `findSignedFieldProblem`/`verifyJobSignature`/
`buildSignedJobPolicyDescriptor` enforce `additionalProperties: false` against
the signed object at runtime. That is a **legacy tolerance** property of shipped
code, and it is not license for a new client to be lenient. So there are two
tests: a legacy-tolerance test (fixture job with `agentId`, run through the real
`verifyJobSignature` path, verifies normally) and a **new-client rejection**
test (a new agent's or reference client's gate refuses a job whose `agentId` is
missing or mismatched, even though the signature itself verifies).

Rollout is additive and **server-first**, in four steps. Reversing steps 1 and
3 would fail every job dispatched by an unupgraded control plane against the new
gate, which is the same fleet-wide-outage shape decision 1's capability gate
exists to prevent for the encoding itself:

```text
1. control plane starts signing agentId into the one shared canonical payload
   for both wire shapes (server-only; no client behavior change yet)
2. confirm deployed v1 agents tolerate the extra field IN PRODUCTION, via a
   staged/canary rollout watching for verification-failure regressions
3. only then ship agents/clients that require and validate agentId at the gate,
   advertising a distinct agent-id-binding-v1 capability (separate from
   signed-payload-b64-v1, which gates the envelope shape, not the identity check)
4. a new client meeting a control plane that has not completed step 1 fails
   closed with a named incompatibility error at heartbeat or claim time, never
   silently accepting the field's absence
```

### 4. Trust jobs get their own contract file, not a discriminated union on the certificate job schema

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
versioned. It composes the same shared `signedDispatchEnvelope` from decision 3
and adds only what a trust operation needs: `trustAnchorId`, `action` (enum:
`distribute-trust` | `revoke-trust`), `anchorType` (enum: `root` |
`intermediate`), `fingerprintSha256`, `pem`, `requestedBy`, `metadata`.

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

Trust and certificate payloads are siblings sharing one envelope definition,
not a single polymorphic schema. The discriminated union of decision 3 exists
at the validation entry point because `agentId` must be required uniformly; it
does not merge the certificate and trust *bodies*, which stay independently
versioned files.

### 5. Persistence reuses `certificate_jobs` and `certificate_evidence`, additively

Both tables are already generic:

```text
-- apps/api/migrations/migrate.js, certificate_jobs
subject_type TEXT NULL CHECK (subject_type IS NULL OR subject_type IN
  ('managed_certificate', 'certificate_instance', 'certificate_target',
   'token', 'domain', 'endpoint', 'external')),
subject_id TEXT NULL ...
payload JSONB NOT NULL DEFAULT '{}'::jsonb,
```

There is no `certificate_id` column and no `NOT NULL` constraint that assumes a
certificate subject; `certificate_jobs` is already a generic job table scoped by
`(subject_type, subject_id)` and a JSONB `payload`. The same is true of
`certificate_evidence`. A trust job is therefore not a new table; it is a new
`subject_type = 'trust_anchor'` value and a new pair of `operation` values, both
additive `ALTER TABLE ... DROP CONSTRAINT ... ADD CONSTRAINT` migrations that
widen an existing `CHECK`, never a column addition and never a backfill.
`certificate_jobs.operation` gains `'distribute-trust'`, `'revoke-trust'` and
`'protocol_smoke'`; `certificate_jobs.subject_type` and
`certificate_evidence.subject_type` both gain `'trust_anchor'`.

This is also why `jobApprovals.js` needs no code change:
`buildCanonicalExecutionIntent` already hashes
`{operation, subjectType, subjectId, payload}` off the generic columns, so the
existing approve/reject/canonical-intent-hash machinery covers trust jobs the
moment the `CHECK` constraints admit the new values. Approval is a property of
"a job", not of "a certificate job".

### 6. A trust anchor is a new row type, and ownership is tracked by reference rows

A trust anchor (a root/intermediate CA bundle to be distributed to or revoked
from machine trust stores) is not a certificate: it has no private key, no
renewal, no `managed_certificates` row. New table:

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
subject type). `fingerprintSha256` is carried on both the anchor row and the job
payload so the agent can verify the anchor it is about to install/remove against
the fingerprint the control plane signed, the same integrity pattern
`certificatePemSha256` already establishes for certificate deploy jobs.

`anchor_type` is stored on the anchor row as well as being signed into each
trust job payload, so the intended destination store is auditable independently
of any single job, and a disagreement between the anchor row and a signed job
payload is a detectable inconsistency rather than a silent reroute. Evidence
records the concrete store the agent actually wrote, so an audit can confirm the
routing end to end rather than trusting the request alone.

Trust anchor writes are additive-only at the row level: `revoke-trust` sets
`status = 'revoked'` and `revoked_at`, it does not delete the row. A revoked
anchor stays queryable for audit ("this host trusted this CA between these two
dates"), which a hard delete would destroy. Leaf certificates and invalid CA
material are rejected before the store is opened, and there is **no
desired-state pruning mode**: removal only ever matches a fingerprint
TokenTimer installed.

**Ownership is tracked by ownership-reference rows, with a durable transition
state.** These are called *ownership references*, never "claims", so they are
never confused with job claims (`certificate_jobs.claim_id`) in the same
document set. There is one **unique row per `(host, store, fingerprint, owner)`**
and the reference count is derived by `COUNT(*)`, rather than a mutable counter
column that can drift from the rows it summarizes. If two jobs depend on the
same anchor, releasing the first must not remove a root the second still holds,
so the store is only physically touched when the last reference is released.

Because the OS certificate store and the database cannot be updated atomically,
the locking and reconciliation model is explicit rather than assumed:

```text
1. write the ownership reference inside the job's transaction, in state
   pending_install (or pending_remove)
2. commit
3. perform the OS-level install/remove
4. transition the row to installed (or removed)

a reconciliation sweep compares recorded references against what the store
actually contains, catching a crash between 2 and 4 in either direction:
a row committed but never applied, or an OS change whose row never landed
```

Provenance is recorded as `preexisting` or `tokentimer_installed`, so a removal
can never strip an anchor that pre-existed TokenTimer's operation. A trust
anchor is never created by the scheduler and never derived into a renewal
profile. JKS/PKCS#12, NSS and GPO/Intune distribution are out of scope, with the
reasons recorded in the architecture plan rather than here.

### 7. Diagnostic clients are isolated server-side by `agent_kind`, not by capability

A reference client that speaks the agent protocol must never be able to claim
real certificate work. Refusing `mode: "real"` *after* claiming is too late: the
job is already leased to a diagnostic tool, and there is no way to hand it back
early (see below).

Capability-based gating cannot provide this boundary. `declaredCapabilities` is
client-supplied and clearable by sending an empty array, so it can gate work an
agent *cannot* do but never work an agent *must not be given*.

Decision: registration through a dedicated **diagnostic bootstrap scope** sets an
agent-immutable `agent_kind: diagnostic` on the fleet row, and dispatch offers
such an agent only the `protocol_smoke` job type in `mode: dry_run`. Enforcement
is keyed on `agent_kind`, a server-assigned column, never on anything the client
sends.

`protocol_smoke` is a full contract, not a job-type label:

- a new `operation` value via the additive `CHECK` widening of decision 5;
- a new wire `action`, **not** a reuse of `noop`, which is a real production
  operation in `EXECUTABLE_JOB_ACTIONS` and would let a diagnostic client and a
  production agent share an action;
- an `agent_kind` column, `NOT NULL DEFAULT 'normal'` with a `CHECK`;
- the typed `{ mode, echo }` payload of decision 3, with no target, command or
  key material;
- terminal `dry_run_complete` or `rejected` only;
- a dedicated bootstrap route behind a new `certops.agents.diagnose` permission;
- bootstrap-consume plus diagnostic-agent-create plus smoke-job-create in **one
  transaction**, which removes the interval where an agent exists with no job;
- a 15-minute single-use bootstrap and a per-workspace rate limit;
- a 24-hour inactivity TTL and audited retirement, never physical deletion,
  fenced against a live claim.

Diagnostic fleet rows are ordinary but labelled. `protocol_smoke` jobs are
excluded from certificate quotas, per-CA limits, approval flows, renewal alerts,
certificate inventory and fleet-health metrics, so a diagnostic run can never
distort a production number.

**There is no lease-release endpoint, so an unexpected job is rejected rather
than handed back.** `POST /api/v1/certops/agent/jobs/:jobId/lease` is
`renewJobLease` and moves `claimed -> running` while extending the lease and
nonce; nothing releases early. A client offered a job it must not execute
therefore terminates with a replay-bound `rejected` result carrying `claimId`,
`nonce` and a new **`unexpected_job_type`** value in the closed
`rejectionReason` enum, which is itself a contract change belonging to this
record. This path sits below the trusted-identity gate of decision 2: the job's
signature verified, and only then was it found unexpected.

**Registration is not replayable.** A retry model that returns the same
`{agentId, credential, job}` for a repeated idempotency key cannot work here,
and the reason is a property of the credential store rather than a design
preference: `certops_agents` and the dispatch service that reads it carry only
`credentialHash`. After a registration whose HTTP response is lost, the server
holds no raw credential to return a second time, and re-hashing a new one would
not match what the client never received. So a retry against a consumed
bootstrap fails with a distinct `diagnostic_bootstrap_already_consumed` error
and the client requests a fresh bootstrap. The alternatives (a short-lived
encrypted registration-response replay record, or deriving the credential from
client-held bootstrap material) were rejected as adding a second secret-bearing
mechanism to a surface whose entire point is to be low-stakes, for a failure
this cheap to recover from.

The orphaned agent/job left by that lost response is retired by the inactivity
sweep, which is a **state machine**, not a single "terminal or expired" rule,
because the smoke job can be in any of four states relative to the retirement
and only one is safe to act on immediately:

```text
pending / unclaimed      -> cancel the job and retire the agent atomically in
                            one transaction (nothing was ever leased, so there
                            is no in-flight claim to race)
active, unexpired lease  -> defer retirement; a client may be executing now
active, expired lease    -> terminalize the job first (the same behavior the
                            lease reaper already applies to any expired lease),
                            then retire the agent
terminal                 -> retire normally
```

Without the explicit `pending`/`unclaimed` branch, a lost registration response
would orphan a smoke job with no lease to expire and therefore no path back to
retired: a permanent targeted job against an agent nothing will ever claim.

### 8. The reference clients are Node-free, with explicit prerequisites

The reference clients exist so an operator on a restricted, hardened Windows
server can test registration and authentication, claim and inspect a job, verify
a signature, and diagnose a failed install. Requiring an application runtime for
that defeats the purpose: it adds a second runtime, patch lifecycle, approval
process and executable surface to precisely the hosts least willing to accept
one.

Decision: the clients are **Node-free with explicit, minimal prerequisites**,
never "dependency-free". Node remains an implementation choice for the
production agent and is **not** a protocol requirement; the production agent is
not being removed or rewritten by this record.

```text
Bash        bash, curl, jq, OpenSSL 3
PowerShell  Windows PowerShell 5.1-compatible subset (or PowerShell 7),
            plus a bundled Authenticode-signed tokentimer-verify binary
```

`jq` is listed explicitly because Bash cannot safely read arbitrary JSON alone;
zero external dependencies is not achievable there, and a supported
distro/tool matrix is published instead of pretending otherwise. PowerShell
targets the **5.1-compatible subset** as well as 7, because 7 is not built into
many supported Windows Server installations and requiring it would contradict
the no-runtime-installation goal.

Ed25519 verification uses a bundled, verification-only `tokentimer-verify`
binary from a minimal in-repo Go module, because nothing built into Windows can
verify Ed25519: stable .NET exposes no general Ed25519 API, and CNG exposes
curve25519 for ECDH only, not EdDSA. That binary performs the byte-verification
step **only**: no JSON parsing, no time checks, no dynamic algorithm selection,
no canonicalization. Everything else in the normative order of decision 2 stays
in the script, where it is auditable.

PowerShell 5.1 must hand the decoded payload to the verifier through a
**byte-preserving binary stream or binary file**, never the PowerShell text
pipeline or a string conversion, since either can transcode the bytes before Go
ever sees them. Parity tests must prove the wrapper-decoded byte array reaches
Go unchanged for non-ASCII, BOM, malformed-UTF-8 and invalid-JSON signed
vectors.

The clients implement the agent surface only: register, adopt the returned
identity, heartbeat, claim, verify, submit a replay-bound result. An
`--mode executor` was considered and dropped: the external-executor path is an
event-reporting surface with its own schema (`executor-event.schema.json`), its
own auth model and no signed-job claim/lease semantics, so an executor mode
would share no code path beyond argument parsing, and a green run would prove
the wrong thing under one name.

**Credential handling.** Credentials come from the environment, a
mode-restricted file, or the current register response, and never appear in
`argv`, logs or `--json` output. They are removed from the environment before any
child process starts, because `curl`, `jq`, OpenSSL and the verifier all inherit
it and `/proc/<pid>/environ` is readable. The Bash client passes its credential
to curl through `curl --config -` on standard input; `-H "Authorization: Bearer
$t"` leaks through `/proc/<pid>/cmdline`. Secret handling runs with `set +x`.
A temporary config file plus traps is **not** an acceptable substitute, because
traps do not run on `SIGKILL` or power loss; any unavoidable file inherits the
PFX journal-and-sweep model of decision 9 with the residue window acknowledged
rather than denied. `--json` output is built from an explicit field allowlist,
authenticated requests refuse cross-origin redirects, and there is no
TLS-insecure option and no `--insecure` escape of any kind. The flag that means
"contact the real API and complete a smoke job" is named **`--live`**, not
`--execute`, because the latter reads as permission to perform production
certificate work, which is exactly what this client must never do.

**The verifier trust bootstrap must terminate rather than be circular.** Expected
signer identity and hashes cannot live only in the same script whose integrity is
unspecified: an attacker replacing both files rewrites the expected identity too.
Script and verifier are both Authenticode-signed and delivered through a signed
installer/package, or through a signed release manifest pinned to an
operator-pinned publisher certificate for tarball distribution. The script
validates its **own** signature on invocation, requires
`Get-AuthenticodeSignature` to return `Valid`, and pins signer identity as
subject plus a set of accepted thumbprints so certificate renewal does not brick
installed clients. RFC 3161 timestamping applies, and hashes are mapped per
version and architecture. Revocation behavior is set by **installation policy,
not at runtime**: under the default online policy an unreachable CRL/OCSP
endpoint fails closed, and an air-gapped host must be deployed with the signed
offline manifest or cached revocation material. A runtime override would be
`--insecure` by another name. Published hashes are version/integrity checks,
never the trust anchor. Reproducibility applies to the unsigned build, so hashes
and provenance are published for both unsigned and signed artifacts, and the
unsigned binary never ships in a production bundle.

FIPS-only hosts must fail with an explicit unsupported-algorithm error, detected
**before** the verifier is invoked: Go's standard library will compute Ed25519
even where policy forbids it, so "it worked" is not evidence of compliance. A
FIPS-approved algorithm would be a separately versioned envelope decision, never
an automatic fallback. In strict FIPS environments the blocker is Ed25519
itself, not the choice of runtime.

Client tests compare deterministic normalized fixtures rather than attempting
byte-identical live runs. Canonicalization and signature parity vectors stay in
the dev-time test suite; no JavaScript canonicalizer ships in the client bundle.

### 9. CNG-native key custody is the default; PFX import is the disciplined fallback

Windows offers two paths to get a certificate into `LocalMachine\My`:

- **CNG-native**: `certreq -new` against an INF request descriptor generates the
  key pair directly inside the CNG machine key store (backed by the Microsoft
  Software KSP unless a hardware KSP is configured) and `certreq -accept` binds
  the CA's response to it. The private key never exists as a file; it is a CNG
  key handle, non-exportable by default.
- **PFX import**: a key pair is generated off-host, or agent-side by the local
  ACME client tooling when it cannot be pointed at a CNG-generated CSR, and
  imported as a PFX/PKCS#12 bundle via `Import-PfxCertificate`. The private key
  exists as bytes, however briefly, before import.

Decision: CNG-native is the default and required path for any certificate the
Windows agent itself requests (a `renew` or `issue` job targeting a Windows
target whose custody is the OS certificate store). Such jobs carry
`keyMode: os-store-managed`, not `agent-local`.

The distinction is semantic, not cosmetic. `agent-local` in
`job-payload.schema.json` means the agent holds the key as agent-managed material
on the filesystem (the `openssl genrsa`/`certbot` shape), which is why
`jobs.js`'s `AGENT_DEPLOYABLE_KEY_MODES` admits `agent-local` and
`proxy-agent-local` for file-deploy paths. A CNG-native key is categorically
different: it is a non-exportable handle owned by the OS store, the agent cannot
read its bytes, and any code path that assumes it can write the key to a
`keyPath` is wrong for it. `os-store-managed` already exists in the `keyMode`
enum for exactly this custody model, so the Windows cert-store work extends the
deployable set with `os-store-managed` rather than overloading `agent-local` with
a second, incompatible meaning.

PFX import is the disciplined fallback, not a second default, for two distinct
cases:

1. `deploy` jobs where the certificate material already exists off-host and is
   being placed onto a Windows target, the same shape ADR-0001's zero-custody
   model already permits for other platforms.
2. `issue`/`renew` jobs where the local ACME client cannot be pointed at a
   CNG-generated CSR (some ACME client integrations generate their own key pair
   and CSR internally and have no supported hook to consume an externally
   supplied one). This case is still agent-originated custody
   (`keyMode: agent-local`, not `os-store-managed`, since the key transits
   agent-local file bytes before the store wraps it) and is gated by the same
   discipline as case 1, not an open door to default-to-PFX.

In both cases the control plane never holds the private key, and the PFX bytes
are agent-side and ephemeral, bound by the following:

- **In-memory password.** The PFX password is generated per-operation with
  `RandomNumberGenerator`/`node:crypto`, held only as a `SecureString` (or
  cleared `Byte[]`) in process memory, and passed directly to
  `Import-PfxCertificate -Password`. It is never written to disk, logged, or
  passed as a plain command-line argument.
- **ACL-restricted staging file.** `Import-PfxCertificate` requires a file path,
  so the PFX bytes touch disk for the minimum required window, in a dedicated
  protected staging directory carrying the same restrictive ACL discipline as the
  agent's config/credential files (decision 10): the configured service SID plus
  `SYSTEM` only, inheritance disabled.
- **Non-exportable import.** Import always runs without `-Exportable` (its
  default is non-exportable), so the store-side key ends up with the same
  "cannot be read back out" property CNG-native keys have natively.
- **Crash recovery, not just an exit path.** A `finally` block cannot survive
  `SIGKILL` or a host reset, so cleanup is a journal plus a sweep: every
  temporary PFX is journaled (path and job metadata only, **never** the
  password), and a startup sweep of stale artifacts runs **before the agent
  accepts any claim**, failing closed with required operator action reported if a
  stale PFX cannot be deleted.
- **No secure-erasure claim.** Deletion on NTFS/SSD does not reliably destroy
  bytes. The honest claim is prompt removal plus a recorded exposure window, not
  erasure.
- **Evidence of the transient file window.** Because the private key existed as
  file bytes for a bounded window, the issue/renew/deploy evidence item records
  that fact (a boolean `keygen.pfx_transient_file` marker plus the staging
  directory's ACL posture), even though the file itself never leaves the host and
  is gone before the evidence item reaches the outbox.

This mirrors ADR-0001's zero-custody invariant: CNG-native gives Windows the
same "the agent generates it, the agent holds it, nothing else ever sees it"
property that Linux `agent-local` key generation already has via `openssl
genrsa`/`certbot`, while keeping the custody *mode* honest about who can actually
read the key.

### 10. The Windows permission model: one ACL matrix, enforced, never skipped

POSIX hosts express "only this identity may read this file" with `chmod 0600` /
`0700`, and the agent has always asserted those modes. Windows has no `chmod`
equivalent, and the shipped behavior was to wrap every `chmod` in an empty catch
and skip the credential-file preflight outright on win32. That is the one thing
the agent must never do: treat "this platform cannot express the permission I
need" as success. This is shipped behavior being corrected, not new scope.

Decision: one ACL matrix, stated once, canonically:

```text
agent-created state (config dir, credential file, generated keys, replay
store, outbox, job journal, PFX staging dir):

  granted    configured service-account SID + SYSTEM, full control
  inheritance removed (/inheritance:r)
  directories (OI)(CI)(F), so files created inside - including the temp
             file of an atomic write - start out restricted
  Administrators  ACCEPTED but NEVER GRANTED
  owner      must itself be a trusted SID

operator-provided credential files:

  every EFFECTIVE principal must be inside the same allowlist
  inheritance MAY be retained
  any deny ACE removing required rights is a named rejection
```

The identity is the **configured service-account SID, not the current process
user**. Resolving the SID from `whoami /user` is correct at runtime but wrong at
installation, where the current user is typically the installing administrator
rather than the account the service will run under; granting that SID yields a
DACL that *looks* restrictive while omitting the account that actually needs
access. The agent additionally requires its runtime identity to match the
configured service SID at startup. The process SID remains only the operator-run
(non-service) fallback where the two coincide.

`BUILTIN\Administrators` is accepted but never granted, because a member can take
ownership of any file on the machine: excluding it buys no confidentiality while
breaking routine operator maintenance.

The **owner SID must itself be validated as trusted**. Checking ACEs while
permitting an arbitrary owner is insufficient, since the owner can rewrite the
DACL at will.

For operator-supplied files the check is **effective access**, not principal
membership alone. A deny ACE naming the service account or `SYSTEM` is inside the
allowlist by principal yet still blocks required access, because deny ACEs
evaluate first. Conversely, requiring an explicitly protected DACL there would be
a false rejection: a file inheriting service-SID-plus-`SYSTEM` from a locked-down
parent is exactly as confidential as one with an explicit DACL. The principal
allowlist is the security property; the protected flag is a
durability-of-intent property, required only for state the agent creates itself.

Enforcement mechanics, because a partially restricted credential file is not an
acceptable outcome of a successful write: `icacls /grant:r` only replaces entries
for the principals it names, so a pre-existing explicit ACE for someone else (an
operator's `icacls /grant`, a tool that added Everyone) survives it. Enforcement
therefore grants, re-reads the resulting DACL, removes every principal outside
the allowlist (resolving SDDL aliases to SIDs), and re-reads to confirm, raising
if anything foreign remains.

Verification parses **SDDL**, never `icacls`' human-readable output: SDDL is
SID-based and locale-independent, while the readable form is localized ("AUTORITE
NT\Systeme" on a French host). A missing `icacls`, a non-zero exit, an empty
DACL, or an unparseable descriptor is an error, never a silent skip.

Directory fsync is a **recorded durability limit**, not a swallowed no-op:
Windows cannot open a directory for fsync, so the agent records the limitation in
evidence metadata rather than discarding the error, while the atomic rename still
prevents torn files.

### 11. The Windows agent service runs as `LocalSystem`

Three operations the Windows agent must perform are administrator-level by
Windows design, not by choice: writing `LocalMachine\My` for a CNG-native
enrollment tied to the machine (not the user) context, binding a certificate to
an IIS site (`netsh http add sslcert` / the IIS
`Microsoft.Web.Administration` binding APIs), and writing
`LocalMachine\Root`/`LocalMachine\CA` for trust-anchor distribution. There is no
supported Windows API to delegate exactly these three rights to an unprivileged
service account without also granting enough to reach the same operations by
other means (for example `WebHosting` store write access effectively also permits
binding certificates other services rely on).

Decision: the Windows agent Windows Service runs as `LocalSystem`. This matches
established prior art for this exact problem (win-acme, Certify The Web, and
other IIS-certificate-lifecycle tools all run their service as `LocalSystem` or
an equivalently privileged account for the same reason), and it is honest about
the actual privilege boundary rather than presenting a narrower one that does not
hold up: a service that can rewrite IIS bindings and the machine trust store
already has host-administrator-equivalent blast radius regardless of the account
name.

The compensating controls are the ones already established elsewhere in the
protocol, not a narrower account:

- **Agent-local policy wins** (ADR-0002): the agent still refuses any
  `certPath`/`reloadService`/site-binding target outside its own configured
  allowlist, `LocalSystem` or not. Running as `LocalSystem` does not bypass
  agent-local policy; it only means the OS would *let* the agent do more than
  policy allows, which is exactly why agent-local policy, not OS ACLs, is the
  enforcement point per ADR-0002.
- **Config/credential file ACLs** (decision 10): the agent's own config and
  credential files are still ACL'd to deny access to *other* principals. A
  `LocalSystem` service reading its own config is not a new exposure, since
  `LocalSystem` already has ambient access to the entire machine. `SYSTEM` is in
  the allowed-principal list precisely because the service that must read those
  files runs as `SYSTEM`; the ACL's job is excluding everyone else, not excluding
  the service that owns the file.
- **Evidence and audit** (decision 13): every distribute-trust, revoke-trust and
  IIS-binding action produces evidence and an audit event, so `LocalSystem`
  breadth is paired with a durable trail of what it actually did, which is the
  control the account name cannot provide by itself.

### 12. Rejected privilege models

- **Delegated ACLs on the machine cert store for a low-privilege service
  account.** Windows does not expose a supported public API to grant
  `LocalMachine\My`/`LocalMachine\Root` write to an arbitrary account short of
  administrator-group membership or `LocalSystem`; the closest primitives
  (`certutil -importPFX`'s ACL flags, `CertSetStoreProperty`) operate on a store
  already opened by a caller who already has store-level access, so they do not
  solve the initial-access problem. Rejected as unsupported for the exact rights
  needed.
- **A dedicated `BUILTIN\Administrators`-member service account** instead of
  `LocalSystem`. This trades nothing meaningful: an account in `Administrators`
  has a strict superset of what the three operations need, it still cannot be
  scoped down to just those three operations, and it adds an extra credential
  (the account's own logon secret) to protect that `LocalSystem` does not have,
  since `LocalSystem` has no logon secret to steal. Rejected as added attack
  surface for no added safety.
- **A group-managed service account (gMSA).** gMSAs solve cross-machine Kerberos
  delegation and automatic password rotation for a *domain* identity; they do not
  by themselves grant machine-cert-store or IIS-binding rights, and a large
  fraction of target hosts (standalone IIS boxes, non-domain-joined servers)
  cannot use a gMSA at all. Rejected as solving a different problem than the one
  blocking this ADR, and as unavailable on a meaningful fraction of the fleet
  this feature targets.
- **A split design: a low-privilege long-running service plus a short-lived,
  separately-launched privileged helper process for the three operations.** This
  is the standard pattern for minimizing standing privilege, and it was seriously
  considered. Rejected for this decision specifically because the helper would
  still need to run as `LocalSystem` (or Administrator) to do its three jobs, so
  the split does not lower the ceiling of what an attacker who compromises the
  agent can reach; it only adds an IPC boundary and a second process to keep
  patched, in exchange for a privilege-duration reduction that does not apply
  here anyway (the service is long-running and heartbeats continuously; there is
  no idle low-privilege majority of its lifetime to protect). This is a
  legitimate design for a service that is privileged rarely and unprivileged most
  of the time; it is not this service.

### 13. IIS binding deploy is verified against the binding itself

Deploy is: import, record the outgoing thumbprint, rebind, verify by a real TLS
handshake, and roll back by rebinding the recorded thumbprint on failure.

The handshake targets **the binding's own local address and port** while
supplying the configured SNI hostname, and compares the leaf fingerprint. It
never connects to a DNS-resolved name: that could verify a load balancer or
another host entirely and green-light a binding that never changed.

Wildcard bindings (`*:443`, `0.0.0.0:443`, `[::]:443`) have no exact IP to
connect to, so they use a defined loopback probe (`127.0.0.1`, or `[::1]` for the
IPv6 wildcard) on the binding's port while still supplying the configured SNI
hostname, which is what selects the certificate under a wildcard binding. The
probe still exercises the http.sys binding that was just changed.

There is no `iisreset`; an app-pool recycle is a per-target opt-in. The
per-target mutex covers the **store** as well as the binding, since two jobs
racing on the same machine store is as damaging as two racing on one binding.
Windows discovery enumerates the machine store and the binding set, reporting key
presence without export.

### 14. New operations, actions, capability gate, and RBAC

Control-plane `operation` values: `distribute-trust`, `revoke-trust`,
`protocol_smoke` (all added to `certificate_jobs.operation`'s `CHECK` per
decision 5). Agent-facing `action` in the trust job payload mirrors the trust
operations 1:1: no separate `operation`/`action` naming split is needed the way
ADR-0008 needed one for `issue`, because a trust job's control-plane intent and
agent-side action are the same concept, with no multi-step lifecycle to
distinguish. `protocol_smoke` gets its own distinct wire action rather than
reusing `noop`, per decision 7.

Per ADR-0002's addendum pattern, three new capability strings gate the work:

```text
signed-payload-b64-v1    receive the v2 envelope instead of the v1 object
agent-id-binding-v1      client validates signed agentId at the gate
trust-anchor-deploy-v1   claim distribute-trust / revoke-trust
windows-cert-store-v1    claim Windows machine-store custody work
iis-binding-v1           claim IIS binding deploys
```

Capability gating is a **matching predicate, not a rejection**: an agent that has
not declared a capability simply never gets offered the corresponding jobs, which
surface to the operator as an unclaimed `pending` job, consistent with how
`evidence-claim-binding-v1` already behaves. It is emphatically **not** a
security boundary; that is what `agent_kind` is for (decision 7). Wiring the gate
into `agentDispatch.js`'s claim path is a follow-up change: the capability
strings and schemas land first, the gate lands in a subsequent PR.

**`certops.agents.diagnose` is a new named permission with a two-repo rollout.**
Existing CertOps permissions (`certops.kill_switch.manage`,
`certops.renewal_profile.manage`) are entries in `actionPolicy` with role
documentation explaining why they sit above ordinary job creation. The new
permission needs the equivalent: an `actionPolicy` entry (admin and
workspace_manager, never viewer), the route's `authorize()` call, OpenAPI
documentation of the 401/403 shape matching the existing pattern, and unit
coverage. Because Cloud maintains its own `actionPolicy` copy rather than
importing core's, this is a **second, independent edit in Cloud**, not something
core's change propagates automatically.

### 15. Evidence and audit

`certificate_evidence.evidence_type` gains `'trust.distributed'` and
`'trust.revoked'`, following the existing `<domain>.<verb>` naming convention
(`certificate.observed`, `deployment.updated`).
`certificate_evidence.subject_type` gains `'trust_anchor'` (decision 5).

New audit events, following ADR-0011's naming convention
(`CERTOPS_<NOUN>_<VERB>`): `CERTOPS_TRUST_ANCHOR_DISTRIBUTED`,
`CERTOPS_TRUST_ANCHOR_REVOKED`. Per ADR-0011's asymmetric-audit rule (success is
audited, routine non-events are not), a claim or an in-flight attempt does not
itself produce an event. Both fire only on that action's own terminal `succeeded`
transition, matching how `CERTOPS_CERTIFICATE_ISSUED` is emitted only for a
successful issuance today, never for a failed one. A terminal `failed` transition
for either action reuses the existing generic `CERTOPS_JOB_FAILED` event
(`agentDispatch.js`'s pattern for certificate job failures), rather than a
success-named event, and rather than inventing two more one-off failure events
for actions that already share a job-failure shape with every other job type.

Consistent with decision 2, a signature-verification failure produces **no**
agent-submitted result and therefore no agent-originated audit row: there is
nothing trustworthy to attribute it to. Server-side observability of such
failures is a separate concern from an agent-reported result.

### 16. The already-shipped production agent is fixed in the same wave

The review that produced decision 2 found the identical unsafe pattern in shipped
code: `handleSignedJob` in `packages/agent/src/index.js` reads `job.claimId` and
`job.nonce` off the received object **before** `verifyJobSignature` runs, then
passes them into `reportJobRejection` on a signature-verdict failure. That is
exactly what decision 2 forbids, in the v1 agent that is already deployed.

Decision: this is fixed as part of the envelope work, not deferred as follow-up.
Shipping a hardened reference client next to a softer production agent
implementing the same protocol would leave the weaker implementation as the real
security posture. Verification runs strictly first, and no identifier is read,
logged, or used to construct any result (a rejection included) until
`verifyJobSignature` has returned an allowed verdict and the trusted-identity gate
has separately passed. Regression tests cover both wire shapes and assert that no
result is submitted on signature failure, that no field is read from the job
object before verification, and that a semantic rejection is only ever built from
post-gate identifiers.

## Alternatives considered

(Envelope, trust-job shape, persistence, custody and privilege alternatives are
covered inline in the decisions above, alongside the specific reasons each was
rejected, since they are mechanically inseparable from the decision they inform.
The privilege-model rejections are decision 12.)

- **Ship the reference clients with a pinned Node dependency.** Rejected. The
  reasoning that led there was sound (canonical JSON is specified in JavaScript
  terms, so a pure-Bash reimplementation cannot be *proven* byte-identical, and a
  merely-probably-identical canonicalizer is a silent verification bypass), but
  the remedy was wrong: it accepted an application runtime on hardened hosts
  instead of fixing the contract that created the need. Decision 1 fixes the
  contract.
- **Gate diagnostic clients with a declared capability**
  (`reference-client-dry-run-v1`) instead of a server-assigned `agent_kind`.
  Rejected: declared capabilities are client-supplied and clearable, so they can
  gate work an agent cannot do but never work an agent must not be given. The
  capability string degrades to a compatibility signal.
- **Have the client release the lease on an unexpected job.** Rejected as
  unimplementable: there is no lease-release endpoint, only `renewJobLease`. A
  replay-bound `rejected` result carrying `unexpected_job_type` is the honest
  mechanism (decision 7).
- **Model a trust anchor as a `managed_certificates` row with a sentinel
  `key_mode`.** Rejected: a trust anchor has no key, no expiry-driven renewal,
  and no deployment-target list in the certificate sense; forcing it into
  `managed_certificates` would mean every certificate-shaped query
  (`skipped_incomplete_profile`, renewal scheduling, key-mode-based
  deployability) needs a trust-anchor exclusion clause added defensively,
  forever. A dedicated table has none of that risk.
- **Track anchor ownership with a mutable reference-count column.** Rejected in
  favor of unique ownership-reference rows with a derived `COUNT(*)`: a counter
  can drift from the rows it is meant to summarize, and the failure mode is
  removing a root another job still holds.
- **Give trust jobs their own status/audit vocabulary instead of reusing
  `certificate_jobs`'s.** Rejected: the status machine (`pending` -> `claimed` ->
  `running` -> `succeeded`/`failed`, plus
  `pending_approval`/`approved`/`rejected`/`blocked`/`cancelled`) is already
  subject-agnostic; duplicating it for trust jobs would duplicate every consumer
  that walks job status (dashboards, the scheduler's own job-status queries,
  `agentDispatch.js`'s claim loop) for no behavioral difference.

## Consequences

- **Sequencing is fixed by decision 1's prerequisite chain**, and it is not the
  order the work was originally planned in: the heartbeat `declaredCapabilities`
  contract lands first (the envelope needs a re-advertisable capability), then
  envelope v2 together with the required signed `agentId` and the decision-16
  agent fix, then the Node-free client rewrite. The Windows platform work of
  decisions 9-13 is **independent of the reference client** and does not wait for
  the envelope; coupling them would delay a shipped-behavior security correction
  behind a protocol rewrite for no reason.
- A shared contract-foundation change owns: the `signedDispatchEnvelope`
  definition and the two per-action schemas, the new trust-job schema file, the
  `certops_trust_anchors` and ownership-reference migrations, the `agent_kind`
  column, the `operation`/`subject_type` `CHECK` widenings on `certificate_jobs`
  and `certificate_evidence`, the `unexpected_job_type` `rejectionReason` value,
  and the capability-string constants. Nothing in this list is exclusive to the
  Windows execution work or the trust-anchor work, which is why it lands before
  both.
- **Dual-format dispatch is carried for as long as legacy v1 agents exist.** That
  is an accepted, explicit cost with a defined end state (v1 retires when the
  fleet has upgraded), not an indefinite compatibility layer.
- **The runtime boundary is now unambiguous and must be documented as such:** the
  Bash and PowerShell diagnostic clients are Node-free but *not*
  dependency-free, and the production agent remains Node-based and is not being
  removed. Advertising either half loosely would mislead operators in opposite
  directions.
- `LocalSystem` is a documented, operator-visible fact of the Windows install
  (the install script and the operator runbook must both say so plainly), not an
  implementation detail. An operator who cannot accept a `LocalSystem` service on
  a given host should not install the Windows agent on that host; there is no
  lower-privilege mode for the IIS/trust-anchor feature set. A future
  "observe-only, no IIS binding, no trust anchors" Windows agent profile could run
  less privileged, but that is a new, narrower agent capability set, not a
  configuration flag on this one.
- **The Windows permission change makes the agent fail closed where it currently
  succeeds quietly.** That is the right end state and the wrong change to slip
  into an already-validated release candidate, so it ships in its own release
  alongside honest platform-support documentation, not as a backport.
- Because CNG-native keys are non-exportable CNG handles rather than files, a
  Windows agent uninstall/host decommission does not leave a private key file
  behind to shred; the key is destroyed with the CNG key container, which the
  uninstall path must explicitly delete (`certutil -delkey` semantics) rather than
  assume filesystem cleanup covers it.
- The `CHECK` widenings, the new tables and the new columns are all additive; no
  existing row or query changes behavior, and the only consumer-visible change is
  that capable agents receive a different envelope shape, which is capability-
  gated precisely so it is opt-in. Cloud and Enterprise inherit trust-anchor,
  envelope and Windows-target support through the shared migration and contract
  path the same way they inherit every other CertOps change, with two exceptions
  that must be tracked explicitly rather than assumed: Cloud needs its own
  `actionPolicy` entry for `certops.agents.diagnose` (decision 14), and both
  downstream repos' feature-adoption work is deferred past this ADR's boundary.

