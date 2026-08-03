# ADR-0012: Windows execution surface, trust-anchor operations, signed-dispatch envelope, and CNG-vs-PFX custody

## Status

**Accepted (2026-08-03).** Proposed 2026-08-02; amended seven times against
successive external audits, five on 2026-08-02 and two more on 2026-08-03,
before acceptance: decisions 2, 3 and 16 first (Finding A's
misattribution, the observe-only carve-out, and `agentId` absence-versus-mismatch),
then decisions 2, 3, 4 and 8 again (the signed-payload/wire-wrapper split,
`agentId`'s requiredness sequencing and effective-flag capability gating, the
PowerShell pre-execution trust boundary, the signed-script encoding constraint,
and the replacement of "zero network calls" with a testable post-verdict-request
property), and finally decision 8 once more plus decision 3's heading: the Bash
decoded-payload transport said "a file or a process substitution", which this
same decision's command-allowlist test forbids by excluding `mktemp`, so the
normal path is now one byte-preserving stream and a named file is a declared
exception with explicit obligations; and decision 3's title still called the
shared definition an "envelope", the one word its own body rules out.
**A fourth amendment (2026-08-02) added decision 17** (a capability epoch and
claim-time freshness bound, closing Finding C) and corrected decision 8's Bash
sequence, which described a single decode reused for both verification and
parsing; Ed25519 verification consumes and does not re-emit its input, so the
implementable form is two deterministic decodes of the same immutable
`payloadB64`, the second gated on the first's verdict. The same pass synced
decision 8's PowerShell file-transfer clause with the Bash-side declared-
dependency obligations, and corrected the Consequences section's sequencing,
which had said envelope v2 ships "together with" mandatory `agentId`,
contradicting the deliberate split of that work into separate changes.
**A fifth amendment (2026-08-02) corrected four further issues found in the
fourth amendment itself**, all in decisions 14, 17, and 1: (1) decision 14's
"ship undeclared" mechanism was specified as an environment variable,
`CERTOPS_AGENT_QUALIFIED_CAPABILITIES`, which cannot be release-controlled
since an environment variable is by definition operator-configured, and which
additionally created a qualification loop with no fixed point between "test
before enabling" and "enable after evidence exists"; replaced with a
build-time manifest embedded in the binary, so the tested artifact and the
promoted artifact are the same bytes. (2) decision 17's freshness bound
justified 900000ms as "three times" a 30-second heartbeat, which is off by a
factor of ten, and separately claimed the bound equalled the lease TTL so a
lease could not outlive the assertion, which is false regardless of the
multiplier since the two durations compose additively; the bound is now
600000ms, derived from the existing agent-offline SLO rather than from either
piece of the original, retracted reasoning. (3) decision 17 gained explicit
column-initialization semantics: `capabilities_updated_at` is set at
registration and is never backfilled for pre-existing rows, which migrate
with it `NULL` and are treated as maximally stale until their next
capability-reporting heartbeat, rather than being given a fabricated
timestamp. (4) decision 1 had permitted Bash to use "`openssl pkeyutl -verify`
or the bundled verifier", which would let either reference client silently
fall back to the other's Ed25519 implementation and erase the independence
the two-client design exists to provide; Bash now uses `openssl pkeyutl
-verify` exclusively and PowerShell uses the bundled `tokentimer-verify`
exclusively, with neither permitted to call the other's path.
**A sixth amendment (2026-08-03) closes the three remaining open questions**
rather than leaving them as unresolved prose: decision 8 gains a stated
PowerShell trust default (the signed launcher, with enforced WDAC as the
documented hardened alternative, closing open question 5); a new decision 18
sets a named, bounded superseded-certificate retention window
(`windows.supersededRetentionHours`, default 168 hours, range 24-720, zero
rejected) with an explicit multi-condition deletion gate, closing open
question 8; and a new decision 19 states this record does not require
`mlock`/`VirtualLock` for agent-side key memory and does not claim locked or
non-pageable memory anywhere it is not actually held, relying instead on
non-exportable custody (CNG-native by default), buffer-not-string handling,
zeroization on every path, disabled core dumps, and a documented residual
swap/pagefile risk, closing open question 9. **This adds no wire-protocol or
control-plane database change; decision 18 adds agent configuration and
persistent local lifecycle state, while decision 19 adds service-packaging
and runbook requirements.**
**A seventh amendment (2026-08-03) corrected four issues found in the sixth
amendment itself, all in decisions 18 and 19.** (1) Decision 18's clock-skew
grace was "a small fixed" value with no number; it is now the named,
existing 300-second constant (`DEFAULT_NONCE_TTL_SECONDS` /
`NONCE_TTL_GRACE_SECONDS`, both already 300 elsewhere in this program), not a
newly invented figure. (2) Decision 18 stated "retained for 168 hours" as
though that duration were unconditional, when the decision's own
earlier-of-two-clocks rule means the actual retained duration is frequently
shorter; corrected to "retained for up to 168 hours". (3) Decision 18 gained
a specified restart-safe superseded-material ledger (persisted fields, ACL
discipline, atomic writes, startup-and-periodic sweeps, and explicit
active/closed rollback-journal-reference semantics), since safe cleanup
cannot survive an agent restart between cutover and the cleanup deadline
without one, and the sixth amendment's text implied the ledger's existence
without ever specifying it. (4) Decision 19's "core dumps are disabled"
clause named no platform-specific mechanism or verification method; it now
names the Windows Error Reporting `LocalDumps` registry key (`DumpType=0` or
absent) and the Linux `LimitCORE=0`/`RLIMIT_CORE` mechanism, each with its
own verification command, rather than an unqualified claim.
**This record is accepted as of 2026-08-03 following this seventh amendment;
the Windows execution-surface, signed-envelope and trust-anchor work
described below may now begin.** The PRs that implement this feature set
follow this decision rather than re-deciding it; any future change to a
decision here is a new, explicitly logged amendment, not a silent
divergence in code.

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

**Nothing above the gate may produce a result built from the signed payload's**
**own identifiers.** `jobId`, `claimId` and `nonce` live inside the signed
payload, and the claim response is `{ jobs: [signedJob] }` with no unsigned
handle, so a failure at or before step 10 must fail locally and let the lease
expire. A **signature-verdict failure** therefore produces **no** result,
`job_integrity_failed` included: the verdict has affirmatively established that
the payload is not control-plane-issued, so the fields a report would be built
from are exactly what an attacker controls. Integrity-failure telemetry would
require a separate opaque claim handle in the claim response, which is a
protocol addition and is deliberately not part of this record. Below the gate, a
replay-bound `rejected` result may be built for a semantic problem (unsupported
action, invalid mode, stale window).

Stated as a testable property, and **not** as "zero network calls", which is
false on its face because registration, heartbeat and the claim itself are all
network calls that necessarily already happened: **after the envelope is
received, a pre-gate failure produces no result, no evidence, no lease renewal,
and no other post-verdict request.** Local error classification may and should
differ between failure modes — malformed base64 is a different local log line
and a different exit code from an unsupported FIPS policy or an unparseable
wrapper — because an operator debugging a broken install needs to tell them
apart. What may never differ is the content: no local error, log line, exit
code, or metric may carry an identifier taken from an unverified payload.

One case sits above the gate and still reports, and the distinction is
substantive rather than a carve-out: when **no signing key is pinned at all**,
verification is not possible in either direction. No signature has proven the
payload false, the agent cannot execute anything until an operator fixes the
pin, and that is precisely the state an operator needs to see, so the agent
reports `blocked` with an explanatory message. Echoing the received
`claimId`/`nonce` there opens no forgery vector, because the identifiers return
only to the authority that issued them and the server's own nonce ledger, bound
to `(jobId, workspaceId, agentRowId)`, decides whether the report binds: a
fabricated nonce fails to consume and the submission is refused rather than
causing a false state transition. The rule is therefore "a signature verdict
against a job silences all reporting about that job", not "anything unverified
is unreportable".

The gate is drawn between identity and intent on purpose. An earlier draft put
one "validate required fields" step here, covering both the identifiers a
rejection is built from and the fields describing what the job wants; that is
wrong precisely when the identifier validation itself fails, because then there
is nothing trusted to report with.

**There is no observe-only carve-out from this order.** An agent running
without execution configured (`executionContext` null or `enabled: false`)
still runs steps 1-14 unchanged before doing anything else with a job object;
"observe-only" changes only what happens at step 15. Observe-only avoids
certificate side effects, but the shipped agent's separate observe-only branch
still terminates the job and submits evidence and a result, which is enough to
corrupt operational state from an unverified payload if that branch is ever
reached. A signature-verdict failure in observe-only mode is governed by the
identical silent-failure rule as the execution-enabled path: no result, no
evidence, `job_integrity_failed` included, and the lease is left to expire.
Only after a verdict is available does execution status matter, and only to
choose between running the job and reporting a policy rejection or `blocked`
from the now-verified payload's own fields — never to decide whether
verification runs at all. This closes the finding recorded against
`handleClaimedJob` in decision 16: its observe-only branch must call into the
same verify-then-derive-identity path as its execution-enabled branch, not
`validateClaimedJob` on the raw wire object as a substitute for a signature
verdict. Local execution readiness (configured vs. not, key pinned vs. not) is
heartbeat and diagnostic telemetry; it is never grounds to construct a
job-specific result from identifiers a verdict has not yet blessed.

### 3. The signed payload shape: a shared signed-payload definition plus per-action schemas

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
Both are unacceptable.

**Signed payload and wire wrapper are separate schemas, and conflating them is
not a naming nit.** An earlier draft of this decision named one shared
definition `signedDispatchEnvelope` and gave it both the signed fields *and*
`signature`. That is impossible as a description of signed content: the
signature cannot be one of the fields it signs. The v1 wire object legitimately
carries payload-fields-plus-`signature` (verification excludes the top-level
`signature` when recomputing canonical bytes), but that is a property of the
**wrapper**, not of the payload, and a v2 `payloadB64` decode must contain no
`signature` field at all. Three schemas, named for what they are:

```text
signed-dispatch-payload   the signed fields, and ONLY the signed fields:
                          schemaVersion, jobId, workspaceId, agentId, action,
                          mode, requestedAt, issuedAt, expiresAt, nonce,
                          signingKeyId, claimId, attemptId, leaseExpiresAt,
                          attemptCount. NO signature: this is the content that
                          gets signed, so it cannot carry its own signature

v1 wire wrapper           the signed payload's fields PLUS signature, as one
                          flat object (today's shape, unchanged)

v2 wire wrapper           envelopeVersion, payloadB64, signatureB64,
                          signingKeyId. additionalProperties: false. Carries no
                          payload fields and no sibling job object (decision 1)
```

`signingKeyId` appears in the signed payload *and* on the v2 wrapper on
purpose: the wrapper's copy is the pre-verification selection hint, the
payload's copy is the authenticated value, and step 13 requires them to agree.
That is the one field legitimately present in both, and the equality check is
why.

The per-action composition is then:

- the shared `signed-dispatch-payload` definition carries every field a signed
  job has regardless of action;
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
   for both wire shapes, AND the producer schema makes agentId required, in the
   SAME change (server-only; no client behavior change yet)
2. confirm deployed v1 agents tolerate the extra field IN PRODUCTION, via a
   staged/canary rollout watching for verification-failure regressions
3. only then ship agents/clients that validate agentId at the gate; a
   compatibility DECODER may accept absence while the effective flag is false,
   never mismatch
4. the flag's effective value becomes true so absence also fails closed; only
   then is agent-id-binding-v1 advertised
```

**Step 1 is atomic, and the producer schema is never optional-then-required.**
An earlier draft had the schema relax `agentId` to optional "during rollout" and
tighten it later. That is the wrong lever: the schema that validates what the
**control plane emits** should require `agentId` from the moment the control
plane emits it, in the same change, because a producer schema that permits
omitting the field cannot catch a dispatch path that forgets it — which is
exactly the regression a required key exists to prevent, and exactly the state a
staged rollout would leave in place for a whole release. Nothing is gained by
the looseness: no deployed *control plane* needs to emit a payload without the
field, since step 1 is a single server-side change under the operator's own
control.

What legitimately needs to tolerate absence is the **consumer** side, and only
for a bounded reason: a client may be talking to a control plane that has not
yet deployed step 1. That tolerance belongs in a compatibility decoder path
with its own explicit, named condition, not in the normative schema. The
normative schema stays one thing; the decoder is separately and visibly lenient
while its flag says so.

**Absence and mismatch are not the same failure, and only one of them is ever
allowed a transition period.** A present-but-mismatched `agentId` means a job
correctly signed for one agent was delivered to another: that is exactly what
this decision exists to catch, and it **always fails closed**, unconditionally,
regardless of any flag or rollout step. There is no warn-only mode for a
mismatch, because warning about a caught misdelivery and then executing it
anyway is not a transition period, it is the vulnerability with a log line
next to it. An **absent** `agentId`, by contrast, is a compatibility fact about
which control-plane version a client is talking to, not evidence of anything
adversarial, and step 1's server-first ordering exists precisely so that gap is
temporary and one-directional: it can only be closed by the client refusing to
tolerate it, never reopened by a client accepting a present-but-wrong value.

Concretely, a client-side flag such as `CERTOPS_AGENT_REQUIRE_SIGNED_AGENT_ID`
governs step 3's **compatibility decoder** only, never the normative producer
schema and never mismatch handling. Rows are keyed on the flag's **effective
value in the running process**:

```text
effective false  agentId missing -> compatibility decoder proceeds; agentId
                  present and mismatched -> fails closed always;
                  agent-id-binding-v1 NOT advertised
effective true   agentId missing -> fails closed (named incompatibility error);
                  agentId present and mismatched -> fails closed always;
                  agent-id-binding-v1 advertised
```

**`agent-id-binding-v1` is advertised only once both rows fail closed on the
running client**, which is a function of the flag's **effective value in that
process**, not of the release's compiled-in default. A client shipped with the
default `true` but started with the flag explicitly set to `false` is
absence-tolerant and must not advertise the capability; the reverse holds too,
so an earlier-release client explicitly configured to `true` may advertise it.
Advertisement is computed from the resolved configuration at heartbeat time, not
from a build constant, because the control plane uses it to decide what the
connected agent enforces right now. A client tolerating absence is, by
construction, not yet enforcing the identity check in the one case the
rollout exists to bridge, and advertising the capability while in that state
would tell the control plane the check is live when it is conditionally not.
The **new** Node-free reference clients have no such flag at all: they are new
implementations of a protocol version that already requires
`signed-payload-b64-v1`, so there is no legacy install base of them to keep
compatible, and they validate `agentId` unconditionally from their first
release, advertising the capability immediately.

A new client meeting a control plane that has not completed step 1 fails
closed with a named incompatibility error at heartbeat or claim time, never
silently accepting the field's absence as if step 1 had run: "absence
tolerated" above means the *client's own gate* does not fail on absence, not
that a control plane's failure to sign the field is itself invisible.

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
versioned. It composes the same shared `signed-dispatch-payload` from decision 3
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

**The declared list is exhaustive, and base64 decoding is the trap.** The
obvious way to decode `payloadB64` in a shell script is `base64 -d`, which is
an *undeclared fourth dependency*: it is coreutils on Linux, a different
implementation with different flags on macOS and BusyBox, and its
whitespace/padding tolerance varies, which matters precisely because decision 2
requires canonical-base64 enforcement. The Bash client therefore decodes
through **OpenSSL** (`openssl base64 -d -A`, already a declared prerequisite and
already required for Ed25519 verification), not through a `base64` utility, and
must be binary-safe about it: the decoded payload can contain any byte sequence
including NULs, so it moves through **one byte-preserving stream in the normal
path** (a pipe or a process substitution), never a shell variable, which cannot
hold a NUL and would truncate silently at the first one. "One stream" describes
where the bytes go, not a literal single decode reused for two purposes: the
Ed25519 verify step consumes stdin and reports only a pass/fail verdict on its
exit code, it does not re-emit the bytes it verified, so there is no verified
byte stream available to hand to a JSON parser afterward even if that were
desirable. The implementable sequence is two deterministic decodes of the same
immutable `payloadB64`: the first, piped into the verifier, produces the
verdict; **only if that verdict is pass**, a second decode of the same
`payloadB64`, piped into `jq`, produces the parsed job. Both decodes are pure
functions of the same input and are therefore byte-identical by construction,
not by assumption, and no parsing or action of any kind happens before the
verdict from the first decode is known. A **named file is not
part of the normal path**: an earlier draft of this decision said "a file or a
process substitution", which contradicted this decision's own command-allowlist
test, since creating a file safely requires `mktemp` and `mktemp` is not one of
the four declared commands. If a target platform ever forces a named file (a
verifier build that cannot read stdin, say), the file becomes a **declared**
dependency carrying stated obligations rather than implicit ones: exclusive
creation (`set -C` / `O_EXCL`), a private mode set at creation rather than
afterwards, one cleanup trap covering normal exit and every signal the client
can receive, and a startup sweep for residue left by a crash. Those obligations
are not hypothetical bookkeeping: decision 9's PFX journal exists because the
process that must delete a sensitive file is the process that may die. The same
rule applies to every other
convenience utility a shell author would reach for: if it is not `bash`, `curl`,
`jq` or `openssl`, it is not available, and this is asserted by test rather than
by review (see the command-allowlist test in the acceptance criteria).

**The two clients use two independent Ed25519 implementations, deliberately, and neither may fall back to the other's.** Bash verifies via `openssl pkeyutl -verify -rawin` (OpenSSL 3's `pkeyutl` supports Ed25519 directly; this is the same `openssl` already required for base64 decoding, not an added dependency). PowerShell verifies via a bundled, verification-only
`tokentimer-verify`
binary from a minimal in-repo Go module, because nothing built into Windows can
verify Ed25519: stable .NET exposes no general Ed25519 API, and CNG exposes
curve25519 for ECDH only, not EdDSA. **An earlier draft of this decision said Bash could use "`openssl pkeyutl -verify` or the bundled verifier," which is exactly the ambiguity this correction closes:** if either client could use either implementation, the two clients would not be testing two independent Ed25519 code paths against the same signed test vectors, which is the entire argument for shipping two reference clients instead of one. Bash therefore never bundles or shells out to `tokentimer-verify`, and PowerShell never shells out to `openssl` for the verify step (it may still use OpenSSL-equivalent tooling for other purposes if any exist, but not for Ed25519 verification). The Go binary performs the byte-verification
step **only**: no JSON parsing, no time checks, no dynamic algorithm selection,
no canonicalization. Everything else in the normative order of decision 2 stays
in the script, where it is auditable.

PowerShell 5.1 must hand the decoded payload to the verifier through a
**byte-preserving binary stream**, never the PowerShell text
pipeline or a string conversion, since either can transcode the bytes before Go
ever sees them. **A named file is not part of the normal path here either**,
for the same reason as the Bash side: if a target forces one, it is a declared
dependency carrying the same obligations as decision 8's Bash file exception
(exclusive creation, a private ACL set at creation, one cleanup trap covering
normal exit and every terminating signal PowerShell can receive, and a startup
sweep for crash residue), not a silent alternative with no obligations attached.
Parity tests must prove the wrapper-decoded byte array reaches
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
operator-pinned publisher certificate for tarball distribution.

**Script tamper-detection must happen before the script's own code runs, and a
self-check cannot provide that.** A script that validates its own Authenticode
signature is checking integrity with code an attacker who edited the file has
already had the opportunity to delete: the tampered copy simply does not contain
the check. PowerShell's own execution policy does not close this either, and
Microsoft says so directly — it is
[explicitly not a security boundary](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies),
only a guard against accidental execution, and it is bypassable by any user who
can pass `-ExecutionPolicy Bypass` or pipe the file's text to the interpreter.

The enforcing boundary must therefore sit **outside** the script. One of the
following is required, not optional:

```text
a trusted launcher   a signed installer/bootstrap validates the script's
                     signature and signer identity, and only then invokes it;
                     the operator's entry point is the launcher, not the .ps1

App Control/WDAC     enforced Windows App Control script enforcement, which
                     validates signed scripts at load time inside the runtime
                     itself, before any statement in the file executes
```

App Control script enforcement is the only mechanism here that Microsoft
positions as an actual
[security control for script execution](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/script-enforcement),
and where an operator can deploy a WDAC policy it is the stronger of the two.
The trusted launcher exists because a large fraction of target hosts have no
App Control policy at all, and the client must still have a defined trust story
there.

**(Closes open question 5.) The signed launcher is the documented default;
enforced WDAC is the documented hardened alternative, not a second default.**
The launcher works on an ordinary supported Windows Server installation with
no additional platform configuration, which describes most target hosts;
WDAC is the stronger boundary but is not normally deployed or centrally
manageable on them. The runbook therefore always invokes the trusted launcher
rather than the `.ps1` file directly, and direct `.ps1` invocation is
documented as unsupported, not merely undocumented. The launcher verifies the
script's Authenticode signature, signer identity/thumbprint, architecture,
timestamp, and the configured revocation policy, and only then invokes
PowerShell; the script's own `Get-AuthenticodeSignature` self-check remains
defense in depth only, exactly as stated above. Where an operator has an
enforced WDAC policy already deployed, WDAC becomes the primary boundary for
that host and the launcher may still run ahead of it as defense in depth, but
is not presented to that operator as an additional mandatory layer, since the
runtime-level check already subsumes it. Revocation behavior does not change
by having a default: the default online policy fails closed on an unreachable
CRL/OCSP endpoint, and an air-gapped install requires the signed offline
manifest or cached revocation material, per the revocation-policy text above.
The runbook must never recommend `-ExecutionPolicy Bypass` as a workaround for
either path, since that flag is precisely the non-boundary decision 8 already
rejects.

Acceptance, in addition to the criteria stated earlier in this decision: a
fresh-host installation that follows only the default (launcher) runbook
succeeds with no manual WDAC configuration; a modified script is rejected
before any script code executes under **both** supported trust
configurations, tested separately (the launcher refuses to invoke an edited
script; an enforced WDAC policy independently refuses to load it), so a test
proving only the launcher's own check fires is not sufficient; a wrong
signer, an unsigned script, a revoked signer, and a wrong-architecture binary
each fail closed under the default path; the runbook text contains no
`-ExecutionPolicy Bypass` recommendation anywhere, asserted by a guard over
the shipped documentation rather than left to review.

The script's own self-check is retained as **defense in depth** — it catches an
honest deployment mistake such as an unsigned or wrong-architecture copy, and it
costs nothing — but it is documented as defense in depth and never as the
boundary. The self-check requires `Get-AuthenticodeSignature` to return `Valid`
and pins signer identity as subject plus a set of accepted thumbprints so
certificate renewal does not brick installed clients. RFC 3161 timestamping
applies, and hashes are mapped per version and architecture. Revocation behavior
is set by **installation policy, not at runtime**: under the default online
policy an unreachable CRL/OCSP endpoint fails closed, and an air-gapped host must
be deployed with the signed offline manifest or cached revocation material. A
runtime override would be `--insecure` by another name. Published hashes are
version/integrity checks, never the trust anchor. Reproducibility applies to the
unsigned build, so hashes and provenance are published for both unsigned and
signed artifacts, and the unsigned binary never ships in a production bundle.

**Signed `.ps1` files are constrained to ASCII-compatible UTF-8.** Authenticode
hashing of a PowerShell script is sensitive to how the interpreter reads the
file's bytes, and Microsoft documents signed scripts failing with a
[hash mismatch across locales](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/signed-powershell-script-fails-hash-mismatch)
when a UTF-8 script contains non-ASCII characters and the host's ANSI code page
differs from the signing host's. A client whose signature validates in the build
locale and fails on a French or Japanese Windows Server is worse than unsigned:
it fails closed, correctly, for a reason that looks like an attack. The rule is
therefore that shipped signed scripts contain **no non-ASCII bytes** — no
smart quotes, no accented characters in comments, no box-drawing in help text —
enforced by a CI guard rather than by review. Where non-ASCII content is
genuinely required, the alternative is an explicitly documented signed-script
encoding exception (UTF-8 with BOM, or UTF-16LE, whichever the signing toolchain
and every supported host agree on), chosen deliberately and tested, never
arrived at by accident. Either way the **released artifact** is validated on
PowerShell 5.1 under at least two different system locales, because this failure
is invisible in a single-locale build pipeline.

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

**Three of these five strings are additionally gated at advertisement time,
not only at claim time.** `windows-cert-store-v1`, `iis-binding-v1`, and
`trust-anchor-deploy-v1` depend on real-host evidence (real IIS renewal/rollback, real
Windows-store and Linux trust-store install/removal) that release planning treats as a hard tag gate. "The code ships with the
capability undeclared until that evidence exists" is a release policy, and a
policy with no mechanism is a policy an agent build can violate by simply
having the underlying code and declaring the string.

**Corrected 2026-08-02: the mechanism is a build-time manifest, not a
runtime environment variable.** An earlier version of this decision specified
`CERTOPS_AGENT_QUALIFIED_CAPABILITIES` as an environment variable, which
cannot be release-controlled: whoever configures the agent's runtime
environment - an operator, a Helm values file, a Compose override - is the
one setting it, which is the exact actor this gate exists to take the
decision away from. It also created a qualification loop with no fixed
point: the three capabilities can only be marked qualified after a real-host
test proves them, but a test needs a build that already advertises them to
be tested at all, so "enable after evidence" and "test before enabling" each
presuppose the other.

The fix breaks the loop by moving the decision from runtime to build time and
making the tested artifact the shipped artifact, never a rebuild of it.
A **qualified-capabilities manifest** (a small JSON file, `qualified-capabilities.json`,
committed to the release branch and embedded into the agent binary at build
time via the existing build pipeline, the same way a version string is
embedded) names the capability strings a specific release **candidate**
build claims to qualify. The release process is then linear rather than
circular: (1) cut a release-candidate build with a candidate manifest -
which may name all three capabilities, some, or none, and is a normal code
review decision, not evidence of anything yet; (2) run the real-host tests
this record's exit criteria require against **that exact build artifact**,
identified by its build hash, not against a rebuild or a "close enough"
successor; (3) if every targeted capability's test passes, **promote that
same artifact, unchanged, as the tagged release** - no recompilation, no
manifest edit, no "now enable it" step, because the artifact being promoted
is definitionally the one that was tested; (4) if a targeted capability's
test fails, that capability is removed from the manifest and step (1) repeats
with a new build, which is a different artifact under a different candidate
hash, not the failed one with a flag flipped. A capability absent from the
embedded manifest is never advertised, and therefore never claimed,
regardless of whether the binary that could serve it exists; the underlying
code stays testable in CI at all times, since CI builds its own manifest
locally and is not bound by the release manifest. This is the general
promotion discipline the CI-guard and exact-head-CI rules elsewhere in this
program already use for other artifacts (the merge commit that was tested is
the commit that ships): applied here to a manifest instead of a git SHA,
because a runtime flag has no equivalent immutability.

Acceptance: a release-candidate build with an empty manifest run against a
real Windows/IIS host still completes ACL enforcement, machine-store deploy,
and IIS binding locally, but never advertises the three gated capabilities
and is therefore never offered a job requiring them, proving the gate is
about advertisement and not about disabling the feature; a build with a
populated manifest advertises exactly the capabilities named in it and no
others; an unrecognized string in the manifest is rejected at build time
rather than silently ignored; the promoted release artifact's build hash is
recorded in the release record and equals the exact hash that was tested,
asserted by CI rather than by process discipline alone; there is no code
path, environment variable, or runtime flag anywhere in the agent that can
change which capabilities a built binary advertises after it is built.

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

**Corrected 2026-08-02.** The first version of this decision misattributed the
unsafe read to `handleSignedJob`. `handleSignedJob` already verifies first: it
calls `verifyJobEnvelope`/`verifyJobSignature` before touching any field, and
carries a comment saying so. The actual read is one frame up, in the caller.

`handleClaimedJob` (`packages/agent/src/index.js`) derives `signedAttemptId`
from the received object's `job.attemptId`/`job.claimId` — preferring
`attemptId`, falling back to `claimId`, then to a local value — **before**
`handleSignedJob`, and therefore `verifyJobSignature`, is ever called. That
derived value then flows into every result `handleSignedJob` reports for that
job, including a signature-verdict failure. This is the identical unsafe
pattern decision 2 forbids, in the v1 agent that is already deployed, and it is
also the reason the v2 envelope cannot simply be added beside the existing
code: a v2 envelope carries no outer `jobId` (decision 1), so the caller's own
`hasReportableJobId(job?.jobId)` guard — evaluated before either identifier
read — would mark every v2 job `skipped` before verification ever ran.

Decision: this is fixed as part of the envelope work, not deferred as
follow-up, and the fix is a boundary move, not a reorder inside
`handleSignedJob`. `handleClaimedJob` derives no identifier — not `jobId`, not
`attemptId`, not `claimId` — from the wire object before a verdict is
available. Any value it needs pre-gate (for example to correlate a local log
line) is a local-only value that is never passed into a client call and never
appears in a submitted result. `jobId` and `attemptId` for a submitted result
are derived from the post-gate, verified payload fields, for both wire shapes.
Shipping a hardened reference client next to a softer production agent
implementing the same protocol would leave the weaker implementation as the
real security posture.

Acceptance criterion, restated precisely because the first version's own
criterion ("no field is read from the job object before verification") was
true of `handleSignedJob` and false of its caller, which is exactly how the
misattribution survived review: **no identifier is read from the wire object
by `handleClaimedJob` or `handleSignedJob` before a signature verdict is
available, for either wire shape.** Regression tests cover both shapes and
assert that no result is submitted on signature failure, that neither function
reads a job-object field before verification, and that a semantic rejection is
only ever built from post-gate identifiers.

### 17. Declared capabilities get an epoch; gated dispatch requires a fresh one

**Added 2026-08-02, closing an audit finding about capability-gated dispatch
correctness.** Verified against the
pushed tree, not inferred: `certops_agents.declared_capabilities` is one
`JSONB NOT NULL DEFAULT '[]'::jsonb` column (migration 36) with no epoch, no
`capabilities_updated_at`, and no version counter anywhere in the repository.
Heartbeat treats the field as three-valued — absent preserves the stored set,
an explicit `[]` clears it, a non-empty array replaces it — and replace-never-
union is correct and stays. The absent arm is the hole: an agent downgraded to
a build that predates the field never sends it, and the stored set then never
changes, for as long as that agent runs. Registration cannot correct it
(`ON CONFLICT ... DO NOTHING`), so heartbeat is the only path that can ever
change a live agent's declared capabilities, and it is also the path that can
fail to. Claim time performs no freshness check at all: `claimJobs` reads
`declared_capabilities` straight off the row with no `last_seen_at` predicate,
no recency interval, and no epoch, so a capability-gated job can be offered on
the strength of an assertion of unbounded age.

This matters specifically for dispatch, because dispatch is dual-format, not
dual-write: a stale `signed-payload-b64-v1` makes `useV2Envelope` true for an
agent that can no longer parse a v2 envelope, and every job it claims then
fails. The same hole applies to `evidence-claim-binding-v1` for `issue` jobs,
reaching the exact stuck-in-`provisioning` failure migration 36 exists to
prevent.

**Decision: a capability epoch, not a version-based inference.** Two
candidates were considered. (a) Treat an omitted `declaredCapabilities` as an
implicit clear once the agent's protocol or agent version is known to support
sending the field. Rejected: it breaks any genuinely old build that has not
been touched since before the field existed, turning a correctness fix into a
compatibility break for an unrelated population. (b) **Adopted.** Add
`certops_agents.capabilities_updated_at` (`TIMESTAMPTZ`) and a named freshness
bound, `CERTOPS_CAPABILITY_FRESHNESS_MS`.

**Corrected 2026-08-02: the bound's reasoning was wrong on both the
multiplier and the lease claim, and is replaced rather than patched.** The
original text called 900000ms (15 minutes) "three times the 30-second
heartbeat interval"; 15 minutes is thirty 30-second intervals, not three, an
arithmetic error that happened to still name a plausible-sounding number. It
also claimed the bound was "equal to the default lease TTL so a gated job's
own lease cannot outlive the assertion that made it eligible" - that claim is
false regardless of which multiplier was intended: an assertion admitted at
age just under the freshness bound, paired with a lease granted for a full
additional lease TTL, produces a lease that can outlive the assertion by
nearly one full freshness-bound duration, not zero. The two quantities compose
additively; no choice of bound alone makes one dominate the other, and this
decision does not claim to bound lease/assertion skew at all.

**The bound is instead derived from the existing agent-liveness SLO, not
invented fresh.** `certops_agents`'s existing offline threshold,
`CERTOPS_AGENT_OFFLINE_AFTER_MS` (default 600000ms, 10 minutes -
`agentRegistry.js`), is the number this program already uses to answer "is
this agent's last-reported state recent enough to act on." Capability
freshness reuses that number rather than deriving a second, independently
justified one: `CERTOPS_CAPABILITY_FRESHNESS_MS` defaults to **600000**
(10 minutes), the same value, on the reasoning that an agent whose capability
assertion is stale by more than the threshold that would already mark it
`livenessState: "stale"` has no business being offered a capability-gated
job, and a bound shorter than the liveness threshold would gate on
capabilities before gating on reachability, which is backwards. The two
remain separate signals with separate columns (decision text below is
unchanged on this point): liveness asks whether the agent is reachable at
all, freshness asks whether its last capability assertion is recent enough to
trust for gating, and claim time advances `last_seen_at` independently of
heartbeat, so they can and do diverge. `claimJobs`'s gated-selection predicate
requires
`now() - capabilities_updated_at <= freshness bound` before a job requiring a
gated capability is offered; ungated jobs are unaffected. This fails closed on
exactly the gated path: a stale assertion degrades to "no v2 job offered, or no
gated job offered", never to "job offered on a guess".

A capability set change on heartbeat also gets an audit event
(`CERTOPS_AGENT_CAPABILITIES_CHANGED`, mirroring the existing
`CERTOPS_AGENT_REGISTERED` audit for the initial declaration), so a downgrade
is reconstructable after the fact rather than leaving no trail, which today's
`recordHeartbeat` does not emit.

**Column initialization: set at registration, no unsafe backfill.**
`capabilities_updated_at` is written by `INSERT` at registration time
(`registerAgent`, timestamped alongside the row's initial
`declared_capabilities`, if any is sent at registration; the field's own
absence-tolerant semantics at registration are unchanged by this decision),
and updated thereafter by the heartbeat write path described above. It is
**not** backfilled for agent rows that already exist at migration time: a
migration cannot know when an existing row's currently-stored capability set
was actually asserted, so writing `now()` at migration time would manufacture
a false freshness signal for a set that could in truth be arbitrarily stale -
precisely the failure this decision exists to close, reintroduced at the
column's birth. Existing rows instead migrate with
`capabilities_updated_at IS NULL`, and the gated-selection predicate treats
`NULL` as maximally stale (`NULL` fails `now() - capabilities_updated_at <=
freshness bound` under standard NULL-comparison semantics, and the query is
written so a `NULL` cannot silently pass a `NOT (... > bound)` inversion
either): a pre-existing agent is offered no gated job until its **next
heartbeat that reports capabilities** sets the column for the first time,
which is the earliest point at which freshness is actually knowable for that
row. This is a one-time, self-healing transition cost - not a persistent
gap - paid once per already-registered agent, and it is the correct price
for not fabricating a timestamp the system cannot back up.

Acceptance criteria: capability updates replace rather than union, asserted
against a real database, not a mocked pool; the freshness bound is a named
constant with a test on both sides of it; a downgraded agent that stops
advertising `signed-payload-b64-v1` receives a v1 envelope or no job, never a
v2 envelope, tested end to end from heartbeat through claim; the same for
`evidence-claim-binding-v1` against an `issue` job; a capability-set change on
heartbeat writes the new audit event; the existing test asserting that an
omitted `declaredCapabilities` preserves the stored set is rewritten, not
deleted, since the ungated preserve behavior is still correct and only the
gated selection path changes; a migrated pre-existing row with
`capabilities_updated_at IS NULL` is never offered a gated job, tested
directly against a real database rather than inferred from the freshness-bound
test alone; that same row is offered a gated job normally once a heartbeat
sets the column.

### 18. Superseded certificate retention is a named, bounded window, not an open-ended one

**Closes open question 8.** Wave 2b's cleanup path needs a stated answer to
"how long does the certificate a rotation just replaced stay in the machine
store and CNG key container after the new one is bound", because an unbounded
answer leaves stale key material in the store indefinitely and an
unconditional immediate-delete answer removes an operator's only rollback
target the moment it might be needed. It also needs a **restart-safe** answer,
because the agent process that observes cutover and the agent process that
later runs cleanup are not guaranteed to be the same process: a service
restart, an upgrade, or a crash can land between the two, and a design whose
only record of "this predecessor is now eligible for cleanup" lives in
in-memory state loses that record exactly when it matters.

Decision: **superseded IIS certificate material is retained for up to 168
hours (7 days) after the replacement binding passes its own local TLS
verification**, configured as `windows.supersededRetentionHours`, agent-local
policy per ADR-0002 rather than a control-plane value. "Up to" is precise
wording, not a hedge: the earlier-of-two-clocks rule below means the actual
retained duration is frequently shorter than 168 hours, and a reader who
takes "retained for 168 hours" as an unconditional duration would be
describing a different, wrong decision. The first release permits a
configured range of **24-720 hours**; a value of zero is rejected at
configuration-load time, not silently clamped, because zero collapses
retention to unconditional immediate deletion, which decision 9's own
no-secure-erasure caveat already establishes as an operation this record does
not promise is safe.

**Cleanup eligibility is the earlier of two clocks, not the later:**

```text
verifiedCutoverAt + retentionWindow
old certificate's notAfter + a fixed 300-second clock-skew grace
```

**The grace is named, not "small and fixed" left unquantified: 300 seconds
(5 minutes), reusing the program's existing clock-skew tolerance rather than
inventing a second one.** `apps/api/services/certops/jobSigning.js`'s
`DEFAULT_NONCE_TTL_SECONDS` and `leaseTiming.js`'s `NONCE_TTL_GRACE_SECONDS`
are both already `300`, and section 7.4 of the architecture plan already
calls for "one documented clock-skew tolerance constant," not a family of
similar-but-different ones invented per feature. The second clock exists
because a certificate already past its own `notAfter` provides no rollback
value regardless of how recently it was replaced; holding expired material
for a full week past cutover for no benefit is exactly the "indefinite stale
key material" outcome this decision exists to close.

**Deletion requires every one of the following, not any one of them:**

- TokenTimer's own ownership record for the old certificate was written at the
  time this agent installed it (decision 9's install-time ownership
  recording; an agent must never delete material it did not install, per
  Wave 2b's ownership-aware retention rule).
- No IIS or `http.sys` binding, on this host, still references the old
  thumbprint.
- No active job or rollback journal entry (the same journal decision 9
  requires for PFX staging) still references it.
- No other certificate or ownership record still references the same CNG key
  container, so a key shared across more than one binding is never removed
  out from under a survivor.
- The replacement certificate remains correctly bound and independently
  passes a local TLS handshake at the moment cleanup runs, not only at the
  moment of cutover, so a rebind that silently regressed between cutover and
  the cleanup sweep blocks its own predecessor's removal instead of deleting
  the last-known-good material.
- The cleanup deadline (the earlier of the two clocks above) has actually
  elapsed.

Any one condition failing means cleanup does not run for that certificate in
that sweep; the sweep retries on its next scheduled pass rather than treating
a blocked cleanup as an error requiring operator action, since a still-bound
predecessor is the safe failure mode, not the confidentiality-costing one. A
sweep that defers cleanup writes a durable, named deferral reason
(`ownership_unrecorded`, `binding_still_present`, `active_reference_present`,
`shared_key_container`, `replacement_handshake_failed`, or
`deadline_not_reached`) against the ledger row described below, and exposes a
count of currently-deferred rows per reason as a metric, so a certificate
stuck in deferral forever is a visible, alertable condition rather than a
silent infinite retry with no operator-facing signal.

**A restart-safe, agent-local superseded-material ledger is the mechanism,
not an implied consequence of "the agent remembers."** Each superseded
certificate gets one persisted ledger row, written in the same operation that
completes cutover verification, carrying:

```text
oldThumbprint, replacementThumbprint      identify the pair this row governs
cngKeyContainerId                          the old certificate's CNG key
                                            container identifier, so the
                                            shared-container check (above)
                                            is a lookup, not a live store scan
verifiedCutoverAt                          set once, at successful cutover
                                            verification, never rewritten
oldNotAfter                                copied from the old certificate at
                                            ledger-write time, so eligibility
                                            never depends on the old
                                            certificate still being readable
                                            from the store at cleanup time
ownershipProvenance                        tokentimer_installed / preexisting,
                                            copied from decision 9's
                                            install-time ownership record
jobOrRollbackJournalRefs                   zero or more references into
                                            decision 9's PFX/rollback journal,
                                            each individually active or
                                            closed (below)
lifecycleState                             pending_retention / eligible /
                                            deferred / removed, a durable
                                            state machine, not a computed
                                            value re-derived from scratch
                                            every sweep
```

The ledger is **agent-created state** under decision 10's ACL matrix: written
with the same restrictive, protected DACL as the config directory, the
credential file, and the PFX staging directory, so a row governing which
certificate is safe to delete carries the same tamper-resistance as the
credential material decision 10 already protects. Writes are **atomic**
(sibling-temp-file-plus-rename, the same pattern decision 10's directory-fsync
discussion already establishes for this agent), because a torn or
partially-written ledger row is worse than a missing one: a missing row fails
closed (nothing is known to be eligible, nothing is deleted), while a torn row
could parse as a plausible-looking but wrong value.

**Rollback-journal references are explicitly active or closed, not merely
present or absent.** A reference recorded while a rollback (decision 13's
IIS rebind-and-verify path) is in flight is **active**; once that rollback
either completes or is abandoned by its own protocol, the reference is
explicitly marked **closed**, in the same write that closes the rollback
journal entry itself. Deletion's "no active job or rollback journal entry"
condition above checks for **active** references only: a closed historical
reference is provenance, kept for evidence and audit, and must not block
cleanup forever, which an implementation that treated "any reference, ever"
as blocking would do by construction. This distinction is why the ledger
schema names the field `jobOrRollbackJournalRefs` with a per-reference state
rather than a boolean "has been referenced."

**The ledger is swept at agent startup and on the same periodic schedule as
Wave 2b's reconciliation sweep, not only periodically.** A startup sweep
exists for the same reason decision 9's PFX startup sweep exists: a crash
between writing the ledger row and completing a later state transition must
be resumed on next start rather than left stuck, and a row's `lifecycleState`
is exactly what lets the startup sweep resume correctly, since it re-reads
the durable state rather than trying to reconstruct "was this mid-cleanup
when we died" from partial filesystem or store evidence. **This is why a
process restart between cutover and the cleanup deadline is safe by
construction rather than by accident:** every fact cleanup eligibility depends
on (`verifiedCutoverAt`, `oldNotAfter`, ownership, journal-reference state) is
in the ledger row, not in the process that computed it, so the row surviving
the restart is sufficient for a later sweep, in a different process
lifetime, to reach the identical cleanup decision.

This is additive to, not a replacement for, decision 9's PFX journal-and-sweep
model: the PFX staging sweep runs at agent startup and clears transient
staging-directory residue before any claim is accepted; this retention window
and its ledger govern the separately-lived superseded *store* certificate and
its CNG key container after a completed, verified rotation, on the schedule
Wave 2b's reconciliation sweep already runs.

Acceptance: a rotation followed immediately by a query finds the superseded
certificate and key container still present and still passing the ownership
check, with a `pending_retention` ledger row recording `verifiedCutoverAt`;
the same query after the configured window (or after the superseded
certificate's own `notAfter` plus the named 300-second grace, whichever is
sooner, simulated via an injectable clock in tests rather than a real
seven-day wait) finds both removed and the ledger row `removed`; a
certificate the agent did not install is never removed by this path
regardless of age, tested by seeding a `preexisting`-equivalent record with
no agent-owned installation row; a CNG key container still referenced by a
second, distinct certificate or ownership record is never removed while that
reference exists; a deliberately broken rebind (replacement fails its local
handshake at sweep time) blocks cleanup of the predecessor, is retried on the
next sweep rather than failing the sweep outright, and writes the
`replacement_handshake_failed` deferral reason; an active rollback-journal
reference blocks cleanup while a **closed** one for the same certificate does
not; a configuration value of `0` is rejected at load with a named error, and
values outside `24-720` are rejected the same way, not clamped into range,
with `24`, `168`, and `720` accepted and `0`, `23`, and `721` rejected; a
simulated process kill between writing the ledger row at cutover and the
cleanup sweep running, followed by a restart, still reaches the correct
cleanup decision from the persisted row alone; a deferred-forever case (an
ownership check that never resolves) exposes a non-zero deferred-count metric
under its named reason rather than retrying invisibly with no operator signal.

### 19. Key-memory handling is documented as a residual-risk boundary, not a locked-memory guarantee

**Closes open question 9.** certctl's `keymem.go` locks agent-side private-key
memory (`VirtualLock`/an mlock-equivalent) against swap-to-disk exposure.
Whether this agent needs the equivalent control was left open rather than
silently unaddressed.

Decision: **this record does not require `mlock`/`VirtualLock`, and the agent
must not claim locked or non-pageable memory for key material anywhere it
does not actually hold it.** Locking a single Node `Buffer` would be false
assurance rather than a real control: V8, OpenSSL, the JSON/PEM parsing path,
and underlying system calls can all produce additional copies of the same key
bytes outside that one locked allocation, so a lock on one buffer protects one
buffer, not the key. Adding a native locking dependency to buy a guarantee the
rest of the path does not honor is a cost with no matching benefit, and an
advertised "keys are locked in memory" claim that is actually "one buffer,
sometimes" is worse than no claim, for the same reason decision 9 refuses a
secure-erasure claim it cannot back.

The controls this record requires instead, all already true or already
decided elsewhere in this ADR and restated here as one checked set rather than
scattered facts:

- CNG-native keys (decision 9's default path) remain non-exportable OS-store
  handles and never become raw process buffers at all; there is no allocation
  to protect because the private key never enters process memory in the first
  place.
- Linux/filesystem key bytes are held as `Buffer`, never as a JavaScript
  string, since a string is immutable and cannot be zeroized; this is
  existing practice, restated as a requirement rather than a convention.
- Any agent-owned key buffer that does exist has the narrowest practical
  lifetime and is zeroized in a `finally` block covering both the success
  path and every failure path, not only the success path.
- No unnecessary private-key export from a `KeyObject` or a CNG handle; export
  happens only where a consuming API leaves no alternative, per decision 9's
  PFX-import cases.
- **Core dumps are disabled for the production agent Windows Service and its
  Linux daemon equivalent, by a named, platform-specific mechanism, not by an
  unspecified "disabled" claim**, since a core dump is an alternate, unlocked
  copy of process memory that no in-process buffer discipline can prevent:
  - **Windows.** The Windows Error Reporting `LocalDumps` key for the agent's
    service executable is either absent or configured with `DumpType=0`
    (no dump), under
    `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\<agent-service-exe-name>`;
    the installer sets this explicitly rather than relying on the
    machine-wide default, since a machine-wide default is exactly the kind
    of ambient configuration decision 10 already refuses to depend on
    elsewhere. Verified by reading that registry value back after install and
    asserting it is either absent or `0`, not by triggering an actual crash
    in CI.
  - **Linux.** The systemd unit sets `LimitCORE=0` (equivalently, the
    process's `RLIMIT_CORE` soft and hard limits are both `0` before the
    Node process starts handling key material), which is authoritative
    regardless of the distribution's `core_pattern`/`ulimit -c` defaults,
    since decision 10's Windows ACL discussion already establishes the
    principle that an ambient OS default is not a control this agent may
    rely on silently. Verified by reading the running service's
    `/proc/<pid>/limits` `Max core file size` row and asserting both the
    soft and hard limits are `0`, not by inspecting the unit file alone,
    since a unit file can be present and still not be the one actually
    governing the running process.
- Operator runbooks recommend encrypted swap/pagefile, or disabling swap
  entirely where local policy requires it, as the actual mitigation for the
  risk `mlock` would otherwise address, stated as a documented residual-risk
  recommendation rather than left unmentioned.
- Keys, passwords, and PFX bytes are excluded from logs, error messages,
  evidence records, diagnostics output, and child-process arguments, which
  this record already requires elsewhere (decision 8's credential handling,
  decision 9's in-memory PFX password) and restates here as part of the same
  key-memory posture rather than a separate concern.
- PFX fallback keeps decision 9's journal, protected staging directory,
  startup sweep, and bounded-exposure evidence unchanged; this decision adds
  no new obligation there and removes none.
- Where a host's policy genuinely requires non-pageable key memory as a hard
  requirement, the answer is a hardware- or OS-backed non-exportable key
  provider (CNG, an HSM, a TPM-backed key, PKCS#11), not `agent-local`
  filesystem custody with a partial software lock bolted on. That policy
  requirement is a reason to choose a different custody mode entirely, not a
  reason to add `mlock` to the filesystem path.

A future locked-memory implementation is not ruled out, but must ship as its
own explicitly versioned capability, must protect the complete allocation
path rather than one buffer, must fail closed rather than silently degrade
where the underlying platform call is unavailable, and must be provable (a
test asserting no unlocked copy of the key bytes exists at any point in the
path) before it is advertised as a guarantee. A best-effort lock that the
agent cannot prove held is not advertised as a security property at all.

Acceptance: the CNG-native flow produces no raw key file and no export call
anywhere in its path, asserted by test; the Linux key-generation path never
assigns key bytes to a JavaScript string at any point, asserted by test; every
agent-owned key buffer is zeroized on both its success path and every failure
path it has, asserted by test rather than by inspection; the production
service's deployed configuration disables core dumps, verified on Windows by
reading back the `LocalDumps` registry value for the agent's service
executable (absent or `DumpType=0`) and on Linux by reading the running
service's `/proc/<pid>/limits` `Max core file size` row (both soft and hard
limits `0`), neither asserted from the installer/unit-file source alone; a
canary key/password value seeded at the start of a key-handling test run does
not appear in process arguments, environment, logs, evidence, or crash
diagnostics captured during that run; the shipped documentation states the
residual swap/pagefile risk plainly rather than implying a stronger guarantee
than this decision makes.

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
  envelope v2 and the decision-16 agent fix (inseparable, since the fix is a
  precondition for a v2 job to be claimable at all), **then, as its own later
  step, mandatory signed `agentId` behind the staged flag** (decision 3's
  four-step server-first rollout), then the Node-free client rewrite. Envelope
  v2 does **not** ship together with mandatory `agentId`: these are deliberately
  separate changes precisely because
  a schema's `required` list and its emitting code must flip in the same
  commit, which is a different commit than the one that makes v2 dispatch work
  at all. An earlier version of this consequence said "together with", which
  read as one atomic change and contradicted that split. The Windows platform work of
  decisions 9-13 is **independent of the reference client** and does not wait for
  the envelope; coupling them would delay a shipped-behavior security correction
  behind a protocol rewrite for no reason.
- A shared contract-foundation change owns: the `signed-dispatch-payload`
  definition, the v1 and v2 wire-wrapper schemas, and the two per-action
  schemas, the new trust-job schema file, the
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

