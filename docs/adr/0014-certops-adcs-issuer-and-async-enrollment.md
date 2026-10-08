# ADR-0014: Microsoft AD CS issuer and asynchronous enrollment lifecycle

## Status

**Accepted (2026-10-08).** No production release may ship the `adcs` issuer
kind before every case in "Release gate" has passing tests and real-host
evidence.

History: proposed on 2026-10-08 with the architecture approved for a Windows
real-host proof of concept, then amended the same day with its findings and
accepted after review of the amendment. The findings changed decisions 5 to
10: the template is bound at submit and checked on the issued certificate
instead of signed into the CSR; dispositions come from the CA-signed CMC
response plus the exit
HRESULT; the CA's `InterfaceFlags` are checked; and reconciliation without
operator help is limited to issued certificates unless an operator grants
the CA Read right. Follow-up checks the same day replaced the pinned CA
certificate thumbprint with a pinned CA public key (a CA certificate renewal
changes the thumbprint but not the key), mapped submit-time permission and
template-availability denials, qualified EC keys on schema version 4
templates, and made a submit that never reached the CA retryable. Writing
the wire contracts then added the `requested` and `refused` enrollment
states, named the remaining error codes and rejection reasons, and aligned
the evidence type names with the existing convention.

## Context

The Windows agent already issues and renews certificates for IIS without
the private key ever leaving the machine (ADR-0012 decision 9): `certreq
-new` creates a non-exportable CNG key in the machine store and writes a
PKCS#10 CSR, an ACME client gets that CSR signed, and `certreq -accept`
binds the signed certificate to the same key before the IIS binding is
rewritten and verified (decision 13).

Many Windows estates do not use ACME for internal names. They run Microsoft
Active Directory Certificate Services (AD CS) and expect servers to enroll
against an enterprise CA with a certificate template. Native autoenrollment
already covers part of this for domain-joined Windows hosts, but it gives no
central inventory, approvals, evidence, multi-binding handling, or one
control plane alongside ACME. Today an operator can only bridge AD CS by
hand through the public CSR workflow, or by putting an ACME gateway in front
of AD CS.

Three properties make AD CS different from the ACME path and drive most of
this record:

- **Issuance can be asynchronous.** A template can require CA-manager
  approval. `certreq -submit` then returns a RequestId and a pending
  disposition, and the certificate may arrive hours or days later. The
  current job model assumes one job runs to a terminal result.
- **Templates and CA settings can be dangerous.** Misconfigured templates
  and CA flags are a well-documented privilege-escalation surface in AD CS
  (enrollee-supplied subjects with authentication EKUs, Any Purpose EKUs,
  enrollment-agent EKUs, schema version 1 application-policy injection, and
  the CA-wide `EDITF_ATTRIBUTESUBJECTALTNAME2` flag). An agent that enrolls
  on any template it is told to would turn TokenTimer into a delivery
  mechanism for those misconfigurations.
- **`certreq -retrieve` does not prove the certificate belongs to this
  request.** It can return certificates that were never part of the pending
  request, including expired or revoked ones. What the CA hands back must be
  validated before anything is installed.

## Decision

### 1. Issuer kinds are explicit, and `adcs` is a Core issuer kind

Jobs gain an optional `issuer` object. `issuer.kind` is `acme` or `adcs`.
A job without `issuer` is an `acme` job and keeps using `caEndpoint`,
`acmeKind` and `commandRef` exactly as today, so existing renewal profiles
and agents are unaffected.

For `adcs`, the issuer configuration names:

- `caConfig`: the CA configuration string `host\CA Name`. Host is a DNS name
  matching the existing hostname pattern; the CA name is limited to
  `[A-Za-z0-9 ._()-]{1,64}`.
- `template`: the template common name (not its display name),
  `[A-Za-z0-9_.-]{1,64}`.
- `transport`: `dcom`. No other value is accepted by Core in this record.

The control plane holds a pluggable issuer-kind registry. Core registers
`acme` and `adcs`, and an unknown kind fails closed when a profile or job is
created. Core allows any number of `adcs` issuer configurations in a
workspace; there is no count limit. Downstream editions may register
additional transports or governance on top of the registry, but they cannot
weaken any rule in this record.

AD CS needs no stored credentials in this record: the agent authenticates
to the CA as its own machine identity (decision 8). The control plane
therefore never stores CA credentials for `adcs`.

### 2. Enrollment is its own lifecycle; jobs are execution attempts

A new `certificate_enrollments` table is the durable record of one issuance
attempt for one certificate: one key, one CSR, at most one CA RequestId.
Jobs reference it by `enrollmentId` and are execution attempts against it.
This keeps both state machines monotonic:

- A job that submits a request and must then wait for the CA ends in a new
  **terminal** job status, `awaiting_issuer`. It is never reopened.
- Every later step (retrieve, deferred validation, install recovery) is a
  new continuation job with the agent-facing action `continue-enrollment`,
  bound to the same agent (one job binds one agent, ADR-0002).
- The enrollment state, not the job status, says where issuance stands.

Enrollment states:

```
requested -> prepared
prepared -> submitting
submitting -> pending_issuance | issued | denied | submission_uncertain
submission_uncertain -> pending_issuance | issued | abandoned
pending_issuance -> issued | denied | expired | cancelled
issued -> validated | rejected_invalid | validation_deferred
validation_deferred -> validated | rejected_invalid | validation_expired
validated -> installing
installing -> installed | install_failed
```

`requested` is the state the control plane creates the enrollment in,
before the agent has generated a key. Any state before `installing` can
also move to `refused` when the agent declines to continue: an agent-local
rule no longer matches (decision 4), or a template or CA check fails
(decision 5). The key, if one exists, is freed.

Terminal enrollment states are `refused`, `denied`, `abandoned`, `expired`,
`cancelled`, `rejected_invalid`, `validation_expired`, `installed` and
`install_failed`. Transitions are forward-only; a late or replayed agent
report never moves an enrollment backwards.

These states are the control plane's record. The agent journal (decision
10) tracks execution substates within them, and exactly one journal move
goes backwards: after a submit the transport proves never executed
(decision 9), the journal returns from `submitting` to `prepared`, meaning
"key ready, nothing sent". The control-plane enrollment stays in
`submitting` with the retryable error `ADCS_CA_UNREACHABLE` until a later
continuation's submit resolves it. No other journal move goes backwards,
and tests assert the two views separately.

The control plane allows at most one active continuation per enrollment.
Continuations are scheduled at the snapshot's `pollInterval` (default 15
minutes) while `pending_issuance`, and the enrollment moves to `expired` at
the snapshot's `pendingTimeout` (default 14 days). Cancelling an enrollment
dispatches a final continuation that frees the key. Downstream metering
should count one issuance per `enrollmentId`, never per continuation.

`awaiting_issuer` is generic: future asynchronous issuers reuse the same
enrollment model rather than inventing their own.

### 3. The issuer configuration is frozen into a signed enrollment snapshot

When an enrollment is created, the control plane resolves the renewal
profile and issuer configuration into an immutable snapshot and stores its
exact bytes on the enrollment row. Every job for that enrollment carries:

- `enrollment.enrollmentId`
- `enrollment.attempt`: a monotonically increasing integer
- `enrollment.snapshotB64`: base64 of the stored snapshot bytes
- `enrollment.snapshotSha256`: SHA-256 hex of those bytes

These fields are inside the signed payload. The agent hashes the decoded
bytes itself rather than re-canonicalizing JSON, for the same reason the v2
envelope signs exact bytes (ADR-0012 decision 1).

The snapshot contains `issuerId`, `issuerVersion`, `kind`, `caConfig`,
`caKeySha256` (SHA-256 of the CA certificate's SubjectPublicKeyInfo, pinned
when the issuer is validated; see decision 6), `template`,
`transport`, `authorizedDnsNames`, `keyAlgorithm`, `keySize` (RSA bits, or
256/384 for the EC curve, matching the existing job fields), `policyVersion`,
`pollInterval`, `pendingTimeout`, `minimumRemainingValidity` and
`requireLaterNotAfter`.

The agent records `snapshotSha256` when the enrollment reaches `prepared`
and rejects any continuation carrying a different hash with the rejection
reason `enrollment_snapshot_mismatch`. Agent-local policy is still
re-evaluated on every continuation: if local policy has become more
restrictive, the enrollment is `refused` and its key is freed. Editing an issuer or profile affects
only new enrollments; the dashboard lists pending enrollments that still use
an older issuer version and offers cancel and re-enroll. A profile change can
therefore never silently redirect an existing enrollment to another CA or
template.

### 4. Agent-local policy matches whole enrollment rules

The agent configuration gains `adcs.enrollmentRules`, a list of
`{ caConfig, template, dnsScopes, keyAlgorithms }`. A job is allowed only if
one rule matches on every field at once; independent CA and template
allowlists are not used, because they would permit combinations the
operator never intended. `dnsScopes` uses the same zone-coverage rule as the
existing DNS zone allowlist. A job outside the rules is `rejected` with the
rejection reason `issuer_not_allowlisted` and no CA contact.

The agent also refuses `transport` values other than `dcom` and never passes
`-rpc` to `certreq`.

### 5. Template and CA safety checks fail closed

These checks are defense in depth. The real boundaries remain CA and
template permissions, agent-local policy (decision 4) and issued-certificate
validation (decision 6). They run before the first submit for a
(CA, template) pair and are cached with a time-to-live; each verdict is
recorded as evidence.

The agent reads the template with `certutil -dstemplate` and refuses with
`ADCS_TEMPLATE_UNSAFE` when any of the following hold, or when any attribute
cannot be parsed:

- the extended key usage set is not exactly Server Authentication
  (`1.3.6.1.5.5.7.3.1`), including an absent EKU, Any Purpose, Certificate
  Request Agent, Client Authentication, Smart Card Logon or PKINIT
- the application policies are not Server Authentication only
- the template is schema version 1
- the key constraints are incompatible with the snapshot: a key smaller
  than `msPKI-Minimal-Key-Size`; on schema version 3 and later, a key
  algorithm other than the template's `msPKI-Asymmetric-Algorithm` (read
  from `msPKI-RA-Application-Policies`); on schema version 2, any EC key,
  because such a template cannot name an EC algorithm

An enrollee-supplied subject is accepted only together with the
Server-Authentication-only EKU; the names actually requested are then
bounded by the matching rule's `dnsScopes`.

For the CA, the agent reads `EditFlags` with
`certutil -config <caConfig> -getreg policy\EditFlags` and refuses when
`EDITF_ATTRIBUTESUBJECTALTNAME2` is set. It also reads
`certutil -config <caConfig> -getreg CA\InterfaceFlags` and refuses when
`IF_ENFORCEENCRYPTICERTREQUEST` (`0x200`) is clear. If either value cannot be
read under the agent identity, the agent refuses unless agent-local policy
carries an explicit operator attestation for that CA. Either refusal uses
`ADCS_CA_CONFIG_UNSAFE`. The agent never adds a `SAN:` request attribute.
Every refusal in this decision ends the enrollment `refused` before any
submit.

The agent also fetches the CA's certificates from the CA itself
(`certutil -config <caConfig> -cainfo certcount`, then `-ca.cert <index>`
for each), which the computer account may do with default permissions. It
refuses with `ADCS_CA_KEY_UNPINNED` when none of them carries the pinned
`caKeySha256`, and keeps them for verifying CMC responses (decision 9).

Issuer validation runs the same checks without enrolling. When an operator
creates or edits an `adcs` issuer, the control plane dispatches a read-only
`adcs-preflight` job to an agent the operator picks. It reports the template
and CA verdicts and every CA certificate with its key hash. The operator
confirms the key, which becomes `caKeySha256` on a new issuer version.

Read-only does not mean unrestricted: preflight contacts a CA on the
operator's behalf, so it is constrained like enrollment.

- It is a signed job, dispatched only by users allowed to manage issuers.
- The agent refuses it without contacting any CA unless
  `adcs.enrollmentRules` names that exact `caConfig` and template, so it
  cannot be pointed at arbitrary hosts.
- It runs only the fixed read-only `certutil` calls above, with argv built
  from the validated fields.
- Each call has a timeout, and the whole job a time budget.
- It returns only parsed fields and the CA certificates, size-capped, never
  raw command output.

The control plane rate-limits preflight per workspace and records an audit
event for each run.

The proof of concept showed why these checks cannot be left to the CA: it
issued a certificate on a template carrying Client Authentication next to
Server Authentication without objection. It enforces the template's minimum
key size, and on a schema version 4 template its key algorithm, only by
denying the request after submission. The preflight also records the
template's `msPKI-Cert-Template-OID`, which decision 6 needs.

### 6. Issued certificates are validated before `certreq -accept`

A mandatory validation stage runs on whatever certificate the CA returns,
from `-submit` or `-retrieve`, before it touches any store. It is written
issuer-agnostically so the ACME path can adopt it later, first in
report-only mode.

Definitive failures move the enrollment to `rejected_invalid` with
`ADCS_CERTIFICATE_INVALID` (or `ADCS_CA_KEY_CHANGED`, below); the
certificate is never accepted and the key is freed:

- the certificate's SubjectPublicKeyInfo differs from the journaled CSR's
  (this rejects any certificate that was not issued for this request)
- a SAN outside `authorizedDnsNames`, a missing IIS binding hostname, or a
  subject CN outside `authorizedDnsNames`
- an EKU other than Server Authentication only
- key usage not matching the algorithm (RSA: digitalSignature and
  keyEncipherment; EC: digitalSignature), any keyCertSign, or a
  basicConstraints CA flag
- `notBefore > now + 300 s` clock skew
- `notAfter <= now + minimumRemainingValidity`
- `notAfter <= existing.notAfter`, only when the snapshot sets
  `requireLaterNotAfter`
- a serial equal to the currently installed certificate's
- a chain whose issuing CA certificate does not carry the pinned CA key
  (`caKeySha256`)
- a chain-policy failure, or a revoked certificate
- a Certificate Template Information extension (`1.3.6.1.4.1.311.21.7`)
  that is absent or names an OID other than the template OID recorded by
  the preflight (decision 5); this is the binding between the certificate
  and the snapshot's template, since the template is not covered by the CSR
  signature (decision 7)

A certificate issued long before a delayed retrieval is valid: `notBefore`
is bounded only from above. The CA sets `notBefore` about ten minutes
before the moment it issues (its default clock-skew allowance), and for a
manager-approved request that moment is the approval, not the submission.
`notBefore` is therefore not related to the submission time at all.

**The CA is pinned by key, not by certificate.** A CA certificate renewal
changes the thumbprint, and with key reuse (the common case) keeps the key.
After the lab CA renewed that way, it signed CMC responses with the new
certificate, while members kept building chains to the old one their trust
store still held. A thumbprint pin would have rejected every enrollment
snapshotted before the renewal, including a request approved after it,
which in the proof of concept retrieved and validated normally. A renewal
with a new key is a trust change: validation fails with
`ADCS_CA_KEY_CHANGED` (the enrollment ends `rejected_invalid`), and the
operator approves the new key as a new issuer version (decision 3) before
new enrollments use it.

A successful retrieve proves nothing about current validity: the proof of
concept retrieved a revoked certificate with exit code 0 and a CMC success
status. The revocation check is therefore what stops a revoked certificate
from being installed, not an optional extra.

Chain and revocation decisions use Windows CryptoAPI:
`CertGetCertificateChain` with revocation checking (end certificate and
intermediates, root excluded) and a Server Authentication application
policy, then `CertVerifyCertificateChainPolicy`. The verdict maps from the
chain's trust-status flags, which are numeric and not localized:
`CERT_TRUST_IS_REVOKED` is a definitive failure, while
`CERT_TRUST_REVOCATION_STATUS_UNKNOWN` together with
`CERT_TRUST_IS_OFFLINE_REVOCATION` means revocation is unavailable. The
check runs in a short-lived helper process, one per check: in the proof of
concept a retry inside the same process kept reporting "unknown" after the
distribution point was reachable again, while a fresh process validated
immediately. Whether an in-process cache or timing caused this was not
isolated; a fresh process avoids both. `certutil -verify -urlfetch` output
is collected for diagnostics and evidence only, never as the decision.

**Revocation unavailable is not invalid.** When CRL or OCSP status cannot be
obtained, the enrollment moves to `validation_deferred`: the certificate
stays uninstalled, the key is retained, and validation is retried with
backoff until an agent-local deadline (default 24 hours), after which the
enrollment ends `validation_expired` and the key is freed. The agent-local
`adcs.revocationCheck` setting is `require` by default; `best-effort` is an
explicit local exception, and every certificate accepted under it is
recorded as such in evidence.

### 7. One key path, in machine context

AD CS reuses the existing CNG path (`generateCsrViaCng` and
`buildCertreqInf`); there is no second key-generation implementation. The
request descriptor keeps `MachineKeySet = TRUE`, `Exportable = FALSE`,
`ExportableEncrypted = FALSE`, `PrivateKeyArchive = FALSE`,
`UserProtected = FALSE`, the Microsoft Software Key Storage Provider with
`ProviderType = 0`, `RequestType = PKCS10`, `HashAlgorithm = SHA256` and the
SAN extension, and changes as follows:

- `Silent = TRUE` is added.
- The request descriptor never names the template. For `adcs` the template
  is passed at submit as `certreq -submit -attrib CertificateTemplate:<template>`.
  An earlier draft put it under `[RequestAttributes]` so the CSR signature
  would cover it. The proof of concept showed that `certreq -new` then
  fails with `NTE_PROV_TYPE_NOT_DEF` (`0x80090017`) for the Software Key
  Storage Provider on schema version 1 and 2 templates, including the
  built-in Web Server template, on all three Windows versions. It worked on
  a schema version 4 template that names the Key Storage Provider, which
  suggests `certreq` applies the template's provider settings. Most deployed
  web-server templates are version 1 or 2 and `-attrib` works on every
  version, so the template always travels at submit. The binding is
  enforced instead by the template-extension check of decision 6, and the
  submit itself travels over the encrypted, authenticated DCOM channel of
  decision 8.
- `KeyUsage` is chosen per algorithm (`0xa0` for RSA, `0x80` for EC) instead
  of the current fixed `0xa0`.
- `certreq -new` and `certreq -accept` pass `-machine` explicitly. Under
  `LocalSystem` the proof of concept saw identical results with and without
  it on Windows Server 2019, 2022 and 2025 (machine key, `LocalMachine\My`),
  so the flag removes ambiguity without changing the ACME path's behavior.
  `-submit` and `-retrieve` do not take it.
- `-submit` and `-retrieve` always receive all four paths: request (or
  RequestId), certificate, chain and full response. With the response path
  omitted, `certreq` derives `<certificate>.rsp` itself; a name collision then
  fails under `-q` with `ERROR_FILE_EXISTS` (`0x80070050`) after the CA has
  already issued.

An EC key needs a template built for it: a schema version 2 template with a
2048-bit minimum denied a P-256 request with `CERTSRV_E_KEY_LENGTH`, while a
schema version 4 template restricted to `ECDSA_P256` issued one end to end
(machine key in the Software Key Storage Provider, not exportable, valid
chain and revocation) and denied an RSA request. The decision 5 preflight
catches both mismatches before submission.

Because the ACME Windows path shares this code, these changes must stay
backward-compatible and are proven by ACME regression on every supported
Windows Server version.

The CNG container name is derived from `enrollmentId`. After `-accept` the
agent confirms through the store that the installed certificate has a
private key, that its key container is the journaled one, and that the key
is not exportable.

### 8. Identity and transport

The agent keeps the identity ADR-0012 decision 11 established: the Windows
service runs as `LocalSystem`, so it reaches the CA with Kerberos as the
computer account (`DOMAIN\HOST$`). Template Enroll permission is granted to
that computer account or to a group containing it. A group-managed service
account stays rejected (ADR-0012 decision 12); supporting one would require
amending that decision first. Qualification evidence counts only when it is
produced under the real service identity, never under an interactive
administrator session.

The transport in this record is DCOM, the `certreq` default. `-rpc` is
never used. Deployment documentation requires
`IF_ENFORCEENCRYPTICERTREQUEST` to remain enabled on the CA, and lists the
firewall requirement (TCP 135 plus the dynamic RPC range to the CA).

Enrollment over HTTPS (the Certificate Enrollment Policy and Certificate
Enrollment web services) is out of scope. Before any such transport is
proposed it needs its own security review, covering at least: `certreq -p`
puts the password on the process command line, so it is not acceptable;
credentials must never appear in argv; and Kerberos constrained delegation
is required when the enrollment web service and the CA run on separate
hosts.

### 9. Disposition parsing never guesses

Outcomes are decided only from structural signals, never from `certreq`
console text. The primary signal is the full CMC response file that
`-submit` and `-retrieve` write (decision 7). The agent decodes it as DER
and verifies its CMS signature with a CA certificate that carries the
pinned key. The CA signed every response the proof of concept produced,
including denials, but only issued responses embed certificates; pending
and failed responses name the signer by issuer and serial number alone, so
the agent verifies them against the CA certificates the preflight fetched
(decision 5). The signature is defense in depth: the channel is already
authenticated and encrypted (decision 8), and nothing is installed without
passing decision 6. From the response the agent reads:

- the `CMCStatusInfo` status: `0` success, `2` failed, `3` pending
- for pending, the pend token, which carries the RequestId as a 32-bit
  little-endian integer
- for success, the issued-certificate hash attribute
  (`1.3.6.1.4.1.311.21.17`), which must match the certificate file

The decoder is a trust boundary and fails closed. It enforces a fixed size
bound (64 KiB) and strict DER with no trailing data. Each of the following
yields `ADCS_DISPOSITION_UNKNOWN`:

- a malformed or truncated structure
- a signature that does not verify, or a signer whose key is not the
  pinned one
- CMC status values that disagree with each other
- a success status without a certificate, or with a hash attribute that
  differs from the certificate
- a pending status without a pend token
- on retrieve, a pend token that differs from the journaled RequestId

Its tests use the proof-of-concept responses as known-good fixtures, and
adversarial variants of them for each case above.

A failed response carries no machine-readable reason, only a status string
in the CA's language, so failures are told apart by the process exit code,
an HRESULT:

| CMC status | Exit HRESULT | Meaning | Outcome |
|---|---|---|---|
| 0 | any | certificate returned | `issued`, then decision 6 (the exit code is ignored, see decision 7) |
| 3 | `0` | taken under submission | `pending_issuance` |
| 2 | `0x80094014` `CERTSRV_E_ADMIN_DENIED_REQUEST` | denied by a CA manager | `denied` |
| 2 | `0x80094012` `CERTSRV_E_TEMPLATE_DENIED` on submit | the computer account lacks Enroll on the template | `denied` |
| 2 | `0x80094800` `CERTSRV_E_UNSUPPORTED_CERT_TYPE` on submit | the CA does not publish the template, or it does not exist | `denied` |
| 2 | any other HRESULT on submit | denied by CA policy; observed: `0x80094811` `CERTSRV_E_KEY_LENGTH`, and `0x80094003` `CERTSRV_E_BAD_REQUESTSTATUS` for a key algorithm the template excludes | `denied` |
| 2 | `0x80070005` `E_ACCESSDENIED` on retrieve | RequestId belongs to another requester | `submission_uncertain` |
| 2 | `0x80094004` `CERTSRV_E_PROPERTY_EMPTY` on retrieve | RequestId unknown to the CA | `submission_uncertain` |
| no response file | `0x800706BA` `RPC_S_SERVER_UNAVAILABLE` or `0x800706BF` `RPC_S_CALL_FAILED_DNE` on submit | the request never reached the CA | not submitted, retried (below) |
| missing, unsigned, or any other combination | | | `ADCS_DISPOSITION_UNKNOWN`, treated as `submission_uncertain` |

A signed failed status on submit is the CA's own verdict, so every submit
failure maps to `denied`; the HRESULT only names the reason, and the raw
code is always shown. Every submit-time denial in the proof of concept,
including the permission and template-availability ones, was recorded as a
denied row in the CA database. On retrieve, only `0x80094014` maps to
`denied`; any other unmapped result is never treated as denied or pending
(decision 10).

The two RPC codes in the table are the runtime's "did not execute" signals,
and the classification is deliberately narrow. It requires both an exit
HRESULT from that pair and no response, certificate or chain file. A
missing response alone never qualifies. The following all stay
`submission_uncertain`:

- any other HRESULT
- a `certreq` the agent timed out or that was killed
- a response file that is present but empty, unparsable or unsigned
- `RPC_S_CALL_FAILED` (`0x800706BE`), which may follow execution

With the CA service stopped and with TCP 135 to the CA blocked, `certreq`
failed with `RPC_S_SERVER_UNAVAILABLE` within about a second, wrote no
response, and the CA database gained no row. The agent then returns its
journal entry to `prepared` and ends the job with the retryable error
`ADCS_CA_UNREACHABLE` (decision 2). The next continuation submits the same
CSR, which cannot create a duplicate because nothing reached the CA.

The proof of concept produced these codes only before the CA received
anything. Whether a CA that executed the request, but whose reply was lost,
can surface the same codes is a release-gate case. If it can, the
classification is removed and every transport failure stays uncertain.

`certreq`'s own console text localizes under `LocalSystem`, so it is never
parsed. The RequestId line alone reads `RequestId: "29"` on English hosts,
`Anforderungs-ID: "22"` on German ones and `IDDemande : « 29 »` on French
ones. Status strings that come from the CA, such as "Taken Under
Submission", stay in the CA's language instead, so they are not parsed
either. The CMC status, the pend token and the exit HRESULTs were identical
on all three. Parser fixtures include English, German and French Windows
output. The `ICertRequest` COM fallback this decision originally reserved is
not needed.

### 10. Crash safety: the agent journals before every side effect

The agent keeps an enrollment journal keyed by `enrollmentId`, written
atomically, fsynced and ACL-protected like the existing issued-container
records. Each entry holds the snapshot hash, container name, the CSR's
SHA-256, the SHA-256 of its SubjectPublicKeyInfo, `caConfig`, `template`,
the RequestId once known, and the current state.

- `prepared` is written after key generation, and `submitting` is written
  **before** `certreq -submit` runs.
- An agent that restarts and finds `submitting` moves the enrollment to
  `submission_uncertain`. It never resubmits automatically.
- `installing` is written before `certreq -accept`. An agent that restarts
  in `installing` first inspects the target store (is the expected
  thumbprint present, bound to the journaled container?) and the IIS binding
  (does it already point at that thumbprint?), then resumes at the first
  incomplete step: accept, store mirror, bind, or verify. Every step is
  idempotent.
- Recovery and `install_failed` never delete a key container whose
  certificate is bound in IIS or held by the predecessor certificate; the
  ownership gate of ADR-0012 decision 18 applies unchanged.
- The startup orphan-container sweep skips containers that belong to an
  open enrollment.
- Continuations take a per-enrollment lock. A continuation whose step the
  journal has already passed returns the recorded result instead of
  repeating the side effect.

**Reconciling an uncertain submission.** With default CA permissions the
computer account cannot read the CA database at all (`certutil -view` fails
with `E_ACCESSDENIED`). Granting it the CA Read right does make `-view` work,
including requester names with a backslash, but Read exposes every row in
the database, not just the caller's. Reconciliation therefore has three
tiers:

1. **Operator, always available and the default.** The dashboard marks the
   enrollment as needing intervention and shows the key hash. The operator
   either supplies the RequestId or abandons the enrollment. A supplied
   RequestId is accepted only after a retrieve whose certificate passes the
   SubjectPublicKeyInfo check of decision 6.
2. **Requester-scoped retrieve, no extra CA permission.** `certreq -retrieve`
   answers only for the caller's own requests (another requester's RequestId
   returns `E_ACCESSDENIED`). The agent journals the highest RequestId it has
   seen per CA and may retrieve a bounded window above it. A returned
   certificate whose public key matches the journal reconciles the
   enrollment to `issued`. Pending and denied candidates carry no public key
   and other processes enroll as the same computer account, so they are
   never matched this way; they fall through to the operator.
3. **Database query, only when an operator grants the CA Read right
   knowingly.** The agent fetches raw requests by requester name and
   submission time window and compares each candidate's public key and
   request hash locally against the journal. Exactly one match reconciles
   the enrollment to the CA's recorded state; zero or several leave it to
   the operator. Documentation states that this grant makes the whole CA
   database readable to every account it covers.

Abandoning destroys the CNG container, so a certificate the CA issues later
for that request is useless without its key; it is recorded for revocation
follow-up. A new enrollment always generates a new key and CSR. An uncertain
request is never resubmitted.

### 11. Capability gating and evidence

The agent advertises a new gated capability, `adcs-enroll-v1`. It is named
in the build-time qualified-capabilities manifest only after the release
gate below is met, and dispatch requires a fresh capability epoch as for the
other gated capabilities (ADR-0012 decisions 14 and 17).

New evidence types, following the existing `<domain>.<event>` naming:
`adcs.template_checked`, `adcs.submitted`, `adcs.pending`, `adcs.issued`,
`adcs.denied`, `adcs.uncertain`, `adcs.validation_deferred` and
`adcs.rejected_invalid`. Evidence carries the RequestId, CA config,
template, certificate fingerprints and the validation verdict, never key
material.

## Questions the proof of concept must answer

The proof of concept runs on a domain controller with an enterprise CA and a
domain-joined member server running the agent as `LocalSystem`, on every
supported Windows Server version. Each answer is recorded in the amendment
that accepts this record.

1. Does adding `-machine` to `certreq -new`, `-submit`, `-retrieve` and
   `-accept` behave as decision 7 assumes, and does the existing ACME
   Windows path still pass its regression suite with it?
2. Does `certutil -dump` of the generated request show `CertificateTemplate`
   as a signed PKCS#10 attribute on every supported version?
3. Which machine-readable signals (exit code, HRESULT, RequestId, output
   files) identify issued, pending and denied outcomes, including on German
   and French Windows? If none are reliable, the COM fallback of decision 9
   is triggered.
4. Can the computer account read the template attributes decision 5 needs,
   and the CA `EditFlags`?
5. Can the computer account query the CA database with `certutil -view` and
   fetch raw requests by requester and time window, including requester
   names containing a backslash? If not, reconciliation is operator-only.
6. How does the agent call `CertGetCertificateChain` and
   `CertVerifyCertificateChainPolicy`? The preferred answer is a small native
   helper built and signed alongside the existing Windows service host,
   rather than a new PowerShell surface.
7. Does the post-accept check of decision 7 reliably expose the key
   container and non-exportability?

## Proof-of-concept findings (2026-10-08)

Lab: one Windows Server 2022 domain controller hosting an enterprise root
CA with default settings, and domain-joined members on Windows Server 2019
(build 17763), 2022 (build 20348) and 2025 (build 26100). The 2025 set was
repeated with a German system UI language and on a second member with a
French one. Every probe ran as
`LocalSystem` through the platform's run-command channel, never in an
interactive session. Decisions 5 to 10 above already include the resulting
changes; this section records the answers.

1. **`-machine`:** `certreq -new` and `-accept` gave the same result with and
   without it on all three versions: a machine key in the Software Key
   Storage Provider and the certificate in `LocalMachine\My`. The ACME path
   should therefore be unaffected, but its regression suite has not run
   with the change yet (release gate). `-submit` and `-retrieve` do not use
   it.
2. **Template in the signed CSR:** not viable in general. `certreq -new`
   fails with `NTE_PROV_TYPE_NOT_DEF` when the descriptor names a schema
   version 1 or 2 template, on all three versions; it worked on a schema
   version 4 template. The template moves to `-submit -attrib` for every
   version, and decision 6 checks the issued certificate's template
   extension instead.
3. **Disposition signals:** the CA-signed CMC response file plus the exit
   HRESULT distinguish issued, pending, denied by a manager, denied by
   policy, foreign RequestId and unknown RequestId (decision 9 table). The
   exit code alone is not reliable: an issued submit returned
   `ERROR_FILE_EXISTS` when the response path collided. The same signals
   held on German and French hosts, where all console text, including the
   RequestId line, was translated. No COM fallback is needed.
4. **Template and CA reads:** the computer account read every template
   attribute decision 5 needs through `certutil -dstemplate`, and the CA's
   `EditFlags` and `InterfaceFlags` remotely through `-getreg`. A default
   enterprise CA has `IF_ENFORCEENCRYPTICERTREQUEST` set and
   `EDITF_ATTRIBUTESUBJECTALTNAME2` clear.
5. **CA database:** denied by default. With the CA Read right granted,
   `-view` worked with either backslash form of the requester name and
   returned raw requests, but also every other requester's rows. Hence the
   three reconciliation tiers of decision 10.
6. **Chain validation:** CryptoAPI chain building through the .NET
   `X509Chain` wrapper returned clean, non-localized verdicts: valid,
   revoked (CRL published to the CA's LDAP distribution point), and
   revocation-unknown plus offline-revocation when the distribution point
   was blocked. The online check then waited for its full URL retrieval
   timeout. The production helper should be a small native binary built and
   Authenticode-signed alongside the existing `tokentimer-verify` binary,
   calling `CertGetCertificateChain` and `CertVerifyCertificateChainPolicy`
   directly, one process per check.
7. **Post-accept check:** the store reported the journaled key container
   name, the Software Key Storage Provider, a machine key and "not
   exportable", and the CNG handle reported an export policy of none. This
   held both for an immediate accept and for a retrieve-then-accept after
   CA-manager approval in a later run.

Other behavior observed: a CA-manager approval and a later retrieve bound
the certificate to the key generated at submit time; a revoked certificate
was still retrievable with a success status; and the CA set `notBefore`
about ten minutes before issuance.

Follow-up checks, run the same day against the same lab:

- **Ground truth.** An export of the CA database, cross-checked offline
  against every certificate, CSR and CMC response the probes kept, found no
  inconsistency: each issued certificate was a CA row for the expected
  computer account, carried the CSR's public key and the template
  extension the preflight would read, and chained to the CA; each response
  was CA-signed; each pend token was the CA's RequestId.
- **Kerberos.** Every network logon of the member computer accounts on the
  domain controller during the proof of concept used Kerberos; none used
  NTLM.
- **Submit-time denials.** A template the computer account may not enroll
  in, an unpublished template and a nonexistent one produced the codes in
  the decision 9 table.
- **EC.** P-256 issued end to end on a schema version 4 template, and an
  RSA key against that template was denied (decision 7).
- **CA unreachable.** A stopped CA service and a blocked endpoint mapper
  both failed fast without reaching the CA (decision 9).
- **CA certificate renewal.** The computer account fetched the CA
  certificates from the CA with default permissions. After a key-reuse
  renewal, a request submitted before it and approved after it was
  retrieved, bound to its original key and validated (decision 6).

Not covered by the proof of concept, and therefore part of the release
gate: a two-tier hierarchy (offline root, enterprise issuing CA) with HTTP
distribution points, a CA renewal with a new key, the ACME regression suite
with the changed key path, an agent running on a domain controller, and
Windows Server 2016, which the agent supports but has not verified on real
hosts for any issuer.

## Release gate

The `adcs` issuer kind is not released, and `adcs-enroll-v1` is not
qualified, until each of the following passes on a real host under the
agent service identity:

- auto-issue, and CA-manager approval including a late approval of an older
  certificate (the validity rules of decision 6)
- denial, pending timeout and cancellation
- an agent restart at `prepared`, `submitting`, `validation_deferred` and at
  each `installing` step (accept, store mirror, bind, verify), with no
  in-use key deleted
- a duplicate continuation, and CA downtime
- a foreign, expired or revoked certificate returned on retrieve
- a CRL or OCSP outage that recovers, and one that reaches
  `validation_expired`
- reconciliation with zero, one and several candidate requests, and the
  operator fallback
- each unsafe-template rule, an RSA key size and an EC curve mismatch, a CA
  with `EDITF_ATTRIBUTESUBJECTALTNAME2` set, and a CA with
  `IF_ENFORCEENCRYPTICERTREQUEST` clear
- an issued certificate whose template extension does not match the
  snapshot's template
- a retrieve of another requester's RequestId and of an unknown RequestId
- a submit to a template the host may not enroll in, and to an unpublished
  template
- EC P-256 and P-384 issuance on schema version 4 templates
- a CA certificate renewal with key reuse while an enrollment is pending,
  and one with a new key (`ADCS_CA_KEY_CHANGED`)
- a two-tier hierarchy whose distribution points are HTTP only
- the existing ACME Windows regression suite with the changed key path
- a submit the CA executes but whose reply never reaches the agent (CA
  responses to the agent dropped), which must end `submission_uncertain`
  and never be resubmitted; a CA unreachable before submit, which must
  retry without a duplicate CA row
- an `adcs-preflight` naming a CA or template outside the agent's
  enrollment rules, refused without any CA contact
- orphan-container cleanup

The unit suites for the CMC decoder's adversarial cases and for the
not-submitted classification (decision 9) must also pass.

Each case runs on Windows Server 2019, 2022 and 2025, and the disposition
cases also run on a German and a French installation.

## Alternatives considered

- **Reopening the running job while the CA is pending.** Rejected: it breaks
  monotonic job status and lease semantics, and asynchronous issuance would
  need special cases in every consumer of job state.
- **Referencing the live issuer profile from continuations.** Rejected:
  editing a profile during a long approval window could redirect a pending
  enrollment to another CA or template without anyone deciding that.
- **Automatic resubmission after an uncertain submit.** Rejected: it can
  create duplicate requests at the CA for the same key, one of which a CA
  manager may later approve without anyone tracking it.
- **Independent CA and template allowlists.** Rejected in favour of whole
  enrollment rules, because the cross product permits unintended
  combinations.
- **Rejecting every validation failure, including revocation outages.**
  Rejected: a temporary CRL outage would destroy keys for valid
  certificates and force re-approval.
- **Calling AD CS from the control plane.** Rejected: it would require CA
  credentials or network reach from the control plane, contradicting zero
  custody of execution credentials and the outbound-only agent model.
- **The legacy web enrollment pages.** Rejected: NTLM-based and a known
  relay target.

## Consequences

- Core gains a working AD CS issuer for domain-joined Windows hosts, with
  no CA credentials stored anywhere.
- The job model gains `awaiting_issuer`, the `continue-enrollment` action
  and the `certificate_enrollments` table. Consumers that treat every
  terminal job as an issuance outcome must read the enrollment state
  instead.
- The shared Windows CNG path changes (`-machine`, `Silent`, per-algorithm
  `KeyUsage`) and must be re-qualified for ACME as well.
- The agent gains a native, signed chain-validation helper next to
  `tokentimer-verify`, and a DER decoder for CMC responses.
- Issuers pin the CA by public key. Routine key-reuse renewals need no
  operator action; a new CA key needs an issuer re-approval.
- Uncertain submissions need operator action unless the certificate was
  issued and is found by a requester-scoped retrieve. Database-backed
  reconciliation requires a CA permission most operators should not grant
  broadly, so it stays opt-in.
- Linux hosts and hosts without RPC reach to the CA are not covered by this
  record. An ACME gateway in front of AD CS remains the documented option
  for them.
