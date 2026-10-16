# HTTP-only leaf CRL endpoint availability

This source fixture renews the existing managed RSA2048 IIS certificate through
the real public enrollment API and the installed SYSTEM agent. It temporarily
sets the disposable issuing CA's leaf CDP to one exact member-owned HTTP URL.
It adds no machine, HTTP role, issuer preflight, or automatic Azure campaign.

Before changing publication, the fixture requires an otherwise idle native lab.
A fixed CA mutex and protected original/applied publication receipt precede the
registry write. The original CA certificate remains pinned. The member admits
only its actual signed, current base CRL after independently verifying its DER,
issuer, signature and CA key. A retained HTTP server serves that one byte buffer
at one exact path on `10.64.0.6` and an exclusively bound ephemeral port.

The resulting leaf must have exactly that HTTP CDP, without LDAP or another
URI. Its real CA RequestId, current job claim and validation evidence, protected
My-store CNG association, IIS/HTTP.sys binding and trusted SNI TLS are observed
independently. Enrollment ownership is registered before waiting for acceptance.
An immediate issued CMC response may omit RequestId from the API or journal.
The independent native CA RequestId remains mandatory; reported IDs are compared
when present without rewriting either persisted field.

The first public renewal is admitted while this exact endpoint returns HTTP503.
Its actual failed authenticated result must preserve a durable
`validation_deferred` leaf and generated, unaccepted protected CNG key. A real
native private-key signature binds the key to the issued public leaf, while a
complete native certificate-store reference scan, outgoing custody, binding
and trusted TLS prove no acceptance. The listener's unavailable counter must
advance during installed-agent execution. After HTTP200 is restored, a distinct
signed continuation must install the identical CSR/key/leaf/native RequestId
without another CA request, and the served counter must advance. Both result
nonces, distinct claims and current-claim verification evidence are read back.
Only poll eligibility uses the supported scheduler `now` input; native clocks
and the persisted validation deadline remain actual and unchanged. This is not
background timer qualification. The exact unique-URL cache entry is evicted and
the resynchronization policy refreshed before each admission phase.

Original CA publication is restored before the independent availability probes. The owned
endpoint then returns the same signed CRL with HTTP 200, HTTP 503 without CRL
bytes, and the original CRL with HTTP 200 again. Each asynchronous shipped native
chain probe must actually contact the listener and return `valid`,
`revocation_unknown`, and `valid`, respectively. A cached verdict without a new
listener request fails the fixture. Only the unique owned URL's cache entry is
evicted; the original chain-cache resynchronization policy is restored exactly.
After recovery, a second genuine public renewal under the restored original
publication must install a distinct leaf/key and validate without contacting
the owned HTTP endpoint. That certificate becomes the current fixture before
the listener closes. Exactly two new CA requests are required; no additional
issuer preflight is introduced.

The accepted key, certificate and complete observed binding settings must remain
unchanged throughout the fault. Listener sockets drain before its ownership
receipt can be released. Any uncertain publication restoration, native result,
accepted-leaf ownership or listener drainage preserves the cleanup guard and
borrowed fixture custody.

This covers HTTP endpoint availability for a real HTTP-only leaf CDP. It does
not qualify OCSP, a CA outage, signed CMC renewal requests, or other HTTP clients.
The outage probes independently invoke the shipped native chain helper over an
already installed leaf; the separate mandatory signed continuation composition
supplies `installedAgentFaultRecoveryQualified: true` only after its actual
failed result, native no-acceptance and same-leaf recovery checks pass. Neither
path fabricates a chain verdict or qualifies a deployed background scheduler.
Supporting DER, schema and source tests do not execute AD CS and do not count as
native qualification. Actual domain-backed execution remains pending and belongs
only to explicitly enabled manual AD CS qualification.
