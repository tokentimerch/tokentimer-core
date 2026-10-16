# Late approval after replacement renewal of the same certificate

The existing cancelled-request scenario installs a successor with a different
managed certificate identity on the same endpoint. This separate source keeps
one persisted certificate identity across a cancelled pending renewal and a
new successful renewal, with distinct enrollment IDs, CA RequestIds and keys.

The fixture begins with an independently trusted installed leaf and waits for its
unique actual agent-discovered managed certificate identity, bound by the native
leaf fingerprint and exact IIS site. It creates a
real pending enrollment through the public API, cancels it, dispatches actual
default-clock cancellation cleanup and requires its original key to be absent
while the previously served leaf remains unchanged. A second public enrollment
uses the **same certificate ID** and the already confirmed pending issuer.
Actual officer approval and a qualification-selected continuation eligibility
time install its new leaf. This does not qualify background timer cadence.

Only then does the shared native late-approval checker approve the old cancelled
RequestId. The checker independently binds requester, template, retained public
CSR/SPKI and issued DER, refuses public retry and scheduler revival, requires
the cancelled key to stay absent and the late leaf never to enter a machine
store, and revokes only that owned unused issuance. The successor's current
claim-bound evidence, durable journal, CNG possession, IIS/HTTP.sys selectors
and trusted TLS must remain unchanged.

An ownership guard is registered before the first public admission. Any missing
result, unknown acceptance, failed native observation or unresolved late-leaf
cleanup preserves the fixture. The original distinct-certificate proof keeps
its separate scope and does not gain a same-certificate claim.

Both new scenarios, the first cleanup ownership fence, closed native proof and
critical source fingerprints are mandatory in full root and hierarchy suites.
Supporting source checks passed; protected native execution remains pending.
These checks alone qualify no Windows environment or elapsed retention window.
