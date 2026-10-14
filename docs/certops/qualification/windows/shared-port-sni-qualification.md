# Same-port IIS SNI isolation

The protected Windows host qualification workflow runs the mandatory
`windows-iis-shared-port-sni-isolation` case on Windows Server 2022 and 2025.
It requires an elevated disposable host with IIS and the existing host-suite
prerequisites. Do not invoke the fixture against a workstation or shared server.

The fixture owns two uniquely named IIS sites, two hostnameport selectors on
one free TCP port, and five non-exportable machine certificates with both
fixture DNS names. It refuses existing site/selector collisions and concrete-IP
shadows before mutation. All TLS probes connect to loopback with the actual
SNI hostname and explicit public certificate trust.

The real product binding mutator performs primary cutover and a real
missing-store-certificate rollback while its peer remains unchanged. The
fixture then reverses the roles. Exact native IIS coordinates, store,
`sslFlags`, certificate hash, independently queried HTTP.sys hostnameport
hashes and authenticated TLS must agree after each operation. Reapplying the
same primary certificate must verify without mutation.

The Windows host report must contain `nativeSamePortSni`, the named successful
case, and current source fingerprints for the fixture and its TLS oracle.
Collection retains only bounded counts and boolean observations. The release
verifier rejects omitted facts, collapsed hostname inventories, a failed
isolation direction, or unverified cleanup. These supporting host cases do not
prove a multi-binding installed-agent job or public API workflow.

Each certificate has an owned receipt before JSON output; key-name receipts
recover partial creation failures. Cleanup attempts every exact owned
hostnameport selector, site, certificate subject and CNG key, and independently
requires absence. Cleanup failure prevents a passing report.

Portable oracle and report regressions pass. Native IIS execution remains
pending and must be supplied by the trusted Windows workflow.
