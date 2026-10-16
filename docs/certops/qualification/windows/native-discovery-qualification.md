# Native Windows discovery selector qualification

The mandatory `windows-discovery-http-sys-selectors` case extends the protected Windows Server 2022/2025 host suite. It creates two uniquely identified non-exportable LocalMachine CNG certificates and three HTTP.sys bindings: IPv4 `ipport`, IPv6 `ipport`, and non-IIS `hostnameport`. One certificate is moved to WebHosting. The production observation adapter is configured to scan only My, so the WebHosting binding must cause the referenced store to be included automatically.

Independent native registry records must agree with the exact selector, application identity, store and certificate thumbprint. Independently read public DER supplies the SHA-256 fingerprint. Production observations must preserve the IPv6 address, hostname, port, LocalMachine authority, store and key-presence facts without inventing an IIS site. The fixture records and independently compares all original binding coordinates, application IDs, certificate hashes, stores and flags after cleanup.

Cleanup attempts every owned binding and certificate even after a failure. It refuses to delete a binding whose application identity or certificate hash changed. Certificate receipts permit recovery if a native call succeeded before its JavaScript response was received; key-name receipts also require the owned CNG key file to be absent. Cleanup failure fails qualification. Only public facts and source hashes enter the report, and the helper source is required by the release matrix.

Central Certificate Store bindings are outside the canonical scanner's supported enumeration and are explicitly not qualified. This case proves real native discovery configuration and inventory, not an HTTP.sys TLS listener or remote API certificate deployment.

The source, strict matching negative tests and PowerShell query syntax have been checked. No certificate, store or HTTP.sys mutation was executed on the development workstation. Actual protected hosted-Windows qualification remains pending.
