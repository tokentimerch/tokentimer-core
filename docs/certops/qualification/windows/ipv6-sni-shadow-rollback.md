# IPv6 SNI shadow and rollback

This supporting native Windows fixture borrows the enclosing IIS fixture's existing shadow, baseline and incoming certificates. It owns an IPv6 loopback SNI site and a separate IPv4 sibling port. A real `[::1]:port` HTTP.sys certificate binding must produce the actual product precedence warning and serve the shadow certificate under independently trusted IPv6 TLS.

The unmodified product then deploys the incoming certificate to the hostname endpoint. Its real IPv6 verification must fail and restore the original hostname certificate. Independent native readback and trusted IPv6 TLS after exact shadow removal prove recovery; the IPv4 sibling endpoint and trusted TLS remain unchanged. A separate IPv4 port avoids making an IPv4 non-SNI binding the first warning candidate on the IPv6 target port.

IPv6 loopback, IIS, native HTTP.sys inventory and trusted TLS are mandatory prerequisites. Missing prerequisites fail qualification instead of skipping. A restrictive ownership guard precedes mutations. Exact site coordinates, physical paths, endpoint certificate/store/application identities and filesystem identities gate cleanup; uncertainty preserves the guard and borrowed keys for disposable-host teardown. The product generates fresh application IDs for rollback; only a successfully verified rollback authorizes its exact new readback identity.

The source and offline proof checks do not establish native execution. The public proof explicitly excludes installed-agent and CA qualification. Every Windows host release cell requires the named scenario, closed `nativeIpv6SniShadow` proof and current fixture/oracle fingerprints. Protected native execution remains pending.
