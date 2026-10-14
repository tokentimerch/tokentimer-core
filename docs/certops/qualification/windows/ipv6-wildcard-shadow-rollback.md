# IPv6 wildcard shadow and rollback

The separate supporting case uses a real `[::]:port` HTTP.sys shadow over an owned IPv6 loopback SNI site. It borrows existing certificates and reuses the concrete fixture's reviewed ownership, native deployment, rollback and cleanup lifecycle. Its proof has a distinct scope; concrete IPv6 evidence cannot satisfy it.

The target port must be available on both the IPv6 wildcard and IPv4 loopback before mutation. Every existing IP, wildcard and hostname HTTP.sys selector on the chosen target or separate IPv4 sibling port is refused. The IPv4 sibling uses a different port and must retain its exact endpoint and independently trusted TLS. These bounds prevent knowingly altering an existing endpoint on either address family; they do not claim an IPv4 wildcard test.

The actual product warning must identify `[::]:port`. A genuine product deployment must fail verification and successfully roll back. Native hostname readback and independently trusted IPv6 TLS must recover after exact wildcard removal. Both variants use the same sticky guard: unresolved ownership or cleanup blocks another variant and preserves borrowed keys. No duplicate cleanup framework or native certificate creation is added.

Source and pure contract checks are implemented. The named scenario, closed `nativeIpv6WildcardShadow` proof and current source fingerprints are mandatory in every Windows host release cell. Protected native execution remains pending. No local native mutation or installed-agent/CA qualification is claimed.
