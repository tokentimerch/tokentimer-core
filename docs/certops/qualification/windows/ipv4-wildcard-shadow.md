# Native IPv4 wildcard HTTP.sys shadow and rollback

This supporting Windows host source adds the explicit `0.0.0.0` shadow variant missing from the concrete IPv4 and separate IPv6 controls. Two uniquely owned IIS sites use different free ports. The target is an actual `127.0.0.1` SNI binding; the unrelated IPv4 sibling keeps its native endpoint and trusted TLS leaf throughout.

The fixture borrows three existing certificates only after independent native custody checks. It observes the exact wildcard endpoint, requires the production precedence warning, and verifies that trusted target TLS serves the shadow leaf. A genuine production deployment must then return `VERIFY_FAILED` and successful rollback. Independent HTTP.sys endpoint/store/application metadata must show the predecessor restored. Removing only the owned wildcard must restore trusted predecessor TLS while the sibling remains unchanged.

The existing shared native engine retains original filesystem identities, exact site IDs/binding coordinates and endpoint certificate/store/application ownership. One unresolved receipt blocks cleanup for all shadow variants. Unknown setup, binding or cleanup ownership preserves borrowed keys. This source does not create a new certificate or claim an installed-agent/API or CA journey.

Source and offline adversarial controls are implemented. The named case, closed report proof and current source inventory are mandatory in both Windows host cells. Native Windows execution remains pending; an IPv6 or concrete IPv4 result cannot satisfy the separate IPv4 wildcard proof.
