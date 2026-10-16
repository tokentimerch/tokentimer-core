# Hierarchy HTTP intermediate CRL availability

The hierarchy fixture already issues its enterprise subordinate from an offline
root whose signed CRL remains published over HTTP. This source journey uses
that actual intermediate CDP and the shipped CryptoAPI chain helper's
end-entity-plus-intermediate revocation policy.

It first requires the exact isolated root HTTP CDP with no LDAP alternate, an
actual bounded public DER response, and successful native validation after
clearing the disposable member's CRL cache. A uniquely owned firewall rule then
blocks only the exact chain-helper executable's HTTP connection to the root.
The same HTTP resource must remain accessible to an independent caller, and
the issuing CA's LDAP service must remain reachable. A fresh native validation
must report `revocation_unknown`.

The rule is removed only after its actual executable, address, direction,
action, protocol and port match the registered ownership. The original native
chain-cache policy is restored from a bounded identity-bound private receipt.
Fresh native validation must succeed again. The predecessor certificate's
nonexportable key, native IIS/HTTP.sys selector and independently trusted TLS
must remain unchanged throughout.

The parent must register the ownership guard before any native mutation and
refuse native or durable-state teardown while it remains. Failures retain the
guard and private policy snapshot, including when rule restoration succeeds.
Only a fully observed successful sequence releases ownership.

The hierarchy producer and strict release report require this scenario and its
closed `nativeHttpIntermediateCrl` proof; the root-only suite cannot substitute
for it. Native execution is pending. Its scope is HTTP revocation
of the existing intermediate, not an HTTP-only leaf, OCSP, a signed enrollment
job, or automatic validation-deferred continuation.
