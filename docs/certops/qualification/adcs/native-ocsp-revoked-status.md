# Authoritative OCSP revoked status

This page records a local source, fixture, and collector proof for one
historical unserved leaf. It is separate from the signed-good responder
availability checks in `native-ocsp-responder.md`. Those checks keep
`authoritativeRevokedStatusQualified` false and report native verdicts
`valid`, `revocation_unknown`, `valid`. This proof uses its own scope,
`native-microsoft-ocsp-historical-unserved-leaf-authoritative-revoked`, and
its own scenario, `adcs-real-ocsp-authoritative-historical-revoked-status`.

Native lab execution is still pending. Importing the helpers, parsing the
fixtures, and projecting the offline proof do not revoke a certificate,
configure a responder, or qualify a native Microsoft OCSP cell. A passing
unit or collector test is not native qualification.

The local proof admits only an in-memory shape:

- a signed CRL transition that adds exactly the historical issued serial,
  advances the CRL number, and leaves the current successor unrevoked
- complete IIS and HTTP.sys inventories that exclude the historical
  thumbprint and still contain the current successor
- a delegated OCSP response whose certificate status is `revoked`, with a
  revocation time at or before the response, plus an independent CryptoAPI
  verdict of `revoked`
- a closed public report cross-bound to the same enrollment, request,
  fingerprint, signer, issuer key, original CRL, and final CA request count
  as the signed-good proof
- unsupported promotions stay false, including installed-agent refusal of a
  revoked leaf and authoritative unknown status

`qualifyHistoricalRevoked` refuses to run unless `CERTOPS_ADCS_DISPOSABLE_LAB`
is `1` on Windows. Absence of that lab is a failure, not a skipped pass.
The owned CA operation revokes only the exact historical request, publishes
a fresh base CRL, and replaces only the owned provider `BaseCrl` bytes. It
does not unrevoke the leaf. Cleanup remains the existing responder drain.

The public report field is `nativeOcspRevoked`. Catalog, suite, matrix, and
release-collector projection of that field are outside this local proof.
