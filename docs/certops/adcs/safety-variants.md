# Safety variants

This is an integration contract for the remaining safety refusals. Template mismatch, allowlist miss, disallowed algorithm, foreign request, and revocation/OCSP disagreement each fail closed.

A revocation/OCSP disagreement does not set `authoritativeRevokedStatusQualified`. The existing authoritative OCSP revoked proof remains a separate closed proof and is not weakened here.

`nativeExecutionQualified` stays false. `hostCapabilityAbsentIsPass` stays false. A missing lab fails closed. No disposable forest is executed.
