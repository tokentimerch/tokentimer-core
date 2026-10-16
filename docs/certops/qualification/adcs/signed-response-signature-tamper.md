# Native signed response tampering

The protected domain-backed AD CS lane uses the actual pending response from its owned expiry fixture. It first requires the native decoder to accept the original response and an equivalent DER copy with the pinned CA key and exact native RequestId. A bounded DER traversal then locates the outer CMS SignedData SignerInfo signature OCTET STRING and flips exactly one signature byte in another copy. It does not alter embedded certificates or optional attributes. The native decoder must refuse that copy without exposing a RequestId or accepted certificate, and the original agent response must retain its exact hash.

The mutation utility accepts only one CMS signer, canonical bounded definite lengths and the expected SignedData field order. Pure supporting tests locate and mutate signatures in the committed genuine pending, issued and denied CA response fixtures. They prove one changed DER byte and unchanged inputs; they do not execute the native decoder or qualify native signature validation.

This is a read-only response decoder boundary. It does not submit a CA request, accept a certificate, change enrollment custody or run a renewal request signer. ADR 0014 requires a new key and CSR for each new enrollment. Signed CMC renewal requests remain outside the supported product contract; supported renewal qualification uses fresh enrollment.

Local source and copy-mechanics checks have run. The genuine response tampering refusal remains pending execution in the disposable native AD CS lane.
