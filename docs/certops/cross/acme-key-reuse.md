# ACME client path and key reuse

This contract checks two local gates. A client path outside the owned directory is refused. A second order that presents the same key SPKI fails the key-reuse gate. An in-use key is not deleted. A blanket netsh reset is refused.

Live certbot stays pending. `nativeExecutionQualified` and `sharedFleetQualified` stay false. A missing lab fails closed, and `hostCapabilityAbsentIsPass` is false.

The catalog rows `acme.key-policy`, `acme.linux-certbot`, and `acme.linux-acmesh` are annotated only. This file does not promote them. The existing certificate-signing cell is unchanged. The positive CSR reuse journey in the same helper stays separate: its `verifyProof` and `qualifyKeyReuse` exports are not this local gate.
