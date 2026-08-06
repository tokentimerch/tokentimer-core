# PR #148 Review — Windows/IIS execution surface

## Summary

The overall Windows/IIS execution architecture is strong: CNG-native key generation, ACME issuance, certificate installation, IIS/http.sys rebinding, TLS verification, rollback, evidence reporting, and retention are connected into one renewal path.

Before merging, the following lifecycle and safety gaps should be addressed.

## Findings

### 1. Retention cleanup is not wired into the running agent

The retention module exists, but the agent does not currently run the cleanup sweep at startup or on a schedule. Old certificates therefore remain recorded but are never automatically cleaned up.

### 2. Failed renewals can leave CNG keys behind

A CNG private key is generated before the ACME order. If ACME, certificate acceptance, IIS binding, or another later step fails, the generated key container can remain in the Windows key store.

### 3. Certificate ownership detection is unsafe

The current logic treats a predecessor certificate as TokenTimer-installed when it has a key container. A manually installed certificate can also have a key container, so this is not sufficient proof of TokenTimer ownership before automatic deletion.

### 4. `target.store` is not enforced during certificate acceptance

The target can specify a Windows certificate store, but the `certreq -accept` step does not receive or enforce that store. The implementation therefore cannot guarantee that the certificate lands in the same store later used by the IIS binding.

### 5. IIS/http.sys binding settings may be lost

The binding update deletes the existing SSL binding and recreates it with only the certificate hash, app ID, and store. Existing http.sys SSL options can therefore be lost during a certificate rotation.

### 6. Stale store locks can block future renewals

The store mutex uses an exclusive lock file. If the agent crashes while the lock exists, later renewals can remain blocked because there is no startup recovery for stale locks.

### 7. Non-SNI and specific-IP binding behavior needs clarification

The current job target does not carry a binding IP and the agent builds the binding with `address: "*"`. Specific-IP IIS bindings therefore cannot be represented cleanly, and the non-SNI `ipport` behavior should be explicitly validated.

## Recommendation

**Request changes before merge.**

The core execution path is well designed, but the findings above should be resolved before treating the Windows/IIS renewal path as production-safe.
