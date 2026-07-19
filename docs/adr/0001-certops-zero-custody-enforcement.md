# ADR-0001: CertOps zero private-key custody enforcement

## Status

Proposed (2026-06-25). Phase 0 skeleton; finalize in M0.

## Context

CertOps orchestrates certificate lifecycles across many targets. The strongest
trust and security claim TokenTimer can make is that its control planes never
hold private key material. That claim is only credible if it is enforced
structurally and tested, not stated in marketing copy.

Key material can reach the control plane through many paths: an import body, a
flexible JSONB field, raw command output captured as evidence, an agent message,
or base64-wrapped content under an innocent field name.

## Decision

Zero private-key custody is a structural invariant of Core, Cloud, and
Enterprise. Enforce it in multiple layers:

1. **Field-name redaction** in `apps/api/utils/logger.js` (already present:
   `privateKey`, `private_key`, and regex key matching).
2. **Content-based detection** in `apps/api/utils/secretMaterial.js`
   (`containsPrivateKeyMaterial`), covering PEM private-key variants (PKCS#8,
   PKCS#1, SEC1, DSA, OpenSSH, encrypted) and base64-wrapped PEM, deep-scanning
   nested objects, arrays, and Buffers.
3. **API rejection boundary**: requests whose body contains private key material
   are rejected with HTTP 422 `PRIVATE_KEY_MATERIAL_REJECTED` (see
   `packages/contracts/api/certops-route-compat.contract.json`).
   In M1 this guard is intentionally mounted on CertOps write routes rather
   than globally, to avoid changing unrelated non-CertOps request behavior
   during observe-only work. Domain-checker import keeps its own inline
   `containsPrivateKeyMaterial` guard. Future CertOps write surfaces must attach
   `rejectKeyMaterial` after `express.json()` and before feature gates, RBAC,
   parsing, persistence, or other business logic. Global/content-wide
   enforcement can be revisited later with logger content-scrub work.
4. **Schema design**: no inventory field is intended to hold key material;
   inventory stores public material and opaque, non-secret references
   (`certops-inventory.schema.json`). Flexible JSONB fields are protected by the
   detector, not by the absence of a column.
5. **Evidence scrubbing**: `redactGenericSecrets` runs before evidence storage.

The single private key the platform holds is the **platform operational signing
key** (ADR-0003), which signs jobs and is never used for certificate issuance or
customer key custody.

## Alternatives considered

- Field-name redaction only - rejected: misses key material under innocent
  field names and in raw output.
- Trust the agent to never send keys - rejected: defense in depth requires the
  control plane to reject regardless of sender.

## Consequences

- A shared, well-tested detector is a hard dependency for M1 and M2.
- TODO (M0): define exact 422 error envelope; PKCS#12/PFX binary DER detection
  scope; performance bounds for large evidence scans; where the rejection
  middleware mounts relative to body parsing.
