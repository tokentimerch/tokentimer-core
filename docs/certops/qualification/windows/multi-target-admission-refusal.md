# Public Windows multi-target admission refusal

Public manual renewal resolves the stored profile and accepts only a `reason` override. Its job body cannot introduce another renewal profile. Public profile updates also refuse changes to immutable deployment targets. Although the internal profile parser can represent multiple targets, these APIs cannot establish a multi-target Windows profile from a single-target issuance.

This source checks the genuine public PATCH422 `CERTOPS_PROFILE_FIELD_IMMUTABLE` and manual renewal400 `CERTOPS_RENEWAL_OVERRIDE_INVALID` on an installed Windows fixture. The stored profile, job inventory, actual SYSTEM service processes, protected CNG/native binding, trusted TLS, credentials and actual ACME/DNS observations must remain unchanged. An unexpected admitted job is registered before a sticky guard blocks broad cleanup.

This is public admission refusal coverage. It does not qualify signed multi-target execution or implement multi-target Windows deployment. The existing ten hosted Windows Server/key-profile cells require the closed proof and current source fingerprints. Native execution remains pending.
