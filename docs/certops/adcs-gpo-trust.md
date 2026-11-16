# Distribute AD CS trust with Group Policy

An administrator distributes public CA trust through GPMC; TokenTimer does not manage the GPO or activate leaf services. Never distribute private keys or PFX. This does not create TokenTimer trust-job receipts.

1. Use a domain management host with GPMC/RSAT and permission to edit and link GPOs. Check existing enterprise CA trust first; obtain public CA certificates through a trusted channel and independently verify their fingerprints.
2. Link a dedicated GPO to a pilot computer OU. Under **Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies**, import roots into **Trusted Root Certification Authorities** and intermediates into **Intermediate Certification Authorities**.
3. On a fresh scoped computer, apply computer policy with `gpupdate /target:computer /force`, restart if required, and verify the applied GPO, stores and fingerprints. Confirm an out-of-scope computer remains unaffected.
4. [Verify live TLS](verify-live-service.md). Distinguish missing CA trust, failed GPO application and stale/unreachable CRL or OCSP data.
5. Same-CA leaf renewal needs no new trust distribution. For CA rollover, deploy new trust before migrating services; remove old trust after its dependencies are gone. To roll back, restore prior policy and recheck stores/TLS.

See Microsoft's [Group Policy certificate distribution guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/distribute-certificates-group-policy).
