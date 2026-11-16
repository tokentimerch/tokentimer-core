# Distribute AD CS trust with Group Policy

GPO distributes public CA trust to selected domain computers. It does not issue leaf certificates, distribute private keys or create TokenTimer trust-job receipts.

1. Obtain public root and intermediate certificates through a trusted channel; independently verify their fingerprints. Never import PFX files or private keys.
2. Link a dedicated GPO to a pilot computer OU. Under **Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies**, import roots into **Trusted Root Certification Authorities** and intermediates into **Intermediate Certification Authorities**.
3. Apply computer policy; verify the GPO, stores and fingerprints on a pilot client and confirm an out-of-scope computer remains unaffected.
4. [Verify live TLS](verify-live-service.md), including hostname, chain and CRL/OCSP access.
5. For CA rollover, deploy new trust before migrating services; remove old trust only after its dependencies are gone.

See Microsoft's [Group Policy certificate distribution guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/distribute-certificates-group-policy).
