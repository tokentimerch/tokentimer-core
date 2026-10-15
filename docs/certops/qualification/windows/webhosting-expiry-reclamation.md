# WebHosting certificate/key expiry reclamation

This separate, Azure-free Windows host variant uses the existing genuine short-leaf retention collector fixture in `LocalMachine\WebHosting`, without replacing any `My` store controls. Two real predecessor cutovers retain the unchanged 24-hour policy; actual native expiry plus the production 300-second grace wins. The replacement remains genuinely bound with trusted TLS and protected key custody. A contained child interrupts after real certificate deletion, and ordinary production cleanup must finish the original key and immutable ledger.

The new closed proof requires an independent WebHosting custody/IIS-store receipt in addition to the existing real elapsed/deletion proof. A My-only engine is refused before native work; relabelling its report cannot qualify this variant. Full 24-hour retention and installed service cadence remain outside this bounded scope.

The manual hosted job has one real expiry wait, a 15-minute native test budget and a 20-minute job budget. The existing comprehensive host job already has three waits each bounded below ten minutes; adding a fourth to its 40-minute test would leave inadequate worst-case headroom for builds and other native controls. A separate Azure-free job keeps those controls intact.

The store-aware engine, contained interruption, replacement ownership, dedicated runner/workflow and strict mandatory report registration are implemented. The replacement is deliberately mirrored into WebHosting while its original My certificate, inventory and private-key possession remain independently protected; mirror removal never deletes the shared key. Only after that preservation check does explicit fixture cleanup remove the original owned fixture.

Supporting proof, source and PowerShell parsing checks pass. Native execution remains pending; no certificate/key operation or hosted qualification has been performed locally. Run `certops-windows-webhosting-retention.yml` manually on trusted main to produce the two required Windows Server reports.
