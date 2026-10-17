# Unmodified fixed-root installation

This contract covers an installation that already exists at
`C:\ProgramData\TokenTimerAgent`. The owned run manifest lives in a separate
directory that contains the run id. The plan may read the existing root. It
must not copy, rename, or delete that root.

The proof records `existingRootPreserved` and `installerRewroteFixedRoot:
false`. `nativeExecutionQualified` stays false. A missing host is a failure.
Cleanup may name only the owned hostname binding. A blanket netsh reset is
refused.

This script proof does not qualify a fresh canonical install, a published
upgrade, or native execution on Server 2022 or Server 2025.
Catalog rows `windows-install.release-package` and `windows-install.new-service`
can mention the contract. Their status is not promoted.
