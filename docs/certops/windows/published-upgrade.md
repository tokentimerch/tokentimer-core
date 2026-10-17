# Authenticated published-package upgrade

Published predecessor archives `0.17.2` and `0.17.3` do not contain
`tokentimer-agent-host-amd64.exe` or `tokentimer-agent-host-arm64.exe`.
The contract refuses any member that supplies those executables. It does not
copy a current binary into the archive and it does not report a successful
migration.

`publishedPackageMigrationQualified` stays false. `upgradeSynthesized` stays
false. `nativeExecutionQualified` stays false. A missing archive host is a
failure, not a pass.

The suite level for this gap is `real-host`. The proof object uses evidence
level `script`. Those are different fields. Catalog row
`windows-install.upgrade-rollback` can mention the refusal without a status
change.
