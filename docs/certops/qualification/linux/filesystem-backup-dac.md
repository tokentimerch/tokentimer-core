# Linux deployment backup-directory permission refusal

This source extends the direct production filesystem deployment scope. It runs
only in an explicitly disposable GitHub-hosted Linux qualification environment
as root, resolves the actual nonroot `nobody` UID/GID, then launches the original
production deployer in a child with that identity. Each child must independently
observe zero effective Linux capabilities. No filesystem implementation, clock,
production command result, or permission error is substituted.

The parent first requires real initial deployment and rotation under the same
nonroot identity. Independent reads check certificate/key correspondence, DNS
identity, chain bytes, owner/group and mode0600. The same nonroot child also
requires native OpenSSL verification of the actual deployed certificate and
chain paths after each successful deployment. It then changes only its owned
backup directory to mode0500. An independent exclusive-write control must fail
with actual `EACCES`; production rotation must refuse at stage `backup`, before
any live destination replacement. All predecessor certificate/key/chain bytes,
inodes, modes, ownership and an adjacent sentinel outside all allowlisted deployment/staging/backup
directories must stay unchanged.
This is a pre-mutation refusal, not a rollback-success claim.

After restoring the exact original backup directory identity and permissions,
the same child identity must complete genuine deployment and pass the independent
checks again. The closed public proof contains only the measured nonroot IDs and
mandatory booleans. Child inputs travel over stdin, private staging keys remain
mode0600 inside the owned temporary root, and raw errors, private bytes and local
snapshots are never artifacts. Unproven permission restoration preserves the
owned root for recovery; it must not be uploaded.

`scripts/certops-linux-filesystem-permission.js` exports
`qualifyBackupDirectoryDac({first, second})`, accepting two genuinely distinct
certificate/key/chain fixtures. Its standalone `--report qualification-results/filesystem-linux-dac.json` entry
generates its own genuine OpenSSL fixtures. The existing manual filesystem
workflow runs it separately with the selected absolute Node24 under sudo,
preserving exactly four nonsecret qualification/candidate variables. Its distinct
Linux report is independently verified, then uploaded alongside the original
filesystem report in the existing per-OS artifact; the upload permits exactly
those two public JSON files. Windows requirements are unchanged. Mandatory
release metadata binds separate Ubuntu22.04/24.04 slots to the closed native
proof and all reviewed sources.
Pure proof and benign snapshot tests do not qualify Linux execution, signed API
dispatch, installed services, daemon reload or TLS cutover. Native execution is
pending.
