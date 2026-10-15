# Native destination-scoped backup retention

This source uses real production filesystem deployment with
`backupRetentionCount: 1`, three genuine certificate/key fixtures and the actual
clock. It never injects time, filesystem implementations or command results.
Protected Ubuntu and Windows execution remains pending.

Two destinations deliberately use the same certificate, key and chain basenames
and one shared explicit backup directory. Both receive actual initial deployment
and rotation. Two more rotations affect only the first destination. Each must
remove that destination's older owned generation and preserve its current three
rollback files, the other destination's exact backup bytes/inodes/modes, a legacy
timestamp-only backup, an operator file and an outside sentinel.

Independent native file observations verify every predecessor's leaf identity,
private-key correspondence, chain bytes/CA signature, DNS and key permissions.
Both final target pairs and original private staging files remain exact. Public
proof contains only fingerprints, fixed counts and mandatory observations.
Legacy files are preserved for operator cleanup; this is bounded generation
retention, not elapsed-age expiry or a cross-process locking qualification.

The helper registers a durable receipt before deployments and refuses parent
cleanup while ownership is unresolved. Successful cleanup rechecks original
directory, receipt and outside-sentinel identities before removing owned files.
Pure proof and temporary-file tests cannot qualify the native host scenario.
The mandatory filesystem host case and strict collection/release projection require
all measured observations and ten critical source fingerprints on all four slots.
