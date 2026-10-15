# Native backup-directory alias refusal

The existing filesystem host suite requires this source on Ubuntu 22.04/24.04
and Windows Server 2022/2025. It creates an actual directory symlink or junction
under an allowed directory, pointing to a separately owned directory outside that
allowlist. No operating-system prerequisite may silently skip the case.

After genuine initial certificate/key/chain installation, a real production
rotation with that explicit `backupDir` must return `realpath-policy` before
creating any backup or changing predecessor bytes, inode, ownership or modes.
The outside sentinel and both private staging files must remain exact. An
independent native key-permission oracle checks both the predecessor and later
successful replacement. Local file hashes and key bytes never enter the report.

The harness verifies and removes its exact alias, creates a real allowed backup
directory, then retries the actual rotation. All three predecessor backups must
match the original certificate, key and chain; the installed replacement must
have the expected DNS identity, private-key correspondence and CA signature.
This is refusal before mutation followed by recovery; it does not qualify a
rollback, API admission, service deployment or uninterrupted serving behavior.

A durable owner receipt precedes all deployment operations. Failed or unknown
ownership leaves that receipt and private fixture state in place, and the parent
refuses recursive cleanup. Successful cleanup checks native directory and receipt
identities again. Pure schema and benign file tests are supporting checks;
protected native execution remains pending.
