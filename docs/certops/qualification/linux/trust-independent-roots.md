# Independent native trust ownership

This source creates two unrelated self-signed roots and two genuine leaves,
each signed by its respective root. Actual default OpenSSL verification must
reject both leaves before installation and accept both after production native
distribution and finalized durable ownership receipts. No explicit `-CAfile` or
`-untrusted` option substitutes for the operating system's derived trust.

Production revocation removes only the first receipt-owned root. Its leaf must
then fail default verification while the second leaf continues to verify. The
second root's source file and durable receipt must retain exact bytes, native
identity and permissions. Ubuntu additionally independently observes the native
source symlink names and targets under `/etc/ssl/certs`; the same references must
still resolve to the second root. Alma observes the second root in the native
derived certificate directory. Refresh tools may regenerate derived files, so
the source does not claim that regenerated symlink inodes remain unchanged.

Finally, actual production revocation removes the second owned root and both
leaves become untrusted. Every actual source path is registered with the parent
before distribution; a durable local guard prevents recursive cleanup after
uncertain mutation or changed ownership. Public CA files remain for the parent's
final independent absence checks before it removes the restricted fixture root.
Keys, PEM contents, paths and native store inventories never enter the proof.

This is sequential native selective ownership, not simultaneous OS refresh,
cross-process serialization or signed API/service dispatch. The helper and pure
adversaries are source implemented; the parent and mandatory report integration require all observations and eleven
critical source fingerprints. Protected Ubuntu/Alma execution remains pending.
