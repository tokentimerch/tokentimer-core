# Concurrent paired filesystem rotations

The native filesystem host producer invokes two production
`deployCertificateAndKey` calls for the same certificate, key and chain paths
before awaiting either. A genuine distinct certificate/key baseline is already
installed. Both contenders have independent key/SPKI identities. The fixture
uses the product's default backup directory alongside the live files, ordinary
filesystem operations and the actual clock; it does not substitute filesystem
methods or insert timing delays.

The documented in-process destination mutex must preserve invocation order.
Both rotations must complete as actual mutations. Independent disk observations
require the final certificate/key/chain to match the final contender, the first
contender's backups to preserve the original baseline, and the second's backups
to preserve the first contender. All six backup paths must remain distinct and
contain the exact expected certificate, private key and chain. Local key ACL/mode
checks use the existing native Windows/Linux permission oracle. Original staged
keys and a sentinel outside all allowlisted deployment directories stay unchanged.

One retained loopback TLS listener reads the actual disk files for a baseline
connection and a new connection after both mutations settle. Both clients use
the exact fixture CA and hostname verification; the final served fingerprint must
match the final disk certificate. This qualifies stable checkpoints, not
uninterrupted availability during the individual file writes. It does not claim
cross-process locking, signed API dispatch, ACME issuance or daemon reload.

Every started deploy promise settles before cleanup. The fixture destroys only
its retained sockets and awaits native listener close before removing its owned
files. Unknown listener drainage or ownership retains a durable guard that blocks
the parent host producer's cleanup. Private keys, local file hashes and receipt
paths never enter the public proof or artifact upload.

The source is shared by Ubuntu22.04/24.04 and Windows Server2022/2025 native
filesystem slots. Pure proof/lineage and benign file controls do not qualify those
hosts; protected native execution remains pending. Strict collection and release verification require the mandatory scenario, its
closed native proof and all eight critical source fingerprints.
