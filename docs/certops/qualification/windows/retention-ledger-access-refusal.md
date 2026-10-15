# Native retention ledger access refusal

This supporting Windows fixture tests the production ledger readers against real
filesystem access denial. It creates one normal production ledger with explicit
local prerequisites, then tests `ReadData` denial for that file and
`ListDirectory` denial for its ledger directory. It creates no certificate, CNG
key, CA request, service, or elapsed-retention deadline.

A current-token child begins suspended inside an owned retained native Job
Object. Its native holder opens the exact expected volume/file identity with
`READ_CONTROL`, `WRITE_DAC` and metadata rights, excluding delete sharing. It
rejects reparse points and mismatched native identities. Both the explicit deny
and exact DACL restoration use that same retained handle through file-object
`GetSecurityInfo`/`SetSecurityInfo`; restoration never reopens an unverified
filename. The handle grants no data-reading or directory-listing rights.

After the child's nonce, SID, PID and creation identity match the contained
process, the parent independently opens/reads or enumerates the actual target.
Only an actual `EACCES` or `EPERM` permits the production assertion. A privileged
token bypassing the deny therefore cannot turn this case green. The production
reader must throw the real access error, rather than treating unreadable state
as a missing row or empty inventory.

Each fault ends with exact native SDDL restoration, unchanged bytes and native
file identities, successful production reads, and a normally closed holder plus
verified zero native Job members. The protocol uses bounded, exclusive receipts
and a nonce-bound release. Every error still attempts owned Job drainage. A
failed or uncertain restore/drain leaves both an in-memory hold and a durable
parent receipt; broad fixture cleanup must check that guard first.

The offline proof/guard tests and native C# compile-only check are supporting
validation. The actual ACL denial cases remain pending native Windows execution.
They do not qualify an installed agent, certificate deletion, or real retention
passage.
