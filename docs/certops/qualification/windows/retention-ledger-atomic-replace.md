# Retention ledger atomic replacement refusal

The required `windows-host` scenario `windows-retention-atomic-replace-refusal`
exercises the production retention writer against an exclusively created temporary
ledger. It uses public synthetic thumbprints and container identifiers. It never
reads or mutates an installed agent's state, certificate store, CNG keys, services
or registry.

An independently identified Windows PowerShell 5.1 child opens the existing row
with a real native file handle, allowing read/write sharing and excluding delete
sharing. Its atomic receipt must match the parent's measured process identity,
random release token and the actual file ID. The production `writeLedgerRow`
must fail specifically at `rename` to that exact row, rather than at validation,
file creation or ACL enforcement. The complete original bytes and file identity
must survive; no failed temporary write may remain in the ledger directory.

After the child closes its handle and exits cleanly, the same production writer
must replace the row successfully. A fresh Node process independently reads the
exact updated row through the production reader. Native ACL checks require
protected restrictive permissions on both the ledger directory and the new file.
Exact owned temporary-directory cleanup is a mandatory final fact. Cleanup refuses
recursive deletion while the child remains live or cannot be identified.

The report's `nativeRetentionAtomicReplace` contains only twelve boolean oracles.
Source fingerprints bind the fixture, native handle child, production writer and
platform permission/durability code. Release verification rejects missing or
false facts, and the collector discards extra fields before writing artifacts.
This scenario shares the existing Windows Server 2022 and 2025 host slots.

The focused fixture ran successfully on a local Windows workstation with all
twelve oracles true and owned cleanup verified. That supporting execution does
not qualify either hosted Server slot or the full host suite. It proves atomic
replacement refusal and later successful persistence, not power-loss durability,
crash interception during a write, native certificate deletion or every torn-write
phase.
