# Protected-key and journal recovery

An orphan journal, a weak ACL, and an unreadable journal each fail closed.
The plan queries the owned service and does not delete the protected key.

`protectedKeyDeleted` and `inUseKeyDeleted` stay false.
`nativeExecutionQualified` stays false. A missing journal host is a failure.
A blanket netsh reset is refused.

Catalog rows `windows-retention.container-sweep`,
`windows-retention.durable-ledger`, and `execution.journal-corruption` can
mention the contract without a status change.
