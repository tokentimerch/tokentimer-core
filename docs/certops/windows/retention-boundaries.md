# Retention boundaries

A full 24 hour elapsed qualification cannot be shortened. Any wait below 24
hours records `twentyFourHourElapsedQualified: false` and fails the
qualification gate. This script contract also refuses to claim the elapsed
run when the wait is 24 hours or longer.

Configuration boundaries covered here are zero, negative, below the 24 hour
minimum, the 24 hour minimum, the 168 hour default, above that default
through 720 hours, and above the 720 hour maximum. Deadline boundaries are
before, exactly at, and after the deadline. None of those classifications
set the elapsed flag.

`nativeExecutionQualified` stays false. Catalog rows
`windows-retention.boundary-config` and `windows-retention.interrupted-delete`
can mention the contract without a status change.
