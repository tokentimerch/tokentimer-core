# Installed-service re-registration and custody

Re-registration starts the same owned service and keeps the same CNG key
container. The in-use key is not deleted. A request that names a different
container, more than one container, or an explicit ambiguous flag fails
closed and still does not delete the key.

`nativeExecutionQualified` stays false. A missing custody host is a failure.
A blanket netsh reset is refused.

Catalog row `windows-install.reregister` can mention the contract without a
status change.
