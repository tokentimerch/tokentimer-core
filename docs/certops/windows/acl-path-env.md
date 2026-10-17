# ACL, path, and environment failures

Three defects fail closed:

- a weak ACL, including an Everyone read grant or an unprotected DACL
- an unquoted binary path that contains spaces
- a missing LocalSystem environment

Each refusal has its own proof. `hostCapabilityAbsentIsPass` stays false.
`nativeExecutionQualified` stays false. The owned site path may contain
spaces, and the only binding cleanup selector is the owned hostname binding.
A blanket netsh reset is refused.

A missing host is a failure. Catalog rows `windows-install.state-acl`,
`windows-install.path-quoting`, and `windows-install.system-environment` can
mention the contract without a status change.
