# Native ARM64 execution

A qualifying ARM64 result requires process architecture `arm64` and a real
ARM64 host probe. On any other architecture, or when that host is absent, the
result is a failure. It is never a pass.

`nativeArm64ExecutionQualified` stays false in this checkout because the real
probe is not present. `nativeExecutionQualified` stays false.
`hostCapabilityAbsentIsPass` stays false.

The suite level for this gap is `real-host`. The proof object uses evidence
level `script`. Catalog row `windows-install.release-package` can mention the
refusal without a status change.
