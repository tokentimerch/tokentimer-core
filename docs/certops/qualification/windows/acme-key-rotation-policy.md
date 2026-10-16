# Windows ACME key rotation policy

Windows IIS ACME enrollment creates a fresh non-exportable machine CNG key. It does not support private-key reuse. Profiles must specify `keyRotationPolicy.rotateOnRenew=true`; explicit false is refused with `WINDOWS_ACME_KEY_REUSE_UNSUPPORTED`. New inventory-derived Windows profiles with omitted policy default to true. Existing explicit false values are never silently changed: an operator must update the profile before renewal can resume.

The signed job defense also refuses `keyRotation=false` before native operations or CA allocation, including signed dry runs. Omitted legacy job policy retains fresh-key behavior. Linux file-key reuse remains supported. AD CS continues to use its separately frozen fresh-enrollment policy.

The supporting tests check both real/dry-run admission and Windows/Linux wire boundaries. The native refusal helper uses a genuinely issued installed CNG/IIS certificate, submits a public invalid profile edit and independently compares the stored profile, job inventory, native certificate/key metadata, protected custody, HTTP.sys binding, trusted TLS, configuration/credentials and observed DNS traffic. This is an API admission refusal, not a claim that an invalid job passed strict dispatch. Native execution is pending.

The existing installed Windows stack requires the named `windows-acme-public-key-reuse-refusal` subtest in all five key profiles on Server 2022 and 2025. Its closed `nativeWindowsKeyReuseRefusal` proof is attached only to the successful complete journey, after owned cleanup. Current source digests and strict release/collector validation prevent missing or stale proof from qualifying.
