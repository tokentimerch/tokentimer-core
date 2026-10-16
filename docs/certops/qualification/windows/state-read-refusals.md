# Native state read-access refusals

Three supporting host scenarios deny real Windows file `ReadData` access for
the executing identity on owned temporary `config.json`, `credential` and
`signing-key-pin.json` files. Each production reader must first return the exact
owned configuration, credential or signing identity. An
independent native filesystem read must then fail with `EACCES` or `EPERM`
before its production reader refusal counts.

- `windows-state-config-read-denied`
- `windows-state-credential-read-denied`
- `windows-state-signing-pin-read-denied`

The fixture restores each exact original ACL in a `finally` block, verifies
unchanged native file identity and bytes, and requires the real reader to
recover. Paths, ACLs, file contents and generated credential values are not
public evidence. Only bounded proof facts and explicit supporting scope enter
reports. Cleanup accepts only the exact newly created directory identity under
the parent-owned fixture directory.
An explicit parent cleanup guard is durable before each ACL mutation and is
removed only after exact restoration. If restoration cannot be proven, the
guard preserves owned state and fails qualification instead of erasing evidence.

These cases exercise production state readers with actual native filesystem
permissions. They do not install or start a Windows service, modify a registry
key, create certificate/CNG material, contact a server or qualify installed
service startup. The pin is an independently generated public Ed25519 key; no
certificate private key is involved. Pure proof tests do not execute ACL
mutations or qualify a native host.
