# Native certificate and CNG key usage

The protected Windows host suite checks all five supported key profiles in both
`LocalMachine\My` and `LocalMachine\WebHosting`. Its signer copies extensions
from the actual production-generated CSR. The independent native .NET
`X509KeyUsageExtension` parser then reads the accepted certificate's actual DER.
RSA requires exactly digital signature and key encipherment (`160`/`0xa0`);
P-256/P-384 require exactly digital signature (`128`/`0x80`). Missing extensions
and additional usage bits fail the host qualification.

Certificate KeyUsage differs from the key's NCrypt operations policy.
[Microsoft's certreq reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1)
documents these as separate `KeyUsage` and `KeyUsageProperty` settings.
The production request does not set an exact `KeyUsageProperty` mask. The native
oracle requires signing permission and records the observed operations. Known
decryption/signing/agreement flag combinations and the documented `AllUsages`
value (`0x00ffffff`) are accepted when signing is allowed. Undefined operation
bits are refused. This does not claim an exact default policy or ECDSA
decryption support; the
[CngKeyUsages reference](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cngkeyusages)
distinguishes flags from operations an algorithm can perform.

The bounded `nativeKeyUsage` report contains ten exact profile/store identities,
certificate usage flags and native allowed-operation masks. It carries no key
material. Release verification requires every case and the current oracle source
fingerprint. Existing provider, key-size, non-exportability and independent
signature/export-refusal controls remain separate required observations.

Portable proof tests cover refusal paths. Actual native execution on both
qualified Windows Server versions remains pending; supporting tests do not
qualify certificate creation or native key policy.
