# Native CNG private-export refusal qualification

The protected Windows Server 2022/2025 host suite requires `windows-cng-private-export-refusal`. It reopens the ten already owned accepted certificates: RSA 2048/3072/4096 and EC P-256/P-384, each in LocalMachine My and WebHosting. Every native sample is mandatory, and the helper source hash is bound into both release environment reports.

The exact certificate, CNG container, provider, key size, machine-key identity and export policy are read independently before and after the operation. The protected key signs a fresh public nonce both before and after the private-export attempt. Node verifies both signatures using the independently parsed certificate's public key; EC signatures explicitly use IEEE P1363 encoding.

Each sample creates a uniquely owned exportable control with the same Microsoft Software Key Storage Provider and algorithm/key size. Its actual PKCS8 private export must succeed, proving that the selected API/blob format works for that profile. The protected key's same private-export call must throw a native cryptographic exception. The report records its bounded HRESULT without inventing a policy-specific error classification; a functional key, unchanged None policy, successful same-profile control and failed private export form the custody oracle. The [official export-policy definitions](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cngexportpolicies) describe None and the explicit exportable control flags.

Private arrays from either attempt stay inside the native process. Its finally block clears every returned owned buffer, verifies the bytes are zero, then releases references and key handles. No private blob is printed, written to a file or placed in the report. Work-directory contents must remain unchanged. Public signatures are used transiently for verification and are excluded from the final report too.

Control names are recorded in the parent owned-container cleanup inventory before creation. Per-sample finally deletes the exact control, outer finally retries every recorded control, and independent native key lookup must prove absence. Certificate/store/container custody must remain unchanged. An export, signature or cleanup failure fails the required scenario.

Portable signature and negative-proof tests, PowerShell syntax and source/wiring checks passed. Native CNG calls were not executed on the development workstation. Actual hosted execution remains pending; this source does not qualify additional providers, architectures or an enterprise CA.
