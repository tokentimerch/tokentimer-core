# Native Windows journal ACL refusal controls

This source adds two bounded temporary-filesystem controls to the Windows host qualification surface. It has not been executed on a native Windows qualification host.

The first denies `ReadData` on an actual production v2 AD CS journal. An independent OS read must fail with `EACCES` or `EPERM` before the production reader may count as refusing it. The journal must be classified as corrupt, the exact enrollment container must remain protected, and the global protected-container scan must defer instead of returning an empty set.

The second denies `ListDirectory` on the enrollment root. An independent OS directory listing must fail before the global protection scan is required to defer. This catches unreadable inventory being mistaken for an absent directory.

The positive fixture uses the production software key/CSR writer and production prepared-journal writer. The temporary software private key is removed before either ACL fault. No CNG key, CA request, certificate, IIS binding or installed service is created. Public CSR and journal bytes, native file IDs and directory identities remain unchanged; each exact original ACL is restored and successful production reads are repeated. A durable parent guard prevents cleanup while restoration is uncertain. Foreign or replaced paths are refused.

The public proof scope is `native-temporary-adcs-journal-acl-refusals-not-installed-enrollment`. Both `installedServiceQualified` and `nativeCngQualified` must remain false. Pure contract tests do not qualify either native scenario. Installed-service recovery and real protected enrollment custody remain separate qualification requirements.

Implementation: `packages/agent/scripts/host/journal-read-refusal-fixture.js`. Pure supporting checks: `scripts/certops-windows-journal-read.test.js`.
