# Distribution extension qualification

OpenBao KV v2 publication and Linux deployment are supported. Azure Key Vault material storage, shared Windows/IIS material deployment, independent Linux staging and exact-version Vault/OpenBao cleanup require separate capability qualification. Configuration alone cannot enable a capability absent from the compiled agent manifest.

Use the [certificate lifecycle qualification guide](../../.github/maintainers/certops/e2e-qualification.md) for trusted-main workflows, exact-artifact evidence and independent acceptance. Run all tests only on disposable, explicitly owned resources; remove only those resources and verify teardown.

## Provider tests

The material provider compatibility test is tests/e2e/material-providers-real.test.js. Configure TT_REAL_KV, TT_REAL_KV_PROVIDER, TT_REAL_KV_ADDRESS and TT_REAL_KV_TOKEN for a disposable Vault or OpenBao instance. Azure testing uses TT_REAL_AZURE and TT_REAL_AZURE_CONFIG with a dedicated vault and protected local configuration. Local provider tests are supporting evidence; use the [Azure qualification runbook](azure-keyvault-ci-qualification.md) for the protected real-provider campaign.

## Windows tests

On an elevated disposable Windows Server with Node 24 and IIS, set TT_WINDOWS_MATERIAL_REAL=1 and run tests/e2e/windows-material-custody-real.test.js and tests/e2e/windows-material-real.test.js. The Core CI Windows material matrix also runs native source tests on Server 2022 and 2025 with fixtures and OpenBao. Tests own their sites, certificate store and temporary service-account task; do not use production stores. These source tests do not replace signed API/worker/installed-agent testing on separate hosts.

## Promotion

Qualify each capability against its intended native package and real target, including approval, authorization, interruptions, recovery and verified cleanup. Azure also needs its protected lab and distinct issuer/consumer identities. Staging and cleanup each need their own installed-agent campaigns. Obtain independent evidence acceptance before changing any production manifest.
