# Installed public renewal with failed rollback

The manual `certops-windows-failed-rollback.yml` workflow runs a separate Azure-free Server 2022/2025 RSA2048 lane. It requires a genuine installed-agent public issuance, an independently trusted IIS endpoint and an owned sibling before creating its fault. Native execution remains pending.

A SYSTEM process starts suspended inside the retained qualification Job Object. It retains the predecessor's original certificate context and non-exportable CNG key, independently signs a challenge, and removes only the public My-store entry. It never exports, recreates, deletes or changes the ACL of the key. The owned concrete-IP HTTP.sys shadow and sibling must still serve the exact trusted predecessor after removal; cached behavior is measured rather than assumed.

A genuine public renewal must accept a distinct CA leaf and protected key, then fail TLS verification. Its actual signed current claim must persist `validation.failed` with `step=iis-bind`, `code=VERIFY_FAILED` and `rolledBack=false`. Independent native inventory must show that the predecessor SNI binding was not restored. The installed protocol does not expose the direct executor's rollback diagnostic field, so the report does not invent one.

The holder restores the same retained certificate context. A fresh store read must prove the original DER, container, unique key identity, provider, machine-key policy and private-key possession. Natural holder exit, native Job drainage and closed handles are required before removing the exact shadow. A distinct public renewal must then succeed with a third leaf/key, current-claim verification evidence and trusted TLS. This is an explicit fresh retry, not automatic recovery of the failed operation.

Original profile/configuration/credential/signing-pin bytes, installed process identities, predecessor custody and sibling binding/TLS are preserved. Unknown process, public association, endpoint or protocol ownership blocks certificate/key/database/private-state cleanup. Native facts are published only after the complete owned parent cleanup; the producer also waits for Pebble teardown before writing a passing report.

The finite bounds are 20 minutes for the native test, 22 for its producer, 27 for the receipt wait, 28 for its SYSTEM task and 40 for the hosted job. This lane does not qualify bind failure, automatic reconciliation, transient candidate binding observation, AppID preservation, custom accounts, or additional algorithms.
