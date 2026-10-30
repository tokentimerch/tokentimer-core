# ADR-0015: Material providers and Windows shared-material consumers

Date: 2026-10-25. Status: Proposed (implemented); production qualification is per
capability, independently of schema availability. Tracks Core #248.

## Decision

Extend the distribution lifecycle introduced in PR #329. Issuance, customer
key custody and deployment remain separate outcomes. Agents alone publish or
retrieve bundles; API/worker code stores public references and evidence. Do
not reuse the control-plane Azure inventory client, or add network clients
to orchestration. The existing `vault-managed` custody value and `vault:`
opaque reference scheme continue to mean customer secret-store custody;
`material_store_provider` now identifies the actual provider explicitly.

`createMaterialStore` selects Vault KV v2, OpenBao KV v2 or Azure Key Vault.
Vault and OpenBao share the same adapter. Existing configurations without a
provider retain Vault semantics, numeric revision fields and signed payloads.
New publication types and optional deployment/receipt provider identifiers
are additive. An explicitly configured provider must match the signed intent.

Azure uses the **Secrets value API**, with one deterministic, tenant/group/
logical-version-scoped secret name containing the validated bundle JSON.
The Certificates API's public certificate metadata is insufficient for
private-key distribution. Non-exportable keys, Managed HSM, certificate-only
objects, sovereign-cloud endpoints and bundles over 25 KiB are unsupported.
No certificate import or CA order occurs in Azure.

Azure secret versions are opaque 32-hex identifiers. Preserve KV v2's integer
database column; add `provider_version_ref` for Azure and return a number or
string, respectively, in the existing `providerVersion` wire field. Published
rows and group/provider authority remain immutable under the existing
triggers. Database constraints reject a provider/version-type mismatch.
The canonical provider migration is 82, following main's unchanged migration
78 for installed-file assurance and migrations 79–81 for auto-sync telemetry.
Explicit preview-history composition retains providers already applied at 78,
79 or 81 and appends only missing schema; no recorded row is renamed or rewritten.
The [cross-PR numbering plan](../migrations/open-pr-numbering.md) reserves distinct
versions for recipient verification, PagerDuty and distribution lifecycle work.
Rollout approval snapshots and signed consumer jobs bind the exact provider
and version. Consumers never request an unversioned/latest Azure secret.

Azure Set Secret has no create-only/CAS precondition. The single authorized
issuer and existing group lock remain mandatory. Before a write, discover
versions of the unique logical object. Adopt only one exact, fully validated
bundle; multiple versions fail closed. Persist a local write-ahead marker
before PUT. After a lost response, reconcile by enumerating then reading the
exact version. An absent object after an uncertain write never authorizes a
second PUT or a fresh CA order. Proven authentication/configuration rejection
can clear the write marker; an ambiguous result cannot. This detects
conflicting writers but does not claim Azure provides atomic CAS. Customers
must exclude other writers from the publication namespace.

Azure authentication is customer-local: workload federation, Azure IMDS
managed identity, or a protected renewable access-token sink. Renew identities
before expiry, reread token sinks on each request, use the fixed public Azure
authority/resource, and bound GET retries. Never follow redirects, challenge
URLs or version-list next links. PUT timeouts are reconciled, never retried.
Provider bodies, tokens, private-key bytes and endpoint URLs cannot enter
public receipts or error messages.

## Windows connector

The existing CNG enrollment surface intentionally has no shared-key import.
Keep it unchanged. Add the focused `windows-material-iis-v1` local connector
contract: exact approved `(site,address,port,SNI,store)` target, service-account
SIDs, `rebind` activation, preflight, import, activate, verify and reconciliation.
Issue #366's broader service connector framework is still open; arbitrary
Windows services and restart/script actions are outside this contract.

Build an encrypted PKCS#12 import bundle inside the customer agent using
Node's PKCS#8 encryption and RFC 7292 password integrity. Stage inputs under
verified owner/SYSTEM ACLs. A fixed installed PowerShell/C# helper imports
using native Crypt32 with machine/CNG flags and without export/overwrite
flags. Verify persisted non-exportable CNG custody, exact SHA-256 identity,
private-key signing association and a protected SYSTEM/Administrators plus
explicit service-account read DACL. Existing keys are adopted only when all
checks pass; their ACLs are never rewritten. Chain certificates enter only
the selected personal store, never trusted roots.

Reuse the existing CNG store locks and IIS binding/rollback helper. Add a
cross-store IIS mutex because HTTP.sys selectors span sites and stores. Exact
IIS preflight rejects shared selectors and centralized-certificate-store mode.
Preserve SNI/other binding flags, update IIS metadata, reread store and binding,
then verify every configured TLS listener against the pinned fingerprint and
authorized hostname. Lock-loss/job cancellation signals abort helper processes.

The material binding journal is written **before import**, and the existing
attempt journal records the side effect. Interrupted import/activation, lease
loss or failed verification stays uncertain, including when the older IIS
helper attempted compensation. Read-only local reconciliation proves installed
key association, IIS metadata, HTTP.sys and every listener before clearing that
marker. The subsequent original signed retry still needs current authorization
and generation. Explicit rollback uses a newly authorized generation pinned to
a retained, permitted material version. No certificate/key deletion is added.

Protected PFX input files are removed after helpers finish and swept only while
the global connector mutex proves no live helper owns them. Hard-killed
binding-lock files require the existing operator reconciliation procedure.
JavaScript strings and platform crypto memory do not provide guaranteed
zeroization; custody remains inside customer-controlled hosts.

## Compatibility and qualification

Approval, separation of duties, canaries, concurrency, required/optional
consumers, expiry/revocation admission, offline-agent claim rules and immutable
retirement fences are reused. New providers and Windows import have separate
build-time qualification capabilities, checked at dispatch and execution.
Do not qualify Azure using its mock tests or Windows using a client-OS parser
test. Exact production-artifact campaign requirements in ADR-0012 still apply.

Migration 78 follows all supported Core histories without rewriting old ledger
rows. Editions must compose this migration and the widened contracts together;
their release pins are not changed by this implementation. Cloud's older
independent migration/route overlay needs review on adoption; Enterprise inherits
these base services. Neither edition gains customer provider credentials.

## Sources

- [Azure Set Secret](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/set-secret/set-secret): every successful set creates a version.
- [Azure version enumeration](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret-versions/get-secret-versions): list permission and public identifiers.
- [OpenBao KV v2](https://openbao.org/docs/secrets/kv/kv-v2/): CAS and pinned-version semantics.
- [Native PFX import](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-pfximportcertstore): machine/CNG and exportability flags.
