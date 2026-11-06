# Customer-side retention and exact-version cleanup

Retention preview never authorizes deletion. The optional `cleanup-from-store` job implements **Vault/OpenBao KV v2 exact-version soft deletion** on a customer agent, after a separate human approval. The providers have separate capability gates. It does not destroy versions, remove metadata/all versions, purge objects or implement Azure deletion. Public material, job, approval and incident history remains.

Existing workspaces retain manual/report-only defaults: minimum 30 days, three versions and seven days of rollback preservation. Cleanup is disabled. The current release manifest qualifies **neither** `material-cleanup-vault-kv2-v1` **nor** `material-cleanup-openbao-kv2-v1`; runtime settings cannot enable either capability in an unqualified binary.

## Operator workflow

The [2026-11-03 qualification record](pr498-production-qualification-20261103.md)
verifies current-head hosted real-provider cleanup evidence: 15/15 cases for
Vault and 15/15 for OpenBao, with zero skips and successful fixture teardown.
Those signed API/source-executor cases use public setup fixtures. The separate
fresh packaged publication/deployment journeys keep cleanup disabled and do not
replace its missing installed-agent/API/worker release campaign. Both provider
capability gates and cleanup's default-deny settings remain unchanged.

1. Review the customer-owned group/store namespace and all known consumer references. Configure the retention duration, minimum count and rollback period in Distribution Management. Zero durations are explicit policy choices; at least two available versions remain protected. Customer-local policy can enforce a stricter duration.
2. Keep **Report only** enabled to inspect reasons without creating work. Referenced material, pending approvals, current desired/observed versions, resumable rollouts and uncertain/reconcilable operations remain protected.
3. After the agent operation is qualified, configure its local cleanup policy and metadata-only credential, enable `CERTOPS_MATERIAL_CLEANUP_ENABLED=true` on the API and enable cleanup requests with report-only disabled for the group.
4. An administrator selects an eligible exact version and confirms **Request cleanup approval**. Jobs contains the immutable version/provider reference, customer store alias, local profile revision, policy revision, retention settings, scope hash and bounded expiry. A different authorized reviewer approves it through existing Jobs permissions. Workspace-wide approval settings or a standing rollout grant cannot bypass this approval.
5. At agent claim, the API rechecks current scope and eligibility under workspace/group locks, then permanently fences that material version in the same transaction as dispatch. Concurrent rollout admission and cleanup cannot both win. Each subsequent claim/lease renewal revalidates the current authorization.
6. The customer agent checks its own opt-in, profile revision, retention floor, exact store metadata and live lease. It soft deletes only the signed provider version, reads fresh metadata and returns a claim-bound public receipt. No private bundle is fetched by cleanup.
7. Inspect the cleanup job and **planned / fenced / soft deleted** state in retention preview. Approval, dispatch and completion are separate states. The original immutable publication record remains visible in history; a fenced/cleaned version is excluded from rollback selection.

The intent expires after at most 24 hours. Changing relevant policy, membership, reviewer authority, ownership or source/store configuration invalidates old authority. A material version whose original store profile differs from the current group is protected rather than guessed to belong to a new namespace.

## Customer-local configuration

Add this fragment under the existing `materialStores.<alias>.groups.<group UUID>` entry; keep the existing workspace, prefix, SAN and key-algorithm scope:

```json
{
  "cleanup": {
    "softDelete": true,
    "profileRevision": 1,
    "minimumSeconds": 2592000,
    "tokenFile": "/etc/tokentimer/credentials/group-cleanup.token"
  }
}
```

The protected token file stays on the customer agent. It is separate from issuance/consumer credentials. The existing agent execution policy and registered target selectors must permit the exact group UUID, which is the cleanup job's endpoint reference. No public API accepts a Vault endpoint, namespace, path, token file, token value or command for cleanup.

New signed intents separate `operation: "soft-delete"` from `provider: "vault-kv2"`.
Legacy `type: "vault-kv2-soft-delete"` authorizations retain their original signed
payload and journal hash; only an adapter copy is normalized for the shared provider
contract. OpenBao uses `provider: "openbao-kv2"`, `openbao-kv2-soft-delete` receipts
and a separate `material-cleanup-openbao-kv2-v1` gate. Azure and unknown providers
are rejected before cleanup fencing. A Vault legacy intent cannot be relabeled
as OpenBao. Neither cleanup capability is qualified by source tests. A fenced failure
can retry its original intent or obtain a fresh independent review without
releasing the material reuse fence. See [integration compatibility](distribution-compatibility.md).

Vault metadata proves effective deletion only when `deletion_time` is valid and
at or before the current time. Future scheduled deletion does not bypass retention
or count as completed deletion. Both pre-delete shortcuts and post-delete readback
apply this rule. Missing/invalid/future post-delete evidence remains uncertain and
cannot produce a `softDeleted: true` receipt.

A narrowly scoped Vault policy can grant only:

```hcl
path "secret/metadata/<customer-prefix>/<group>/bundles/*" {
  capabilities = ["read"]
}
path "secret/delete/<customer-prefix>/<group>/bundles/*" {
  capabilities = ["update"]
}
```

Do not grant data reads, destroy, metadata deletion or purge for this operation. The group prefix comes from existing customer-local configuration, and the agent derives its exact object from the immutable material UUID. The signed intent contains one positive provider-version integer, never an arbitrary path or version list. Namespace, TLS CA and transport settings remain the existing local store settings.

The API requires an active, recently seen issuer agent with fresh material-store and cleanup capabilities. The agent independently applies its compiled qualification gate and Linux platform gate. Qualification of existing publication/deployment capabilities does not qualify cleanup.

## Durable fencing and recovery

```mermaid
stateDiagram-v2
  [*] --> planned: administrator request
  planned --> planned: independent Jobs review
  planned --> fenced: atomic eligibility recheck and signed claim
  fenced --> fenced: lease loss / cancelled job / uncertain response
  fenced --> fenced: explicit fresh review when authority changes
  fenced --> soft_deleted: fresh exact-version claim receipt
```

The `certops_material_cleanups` row is public lifecycle history. SQL triggers prevent new job, rollout or current-consumer references to a fenced/soft-deleted version. Lease expiry, rejection, cancellation, restart and local repair never release the fence. The material-version identity and the fence cannot be reassigned to another workspace/group/version. The minimum retained-version calculation excludes already fenced versions, so concurrent cleanup plans cannot each count the other's material as a surviving rollback copy.

For an interrupted delete, inspect the original job and customer-local journal. After fixing local prerequisites, retry that authorized job with `POST /api/v1/workspaces/:id/certops/distribution-jobs/:jobId/retry`, sending an empty JSON body. This preserves its exact intent and approval. The agent checks fresh metadata first: an already soft-deleted version yields a fresh receipt without another delete. A missing/destroyed object is reported explicitly rather than claimed as successful soft deletion. Live local locks are never stolen.

If authority changed or expired, **Request fresh cleanup review** creates a new independently approved job for the same fenced object. A live claimed/running job cannot be replaced. Historical uncertain jobs and local journals remain intact; re-review does not silently clear their reconciliation state. Each new job has a separate local journal while the permanent object fence remains.

Restoring bytes customer-side does not make the old fenced UUID deployable again. Any subsequent managed publication must use its own immutable version and normal authorization. Whole-workspace deletion explicitly removes that workspace's lifecycle metadata transactionally; secret-store cleanup itself never deletes public history.

## API and scope

`POST /api/v1/workspaces/:id/certops/distribution-groups/:groupId/cleanups` requires an administrator cookie session, active workspace and the existing CertOps write guards:

```json
{
  "materialVersionId": "<exact immutable material UUID>",
  "expectedRevision": 3,
  "reauthorize": false
}
```

The closed request accepts no provider credentials or private material. Duplicate requests return the existing logical request. New destructive jobs always require genuine approval, including when created through the generic job service. Authorization and eligibility are rechecked at claim, not trusted from a cached preview. The control plane stores public approval scope, fences, receipts and audit events only.

[Vault KV v2](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#delete-secret-versions) and [OpenBao KV v2](https://openbao.org/api-docs/secret/kv/kv-v2/) separate soft deletion, destruction and metadata deletion. This connector implements the first operation only, behind each provider's separate cleanup qualification gate. Arbitrary Azure individual-version deletion is unavailable. No generic delete/purge interface is exposed.

## Completion and acknowledgement recovery

Receipt validation, cleanup metadata, audit, nonce consumption, agent sequence and
terminal job state commit in one transaction. Validation failure or an interrupted
transaction leaves the job/fence intact and does not spend its result nonce. A
fresh valid receipt can retry. A commit followed by a lost HTTP response is
acknowledged on retry using the exact persisted receipt, even after API restart or
lease expiry; it never initiates another provider mutation. A changed receipt is
rejected rather than being acknowledged solely because its status says succeeded.

Malformed receipts return 422; claim/identity mismatches and expired cleanup
leases return 409. Unexpected storage/runtime exceptions remain 500. These
rejections never imply that provider deletion was undone. Preserve the journal
and permanent fence and follow original-intent reconciliation. See the
[acceptance record](pr498-completion-20261103.md) for the reproduced HTTP error
mapping defect and the unresolved provenance of the earlier reported incident.
That historical limitation does not establish a current valid-receipt failure.
Current real-provider functional evidence and the separate closed qualification
gates are classified in the [merge-readiness matrix](pr498-merge-readiness-20261103.md).

Run the normal migration plan before starting updated API/worker/agents. See the [lifecycle guide](distribution-lifecycle.md) and [current implementation/qualification matrix](distribution-lifecycle-status.md). Real isolated Vault metadata/delete ACL tests, PostgreSQL reference races, signed claims/nonces, retained-count concurrency, uncertain retry and fresh re-review are functional support evidence; they do not promote a shipped native capability.
