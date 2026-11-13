# Retention and exact-version cleanup

Retention preview is report-only by default and never authorizes deletion. Existing workspaces retain at least 30 days, three versions and seven days of rollback preservation by default. The duration starts at publication, or creation if publication time is unavailable; it is not a guarantee measured from last use. Active references and uncertain operations remain protected.

Vault and OpenBao KV v2 exact-version soft deletion require separately qualified agent capabilities, explicit API, group and customer-local opt-ins, and independent approval. Both cleanup capabilities are absent from the current production manifest. Azure version cleanup, purge, destroy and metadata deletion are not supported.

## Operator workflow

1. Review the store namespace, consumer references and retention policy in Distribution. Keep **Report only** enabled while inspecting eligibility and protection reasons.
2. Once the relevant cleanup capability is qualified, configure the agent's local cleanup policy and metadata-only credential, enable CERTOPS_MATERIAL_CLEANUP_ENABLED on the API, and allow cleanup requests for the group.
3. Request approval for an eligible exact version. A different authorized reviewer approves the scoped request in Jobs. Changed policy, membership, authority or store configuration can invalidate the review.
4. Inspect the job and retention view. A claimed cleanup permanently fences its version against reuse; approval, claim and completed deletion are distinct states. History remains visible.

The agent needs permission to read the exact object's metadata and soft-delete its selected version. Use a separate customer-local cleanup credential; do not grant bundle reads, destroy, metadata deletion or purge. Customer-local policy can enforce stricter retention than the group. At least two available versions remain protected.

## Interrupted cleanup

Keep the original job and customer-local journal. After correcting the cause, retry the original authorized intent; the agent checks provider metadata before attempting deletion. If authority expired or changed, request fresh independent review for the same fenced version. Neither retry nor re-review releases the fence or silently clears an uncertain job. An already soft-deleted version can be acknowledged without a second delete; missing or invalid provider evidence remains uncertain.

See [Distribution](distribution-lifecycle.md) for consumer setup, verification and recovery, and [Migration compatibility](distribution-compatibility.md) for upgrade precautions.
