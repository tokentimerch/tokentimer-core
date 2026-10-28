# Azure Key Vault qualification bootstrap

This bootstrap registers the qualification workflow for manual dispatch and
installs its independent hourly janitor on the default branch. It provisions
nothing and does not enable the repository spending opt-in.

The qualification workflow on main is a credential-free placeholder. Dispatching
it on main deliberately fails with an explanation, rather than reporting a
qualification pass. After merge, dispatching that filename with the reviewed
feature branch selects the full workflow from that branch.

The janitor runs only on main in `certops-azure-keyvault-cleanup`, with the separate
cleanup identity. It checks out only the helper directories at signed commit
`1d5515a9d83b3ff5799dfb4e34dbb9679c5d18ea`. No branch input, mutable ref, package
installation, provisioning command or secret-value permission is used. The
helpers check exact subscription, resource-group names, ownership tags, two-hour
TTL, original manual GitHub run/source SHA and complete allowed resource inventory
before group deletion. Cleanup never purges. The pinned owner-run policy accepts
main and the exact temporary qualification branch so it can clean those runs;
the janitor job itself remains main-only.

## Activation after merge

1. Keep `CERTOPS_AZURE_KEYVAULT_LAB_ENABLED=false` initially.
2. Confirm both registered workflows are active, then manually dispatch the
   janitor on main and verify it succeeds. No qualifying orphan groups is a valid
   cleanup result, not qualification evidence.
3. Only then enable the spending opt-in and manually dispatch the full workflow
   on `feat/certops-distribution-extensions`, obtaining independent lab approval.
4. Inspect both sanitized scenario evidence and cleanup status. If interrupted,
   the janitor removes only verified expired groups after their TTL.

```powershell
gh workflow run certops-azure-keyvault-janitor.yml --repo tokentimerch/tokentimer-core --ref main
gh workflow run certops-azure-keyvault-qualification.yml --repo tokentimerch/tokentimer-core --ref feat/certops-distribution-extensions -f location=swedencentral
```

## Replace the bootstrap before final feature merge

> [!WARNING]
> The feature PR's temporary branch exception still must be reverted before its
> merge. Remove its two temporary environment policies too. This bootstrap does
> not authorize bypassing repository protections or lab approval.

Resolve the two workflow add/add conflicts explicitly: replace the registration
placeholder with the full main-only qualification workflow, and replace the pinned
bootstrap janitor with the full main-only janitor using the merged helpers.
Replace the bootstrap-only validator contract and its tests with the full
qualification policy/tests at the same time. Preserve independent cleanup
throughout, verify all temporary groups are gone, then retire this bootstrap
runbook. The original feature PR tracks the exact revert commit and policy IDs.
