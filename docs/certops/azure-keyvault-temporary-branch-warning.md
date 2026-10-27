# WARNING: TEMPORARY AZURE CI BRANCH EXCEPTION — REVERT BEFORE MERGING

> [!WARNING]
> Azure Key Vault qualification temporarily accepts manual runs from
> `feat/certops-distribution-extensions`, in addition to `main`.
> **Remove this exception before merging. This is not a permanent trust policy.**

The exception is confined to Key Vault workflow job gates, the credential-free
preflight, the OIDC wrapper, shared ref/environment policy, cleanup owner-run
verification, and the corresponding workflow validation/tests. Other branches,
tags, PR events and automatic branch runs remain denied. AD CS is unchanged.
Independent lab approval, spending opt-in, exact data roles, owned inventory,
run/SHA verification, two-hour TTL, always-run cleanup and artifact restrictions
remain required. The janitor must still be registered and active; this exception
does not bypass its preflight check.

## Before testing

- The new workflows need to be registered with GitHub before manual dispatch.
  A branch-only workflow may still be unavailable for dispatch until it exists
  on the default branch. No repository protection is bypassed by this change.
- Scheduled GitHub workflows execute from the default branch. Until the reviewed
  janitor is installed there, its hourly schedule does not protect branch runs.
  Establish independent cleanup before enabling spending; an active workflow
  listing alone does not prove an hourly schedule is operational.
- Keep `CERTOPS_AZURE_KEYVAULT_LAB_ENABLED=false` until those prerequisites are
  ready. This commit does not dispatch Azure or claim qualification evidence.

## Mandatory rollback before merge

- [ ] Revert the dedicated temporary-exception commit, including workflow,
      PowerShell, shared policy, validator and test changes. Preserve any later
      independent fixes and live evidence.
- [ ] Remove the exact temporary environment deployment policies below. Retain
      the `main` rules, lab reviewers and self-review prevention.
- [ ] Verify both environments have exactly one branch rule named `main`, no tag
      rules, and all code guards reject the temporary branch again.
- [ ] Disable the spending opt-in after the campaign; verify resource cleanup.
- [ ] Keep the permanent janitor active on main and validate the final candidate.

```powershell
gh api --method DELETE repos/tokentimerch/tokentimer-core/environments/certops-azure-keyvault-lab/deployment-branch-policies/64514225
gh api --method DELETE repos/tokentimerch/tokentimer-core/environments/certops-azure-keyvault-cleanup/deployment-branch-policies/64514228
```
