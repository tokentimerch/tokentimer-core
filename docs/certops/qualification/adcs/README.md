# AD CS testing

Run local framework checks with `pnpm run test:certops:qualification` and collector checks with `pnpm run test:certops:release-collector`. These use fixtures; they do not qualify a Windows host.

## Dispatch

Normal CI runs the three AD CS API suites on its existing integration stack and uploads verified reports. From trusted main, dispatch `certops-qualification.yml`: choose `tooling` for local checks or `stack`/`all` for the separate PostgreSQL qualification. No PR dispatch is enabled.

For native enrollment, pending approval/denial, renewal, recovery, IIS/CNG custody and browser authorization, dispatch `certops-enterprise-adcs-qualification.yml`. Choose an Azure region and VM size available to the subscription, Server version and language explicitly. The lab checks SKU restrictions and six-vCPU regional/family quota before creating resources. This creates a temporary domain-backed lab; it requires repository variable `CERTOPS_ADCS_LAB_ENABLED=true` and protected environment `certops-adcs-lab` with Azure OIDC variables `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`. Non-English images also require `CERTOPS_WINDOWS_LANGUAGE_ASSETS`. Azure is used only for the domain lab.

Set `CERTOPS_WINDOWS_LANGUAGE_ASSETS` to a JSON object keyed by OS/language, for example `2022/de-DE`, with `uri` and `sha256` for each official Server display-language CAB. Use a private HTTPS Azure Blob and a read-only SAS that remains valid through installation on both CA and member; refresh expired URLs before another dispatch. The checksum, installed resources and actual SYSTEM language are verified. A Basic language capability alone does not qualify a display-language slot.

## Results and cleanup

**Shards.** The `shard` input defaults to `all`: one serial lab, the only mode that produces release evidence. `parallel` provisions five labs at once (`issuance`, `renewals`, `pending-and-ca`, `templates-and-uncertain`, `uncertain-recovery`; 30 vCPUs, so check regional quota) and a failure in one shard cannot hide the scenarios of another. Shards are diagnostic: their reports are `not-qualified`/`experimental`, each is checked only for completing every scenario it owns, and none can fill a native release slot. Shards apply to the plain comprehensive scope only; `issuance` also carries the production worker and package acceptance. The scenario-to-shard map is `tests/e2e/helpers/certops-adcs-shards.js`, and a unit test fails if a mandatory scenario has no owner.

Read the run summary and sanitized JSON artifacts. Missing prerequisites or mandatory scenarios fail the run. Fixture results never substitute for native evidence. Collect completed core native runs using `certops-release-qualification.yml` with the exact main candidate SHA and run IDs. Its verdict lists omitted environments and cannot claim full coverage.

Lab teardown runs with `always()`. Keep scheduled `certops-adcs-lab-janitor.yml` enabled and its separate `certops-adcs-cleanup` environment able to authenticate without human approval. It deletes only expired, owned labs; verify both normal teardown and cancellation cleanup before relying on this infrastructure.

Hierarchy, issuer reassignment, standalone CA feasibility, response-loss/journal crash experiments and elapsed 24-hour campaigns are deferred to the extended follow-up branch. No native qualification is claimed until actual runs pass.
