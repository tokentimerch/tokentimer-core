# AD CS testing

Run local framework checks with `pnpm run test:certops:qualification` and collector checks with `pnpm run test:certops:release-collector`. These use fixtures; they do not qualify a Windows host.

## Dispatch

Normal CI runs the three AD CS API suites on its existing integration stack and uploads verified reports. From trusted main, dispatch `certops-qualification.yml`: choose `tooling` for local checks or `stack`/`all` for the separate PostgreSQL qualification. No PR dispatch is enabled.

For native enrollment, pending approval/denial, renewal, recovery, IIS/CNG custody and browser authorization, dispatch `certops-enterprise-adcs-qualification.yml`. Choose an Azure region and VM size available to the subscription, Server version and language explicitly. The lab checks SKU restrictions and six-vCPU regional/family quota before creating resources. This creates a temporary domain-backed lab; it requires repository variable `CERTOPS_ADCS_LAB_ENABLED=true` and protected environment `certops-adcs-lab` with Azure OIDC variables `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`. Non-English images also require `CERTOPS_WINDOWS_LANGUAGE_ASSETS`. Azure is used only for the domain lab.

## Results and cleanup

Read the run summary and sanitized JSON artifacts. Missing prerequisites or mandatory scenarios fail the run. Fixture results never substitute for native evidence. Collect completed core native runs using `certops-release-qualification.yml` with the exact main candidate SHA and run IDs. Its verdict lists omitted environments and cannot claim full coverage.

Lab teardown runs with `always()`. Keep scheduled `certops-adcs-lab-janitor.yml` enabled and its separate `certops-adcs-cleanup` environment able to authenticate without human approval. It deletes only expired, owned labs; verify both normal teardown and cancellation cleanup before relying on this infrastructure.

Hierarchy, issuer reassignment, standalone CA feasibility, response-loss/journal crash experiments and elapsed 24-hour campaigns are deferred to the extended follow-up branch. No native qualification is claimed until actual runs pass.
