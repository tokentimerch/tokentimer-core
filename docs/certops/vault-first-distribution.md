# First Vault publication and distribution

Publish one certificate version and install it on Linux consumers. Choose file delivery alone, or also reload and verify a service. The issuer owns issuance/renewal; consumers retrieve that exact version instead of issuing independently. TokenTimer stores public evidence, not the bundle's private key.

## Prepare

Use an HTTPS Vault KV v2 mount, reachable CA/DNS and a registered issuing agent. Consumers can be registered later in **Prepare the consumer server**; their absence does not block publication. A web service is needed only for the service-reload choice. Job approval is off by default, so one authorized operator can complete this workflow. If your workspace requires approval, arrange another authorized manager. Keep one workspace throughout.

**Operator action:** file-only delivery requires the matching API/worker migration 78 and updated consumer agents. Older agents reject the new `installed` policy before changing files; do not work around that by approving an empty reload command.

Open the [setup guide](setup-guide.md) and choose **Share one certificate across servers with Vault → Linux server**. Select existing agents where appropriate. Preserve their identity, allowlists and local custody state.

Complete **Turn on execution safely → Send a test job** for the issuing agent before opening the Vault distribution step. Use the inline **Send a test job** control for each consumer as well, with `execution.enabled: true` and `execution.dryRun: true`. The guide shows the returned status, evidence and read-only Agent output. This checks dispatch/reporting, not later publication or deployment permissions. Do it before queuing real work: enabling polling with local dry-run protection can claim and block a queued real publication.

## Allocate the group and configure hosts

The first publication job allocates the real `job.payload.publication.groupId`. Use that UUID in [local material-store/binding configuration](wildcard-vault-operations.md#customer-local-configuration) and [separate Vault Agent roles](vault-agent-authentication.md).

- If ordinary job approval is required, keep the publication unapproved while preparing policy and token sinks.
- If approval is off, set issuer `execution.enabled: false` and restart **before** allocation. Keep polling disabled until the returned group is configured and readiness checks pass. Submission alone does not hold work.

Keep Vault credentials, private bundles and filesystem destinations on the hosts. Each consumer needs its own identity, read-only bundle access, deployment profile and authorization revision. At the start of **Prepare the consumer server**, choose:

- **Distribute certificate files only:** configure a destination directory. The agent installs and reads back the certificate/key pair; no web server, placeholder certificate, reload permission or TLS probe is required. The guide completes from fresh installation evidence.
- **Distribute and reload a service:** choose NGINX, Apache or HAProxy and configure its paths. This adds service setup, allowlisted validate/reload commands and a live TLS probe. All required reload and listener checks must pass.

Choose before assigning consumers. Existing assignments retain their policy; changing that policy requires a new reviewed assignment and matching local configuration. The six-part guide layout is unchanged; service-specific instructions appear only for the selected service.

In the Vault GUI, inspect the KV v2 engine, group-scoped policies and published version metadata/history. Issuers need the intended create/read access; consumers need read access. Use metadata for status checks; bundle Data/raw JSON contains private keys.

## Publish, assign and roll out

After readiness checks, deliberately set `execution.enabled: true` and `execution.dryRun: false` on the prepared hosts and restart their agents. Do not insert another dry-run polling phase while the real publication is queued. Approve the held job if required and follow the original publication under the actual workspace policy. Inspect its public receipt; publication alone is not installation.

In **Assign consumers and deploy**, select the first consumer (use **Check registered consumers** after a new registration), assign it and use **Additional consumer → Add consumer** for the second. Each assignment returns its actual authorization revision and a matching host configuration. Signed checks here belong to that selected host, not the issuer. Copy the configuration to that host, preserve the enrolled identity, and confirm the saved configuration after restarting the agent. A confirmation records your action; it is not deployment evidence.

For a fresh consumer, use **Create a consumer bootstrap token** in **Prepare the consumer server**. Each host needs a separate single-use token; paste it at the installer's hidden prompt. Existing registered agents keep their identity and need no new token.

Choose the **Published certificate version**, review **Maximum parallel deployments**, then choose **Deploy the selected version**. The request pins that exact version. Follow its timeline and each consumer's deployment/Agent output without leaving onboarding. A successful coordinator request alone does not prove installation. The guide reads back current desired/observed versions and the selected policy's evidence: **Certificate files installed on all selected consumers** for files, or **All selected consumers verified** after service reload/TLS checks.

With workspace Job approval off, the rollout starts without a second user. With workspace approval on, another authorized manager must approve it through the existing Jobs review surface; its actual pending status is shown in the guide. Child-job approval also follows workspace policy. Keep the setting off for unattended execution; publishing a renewed version does not automatically request a new rollout. The [API reference](wildcard-vault-operations.md#public-workflow) remains available for automation and advanced administration; it is not required for this first guided distribution.

If a required deployment fails, repair the host and follow the guide's reconciliation instructions before **Retry deployment**. Then use **Resume rollout** in the same guide. It resumes the existing version and assignments; fresh deployment evidence is still required before the guide reports success.

## Confirm the selected result

For file delivery, inspect the installation/readback evidence and installed certificate/key paths. Completion does not claim an application has loaded or served those files. Service preparation and live checks do not block this mode.

For service reload, inspect each install, reload and validation result in the timeline/read-only **Agent output**, then [probe the concrete TLS listeners](verify-live-service.md). Match the intended fingerprint and validity with hostname and CA trust checks.

In **Certificates → certificate → Deployments**, review desired/observed versions, file-only versus service verification policy and evidence freshness. Renewals contains the source profile. **Published → files installed → verified in use** are distinct outcomes; a later source renewal publishes another version but does not prove every consumer rolled out. For failures or uncertain effects, preserve state and follow the [distribution recovery reference](wildcard-vault-operations.md#pause-retry-drift-and-rollback).
