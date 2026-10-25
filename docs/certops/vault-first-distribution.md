# First Vault publication and distribution

Publish one certificate version, install it on two Linux consumers and verify both listeners. The issuer owns issuance/renewal; consumers retrieve that exact version instead of issuing independently. TokenTimer stores public evidence, not the bundle's private key.

## Prepare

Use an HTTPS Vault KV v2 mount, reachable CA/DNS, registered issuer/consumer agents and two existing web services. Job approval is off by default, so one authorized operator can complete this workflow. If your workspace requires approval, arrange another authorized manager. Keep one workspace throughout.

Open the [setup guide](setup-guide.md) and choose **Share one certificate across servers with Vault → Linux server**. Select existing agents where appropriate. Preserve their identity, allowlists and local custody state.

Complete **Turn on execution safely → Send a test job** for the issuing agent before opening the Vault distribution step. Use the inline **Send a test job** control for each consumer as well, with `execution.enabled: true` and `execution.dryRun: true`. The guide shows the returned status, evidence and read-only Agent output. This checks dispatch/reporting, not later publication or deployment permissions. Do it before queuing real work: enabling polling with local dry-run protection can claim and block a queued real publication.

## Allocate the group and configure hosts

The first publication job allocates the real `job.payload.publication.groupId`. Use that UUID in [local material-store/binding configuration](wildcard-vault-operations.md#customer-local-configuration) and [separate Vault Agent roles](vault-agent-authentication.md).

- If ordinary job approval is required, keep the publication unapproved while preparing policy and token sinks.
- If approval is off, set issuer `execution.enabled: false` and restart **before** allocation. Keep polling disabled until the returned group is configured and readiness checks pass. Submission alone does not hold work.

Keep Vault credentials, private bundles, filesystem destinations and reload commands on the hosts. Each consumer needs its own identity, read-only bundle access, deployment profile, authorization revision and listener probes. Validate/reload configuration through the service's approved local commands.

In the Vault GUI, inspect the KV v2 engine, group-scoped policies and published version metadata/history. Issuers need the intended create/read access; consumers need read access. Use metadata for status checks; bundle Data/raw JSON contains private keys.

## Publish, assign and roll out

After readiness checks, deliberately set `execution.enabled: true` and `execution.dryRun: false` on the prepared hosts and restart their agents. Do not insert another dry-run polling phase while the real publication is queued. Approve the held job if required and follow the original publication under the actual workspace policy. Inspect its public receipt; publication alone is not installation.

In **Assign consumers and deploy**, assign the first consumer and use **Additional consumer → Add consumer** for the second. Each assignment returns its actual authorization revision and a matching host configuration. Copy it to that host, preserve the enrolled identity, and confirm the saved configuration after restarting the agent. A confirmation records your action; it is not deployment evidence.

Choose the **Published certificate version**, review **Maximum parallel deployments**, then choose **Deploy the selected version**. The request pins that exact version. Follow its timeline and each consumer's deployment/Agent output without leaving onboarding. A successful coordinator request alone does not mean consumers are verified. The guide reads back their current desired/observed versions and convergence before showing **All selected consumers verified**.

With workspace Job approval off, the rollout starts without a second user. With workspace approval on, another authorized manager must approve it through the existing Jobs review surface; its actual pending status is shown in the guide. Child-job approval also follows workspace policy. Keep the setting off for unattended execution; publishing a renewed version does not automatically request a new rollout. The [API reference](wildcard-vault-operations.md#public-workflow) remains available for automation and advanced administration; it is not required for this first guided distribution.

## Verify both services

Inspect each install, reload and validation result in the timeline/read-only **Agent output**, then [probe both concrete TLS listeners](verify-live-service.md). Match the intended fingerprint and validity with hostname and CA trust checks.

In **Certificates → certificate → Deployments**, review desired/observed versions and verification freshness. Renewals contains the source profile. **Published → deployed → verified in use** are distinct outcomes; a later source renewal publishes another version but does not prove every consumer rolled out. For failures or uncertain effects, preserve state and follow the [distribution recovery reference](wildcard-vault-operations.md#pause-retry-drift-and-rollback).
