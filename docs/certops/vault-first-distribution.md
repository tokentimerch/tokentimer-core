# First Vault publication and distribution

Publish one certificate version, install it on two Linux consumers and verify both listeners. The issuer owns issuance/renewal; consumers retrieve that exact version instead of issuing independently. TokenTimer stores public evidence, not the bundle's private key.

## Prepare

Use an HTTPS Vault KV v2 mount, reachable CA/DNS, registered issuer/consumer agents and two existing web services. Arrange a second authorized manager for rollout approval. Keep one workspace throughout.

Open the [setup guide](setup-guide.md) and choose **Share one certificate across servers with Vault → Linux server**. Select existing agents where appropriate. Preserve their identity, allowlists and local custody state.

## Allocate the group and configure hosts

The first publication job allocates the real `job.payload.publication.groupId`. Use that UUID in [local material-store/binding configuration](wildcard-vault-operations.md#customer-local-configuration) and [separate Vault Agent roles](vault-agent-authentication.md).

- If ordinary job approval is required, keep the publication unapproved while preparing policy and token sinks.
- If approval is off, keep issuer execution disabled during allocation until the returned group is configured and readiness checks pass. Submission alone does not hold work.

Keep Vault credentials, private bundles, filesystem destinations and reload commands on the hosts. Each consumer needs its own identity, read-only bundle access, deployment profile, authorization revision and listener probes. Validate/reload configuration through the service's approved local commands.

In the Vault GUI, inspect the KV v2 engine, group-scoped policies and published version metadata/history. Issuers need the intended create/read access; consumers need read access. Use metadata for status checks; bundle Data/raw JSON contains private keys.

## Publish, assign and approve

Run signed no-op smoke checks, then deliberately enable mutating execution. Complete the original publication under the actual workspace approval policy. Inspect its public receipt; publication alone is not installation.

Follow the [publication and consumer API sequence](wildcard-vault-operations.md#public-workflow) for both destinations. Apply each returned authorization revision to the matching host-local binding before rollout. Request the intended material version and have a **different authorized manager** approve the rollout even when ordinary job approval is off. Child-job approval still follows workspace policy.

## Verify both services

Inspect each install, reload and validation result in the timeline/read-only **Agent output**, then [probe both concrete TLS listeners](verify-live-service.md). Match the intended fingerprint and validity with hostname and CA trust checks.

In **Certificates → certificate → Deployments**, review desired/observed versions and verification freshness. Renewals contains the source profile. **Published → deployed → verified in use** are distinct outcomes; a later source renewal publishes another version but does not prove every consumer rolled out. For failures or uncertain effects, preserve state and follow the [distribution recovery reference](wildcard-vault-operations.md#pause-retry-drift-and-rollback).
