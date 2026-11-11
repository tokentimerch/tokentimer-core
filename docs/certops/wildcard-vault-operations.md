# Distribute certificates through Vault

Use this workflow when several servers need the same certificate. One **issuer
agent** obtains or renews it and writes the certificate and private key to your
Vault. Each **consumer agent** retrieves that version and installs it on its
server. Ordinary, multi-domain (SAN), and wildcard certificates use the same
workflow. Sharing a private key increases the impact of a compromised server;
use separate certificates when sharing is unnecessary.

TokenTimer records version IDs, certificate fingerprints, job status and
verification results. Private keys and Vault/DNS credentials stay on your
infrastructure.

## Start with the guided setup

Follow [First Vault publication and distribution](vault-first-distribution.md),
or [watch the walkthrough](https://www.youtube.com/watch?v=BYe8S1Ux9PI).
In the [setup guide](setup-guide.md), choose **Share one certificate across
servers → Linux server**. It walks through publication, consumer assignment
and deployment without terminal API calls.

**Job approval is off by default.** If your workspace requires approval,
arrange another authorized manager to approve jobs in **Jobs**. Rollouts and
their consumer jobs can require separate approval. Publishing a renewed
certificate does **not** automatically deploy it; request a rollout of that
new version.

## Deployment boundary and qualification

This guide covers Vault KV v2 and native Linux agents. File-only delivery needs
no web server. Service delivery also needs locally approved validation/reload
commands and TLS listener checks; see [live-service verification](verify-live-service.md).
Test Vault authentication, DNS access, file permissions and every intended
listener on your actual hosts before relying on the setup.

For OpenBao, Azure Key Vault and Windows/IIS shared import, read
[distribution extensions](distribution-extensions.md) and their
[qualification status](distribution-extensions-qualification.md). A lab result
or configuration example does not establish support for arbitrary appliances
or high-availability configurations.

## Host configuration

Merge the [issuer example](examples/wildcard-vault/issuer.json) or
[consumer example](examples/wildcard-vault/consumer.json) into each agent's
existing configuration. Preserve its enrolled identity and replace placeholder
IDs and paths. API assignments use the agent's database row ID; local
configuration uses its `agentId`.

Keep the workspace, distribution group, certificate names, key algorithm,
profile references and revisions consistent with the setup guide. Update the
local consumer configuration when its assignment or authorization revision
changes. Store credentials, filesystem paths and reload commands locally;
never put them in TokenTimer job payloads. See the
[configuration reference](agent/configuration.md).

### Vault access

Give the issuer and each consumer separate Vault Agent identities and protected
token files. The issuer needs create/read access to its group's bundles;
consumers need read access only. Follow the
[Vault Agent authentication walkthrough](vault-agent-authentication.md) for
AppRole setup, token renewal and access checks. Use HTTPS with a trusted CA;
keep token files at mode `0600` inside `0700` directories.

Inventory scanners must use separate credentials and must not read bundle
contents. Protect Vault backups as private keys. Retain old bundles for the
recovery and rollback period you require.

### Files and job routing

Create deployment directories with the installer's `--write-path` option.
The agent must own any existing certificate/key files. Root-owned files can
cause `material_install_failed` followed by `material_binding_uncertain`.

On the Linux installer layout, keep `execution.keysDir` at
`/opt/tokentimer-agent/state/keys` and include it in `policy.allowedPaths`.
Set `declaredTargetSelectors` to the issuer's certificate names or the
consumer's binding ID; the issuer also needs `declaredCommandProfileNames`.
An agent can register successfully yet claim no work if these are missing.
For NGINX validation/reload permissions, use the
[Linux installer instructions](agent/install-linux.md#nginx-reload).
The issuer example agrees to CA terms without an email address; configure
Certbot's `--email <address>` if you want notices from the CA.

### Turn on execution safely

The examples start with `dryRun: true`. Complete the guide's signed test jobs
**before** queuing real work; they check dispatch and reporting only.

Before allocating the first publication, either keep it unapproved or, when
Job approval is off, set issuer `execution.enabled: false` and restart it.
Configure the returned group and host policies while execution is held.
When ready, restart with `execution.enabled: true` and `execution.dryRun: false`.
Do not poll in dry-run mode with a real publication queued: the agent can claim
and block that job. The [first-distribution guide](vault-first-distribution.md)
gives the complete order.

## Check the result

Open **Certificates → certificate → Deployments** and check each assigned
consumer. **Renewals** contains the source profile. Publication alone proves
neither installation nor that a service uses the new certificate.

- **Installed files only** (`installed`): the agent installs and reads back
  the certificate/key pair. Configure no reload commands or listener probes.
- **Served** (`served`): the configured listeners must present the requested
  certificate fingerprint after deployment.
- **Trust** (`trust`): also checks hostname/SNI and CA trust. Every configured
  listener must pass.

A rollout containing any file-only consumer finishes as `installed`, not
`verified`. Offline consumers and old or expired evidence do not count as current.

## Pause, retry, drift and rollback

- **Pause:** stops new deployment work. A required consumer failure pauses
  the rollout; an already executed change may still need reconciliation.
- **Retry:** repair the cause, then retry the original publication or deployment
  job. Retries keep the same version and are limited to three claims. After a
  consumer retry, resume the rollout explicitly.
- **Drift check:** request a rollout with `verificationOnly: true`. It checks
  files and configured listeners without installing or reloading.
- **Rollback:** request a new rollout of an older retained version. Check its
  expiry, CA revocation status and your policy first; expired or locally
  recorded revoked identities are rejected. Obtain approval when required.

## Crashes and uncertain effects

An uncertain result means the agent cannot prove what changed. Preserve its
state and investigate before retrying. For `material_issuance_uncertain`, inspect
the CA order, Vault object and issuer staging. Retry the original publication;
do not create another ACME order to bypass the failure. An unresolved version
blocks fresh issuance for that group.

Issuer staging is under `material-artifacts/<workspace>/<group>/<version>`
in the agent state directory. **`bundle.json` contains the private key.** Never
upload it to a ticket, support request or evidence store.

### Recover a consumer

For `material_binding_uncertain` or `orphaned_unknown_effect`, first repair the
actual certificate/key files and, for service delivery, the configured service
and listeners. Then run reconciliation as the agent account, replacing
`<bindingId>` with the consumer binding UUID:

```sh
sudo -u tokentimer-agent env TOKENTIMER_AGENT_CONFIG_DIR=/opt/tokentimer-agent/state \
  node /opt/tokentimer-agent/app/bin/reconcile-material-binding.js <bindingId>
```

This checks local files/listeners and clears the local uncertain marker.
It does not update server verification. Retry the original deployment job,
then resume the rollout. Fresh, accepted deployment evidence is still required.

### Recover after an agent crash

Locks under `material-locks` do not expire automatically. Stop the affected
agent and verify that the recorded process is no longer running, including
possible PID reuse. Preserve public lock/checkpoint/receipt metadata, then
remove only a confirmed abandoned lock. Restart and reconcile.

Never delete live locks, generation records or staging to force a retry.
Removing a lock does not prove whether an external change happened. Lost or
corrupt state needs investigation; restoring an old state-directory backup
does not safely reset deployment ordering.

## Emergency leaf revocation

1. Pause affected rollouts/execution, stop affected agents and restrict
   compromised Vault, DNS or agent credentials.
2. Revoke the certificate through its issuing CA on your infrastructure. For
   Certbot, consult `certbot revoke --help` for the installed version. Never send
   a private key to TokenTimer or a support ticket.
3. Confirm CA acceptance and available OCSP/CRL status, then mark the inventory
   identity revoked. Inventory retirement or Vault deletion does not revoke
   a certificate at the CA.
4. Issue with a new key, distribute the replacement and verify every affected
   listener, including each high-availability member.

## Public workflow

For automation, use the [OpenAPI reference](../../packages/contracts/openapi/openapi.yaml)
and [distribution request schemas](../../packages/contracts/certops/material-distribution.schema.json).
The group resources are under
`/api/v1/workspaces/{id}/certops/distribution-groups`:

- `GET` the groups, `/{groupId}/versions` or `/{groupId}/consumers` for status.
- `PUT /{groupId}/consumers/{bindingId}` to assign a consumer explicitly.
- `POST /{groupId}/rollouts` with an `Idempotency-Key`, `materialVersionId` and
  `maxParallel` to deploy a selected version.
- `POST /{groupId}/rollouts/{rolloutId}/state` with `paused`, `deploying`
  (resume) or `retired` to change rollout state.
- Retry the original job with
  `POST /api/v1/workspaces/{id}/certops/distribution-jobs/{jobId}/retry`.

Changed assignments, verification policy or workspace authorization can require
a new rollout request and fresh approval. Pausing or retiring remains possible
when execution is blocked; resuming and retrying still require permission to execute.

## Upgrades

Back up the database and protected agent state before upgrading. Drain active
writers, run migrations and deploy matching API/worker versions. File-only
delivery also needs updated consumer agents; see the
[first-distribution prerequisites](vault-first-distribution.md#prepare).

Keep applied migration history intact. Use a tested backup/restore or forward
correction rather than downgrading across distribution migrations. Pause
execution before a restore and reconcile uncertain effects before restarting.
For version-specific changes, consult the [changelog](../../CHANGELOG.md).
