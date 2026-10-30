# Certificate material distribution candidate

For explicit OpenBao compatibility, Azure Key Vault Secrets and Windows/IIS
shared import, see [distribution extensions](distribution-extensions.md) and
their [qualification status](distribution-extensions-qualification.md). Existing
Vault and Linux instructions below retain their original defaults.

Customer issuer → existing native ACME DNS-01 → customer Vault KV v2 →
explicitly assigned Linux consumers → installed files, optionally live TLS listeners → public receipts.
The API, workers, inventory scanners, dashboards and queues never receive the
private key or Vault/DNS credentials. Publishing is a separate outcome from
deploying to every consumer. The same certificate may be an ordinary, SAN, or
wildcard certificate; sharing it is independent of its DNS names.
Core preserves AD CS migrations 68 and 70–72, agent console migration 69,
and mainline job-alert/lifecycle migration 73. Fresh installations append
distribution migrations 74–76. Recognized distribution-first, enrollment-first
and previous AD-CS-first distribution preview ledgers retain every applied
version/name and append missing lifecycle safeguards at 76. Unknown or gapped
histories stop before SQL runs; never rename applied ledger rows. Cloud keeps
its independent history and appends job-alert/lifecycle migration 95 after 94.
Enterprise uses the shared append-only composition adapter. Back up the database
and secrets, drain old writers, migrate, then deploy matching API and workers.

Rejected/cancelled publications release their allocation only when the database
proves zero execution attempts and no claim/start/lease evidence. The retained
version records the release reason/time. Generic failures and uncertain attempts
must recover the same version; they never authorize another ACME order.
Issuer key custody uses the configured local `execution.keysDir` throughout
publication and recovery. The checkpoint records the actual rotation outcome.

## Deployment boundary and qualification

The initial path uses the native agent on Linux, an existing DNS provider,
Vault KV v2, local protected files and locally approved reload commands. NGINX
and HAProxy are the proposed first consumers. Their real processes were tested
in the isolated fixture; that does not qualify arbitrary customer configuration.
Appliance models, firmware, service binding and HA coverage are unknown. No
firewall adapter, Windows shared-key import or Kubernetes bundle bridge is
advertised. Existing Windows and Kubernetes execution paths remain separate.

The three distribution capabilities (`material-store-vault-kv2-v1`,
`certificate-publication-v1`, and `deploy-from-store-v1`) are listed in the
shipped `src/capabilities/qualified-capabilities.json` build input and are
declared by the 0.18.0 agent. Your own Vault authentication, DNS provider, host
filesystem and TLS listeners are still customer-owned and must be tested before
you rely on this path. There is no runtime environment-variable bypass.
Registering target labels or declaring capabilities in a test database does not
qualify a release artifact.

Before relying on a customer build, run signed enrollment/heartbeat/claim/lease/
result transport through a real API, the real DNS provider, production Vault
authentication/rotation, the exact service configuration and host filesystem.
Test agent and host crashes, token expiry, revoked agent credentials, Vault
retention/deletion, each HA listener, key permission persistence and recovery.
Record the Core source SHA, packed agent SHA-256, generated capability manifest,
OS/service versions and public test evidence together. Qualify filesystem
ownership, restrictive permissions, parent-directory and symlink defenses,
crash/restart durability, uncertain writes and token replacement on the exact
proposed artifact. The isolated API/Vault/ACME/NGINX/HAProxy lab is supporting
evidence, not release qualification. Windows AD CS has its own real-host CA,
template, CNG, pending-approval and continuation matrix, which qualifies
`adcs-enroll-v1` separately from this one. Appliance HA and multi-listener configurations
need explicit coverage before claiming support.

## Customer-local configuration

Merge `examples/wildcard-vault/issuer.json` or `consumer.json` into the existing
agent configuration, substitute all IDs and paths, then enroll the corresponding
agent normally. The database agent row ID used in assignments differs from the
wire `agentId` in local configuration. Examples intentionally have no tokens.

The issuer and each consumer have separate Vault Agent auto-auth processes and
0600 token sinks (0700 parent directories). The adapter reads its sink on every
request, allowing Vault Agent to renew/replace the token. Static tokens are not a
production authentication proposal. Follow the [complete Vault Agent AppRole
walkthrough](vault-agent-authentication.md) for role creation, login, token sinks,
credential rotation and positive/negative access checks. Use HTTPS with system trust or a locally
approved CA file, optional Vault namespace, bounded request timeout and a KV v2
mount. Vault Agent auth roles, policies, CA files, DNS credentials, mount/prefix
and reload commands are customer-owned configuration, never job fields.

Each local store entry grants one explicit workspace/group, exact SAN set and
key algorithm. Issuer entries also bind wire agent ID, issuance profile/revision,
CA endpoint and DNS provider/zone. Each consumer entry binds wire agent ID,
group/store, deployment profile/revision, authorization revision, destination,
delivery policy, and (for service delivery) reload and all dial address/port/SNI probes. Changing a server binding increments
its authorization revision; update and review the matching local policy before
creating a new approved rollout. No implicit path or alias fallback exists.

Create each consumer deploy folder with the installer (`--write-path`) or with
`sudo install -d -o tokentimer-agent -g tokentimer-agent -m 0750 <folder>`. Any
placeholder `fullchain.pem` and `privkey.pem` must also belong to the agent user
(create them with `sudo -u tokentimer-agent`). With root-owned files the first
rollout failed with `material_install_failed`, and the retry then reported
`material_binding_uncertain`.

The agent reads the issuer's private key from `execution.keysDir`, so that
folder must also be listed in `policy.allowedPaths`. On the Linux installer layout
use `/opt/tokentimer-agent/state/keys`: the hardened service unit only writes
under `/opt/tokentimer-agent/state`, and other locations fail with
`mkdir ... job-journal`. The agent also routes jobs by what it declares, not by
what the policy allows: set `declaredTargetSelectors` (issuer: the SANs;
consumer: the binding ID) and, for the issuer, `declaredCommandProfileNames`.
Without them the agent registers but never claims work.

The examples ship `"dryRun": true`. Before allocating the first publication,
complete signed no-op smoke checks with execution enabled and local dry-run
protection on. They prove dispatch/reporting, not later external effects.
If ordinary approval is off, then disable issuer polling and restart before
allocation. Prepare the returned group, Vault policy and host bindings while
polling is off; once ready, restart with `"enabled": true` and `"dryRun": false`
directly. A dry-run polling phase after allocation can claim and block the queued
real publication. With approval on, keep that publication unapproved until ready.
For the nginx
consumer, `nginx -t` fails for the unprivileged agent user, so the example
validates with `systemctl is-active` and reloads through `systemctl reload nginx`
with a one-time systemd drop-in that tests the configuration as root; see
[nginx reload](agent/install-linux.md#nginx-reload). The certbot argv carries
`--agree-tos` and `--register-unsafely-without-email`; use `--email <address>`
instead if you want expiry notices from the CA.

The example Vault policies separate issuer create/read, consumer read and
scanner denial. Substitute the actual mount and workspace/group prefix. Do not
attach broader policies that defeat the denial. The server scanner also refuses
the reserved `bundles/<UUID>` namespace before data reads or nested metadata
listing, including direct path-prefix probes. The server scanner must not reuse
issuer or consumer credentials. Protect Vault backups as private keys.

## Public workflow

Start with [First Vault distribution](vault-first-distribution.md). The setup guide sends signed checks, creates the publication job, assigns one or more consumers and requests the chosen version's rollout. It displays returned configuration revisions, job timelines, read-only output and consumer verification. No terminal TokenTimer API calls are needed for that first distribution. Inspect later status in **Certificates → certificate → Deployments**; **Renewals** contains profiles and AD CS issuers. The API below remains the reference for automation, advanced binding changes, containment and verification-only checks. Approval review uses the existing Jobs surface when workspace policy requires it.

1. Create an existing `issue` job with `assignedAgentId` set to the issuer's
   database row ID. Its payload includes the existing target/SANs/CA/DNS/key
   settings and `publicationDestination` containing only `materialStoreRef`,
   `issuanceProfileRef`, `profileRevision`. The payload must include
   `keyAlgorithm`; the agent refuses the job without it. A tested combination
   is `ecdsa` with `keySize: 256` in the job and `"keyAlgorithm": "ec"` in the
   local group entry. Supply the existing issuance
   idempotency key. Filesystem/reload/probe destinations are forbidden here.
   `issue` is the stored control-plane operation; signed agent dispatch uses
   the existing `renew` wire action for initial issuance as well as renewal.
2. The server creates one managed source, active management period and group.
   A logical material-version UUID is allocated for this job. Renewals retain
   that owner and group; consumers never become renewal owners. Successful
   renewal creates a new fingerprint identity and leaves old identities intact.
3. The issuer validates and stages the certificate/key pair locally before
   cleanup. It writes `<prefix>/bundles/<materialVersionId>` with CAS=0 and reads
   back pinned KV version 1. Receipt processing requires the live publishing
   claim and active management period, then transactionally updates public
   identity/version state and inserts a deduplicated `material_published` event.
4. Use `GET /api/v1/workspaces/{id}/certops/distribution-groups` and its
   `/{groupId}/versions` resource to obtain public references. Use
   `PUT .../{groupId}/consumers/{bindingId}` to assign each consumer explicitly.
   Required fields are in the shared `consumerBinding` schema. The first wave is the
   canary; subsequent waves wait for earlier required consumers. Optional
   failures remain visible and do not count as verified consumers.
5. `POST .../{groupId}/rollouts` with an `Idempotency-Key` header and body
   `{ "materialVersionId": "UUID", "maxParallel": 1 }` follows workspace
   **Job approval**, which is off by default. With approval off, the request
   freezes the rollout and queues it without a second user. With approval on,
   or an explicit `"requiresApproval": true` in this request, a different
   authorized user approves the job using the existing approval endpoint.
   A rollout's authorization freezes membership, policy revisions,
   verification policy, material version, provider version, fingerprint,
   generation and concurrency. Any change before approved expansion invalidates approval.
   Consumer deployment jobs also follow workspace Job approval; the rollout's
   approval does not release separately gated children. Keep the workspace
   setting off for unattended execution. Publication of a renewed version does
   not automatically request a rollout: submit the new version explicitly.
6. Children are signed `deploy-from-store` jobs assigned to one agent/binding.
   `installed` is the explicit file-only verification policy: install and read
   back the certificate/key pair (and a configured chain), without reload or TLS
   probes. Local bindings for this policy must not contain reload commands or
   listener probes. Its receipt has `installed: true`, with `bound`,
   `servedVerified` and `trustValidated` false. A completed rollout containing
   any file-only consumer has state `installed`, never `verified`.
   Fetch, pair/identity validation, installation, reload, served verification
   and trust validation have separate receipt fields. `served` verifies the
   requested fingerprint; `trust` also requires hostname/SNI and CA trust.
   For `served`/`trust`, every locally configured listener must pass. These
   policies still reject a receipt that only proves file installation. A certificate renewed at the
   source does not mark an offline consumer current.

The consumer matrix at `GET .../{groupId}/consumers` and **Certificates → Deployments**
shows desired/observed logical versions, generation, fingerprint, deployed
expiry, verification method/time and latest deployment failure. Convergence
requires a fresh, unexpired proof of the selected delivery policy for the current binding revision and active
identity. It is never inferred from publication alone.
An optional consumer whose authorization changed makes a completed rollout
`degraded`, even if a successful historical receipt remains available.

## Pause, retry, drift and rollback

`POST .../{groupId}/rollouts/{rolloutId}/state` accepts `paused`, `deploying`
(resume), or `retired`. Pausing prevents new child work and lease reauthorization;
an already executed external effect may still require reconciliation. Required
failure pauses the rollout. Resume explicitly after remediation.
Authenticated, authorized managers can pause or retire even when the workspace
is paused, frozen or no longer entitled to execute. These actions enqueue no
work. Resuming, starting a rollout, changing a binding and retrying still require
current execution admission. Public version responses expose the documented
identity, publication job, version, validity and allocation-release metadata;
publishing claim IDs are never public, including for administrators.

`POST /api/v1/workspaces/{id}/certops/distribution-jobs/{jobId}/retry` requeues the
same failed/blocked/uncertain job, preserves approved payload/version/generation
and is bounded to three claims. Publication retries recover staged material or
the deterministic Vault object; they do not create another order. A consumer
retry fetches the same pinned provider version. A changed intent needs a new
approval. Cloud admission rejects new effects for frozen or unpaid workspaces;
claim-bound continuing results remain accepted.

After an uncertain consumer deployment, repair and reconcile the local files and, when selected, service,
then retry the original job and resume its rollout. Only an accepted, fresh
receipt for the current authorized deployment clears that job's server-side
reconciliation flag. Local reconciliation alone, stale historical evidence and
an invalid receipt leave the flag in place.

For a read-only drift check, request another approved rollout of the desired
version with `verificationOnly: true`. It advances generation, fetches/validates
the pinned bundle, compares the installed pair and (for service policies) probes the listeners, without
installation or reload. Failure reports `material_drift_detected`; previous
verified state remains historical and the matrix becomes unconverged. Schedule
these checks through the existing authorized workflow if periodic checks are
required; this candidate does not silently generate approvals.

Rollback is an explicitly approved new rollout of an older retained version.
Generation always advances, even when the fingerprint becomes older. Expired
or locally recorded revoked identities cannot be deployed. Check the CA's
revocation state and customer policy before rollback. The agent rejects stale
generations and same-generation intent changes durably.

## Crashes and uncertain effects

Issuer artifacts are under `material-artifacts/<workspace>/<group>/<version>`
in the customer state directory. `bundle.json` is key-bearing and protected;
`checkpoint.json` contains public intent metadata. Never upload the bundle to
support, evidence, a queue or a ticket. A started issuance with neither a
validated local bundle nor matching remote object fails
`material_issuance_uncertain`. Investigate the CA order and local disk before
authorizing any replacement. An unresolved version blocks fresh group issuance.

Consumer state is under `material-bindings/<bindingId>.json`. A protected
uncertain marker is durable before the first mutation. Reload failure, lost
lease or failed service proof after mutation yields `orphaned_unknown_effect`;
no automatic compensation or inferred success occurs. Fix the actual binding
and listeners locally, then run the reconcile script as the agent account with
its normal configuration directory (the installer does not put
`certops-reconcile-binding` on `PATH`; the script is `bin/reconcile-material-binding.js`
in the installed app):

```sh
sudo -u tokentimer-agent env TOKENTIMER_AGENT_CONFIG_DIR=/opt/tokentimer-agent/state \
  node /opt/tokentimer-agent/app/bin/reconcile-material-binding.js <bindingId>
```

It takes the binding UUID, reads the protected record under
`material-bindings/` in the state directory (the parent of `execution.keysDir`) and
prints only a short `material_*` error code and exits 1 on failure. This command only reads
the installed pair, verifies all configured listeners and clears the local
uncertain marker. It prints a one-line JSON result and does not promote server state.
Request the original signed retry afterward, with a fresh live claim.

Per-group issuer and per-binding consumer locks use exclusive files under
`material-locks` and never expire by TTL. After a crash, stop the corresponding
customer agent, verify the recorded PID is no longer executing (including PID
reuse), preserve the public lock/checkpoint/receipt metadata, and remove only
that confirmed abandoned lock. Restart and reconcile. Never delete live locks,
generation records or staging to force a retry. Removing a lock does not prove
the external effect. Lost/corrupt state needs operator investigation; restoring
an old state-directory backup is not a safe fencing reset.

Retain old Vault objects and protected staging according to an explicitly
reviewed customer retention policy. Destroying an object can prevent recovery
and rollback. No automated deletion is introduced by this candidate.

## Emergency leaf revocation

1. Pause the workspace/rollouts and stop affected customer executors. Restrict
   compromised Vault/DNS/agent credentials and preserve public incident facts.
2. On customer-controlled infrastructure use the issuing CA's supported leaf
   revocation flow and an authorized ACME account or leaf key. For Certbot,
   review `certbot revoke --help` for the deployed version, select the exact CA
   server/account or protected `--key-path`, certificate and revocation reason.
   Never transmit the private key to TokenTimer or a support ticket.
3. Confirm CA acceptance and the available OCSP/CRL response. Record public
   evidence and mark the affected inventory identity revoked through the
   existing lifecycle workflow. Inventory retirement and Vault deletion are
   not CA revocation and must never be reported as such.
4. Replace material with a new key and approved issuance intent, distribute a
   new pinned version and verify every concrete listener/HA member. Keep the
   incident open while any consumer still serves the compromised fingerprint.

## Coordinated release dependency

The integrated candidate targets the coordinated **0.18.0** train. Existing
`v0.17.3` tags and published images keep their original source meaning. Review
and commit Core first. Cloud's `compatibility.manifest.json` `core.testedCommit`
and Enterprise's `core.lastSyncedCoreCommit` record the same exact integrated
Core SHA; these fields, rather than an earlier preview SHA or a moving branch,
are the source provenance for staged builds. The implementation report and
final-head CI runs record all three candidate heads. Read the exact pin with
`node -p "require('./compatibility.manifest.json').core.testedCommit"` in Cloud
or `node -p "require('./compatibility.manifest.json').core.lastSyncedCoreCommit"`
in Enterprise before materialization or image builds.

Cloud materializes manifest-mapped files and retains tenancy, Pro/Team admission,
quotas, freeze/pause, private-material rejection and signed continuation policy.
Hosted AD CS control-plane APIs are supported on Pro/Team; credentials and CA
execution remain customer-local. Advanced AD CS governance is outside scope.
Enterprise retains RBAC, SSO, licensing and base CertOps independently of
licensed compliance reports. Verify the actual staged API, worker and Renewals
dashboard in both editions, including AD CS and distribution composition.

Version, contract, chart and image-tag metadata are prepared for 0.18.0, but no
tag, publication or deployment is performed by this candidate. A local image
must be labelled with its actual source revision; a published 0.17.3 base image
alone does not prove integrated source composition. Release maintainers must
approve final acceptance, artifact hashes, security scans, production-host
qualification and the coordinated Core → Cloud → Enterprise publication order.
The tag-triggered release pipeline remains a separate post-merge gate; do not
create a beta tag as a validation shortcut for this PR. Keep unqualified
capabilities absent from production manifests until their own evidence passes.

Schema rollback uses a tested backup/restore or a forward correction; downgrading
the application across the lifecycle/distribution migrations 73–76 is not supported. Pause execution before
an upgrade or restore, retain immutable history and customer-local artifacts,
and reconcile uncertain effects before restarting. Never drop distribution or
AD CS tables or edit ledger names to fit an older binary.
