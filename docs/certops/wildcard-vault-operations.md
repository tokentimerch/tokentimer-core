# Certificate material distribution candidate

Customer issuer → existing native ACME DNS-01 → customer Vault KV v2 →
explicitly assigned Linux consumers → concrete TLS listeners → public receipts.
The API, workers, inventory scanners, dashboards and queues never receive the
private key or Vault/DNS credentials. Publishing is a separate outcome from
deploying to every consumer. The same certificate may be an ordinary, SAN, or
wildcard certificate; sharing it is independent of its DNS names.
This candidate adds migrations 69–71, after the existing AD CS migration 68; Cloud applies
the same SQL as migrations 86–88 after main's inventory migration 85. Enterprise
inherits Core through staged composition.

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

Three new capabilities are gated: `material-store-vault-kv2-v1`,
`certificate-publication-v1`, and `deploy-from-store-v1`. They are deliberately
absent from the shipped `src/capabilities/qualified-capabilities.json` build
input. The execution functions and control-plane dispatch are tested, but a
complete enrolled, networked agent build still needs qualification before these
capabilities are added to that input and compiled with
`node packages/agent/scripts/build-qualified-capabilities.js`. There is no
runtime environment-variable bypass. Registering target labels or declaring
capabilities in a test database does not qualify a release artifact.

Before enabling a customer build, run signed enrollment/heartbeat/claim/lease/
result transport through a real API, the real DNS provider, production Vault
authentication/rotation, the exact service configuration and host filesystem.
Test agent and host crashes, token expiry, revoked agent credentials, Vault
retention/deletion, each HA listener, key permission persistence and recovery.

## Customer-local configuration

Merge `examples/wildcard-vault/issuer.json` or `consumer.json` into the existing
agent configuration, substitute all IDs and paths, then enroll the corresponding
agent normally. The database agent row ID used in assignments differs from the
wire `agentId` in local configuration. Examples intentionally have no tokens.

The issuer and each consumer have separate Vault Agent auto-auth processes and
0600 token sinks (0700 parent directories). The adapter reads its sink on every
request, allowing Vault Agent to renew/replace the token. Static tokens are not a
production authentication proposal. Use HTTPS with system trust or a locally
approved CA file, optional Vault namespace, bounded request timeout and a KV v2
mount. Vault Agent auth roles, policies, CA files, DNS credentials, mount/prefix
and reload commands are customer-owned configuration, never job fields.

Each local store entry grants one explicit workspace/group, exact SAN set and
key algorithm. Issuer entries also bind wire agent ID, issuance profile/revision,
CA endpoint and DNS provider/zone. Each consumer entry binds wire agent ID,
group/store, deployment profile/revision, authorization revision, destination,
reload and all dial address/port/SNI probes. Changing a server binding increments
its authorization revision; update and review the matching local policy before
creating a new approved rollout. No implicit path or alias fallback exists.

The example Vault policies separate issuer create/read, consumer read and
scanner denial. Substitute the actual mount and workspace/group prefix. Do not
attach broader policies that defeat the denial. The server scanner also refuses
the reserved `bundles/<UUID>` namespace before data reads or nested metadata
listing, including direct path-prefix probes. The server scanner must not reuse
issuer or consumer credentials. Protect Vault backups as private keys.

## Public workflow

1. Create an existing `issue` job with `assignedAgentId` set to the issuer's
   database row ID. Its payload includes the existing target/SANs/CA/DNS/key
   settings and `publicationDestination` containing only `materialStoreRef`,
   `issuanceProfileRef`, `profileRevision`. Supply the existing issuance
   idempotency key. Filesystem/reload/probe destinations are forbidden here.
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
   `{ "materialVersionId": "UUID", "maxParallel": 1 }` creates a pending
   approval job. A different authorized user approves it using the existing job
   approval endpoint. The worker freezes membership, policy revisions,
   verification policy, material version, provider version, fingerprint,
   generation and concurrency. Any change before expansion invalidates approval.
6. Children are signed `deploy-from-store` jobs assigned to one agent/binding.
   Fetch, pair/identity validation, installation, reload, served verification
   and trust validation have separate receipt fields. `served` verifies the
   requested fingerprint; `trust` also requires hostname/SNI and CA trust.
   Every locally configured listener must pass. A certificate renewed at the
   source does not mark an offline consumer current.

The consumer matrix at `GET .../{groupId}/consumers` and in the Renewals page
shows desired/observed logical versions, generation, fingerprint, deployed
expiry, verification method/time and latest deployment failure. Convergence
requires a fresh, unexpired proof for the current binding revision and active
identity. It is never inferred from publication alone.

## Pause, retry, drift and rollback

`POST .../{groupId}/rollouts/{rolloutId}/state` accepts `paused`, `deploying`
(resume), or `retired`. Pausing prevents new child work and lease reauthorization;
an already executed external effect may still require reconciliation. Required
failure pauses the rollout. Resume explicitly after remediation.

`POST /api/v1/workspaces/{id}/certops/distribution-jobs/{jobId}/retry` requeues the
same failed/blocked/uncertain job, preserves approved payload/version/generation
and is bounded to three claims. Publication retries recover staged material or
the deterministic Vault object; they do not create another order. A consumer
retry fetches the same pinned provider version. A changed intent needs a new
approval. Cloud admission rejects new effects for frozen or unpaid workspaces;
claim-bound continuing results remain accepted.

For a read-only drift check, request another approved rollout of the desired
version with `verificationOnly: true`. It advances generation, fetches/validates
the pinned bundle, compares the installed pair and probes the listeners, without
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
and listeners locally, then run `certops-reconcile-binding <bindingId>` as the
agent account with its normal configuration directory. This command only reads
the installed pair, verifies all configured listeners and clears the local
uncertain marker. It does not promote server state. Request the original signed
retry afterward, with a fresh live claim.

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

Review and commit Core first. Cloud pins that exact candidate SHA, materializes
manifest-mapped files, retains its quota/private-material/continuing-result
policy and runs its own migrations 86–89. Enterprise composes the same candidate, retaining
RBAC/SSO and base CertOps independently of licensed compliance reports. Candidate
SHA compatibility and locally built images are not published release references.
Only after full agent/customer qualification and real release gates should the
three product releases advance their published Core pins and capability input.
