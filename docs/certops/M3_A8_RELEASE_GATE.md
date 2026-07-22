# CertOps M3-A8 release gate

Validation date: 2026-07-22

This record covers the Core M3-A observe-and-provision implementation rebased
onto `c246d6f6c76af32a4c1c65e64a09dfc253456bff`. The pushed head immediately
before the final review patch is
`0a46d5c83646b931ea8bef615138831e26b61d54`, and GitHub reports PR #75 as
mergeable. PR CI run `29903381092` passed. Manual full CI run `29904349164`
also passed, including runtime API contract and full integration tests, backend
and frontend coverage, Helm and Compose validation, and build plus Grype scans
for the API, dashboard, worker, and Kubernetes controller images. The final
review patch remains uncommitted by design, so a pushed exact-head CI result for
that patch is still required. This record is validation evidence, not a release
announcement.

## Architecture source and resolved decision

- Primary source: `TOKENTIMER_CERTOPS_PLAN` v1.21 in `tokentimer-canvas`.

The v1.21 amendment confirms that the M3 Kubernetes controller uses the
additive, controller-specific routes
`POST /api/v1/certops/executor/observations` and
`POST /api/v1/certops/executor/provisioning-commands/next`. It also confirms
that the controller is not an M4 agent-protocol client. The implementation
matches the approved M3-A0, M3-A6, and M3-A7 contracts: registration,
heartbeat, claims, attempts, leases, signing, nonces, scheduling, and the rest
of the agent protocol remain deferred to M4. The prior documentation conflict
is resolved and is no longer a release gate.

## Final review findings resolved

- The provisioner is now bound to the controller's immutable configured
  workspace as well as its cluster and namespace policy. A mismatched command
  is rejected before any Kubernetes client call.
- The customer-side controller now independently validates the complete,
  strictly allowlisted provisioning response, including UUIDs, Kubernetes
  identities, issuer fields, DNS identities, bounded RFC 3339 event timestamps,
  and private-material exclusion.
- Optional `tls.crt` read or parse failures no longer suppress an independently
  clean status observation. Only a sanitized stable failure code is logged,
  and the final outbound private-material scan remains mandatory.
- The controller package version and default Helm controller image tag now
  match the repository/chart release line at `0.10.0`.

## Deterministic composition evidence

`tests/integration/certops-m3-a8-e2e.test.js` composes real PostgreSQL, real
Express routes, the real observer/reporter/runtime/provisioning runner, and the
real cert-manager client boundary over a controlled Kubernetes API. Its four
database-backed scenarios passed and cover:

- status-first observation without Secret access, plus the bounded streaming
  `tls.crt` fallback that captures only the approved public value;
- malformed, private-key-bearing, and oversized fallback failure;
- stable `cert_manager` source identity, exact replay, fingerprint rotation,
  Kubernetes UID replacement, workspace/cluster isolation, and both `revoked`
  and `decommissioned` D7 terminal states;
- manager provision intent, cluster-bound command delivery, locally built
  Certificate create and Merge Patch, deterministic executor events/evidence,
  and eventual issued-certificate observation;
- pause behavior, generic-secret redaction, and private-key rejection before
  scope and pause decisions.

The suite's serialized Secret fixture also contains private material, unrelated
credentials, and misleading names. The streaming boundary extracts only
`tls.crt` without object-deserializing other data values. No Secret write,
CertificateRequest write, delete capability, raw Kubernetes manifest, or
private-key configuration is exposed.
Focused A6/A7 and controller unit suites retain the detailed redelivery,
ownership-conflict, reporting-failure, readiness, and bounded-shutdown cases.

## Command results

| Gate | Result |
| --- | --- |
| `pnpm install --frozen-lockfile` | Passed with pnpm 11.13.0. |
| `pnpm migrate` | Passed against a fresh disposable database; migrations 1 through 23 are present and current. |
| Controller lint/build/test | Passed; 99 tests passed across 13 suites. |
| Repository lint/build | Passed; lint had zero errors and 31 pre-existing warnings. |
| `pnpm run test:unit` | Passed; 603 tests passed across 71 suites. |
| `pnpm run test:contracts` | Passed static conformance; 25 passed and 1 live-API test was skipped because no API was listening on `localhost:4000`. |
| Contract manifest, integrity, OpenAPI coverage, secret-logging checks | Passed. |
| M3-A8 composition | Passed, 4/4. |
| M3-A7 provisioning API | Passed, 17/17. |
| M3-A7 controller execution | Passed, 2/2. |
| M3-A6 controller observations | Passed, 7/7. |
| M2 executor events/evidence | Passed, 36/36. |
| Controller wiring | Passed, 4/4, including controller package/Helm tag alignment. |
| Migration integration | Passed, 13/13. |
| Private-key detector/rejection/redaction/parser focus | Passed, 64/64. |
| Lockfile override check | Passed, 20 required resolutions pinned. |
| Helm lint and verification | Passed; the checksum-verified Helm v3.20.1 fallback and full controller render/RBAC/NetworkPolicy matrix passed. |
| Compose configuration | Both production and production-images configurations passed. |
| PR CI run `29903381092` | Passed against pushed head `0a46d5c83646b931ea8bef615138831e26b61d54`. |
| Manual full CI run `29904349164` | Passed runtime API contracts, full integration and coverage, Helm and Compose checks, and build plus Grype scans for all four images. |

The local backend coverage command was attempted after the focused suites. Its
WSL/Docker collector remained silent without completing and was stopped within
a bounded run; no coverage threshold or harness change was made. Manual full CI
run `29904349164` is the authoritative completed coverage and integration
result and passed both. The final review patch still requires CI after it is
committed and pushed.

The Helm fallback downloads v3.20.1 to a temporary archive, verifies SHA-256
`0165ee4a2db012cc657381001e593e981f42aa5707acdd50658326790c9d0dc3`, then
extracts it. Its version, URL, and checksum match CI and release. Both installed
Helm lint scenarios and the checksum-verified Bash render matrix passed
locally.

## Helm, Compose, and Kubernetes boundary

`pnpm run helm:verify` passed the disabled, namespace-scoped observe,
cluster-wide observe, fallback, namespace-scoped provision, cluster-wide
provision, provision-plus-fallback, and invalid configuration matrix. The
rendered controller uses its own ServiceAccount. Observe RBAC is read-only;
Secret access is absent unless fallback is enabled and is then exactly `get`.
Provision mode adds only Certificate `create` and `patch` to the read verbs.
There are no delete, wildcard, Secret-write, or CertificateRequest-write
permissions. Provision mode uses a non-overlapping deployment strategy.

The production and production-images Compose configurations passed
`docker compose ... config`. The controller is deliberately not a Compose
runtime: it requires in-cluster ServiceAccount credentials and is deployed
through the Helm resources above. Its image is built and scanned independently
in CI and release workflows.

The repository has no established Kind, k3d, or envtest CI harness, and this
host exposes `kubectl` but no disposable-cluster tool. M3-A8 therefore uses the
deterministic Kubernetes boundary and rendered Helm/RBAC checks rather than
adding an unpinned or unreliable mandatory smoke job. A future optional job may
use a pinned Kind image and pinned cert-manager CRDs to exercise create,
unchanged reconciliation, Merge Patch, and foreign-ownership rejection without
performing certificate issuance.

## Controller image

Manual full CI run `29904349164` built the API, dashboard, worker, and
Kubernetes controller images and passed the Grype gate for all four. The
controller package and default Helm image tag are aligned at `0.10.0`. The
controller image runs as UID 1001, includes only the controller and its required
shared runtime files, and excludes root build manifests, plans, tests, `.env`
files, kubeconfig, token mounts, and unrelated workspace packages. Its packaged
runtime-file smoke check passed.

The repository-pinned Grype 0.112.0 archive was checksum-verified against
`acb14a030010fe9bdb9594b4ae108d9d14ef2f926d936aa0916dc62c89c058ea`.
The manual CI scan used the repository's `--fail-on high --only-fixed` policy
and passed. Workspace overrides pin `ws` 8.21.0 and `js-yaml` 4.3.0. The runtime
layer does not retain unrelated workspace manifests or the unused Corepack,
pnpm, and npm toolchains; this also removes npm's bundled packages from the
shipped vulnerability inventory.

The CI build/scan and publish workflows include the controller at
`linux/amd64`. The release workflow now also applies the release version to the
controller image tag in the packaged Helm chart. No image was published, so no
release digest is recorded.

## Compatibility findings

### Core

The M3 contracts are additive, route/OpenAPI coverage and contract integrity
pass, migration ordering is current through migration 23, and the focused M1,
M2, M3-A6, and M3-A7 regression suites pass. M3 introduces no M4 schema or
runtime and preserves private-key-first rejection and passive reporting while
paused.

The direct self-hosted runtime requirement now states PostgreSQL 15+, matching
the selective `ON DELETE SET NULL (column)` syntax used by the shipped schema.

### Cloud

The local Cloud checkout was reviewed read-only. Its private-key rejection
middleware is correctly composed ahead of SaaS plan/frozen gates, so the
required security ordering can be retained. Its materialized Core executor
wrapper and published documentation are still M2-era and do not yet contain
the observation/provision controller routes or scopes. Cloud adoption must
refresh the Core materialization, add the two controller scopes and immutable
cluster binding, compose its downstream gate at the existing Core seam, and
adopt the controller image/Helm values. The public Core contracts need not
change, and neither kubeconfig nor private material may cross into Cloud.

### Enterprise

The local Enterprise checkout was reviewed read-only. It is pinned to Core and
contracts 0.8.1 and explicitly documents that even M2 is not yet shipped.
Enterprise adoption therefore requires a deliberate Core/chart/image and
contract baseline upgrade before enabling M3. The M3 additions are additive;
an entitlement wrapper can remain downstream of private-material rejection.
No M4 agent expectation, kubeconfig transfer, or private-key custody is
introduced.

## Rebase and branch status

- Branch: `feature/certops-m3-a-cert-manager-controller`
- Pushed head before the final review patch: `0a46d5c83646b931ea8bef615138831e26b61d54`
- Local HEAD after the uncommitted final review patch: `0a46d5c83646b931ea8bef615138831e26b61d54`
- Rebase base: `c246d6f6c76af32a4c1c65e64a09dfc253456bff`
- Passing PR CI run: `29903381092`
- Passing manual full CI run: `29904349164`
- GitHub mergeability: mergeable
- Pre-rebase prompt baseline: `60193a27636c6d297ec6850b6434e72ce69c36e0`
- Actual pre-rebase head: `c602b05208859573997b26c1658ca184e65027af`
- Merge base: `f4558086383a6e0830f9c0f42bd75924d524eadc`
- Rebased tip before this validation amendment: `9fa62336ef4c91331f1d1561d1fccd20eca62e50`

The authorized rebase completed with no skipped or empty commits. It stopped
twice:

- Replaying `feat(certops): add workspace certops kill switch` produced
  conflicts in `apps/api/migrations/migrate.js`, the route compatibility
  contract, and `tests/unit/certops-migration.test.js`. Main's released token
  link remains migration 18, and the unreleased M3 migrations are now 19-23.
  The combined migration tests retain both the token-link and all M3
  assertions; the complete M3 route contract remains at version 0.12.0.
- Replaying `feat(certops): add M3-A2 controller foundation` produced conflicts
  in `apps/worker/package.json` and the root `package.json`. The resolution
  retains version 0.10.0, worker Axios 1.18.0, the shared log-scrub dependency,
  main's build-enabled Compose command, and every controller command and
  aggregate build/lint entry.

Automatically merged release, workspace, lockfile, lockfile-policy, and Helm
verification files were inspected. Main's release-image tags, database SSL
verification, dependency overrides, and CloudNativePG verification coexist
with the full M3 controller/RBAC/NetworkPolicy matrix. A deterministic
lockfile-only reconciliation removed the duplicated merged `js-yaml` mapping;
frozen installation then passed.

The final migration tail is:

```text
18 tokens_certops_api_token_link
19 certops_workspace_kill_switch
20 certops_job_creation_request_fingerprint
21 certops_controller_observation_reporting
22 certops_controller_provisioning
23 certops_controller_provisioning_event_timestamps
```

All versions are unique and strictly increasing. A fresh disposable PostgreSQL
database migrated from zero through version 23. Developers who ran the old,
unreleased feature-branch migration numbering must recreate their local
development database; no production repair migration was added.

## Remaining release actions

1. Commit and push the final review patch, then obtain successful GitHub CI
   against that new exact head.
2. Run the manual real-Kubernetes/cert-manager smoke validation when a pinned
   disposable cluster is available.
3. Only after publication, record the immutable controller image and manifest
   digest in release metadata.
4. Complete Cloud adoption of the M3 routes, scopes, immutable cluster binding,
   and Helm/image wiring without changing the Core public contracts.
5. Upgrade the Enterprise Core/contracts/chart/image baseline before enabling
   M3 there.
6. Complete any separate release-process requirements before declaring M3-A
   released.

Until the new exact-head CI, manual smoke, published image, adoption, and
release-process gates are complete, this document does not claim that M3-A is
released.
