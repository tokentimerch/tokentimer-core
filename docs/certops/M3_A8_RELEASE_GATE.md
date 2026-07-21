# CertOps M3-A8 release gate

Validation date: 2026-07-21

This record covers the Core M3-A observe-and-provision implementation at the
approved pre-A8 head `5f16f0c84af8113fabf8df96823753d05af5961f`, plus the staged M3-A8 hardening
changes. It is validation evidence, not a release announcement. A published
image digest and exact-head GitHub CI result can exist only after these changes
are committed and pushed.

## Architecture source and open decision

- Primary source:
  `https://github.com/tokentimerch/tokentimer-canvas/blob/e3cc88a3769d374cdf03cfbe90bc93a199d817c6/plans/TOKENTIMER_CERTOPS_PLAN.md`
- Retrieved Canvas commit: `e3cc88a3769d374cdf03cfbe90bc93a199d817c6`
- Retrieved plan blob: `ca57802d9f5c9328f66f1fbfb35cf77f73e61428`
- Plan version: 1.20

There is one unresolved architecture-document conflict. Canvas plan v1.20 says
the Cloud controller reports through the agent protocol. The approved M3-A0,
M3-A6, and M3-A7 contracts instead deliberately use the additive,
controller-specific routes
`POST /api/v1/certops/executor/observations` and
`POST /api/v1/certops/executor/provisioning-commands/next`, and explicitly
defer registration, heartbeat, claims, attempts, leases, signing, nonces,
scheduling, and the rest of the agent protocol to M4. The implementation keeps
the approved M3 boundary. Before declaring M3-A released, publish a Canvas
v1.21 clarification or ADR that describes these M3-only transports and leaves
the M4 agent protocol separate.

## Deterministic composition evidence

`tests/integration/certops-m3-a8-e2e.test.js` composes real PostgreSQL, real
Express routes, the real observer/reporter/runtime/provisioning runner, and the
real cert-manager client boundary over a controlled Kubernetes API. Its four
database-backed scenarios passed and cover:

- status-first observation without Secret access, plus an instrumented
  `tls.crt` fallback that proves only that property is read;
- malformed, private-key-bearing, and oversized fallback failure;
- stable `cert_manager` source identity, exact replay, fingerprint rotation,
  Kubernetes UID replacement, workspace/cluster isolation, and both `revoked`
  and `decommissioned` D7 terminal states;
- manager provision intent, cluster-bound command delivery, locally built
  Certificate create and Merge Patch, deterministic executor events/evidence,
  and eventual issued-certificate observation;
- pause behavior, generic-secret redaction, and private-key rejection before
  scope and pause decisions.

The suite's Secret fixture also contains `tls.key`, unrelated credentials, and
misleading names. A proxy at the access boundary fails if any property other
than `tls.crt` is read. No Secret write, CertificateRequest write, delete
capability, raw Kubernetes manifest, or private-key configuration is exposed.
Focused A6/A7 and controller unit suites retain the detailed redelivery,
ownership-conflict, reporting-failure, readiness, and bounded-shutdown cases.

## Command results

| Gate | Result |
| --- | --- |
| `pnpm install --frozen-lockfile` | Passed with pnpm 11.13.0. |
| `pnpm migrate` | Passed; migrations 1 through 22 are present and current. |
| Controller lint/build/test | Passed; 80 tests passed. |
| API lint/build | Passed; lint had zero errors and two pre-existing warnings in `sanitize.js` and `secretMaterial.js`. |
| `pnpm run test:unit` | Passed; 545 tests passed. |
| `pnpm run test:contracts` | Passed static conformance; 25 passed and 1 live-API test was skipped because no API was listening on `localhost:4000`. |
| Contract manifest, integrity, OpenAPI coverage, secret-logging checks | Passed. |
| `pnpm run build` | Passed; Vite retained its existing `env.js` and chunk-size warnings. |
| M3-A8 composition | Passed, 4/4. |
| M3-A7 provisioning API | Passed, 17/17. |
| M3-A7 controller execution | Passed, 2/2. |
| M3-A6 controller observations | Passed, 7/7. |
| M2 executor events/evidence | Passed, 36/36. |
| Controller wiring | Passed, 3/3. |
| Private-key detector/rejection/redaction focus | Passed, 105/105. |
| Lockfile override check | Passed, 20 required resolutions pinned. |
| Workflow YAML parsing | Passed for all four workflow files. |

The established full integration command, `pnpm test:integration`, was also
attempted. It emitted no suite output and completed no test before it was
stopped after approximately 4 minutes 46 seconds. Three idle Node processes
remained and were terminated; no process remained afterward. The focused
database-backed M2/M3 suites listed above all passed independently. No unrelated
integration harness changes were made.

## Helm, Compose, and Kubernetes boundary

`pnpm run helm:verify` passed the disabled, namespace-scoped observe,
cluster-wide observe, fallback, namespace-scoped provision, cluster-wide
provision, provision-plus-fallback, and invalid configuration matrix. The
rendered controller uses its own ServiceAccount. Observe RBAC is read-only;
Secret access is absent unless fallback is enabled and is then exactly `get`.
Provision mode adds only Certificate `create` and `patch` to the read verbs.
There are no delete, wildcard, Secret-write, or CertificateRequest-write
permissions. Provision mode uses a non-overlapping deployment strategy.

Production, production-plus-images, controller-profile, development, and local
PostgreSQL Compose configurations passed `docker compose ... config`. Compose
now passes the explicit cluster-wide setting to the controller.

The repository has no established Kind, k3d, or envtest CI harness, and this
host exposes `kubectl` but no disposable-cluster tool. M3-A8 therefore uses the
deterministic Kubernetes boundary and rendered Helm/RBAC checks rather than
adding an unpinned or unreliable mandatory smoke job. A future optional job may
use a pinned Kind image and pinned cert-manager CRDs to exercise create,
unchanged reconciliation, Merge Patch, and foreign-ownership rejection without
performing certificate issuance.

## Controller image

The controller image built successfully from `apps/k8s-controller/Dockerfile`
as `tokentimer-core-k8s-controller`, image ID
`sha256:91aeef8f1d49a78fafe662ded2ea5bd50c3e56ea1c8b47c9dc42bab71626353d`.
It runs as UID 1001, includes only the controller and its required shared
runtime files, and excludes root build manifests, plans, tests, `.env` files,
kubeconfig, token mounts, and unrelated workspace packages. Its packaged
health endpoint returned 200; readiness changed from 503 to 200 with the
injected lifecycle state.

The repository-pinned Grype 0.112.0 archive was checksum-verified against
`acb14a030010fe9bdb9594b4ae108d9d14ef2f926d936aa0916dc62c89c058ea`.
Scanning the exported final image root filesystem with
`--fail-on high --only-fixed` returned `No vulnerabilities found`. The scan
exposed fixed High findings in `ws` 8.19.0 and `js-yaml` 4.2.0 before
hardening; workspace overrides now pin `ws` 8.21.0 and `js-yaml` 4.3.0, and
the runtime image no longer retains unrelated workspace manifests.

The CI build/scan and publish workflows include the controller at
`linux/amd64`. The release workflow now also applies the release version to the
controller image tag in the packaged Helm chart. No image was published, so no
release digest is recorded.

## Compatibility findings

### Core

The M3 contracts are additive, route/OpenAPI coverage and contract integrity
pass, migration ordering is current through migration 22, and the focused M1,
M2, M3-A6, and M3-A7 regression suites pass. M3 introduces no M4 schema or
runtime and preserves private-key-first rejection and passive reporting while
paused.

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

## Merge and clean-checkout gates

- Branch: `feature/certops-m3-a-cert-manager-controller`
- Current unstaged-code base/head: `5f16f0c84af8113fabf8df96823753d05af5961f`
- Fresh `origin/main`: `6d9cccef54c3676db52261b27f1fcc95dbf9d40b`
- Merge base: `f4558086383a6e0830f9c0f42bd75924d524eadc`

A three-tree, non-mutating merge check found six text-conflict hunks in five
paths:

- `apps/api/migrations/migrate.js`
- `apps/worker/package.json`
- `package.json`
- `packages/contracts/api/certops-route-compat.contract.json`
- `tests/unit/certops-migration.test.js`

They were not resolved, merged, or rebased during M3-A8. Feature validation and
merge readiness are separate gates.

The final staged binary patch passed frozen installation, controller
lint/build/test, the M3-A8 database-backed composition suite, Helm verification,
and full build from a detached clean worktree. The worktree contained no local
plan documents, pre-existing `node_modules`, or generated build output.

## Remaining release actions

1. Publish the Canvas v1.21 clarification or an ADR for the M3-only controller
   transports.
2. Resolve the five `origin/main` conflict paths in a separately authorized
   merge/rebase workflow.
3. Commit and push the reviewed staged patch.
4. Run GitHub CI against that exact pushed head, including the Docker build and
   Grype job (the image-scan job is not executed for pull-request events).
5. Only after publication, record the immutable controller image and manifest
   digest in release metadata.

Until the architecture-document amendment and merge/CI gates are complete,
this document does not claim that M3-A is released or merge-ready.
