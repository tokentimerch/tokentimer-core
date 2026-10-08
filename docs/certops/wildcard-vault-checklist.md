# Wildcard Vault implementation ledger

This is an implementation candidate, not a release qualification statement.

## Isolation and baseline (8 October 2026)

- [x] Read the complete supplied implementation plan and pasted request.
- [x] Inspect audit checkouts read-only. Core: `feat/certops-fingerprint-identity`,
  `9f70f0c764fd75960b9b821f491db34d715fbcbe`, untracked audit/lab files. Cloud:
  `feat/business-marketing-redesign`, `2f8c75be`, local marketing edits. Enterprise:
  `master`, `4efb60a`, local mock API edits. Preserve all three.
- [x] Inspect running services without reading credentials. Manual lab PostgreSQL:
  `tt-manual-lab-postgres`, loopback port 56470. Host PostgreSQL: 5432. Other
  application listeners include 15431, 16431 and 18880–18889. Do not operate them.
- [x] Create separate sibling worktrees under
  `C:/Users/Admin/Documents/tokentimer/wildcard-vault-20261008/`, named
  `tokentimer-core`, `tokentimer-cloud`, `tokentimer-enterprise`; branch in each:
  `feat/wildcard-vault-distribution`. No audit branch switches or stash/reset.
- [x] Query remote default branches. Core `813b0b11` and Cloud `03787b36` match
  the plan. Enterprise has advanced from `4adff535` to `2da15b3`; it now pins Core
  `813b0b11` / 0.17.3, rather than 0.17.2. Cloud remains on Core `6c902405` / 0.17.2.
  Local remote-tracking refs were stale; use queried commit objects as baselines.
- [x] Read contribution instructions and canonical three-repo CI skills.
- [x] Start isolated fixtures. Project `tt-wildcard-vault-20261008`; private
  network/volumes, loopback ports 57470 (PostgreSQL), 58200 (Vault), 57379
  (Redis), 58025 (email UI), 51025 (SMTP), 58400/58500 (Pebble), 58055/58053 (DNS fixture).
  TLS probes run inside the isolated runner on 8443/9443; `compose run` does
  not publish its declared 58443/59443 host ports.
  Maximum one test runner; bounded container memory/CPU. No production credentials.

## Implementation and validation

- [x] Workspace-constrained public distribution model and immutable versions.
- [x] Strict intent/receipt schemas, signed approval coverage and capabilities.
- [x] Customer-local Vault KV v2 publish, pinned read, auth and bounded transport.
- [x] Protected staging, CAS/lost-response recovery without ACME reissuance.
- [x] Issue/renew publication branch and transactional identity reconciliation.
- [x] Typed deduplicated outbox and frozen rollout expansion.
- [x] Consumer locking, generation/lease fences, installation and service/SNI proof.
- [x] Canary/waves, pause/retry/rollback, drift/freshness and consumer matrix.
- [x] Cloud mapped ports, quota/rejection ordering and staged-image validation.
- [x] Enterprise inheritance, RBAC and compliance-license separation.
- [x] Real PostgreSQL/Vault/ACME/two TLS consumer scenario and negative tests.
- [x] Legacy/secret-boundary/contract/static checks.
- [ ] Final coordinated candidate image boot/composition checks (see validation below).
- [x] PR-ready summaries, coordinated release dependencies and operational runbook.

## Pending customer qualification

Actual DNS provider/CA/SANs, Vault edition/version/auth/retention, appliance models,
firmware, HA listeners, customer delegation and billing policy require customer
inputs. Do not advertise appliance, Windows shared-key or Kubernetes support based
on mocks or target labels. Preserve existing billing semantics pending policy.
Do not manufacture a Core release ref: variants can qualify an exact candidate
commit locally, but coordinated release pins require an actual published release.

## Decisions

One workspace/execution scope per customer; one source issuer; immutable logical
object with CAS=0; exact provider version reads; rollback advances generation.
Local aliases grant no authority by themselves. Jobs cannot select network endpoints,
credential files, namespaces, mount paths, device scripts or reload commands.
Publication success and per-consumer convergence are separate. Existing scanner
must have no ACL access to bundle paths. Base CertOps remains ungated in Enterprise.

## Executed validation

- Core full unit suite: 2,271 passed; strict contract suite: 42 passed.
- Cloud full unit suite: 1,330 passed; Enterprise full unit suite: 866 passed.
- Core dashboard and Cloud web production builds passed. Core dashboard type
  check passed. API/worker/agent/dashboard lint has no errors (existing warnings).
- Production dependency audit, contracts/integrity, lockfile and secret-logging
  checks passed. Helm template verification and Compose configuration passed.
- Fresh Core 68- and Cloud 85-migration PostgreSQL databases passed publication,
  immutable identities, non-self approval, frozen canary/waves, real signed
  dispatch/nonces/claims, replay, exact child-job fencing, independent matrix,
  read-only intent, failure recording and same-version retry assertions. Cloud
  additionally passed real outbox expansion, quota and continuing frozen results.
- Real Vault fault/ACL suite: 8 passed, including create/read-only issuer policy,
  consumer read-only access, scanner denial and cross-customer prefix denial.
- Real Pebble/DNS-01 native issuer and NGINX/HAProxy lifecycle passed 15 checks,
  with two orders total (initial + renewal). Offline catch-up/rollback/recovery
  issue no additional certificate. Fixture leases and real PostgreSQL dispatch
  are tested separately; this is not full enrolled-agent release qualification.
- Native packed-agent artifact checks: 3 passed with task-local checksum-verified
  Go 1.26.6. Full agent regression run and final production image checks continue.

## Baseline reconciliation

Cloud advances its candidate Core compatibility baseline from 0.17.2 to the
0.17.3 source baseline plus this feature. Shared fingerprint/management-period
behavior comes through existing source mappings. Reviewed owned UI form limits
are aligned with Core 0.17.3 and its proxy-addr security override is adopted;
Cloud quota/billing and hosted auto-sync exclusions remain owned overrides.
Enterprise already had the 0.17.3 source pin but stale 0.17.2 Compose/Dockerfile
defaults; those defaults are corrected to the existing package baseline.
Candidate builds still explicitly select task-owned Core images.

## Release gates still outstanding

Full enrolled agent transport/customer DNS/Vault Agent rotation/host failure
qualification and actual appliance inventory/HA tests remain required before
capability promotion. Full three-repo release/coverage/integration/Grype gates
are not established by the focused lifecycle tests. Latest inspected Core main
CI (37791839057) was cancelled, including Docker Build & Security Scan; Cloud
main CI was still running; Enterprise master CI (37768437343) succeeded. These
are remote baseline observations, not CI results for this unpushed candidate.
