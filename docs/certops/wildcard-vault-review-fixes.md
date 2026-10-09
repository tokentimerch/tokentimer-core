# Wildcard Vault PR review fixes — 9 October 2026

Scope: Core #329, Cloud #160 and Enterprise #120. The four findings were
verified against heads 7bb65c1d, 0414fb8a and 68fe975e. No
`wildcard-vault-pr-review.md` was found in the worktrees or supplied
Downloads/Documents locations; the pasted request is the review specification.

1. Migration 69 transactionally releases only allocated versions belonging to
   rejected/cancelled jobs with zero attempts and no claim, start or lease
   evidence. A public reason/time and the job/approval/version history remain.
   The migration repairs already-stranded allocations with the same predicate.
   Claimed, staged, uncertain and generic failed publications stay fenced.
2. Publication/recovery receive `execution.keysDir` from local configuration.
   Protected canonical-key promotion follows the lease check. The checkpoint
   preserves the native executor's actual rotation boolean; older/remote-only
   recovery reports unknown rather than inventing rotation. Jobs cannot choose
   the custody directory.
3. Consumer PUT compares validated authorization fields under existing locks,
   including canonical UUIDs. Identical requests return the existing row without
   revision/change-audit churn. Real changes still advance and fence revisions.
4. Rollout requests serialize the workspace-scoped idempotency key and compare
   stable client identity before checking mutable material/membership. Matching
   retries return the original approval job. Legacy jobs derive identity from
   the frozen payload; new jobs persist an immutable separate digest. Full
   snapshot, approval hash and signed-intent coverage remain unchanged.

## Reproduction and isolation

Implementation worktrees remain beneath
`C:/Users/Admin/Documents/tokentimer/wildcard-vault-20261008/` on
`feat/wildcard-vault-distribution`. Audit branches, edits, services, environment
files and databases are preserved.

Start only the dedicated bounded PostgreSQL fixture on unused loopback 57470:

```powershell
docker compose -p tt-wildcard-review-20261009 -f tests/wildcard-vault/compose.yaml up -d postgres
```

Use a fresh `wildcard_candidate_review_*` database for each lifecycle run. Set
`DB_HOST=127.0.0.1`, `DB_PORT=57470`, `DB_USER=wildcard_fixture`,
`DB_PASSWORD=isolated-fixture-only`, `DB_NAME` to that dedicated database,
`NODE_ENV=test` and `CERTOPS_ENABLED=true` in the invoking process. Run the Core
migrator directly, then
`node --test --test-concurrency=1 tests/wildcard-vault/postgres.test.cjs`.
For Cloud use its direct migrator and set `TT_WILDCARD_API_ROOT` to its isolated
`apps/saas` directory before the same scenario. Logs are task-local under
`.scratch/wildcard-review-20261009/`. No root environment loader is used.

PostgreSQL coverage includes rejection rollback, corrected publication after
rejection/cancellation, actual backfill replay, uncertain-attempt fencing,
concurrent identical PUTs, retained proofs, real-change approval fencing,
idempotent replay before approval and after expansion/completion/membership and
identity changes, legacy replay, concurrent first requests, tenant denial,
renewal identities and signed claim/result replay. Agent tests use protected
files and real crypto with a synthetic Vault HTTP fault server to prove custom
custody, lost responses, recovery, CSR key reuse, truthful rotation reporting
and lease loss before promotion.

## Variant and release boundaries

Executed Core checks: 2,272 unit tests; 42 contract tests; both real PostgreSQL
lifecycle scenarios on a fresh 69-migration database; 199 native executor,
key/CSR and material-store tests (four platform/real-Vault tests skipped).
API/agent lint passed with existing warnings. Contracts, OpenAPI coverage,
integrity, lockfile overrides and secret-logging guards passed. This correction
uses synthetic Vault faults; the earlier real Vault/Pebble runs are historical.

Cloud merges main d930cf74, retaining its inventory migration 85; material
distribution is migration 86 and review fixes are migration 87. The earlier
PR-only 85/86 fixture numbering was unreleased: recreate those throwaway
candidate databases. Hosted billing/quota/freeze/continuing-result rules and
Enterprise RBAC/licensing remain owned behavior.

The 8 October image IDs/scans remain historical evidence for Core 7bb65c1d;
they do not qualify these corrections. Full coordinated image, release,
coverage/integration and enrolled-agent/customer-host qualification remain
outstanding. No capability promotion, merge, release or deployment is performed.
