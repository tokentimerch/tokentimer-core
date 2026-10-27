# Distribution lifecycle implementation plan

Baseline: `origin/main` at `69371864`; PR #460 was open on 2026-10-27. Do not import its code, workflows, temporary trust exceptions, or capability claims.

Integration update: main advanced to `63e97bf8` during final validation. Its merged safety changes and auto-sync migrations 79–80 were integrated without rewriting feature commits. The new lifecycle migrations now follow them at 81–84; #460 remains open and untouched.

Reuse `materialDistribution`, `distributionOperations`, `distributionRead`, signed material jobs, Jobs approvals, the CertOps outbox/worker, operational notifications/contact groups/delivery eligibility, the first-distribution guide, and the read-only Deployments component.

1. Add public lifecycle metadata in the next unapplied migration (current ledger ends at 78). Add revisioned, workspace/group-scoped policies, bounded standing authorization through genuine Jobs approval, and deterministic post-publication rollout requests. Defaults remain manual. Preserve workspace mandatory approval on both parent and child jobs.
2. Add per-consumer activation/maintenance policy. Snapshot it in approved intents, enforce it before dispatch and again customer-side, and preserve existing generation/revision fences. UTC-instant evaluation of IANA local calendars handles DST; blackouts win. Unsupported activation connectors fail closed.
3. Add durable verification scheduling through the existing verification-only rollout path. Serialize per group, retain exact-version pins, bound concurrency, back off offline/failing agents, and never replace an in-flight or uncertain operation.
4. Monitor desired/observed identity, independent deployed expiry and proof freshness. Persist deduplicated incidents and redacted lifecycle evidence through existing notification infrastructure. Resolve only on fresh consumer proof.
5. Add a separate Distribution page using existing workspace/RBAC/API/design patterns. Link from Deployments; reuse first-distribution setup. Expose consumers, versions, Jobs approval, pause/resume, verification, retry/recovery, policy, incidents, and retention preview.
6. Add constrained connector descriptors and stable service relationship metadata, non-mutating preflight and guided reconciliation. Do not enable unsupported Windows/OpenBao/Azure capabilities.
7. Add reviewed retention policy and conservative, explainable metadata eligibility. Destructive provider operations remain disabled unless independently implemented and qualified with exact customer-owned object semantics.
8. Qualify with focused unit/contract/agent/frontend tests and real PostgreSQL concurrency/restart/migration tests, run the canonical Core CI skill, update operator/security/qualification docs, commit each coherent slice, and push/open a reviewable PR without merging.

Security invariants: public metadata only; no store credentials or private material in control-plane inputs, persistence, jobs, logs, or notifications. No synthetic approvals, arbitrary shell/PowerShell targets, stolen locks, uncertain-state clearing, or qualification bypasses.
