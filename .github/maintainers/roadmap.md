# Roadmap maintenance

For maintainers coordinating public roadmap scope, release evidence and
tracker consistency. Operator installation and usage guides remain in
`docs/`; contributor entry points are in `CONTRIBUTING.md`.

## Responsibilities

GitHub delivery issues own public Core scope, acceptance and evidence.
ROADMAP.md owns sequencing and release gates. Internal planning owns
priorities, owners and cross-edition dependencies; private mappings stay
there. Featurebase owns customer requests, votes and edition availability.
CHANGELOG.md and a published release establish released Core behavior.

Each outcome has one delivery issue; implementation PRs and smaller issues
link to it. The outcome index is navigation metadata, not another spec.

## Scope and status

Preserve the v1.0.0 RBAC contract and deliberate prerequisite list.
Alongside 0.x is accepted work on its own schedule. Later is queued or
exploratory scope without a version promise. Neither becomes a v1 gate.

Featurebase Ideas/Feedback means uncommitted demand; Next up means accepted
queued scope; In Progress requires active implementation; Live requires
released capability for the stated edition. An umbrella can have one active
increment while others remain queued. Link and name that increment.

Split shipped baselines from remaining extensions. Preserve existing votes
on the remaining request where practical, and create a Live baseline card
with release evidence. Inventory refresh, provider credential rotation and
certificate renewal are distinct outcomes.

## Release review checklist

- [ ] Check linked delivery issues against the exact candidate and released baseline.
- [ ] Record release evidence within existing issue sections. Complete only
      supported acceptance items; close delivered scope and split follow-ups.
- [ ] Remove shipped active roadmap entries, preserve the exact v1.0.0 RBAC
      heading, and update Last reviewed.
- [ ] Reconcile internal status and customer card scope/status per edition.
      Core delivery alone does not establish downstream availability.
- [ ] Inspect active implementation PRs as well as issues. Record partial
      coverage and outstanding qualification. Coordinate overlapping
      migration numbers before integrating parallel feature branches;
      never renumber migrations already deployed on main.
- [ ] Update .github/maintainers/roadmap-outcomes.json for accepted,
      rescheduled or shipped outcomes.
- [ ] Run node scripts/check-roadmap-drift.mjs and reconcile findings.
      Review missing or stale companion evidence before claiming a full audit.
- [ ] Scan changed public files for private references. Use the normal PR
      Summary and Test plan with actual validation and pending checks.

Make coordinated edits once per reconciliation. Do not post routine
progress comments, execution logs or automatic follow-up narration.

## Read-only drift check

Run from the repository root with Node 24 and authenticated gh:

```powershell
node scripts/check-roadmap-drift.mjs
node --test scripts/check-roadmap-drift.test.mjs
```

The checker reads the outcome index and ROADMAP.md, then makes GET-only
GitHub API calls. It never edits files, comments, tickets or status. It
checks roadmap section/horizon mismatches, missing links/issues, closed
active issues, published-release evidence, explicitly referenced unindexed
active PRs, companion status/canonical-link conflicts and stale
snapshots (seven days). It is on demand, not a scheduled job or new CI gate.

For offline use pass --snapshot and a JSON path containing capturedAt and
an issues array of GitHub objects with number/state. Include body and
pull_request for PR discovery; pulls use number/state/merged_at. Released
outcomes require releases with tag_name, draft, prerelease and published_at.
Use --json for machine-readable output.

Pass --companion and a local JSON path for exported internal planning and
Featurebase evidence. Keep that private file outside this public repository:

```json
{
  "capturedAt": "2026-10-28T12:00:00Z",
  "planning": [{
    "issue": 502, "status": "In Progress",
    "links": ["https://github.com/tokentimerch/tokentimer-core/issues/502"]
  }],
  "feedback": [{
    "url": "https://tokentimer.featurebase.app/en/p/mcp-server-to-interact-with-tokentimer",
    "status": "In Progress",
    "issues": [502],
    "edition": "core"
  }]
}
```

Shared cards can link multiple issues. Only mapped outcomes are compared;
unrelated backlog issues are intentionally outside coverage. Missing
companion evidence is reported as partial coverage, never agreement.
For umbrella mappings, set deliveryIssue to the actual child delivery issue,
declare that child in relatedIssues in the index, and preserve its observed
link and status. Open work can legitimately be Backlog, Todo, In Progress or
In Review; only explicit planningStatus expectations require one exact state.
Use implementationPrs to record multiple partial implementations. A card's
overall In Progress state does not make every linked subfeature active.
planningCapturedAt and feedbackCapturedAt may retain independent collection
times. Edition metadata identifies the mapped scope; it does not prove
availability or adoption in another edition.

The report checks mechanical status, links and placement. It does not
certify implementation completeness, acceptance, merge readiness or native
production qualification. Manually reconcile those against PR scope and
release evidence even when the mechanical report has no findings.
Exit codes: 0 no drift in supplied coverage, 1 drift, 2 invalid input or
access failure. A finding does not automatically change a release gate.
