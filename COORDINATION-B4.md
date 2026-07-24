# COORDINATION-B4 — Job `mode` field contract

This documents the dry-run job schema owned by the scheduler/jobs cluster so
the agent execution engineer (`packages/agent/src/index.js`) can match it
exactly.

## Field

| Location | Name | Type | Values | Immutable after create? |
|---|---|---|---|---|
| `certificate_jobs.mode` column | `mode` | `TEXT NOT NULL` | `"real"` \| `"dry_run"` | Yes |
| Job payload / signed dispatch | `mode` | string | `"real"` \| `"dry_run"` | Yes (copied from column at create/claim) |

- Default at creation when omitted: `"real"` (dry-run is never an ambient default).
- Callers must pass `mode: "dry_run"` explicitly to create a dry-run job.
- The claim/signing path always includes `mode` on the signed dispatch payload.

## Terminal status for dry-run

| Job mode | Allowed successful terminal status | Forbidden |
|---|---|---|
| `"real"` | `"succeeded"` | `"dry_run_complete"` |
| `"dry_run"` | `"dry_run_complete"` | `"succeeded"` |

Dry-run jobs must **never** be marked `succeeded`. They did not perform key
generation, renewal, deployment, reload, or verification. Report
`dry_run_complete` (agent result body `status: "dry_run_complete"`) instead.

`failed` / `rejected` / `blocked` / `cancelled` remain valid for both modes.

## Agent-side checklist

1. Read `job.mode` (or `payload.mode`) from the signed dispatch envelope.
2. When `mode === "dry_run"`, plan only; do not mutate keys/certs/services.
3. On completion of a dry-run, report result status `dry_run_complete`, never `succeeded`.
4. Do not rely on ambient `execution.dryRun` config as the source of truth for a claimed job; the job's `mode` field wins.
