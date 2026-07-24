# COORDINATION-B6 — Agent lease renew contract

Parallel agent-runtime work (`packages/agent/src/index.js`) should call this
server endpoint **before every external side effect** (ACME, DNS mutation,
deploy write, reload). The control-plane reaper treats a job that never
renewed as "no side effects proven" (safe automatic requeue) and a job that
renewed as `effects_unknown` (manual reconciliation, never silent retry).

## Endpoint

```
POST /api/v1/certops/agent/jobs/:jobId/lease
Authorization: Bearer <agent credential>
Content-Type: application/json
```

## Request body

```json
{
  "claimId": "<uuid from signed dispatch payload.claimId / attemptId>",
  "sequence": 12
}
```

| Field | Required | Notes |
| --- | --- | --- |
| `claimId` | yes | Opaque claim id from the signed job. Must match the current claim held by this agent. |
| `sequence` | no | Per-agent monotonic counter (same semantics as heartbeat/claim/result). Once the agent has sent any sequenced message, omitting `sequence` is rejected. |

This route does **not** use the agent-protocol message envelope (`messageType`).
The job id is in the path; auth is the agent credential; ownership is
`agent_id + claimId`.

## Success response (`200`)

```json
{
  "ok": true,
  "jobId": "<uuid>",
  "status": "running",
  "claimId": "<uuid>",
  "leaseExpiresAt": "2026-07-24T12:15:00.000Z",
  "leaseRenewedAt": "2026-07-24T12:00:00.000Z",
  "nonceExpiresAt": "2026-07-24T13:20:00.000Z"
}
```

- First successful call transitions `claimed` → `running` and stamps
  `started_at` / `lease_renewed_at`.
- Every successful call extends `lease_expires_at` by
  `CERTOPS_JOB_LEASE_SECONDS` (default 900) and extends the still-open
  dispatch nonce so result reporting stays valid through the reaper hard
  grace (`leaseTiming.dispatchNonceTtlSeconds`).

## Error responses

| Status | Code | When |
| --- | --- | --- |
| 400 | `CERTOPS_AGENT_MESSAGE_INVALID` | Malformed body / jobId |
| 400 | `CERTOPS_AGENT_LEASE_INVALID` | Job not in claimed/running, or missing claimId |
| 401 | (auth) | Bad/missing agent credential |
| 409 | `CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH` | claimId / agent does not own the job |
| 409 | `CERTOPS_AGENT_SEQUENCE_REGRESSION` | Sequence not strictly increasing |
| 410 | `CERTOPS_AGENT_RETIRED` | Agent is retired |
| 404 | `CERTOPS_AGENT_JOB_NOT_FOUND` | Unknown job in this workspace |

## Agent call sites (expected)

1. Immediately after accepting a claimed job (first renew → `running`).
2. Immediately before each side-effecting step (ACME order, DNS upsert,
   file deploy, service reload).
3. Optionally on a timer while waiting on long ACME polls, to keep the
   lease and nonce alive.

Do **not** renew after a terminal result has been submitted.
