# CertOps executor API (M2)

Reference for external systems that report certificate lifecycle events to
TokenTimer without running the (not-yet-shipped) TokenTimer agent. See
`docs/certops/CONTEXT.md` for domain language and ADR-0006 for where the
executor jobs/evidence UI lives in the dashboard.

## 1. Create an executor token

Machine tokens are scoped API keys for non-human callers (scripts, CI jobs,
certbot/ACME hooks). Create one from the dashboard: workspace manager or
admin role, `/certops/operations` page, "Machine API tokens" panel.

- Format: `ttx_<id>_<secret>` (`apps/api/services/certops/apiTokens.js`).
- The plaintext token is shown exactly once at creation time. Store it in a
  secret manager immediately; TokenTimer never stores or displays it again.
- Scopes (grant the minimum an executor needs):
  - `certops:read` - read certificates and jobs.
  - `certops:jobs:read` - poll job status.
  - `certops:events:write` - report job lifecycle events.
  - `certops:evidence:write` - attach evidence records (separate from
    `certops:events:write`; an events-only token cannot attach evidence).
  - M2 ships only the three write/report routes below (all `POST`); no
    machine-token-authenticated read route exists yet, so `certops:read` and
    `certops:jobs:read` are accepted and stored but not yet enforced by any
    route. They are forward-compatible with a machine-token read API planned
    for a later milestone.
- Tokens can have an optional expiry and are revocable at any time from the
  same panel. Revoking breaks any executor using that token immediately.
- Machine-token auth has no session dependency and is not subject to CSRF
  checks (the executor route prefixes below are the only CSRF-exempt paths,
  fail-closed by default elsewhere).

## 2. Report events

> **No public job-creation route yet.** M2 ships only the three
> machine-token routes documented here (events, per-job events, evidence);
> there is no API to create a `jobId`. Jobs must already exist before an
> executor can report against them (seeded by an internal process today).
> Treat `jobId` as an identifier your integration receives out-of-band, not
> one it mints itself; posting events for a `jobId` TokenTimer doesn't
> recognize returns 404 `CERTOPS_JOB_NOT_FOUND` (see below), it does not
> create the job.

```
POST /api/v1/certops/executor/events
POST /api/v1/certops/jobs/:jobId/events
```

Requires `certops:events:write`. Body:

```json
{
  "schemaVersion": 1,
  "eventId": "018f2e2a-6e2a-7c2a-9b1a-000000000001",
  "jobId": "018f2e2a-6e2a-7c2a-9b1a-000000000000",
  "eventType": "job.completed",
  "occurredAt": "2026-07-12T10:00:00.000Z",
  "message": "certificate renewed and reloaded",
  "metadata": { "cert.serial": "0a1b2c" }
}
```

- `eventType` is one of `job.accepted`, `job.started`, `job.progress`,
  `job.completed`, `job.failed`, `job.rejected`, `evidence.attached`
  (`apps/api/routes/certops-executor.js`).
- `eventId` makes ingestion idempotent per `(workspaceId, jobId, eventId)`:
  replaying the same `eventId` with the same payload is a no-op; replaying it
  with a different payload returns 409 `CERTOPS_EXECUTOR_EVENT_CONFLICT`.
- Job status transitions are monotonic. Once a job reaches a terminal status
  (`succeeded`, `failed`, `rejected`, `blocked`, `cancelled`), later events
  cannot reopen it; out-of-order/late events are accepted (202) but do not
  change the stored status.
- Unknown top-level fields are rejected, not silently dropped.
- Every event must reference an existing `jobId`; TokenTimer creates jobs
  (not the executor). Posting to an unknown `jobId` returns 404
  `CERTOPS_JOB_NOT_FOUND`.
- If the body's `workspaceId`/`jobId` conflicts with the per-job route's path
  parameters, the request is rejected with 403
  `CERTOPS_EXECUTOR_WORKSPACE_MISMATCH`. Evidence-mode requests sent with any
  `eventType` other than `evidence.attached` are rejected with 400
  `CERTOPS_EXECUTOR_EVENT_TYPE_INVALID`.

## 3. Attach evidence

```
POST /api/v1/certops/jobs/:jobId/evidence
```

Requires `certops:evidence:write`. Evidence types: `certificate.observed`,
`deployment.checked`, `deployment.updated`, `validation.passed`,
`validation.failed`, `policy.checked` (`apps/api/services/certops/evidence.js`).

- **Never send private key material.** Any payload matching known private-key
  patterns (PEM key blocks, PKCS#8/PKCS#1 headers, etc.) is rejected outright
  with HTTP 422 `PRIVATE_KEY_MATERIAL_REJECTED`, before any other validation
  runs.
- Generic secret-shaped fields (tokens, passwords, API keys) found in
  `output`/`metadata` are redacted in place and replaced with a placeholder;
  the response reports which fields were redacted (`redactionApplied`).
- Evidence output is size-limited (64 KB after redaction); oversized output
  is rejected with `CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE` rather than truncated
  silently.

## 4. Rate limiting

Every machine token is limited to a default of 120 requests per 60-second
window (`apps/api/middleware/machine-token-rate-limit.js`). The limiter key is
`certops-machine:<workspaceId>:<tokenPrefix>[:<machineId>]`, with **no route
segment**: a single token shares one bucket across all three executor routes
(`POST /api/v1/certops/executor/events`, `POST
/api/v1/certops/jobs/:jobId/events`, `POST /api/v1/certops/jobs/:jobId/evidence`),
not a separate budget per route. Exceeding the limit returns HTTP 429
`CERTOPS_MACHINE_RATE_LIMITED` with a `Retry-After` header (seconds). See
`plans/CERTOPS_EXECUTION_PLAN_2DEV.md` (task A3) for the recorded design
decision behind the shared bucket.

## 5. Error codes

| HTTP | Code | Meaning |
|---|---|---|
| 401 | `CERTOPS_API_TOKEN_UNAUTHORIZED` | Missing, malformed, unknown, revoked, or expired token. |
| 403 | `CERTOPS_API_TOKEN_SCOPE_DENIED` | Token is valid but lacks a required scope for this route. |
| 403 | `CERTOPS_EXECUTOR_WORKSPACE_MISMATCH` | Body `workspaceId`/`jobId` conflicts with the token's bound workspace or the per-job route's path parameter. |
| 400 | `CERTOPS_EXECUTOR_EVENT_INVALID` | Malformed event payload: bad schema, unknown top-level/evidence-item field, invalid `eventType`, malformed IDs. |
| 400 | `CERTOPS_EXECUTOR_EVENT_TYPE_INVALID` | Evidence-mode request (`/jobs/:jobId/evidence`) sent with an `eventType` other than `evidence.attached`. |
| 404 | `CERTOPS_JOB_NOT_FOUND` | `jobId` does not reference a job TokenTimer already knows about. |
| 409 | `CERTOPS_EXECUTOR_EVENT_CONFLICT` | Same `eventId` replayed with a different payload than the one first accepted. |
| 422 | `PRIVATE_KEY_MATERIAL_REJECTED` | Payload matched a known private-key pattern; rejected before any other validation or persistence. |
| 422 | `CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE` | Evidence `output` exceeds the 64 KB post-redaction size cap. |
| 429 | `CERTOPS_MACHINE_RATE_LIMITED` | Token exceeded its shared rate-limit bucket (see section 4). |
| 404 | `NOT_FOUND` | CertOps is disabled for the workspace (`certops.enabled` fail-closed) or the route does not exist; identical response either way. |

All error bodies are `{ "error": { "code": "...", "message": "..." } }` with
no sensitive data (tokens, key material, raw secrets) ever echoed back.

## 6. Minimal external executor example

A plain HTTP loop is enough to be a valid executor; there is no SDK
requirement in M2.

```bash
#!/usr/bin/env bash
# minimal-executor.sh - illustrative only, not a shipped tool
set -euo pipefail

API_BASE="https://<workspace-host>/api/v1"
TOKEN="ttx_<id>_<secret>"          # certops:events:write + certops:evidence:write
JOB_ID="$1"

curl -sS -X POST "$API_BASE/certops/jobs/$JOB_ID/events" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"schemaVersion\":1,\"eventId\":\"$(uuidgen)\",\"jobId\":\"$JOB_ID\",\"eventType\":\"job.started\",\"occurredAt\":\"$(date -u +%FT%TZ)\"}"

# ... do the certificate work (renew/deploy/reload) out of band ...

curl -sS -X POST "$API_BASE/certops/jobs/$JOB_ID/events" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"schemaVersion\":1,\"eventId\":\"$(uuidgen)\",\"jobId\":\"$JOB_ID\",\"eventType\":\"job.completed\",\"occurredAt\":\"$(date -u +%FT%TZ)\"}"
```

## 7. certbot / acme.sh renewal hook example

Both certbot's `--deploy-hook` and acme.sh's `--renew-hook` run a shell
command after a successful renewal, with the renewed domain/paths available
as environment variables. Report success from that hook; report failure from
your own error handling around the renewal command (certbot/acme.sh do not
invoke deploy hooks on failure).

```bash
#!/usr/bin/env bash
# certbot-deploy-hook.sh
# certbot renew --deploy-hook /path/to/certbot-deploy-hook.sh
set -euo pipefail

API_BASE="https://<workspace-host>/api/v1"
TOKEN="ttx_<id>_<secret>"
JOB_ID="<job id issued for this certificate's renewal>"

curl -sS -X POST "$API_BASE/certops/jobs/$JOB_ID/events" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"schemaVersion\":1,\"eventId\":\"$(uuidgen)\",\"jobId\":\"$JOB_ID\",\"eventType\":\"job.completed\",\"occurredAt\":\"$(date -u +%FT%TZ)\",\"message\":\"renewed via certbot for $RENEWED_DOMAINS\"}"

curl -sS -X POST "$API_BASE/certops/jobs/$JOB_ID/evidence" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"schemaVersion\":1,\"evidenceType\":\"deployment.updated\",\"observedAt\":\"$(date -u +%FT%TZ)\",\"summary\":\"nginx reloaded after cert renewal\"}"
```

Do not include `$RENEWED_LINEAGE` file contents (certbot's live cert/key
directory) in any event or evidence payload; only reference paths or
fingerprints, never key material. `--deploy-hook` and `--renew-hook` scripts
run with access to the private key on disk, but nothing derived from that key
should ever be sent to TokenTimer.

## 8. Timeline in the dashboard

Reported events and evidence show up under `/certops/operations` (Executor
jobs panel + evidence timeline) for workspace managers/admins, with status
badges, redaction markers, and audit links where available. See
`apps/dashboard/src/components/certops/{JobStatusBadge,EvidenceTimeline,CertificateTimeline}.jsx`.
