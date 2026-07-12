# CertOps executor API (M2)

Reference for external systems that report certificate lifecycle events to
TokenTimer without running the (not-yet-shipped) TokenTimer agent. See
`docs/certops/CONTEXT.md` for domain language and ADR-0006 for where the
executor jobs/evidence UI lives in the dashboard.

Every request/response example in this document is exercised verbatim in
`tests/integration/certops-docs-fixtures.test.js` (fixtures in
`tests/fixtures/certops-docs-examples.js`) against the real executor routes.
If validation or response shape changes, that test fails before this doc
goes stale.

## 1. Create an executor token

Machine tokens are scoped API keys for non-human callers (scripts, CI jobs,
certbot/ACME hooks). Create one from the dashboard: workspace manager or
admin role, `/certops/operations` page, "Machine API tokens" panel.

- Format: `ttx_<id>_<secret>` (`apps/api/services/certops/apiTokens.js`).
- The plaintext token is shown exactly once, in the create-token response.
  TokenTimer stores only a SHA-256 hash of the token; it cannot be retrieved
  or re-displayed later, including by TokenTimer staff. Store it in a secret
  manager immediately, or you will need to revoke it and create a new one.
- Allowed scopes (`ALLOWED_SCOPES` in `apiTokens.js`), grant the minimum an
  executor needs:
  - `certops:read` - read certificates and jobs.
  - `certops:jobs:read` - poll job status.
  - `certops:events:write` - report job lifecycle events (section 2 below).
  - `certops:evidence:write` - attach evidence records (separate from
    `certops:events:write`; an events-only token cannot attach evidence,
    and a request that includes evidence with an events-only token is
    rejected).
  - M2 ships only the two routes below (both `POST`); no machine-token
    read route exists yet, so `certops:read` and `certops:jobs:read` are
    accepted and stored but not yet enforced by any route. They are
    forward-compatible with a machine-token read API planned for a later
    milestone.
- Tokens can have an optional expiry and are revocable at any time from the
  same panel. Revoking breaks any executor using that token immediately.
- Machine-token auth has no session dependency and is not subject to CSRF
  checks (the executor route prefixes below are the only CSRF-exempt paths,
  fail-closed by default elsewhere).

## 2. Report events

```
POST /api/v1/certops/executor/events
POST /api/v1/certops/jobs/:jobId/events
```

Requires `certops:events:write`. The per-job route (`/jobs/:jobId/events`)
takes `jobId` from the URL and rejects a body `jobId` that disagrees with it;
the aggregate route (`/executor/events`) requires `jobId` in the body. Both
routes require `workspaceId` in the body and reject it if it does not match
the token's own workspace (403 `CERTOPS_EXECUTOR_WORKSPACE_MISMATCH`).

A job must already exist before an executor can report against it.
**TokenTimer creates jobs, not the executor** (there is no public "create
job" API for executors in M2); jobs come from the workspace's existing
CertOps flows. Posting to an unknown `jobId` returns 404
`CERTOPS_JOB_NOT_FOUND`.

Body (verified in `tests/integration/certops-docs-fixtures.test.js`):

```json
{
  "schemaVersion": 1,
  "eventId": "evt-2026-07-12-000001",
  "workspaceId": "0b8f2e2a-6e2a-4c2a-9b1a-1a2b3c4d5e6f",
  "jobId": "5f3a1c9e-7d21-4e11-8b2a-9c7d6e5f4a3b",
  "status": "succeeded",
  "eventType": "job.completed",
  "occurredAt": "2026-07-12T10:00:00.000Z",
  "message": "certificate renewed and reloaded",
  "metadata": [{ "name": "cert.serial", "value": "0a1b2c" }]
}
```

A successful submission returns **HTTP 202** (Accepted), not 200/201:

```json
{
  "ok": true,
  "eventId": "...",
  "logId": "...",
  "jobId": "5f3a1c9e-7d21-4e11-8b2a-9c7d6e5f4a3b",
  "status": "succeeded",
  "evidenceIds": [],
  "duplicate": false,
  "idempotent": true
}
```

- Both `status` and `workspaceId` are required top-level fields, not
  optional. `status` must be one of the job/log statuses accepted by
  `normalizeStatus` (`apps/api/routes/certops-executor.js`); it cannot be
  `queued`. `eventType` is one of `job.accepted`, `job.started`,
  `job.progress`, `job.completed`, `job.failed`, `job.rejected`,
  `evidence.attached`.
- `metadata`, when present, is an array of `{ "name": string, "value":
  string|number|boolean|null }` entries, not a free-form object. Metadata
  entry names must not look like key/credential fields (the contract in
  `packages/contracts/certops/executor-event.schema.json` rejects names
  matching private-key/secret/password patterns outright).
- `eventId` makes ingestion idempotent per `(workspaceId, jobId, eventId)`:
  replaying the same `eventId` with the same payload is a no-op (still
  returns 202, `idempotent: true`); replaying it with a different payload
  returns 409 `CERTOPS_EXECUTOR_EVENT_CONFLICT`.
- Job status transitions are monotonic. Once a job reaches a terminal status
  (`succeeded`, `failed`, `rejected`, `blocked`, `cancelled`), later events
  are still accepted (202, logged) but do not reopen or change the stored
  status.
- Unknown top-level fields are rejected, not silently dropped.
- If the body's `workspaceId`/`jobId` conflicts with the per-job route's path
  parameters, the request is rejected with 403
  `CERTOPS_EXECUTOR_WORKSPACE_MISMATCH` (workspace) or a jobId-mismatch 400.
  Evidence-mode requests (section 3) sent with any `eventType` other than
  `evidence.attached` are rejected with 400
  `CERTOPS_EXECUTOR_EVENT_TYPE_INVALID`.

## 3. Attach evidence

```
POST /api/v1/certops/jobs/:jobId/evidence
```

This is the same underlying handler as section 2's per-job events route,
called in evidence mode: it forces `eventType` to `evidence.attached` and
requires `certops:evidence:write` (an events-only token is rejected). You
report evidence either inline as an `evidence` array on a events-route call
that also holds `certops:evidence:write`, or by calling this dedicated route,
whose body is a single event envelope carrying one or more `evidence` items:

```json
{
  "schemaVersion": 1,
  "eventId": "evt-2026-07-12-000002",
  "workspaceId": "0b8f2e2a-6e2a-4c2a-9b1a-1a2b3c4d5e6f",
  "jobId": "5f3a1c9e-7d21-4e11-8b2a-9c7d6e5f4a3b",
  "status": "accepted",
  "eventType": "evidence.attached",
  "occurredAt": "2026-07-12T10:05:00.000Z",
  "evidence": [
    {
      "schemaVersion": 1,
      "evidenceId": "ev-2026-07-12-000001",
      "eventType": "certificate.observed",
      "source": "executor",
      "observedAt": "2026-07-12T10:05:00.000Z",
      "certificateId": "cert-web-01",
      "summary": "Observed public certificate fingerprint after renewal",
      "metadata": [{ "name": "issuer", "value": "Let's Encrypt" }]
    }
  ]
}
```

Evidence `eventType` values (distinct from the event-envelope `eventType`
above): `certificate.observed`, `deployment.checked`, `deployment.updated`,
`validation.passed`, `validation.failed`, `policy.checked`
(`apps/api/services/certops/evidence.js`).

A successful submission is also **HTTP 202**, with `evidenceIds` populated:

```json
{
  "ok": true,
  "jobId": "5f3a1c9e-7d21-4e11-8b2a-9c7d6e5f4a3b",
  "status": "accepted",
  "evidenceIds": ["..."],
  "redactionApplied": false
}
```

Redaction and rejection are two different code paths, do not conflate them:

- **Never send private key material. It is always rejected, never
  redacted.** Any payload matching known private-key patterns (PEM key
  blocks, PKCS#8/PKCS#1 headers, etc., detected by
  `containsPrivateKeyMaterial` in `apps/api/utils/secretMaterial.js`) is
  rejected outright with **HTTP 422** `PRIVATE_KEY_MATERIAL_REJECTED`,
  before any other validation runs and before anything is persisted. This
  applies to the whole request body, not just the `evidence`/`output`
  fields.
- Separately, generic secret-shaped fields (tokens, passwords, API keys,
  matched by `redactGenericSecretsWithReport` in the same file) found in
  evidence `output` are redacted in place to `[REDACTED]` and the evidence
  *is still stored*, with the response reporting `redactionApplied: true`
  (and a redaction count in the audit log). This redaction path is for
  incidental secrets accidentally captured in command output, not an
  alternative to the private-key rejection above.
- Evidence `output` is size-limited (64 KB, `MAX_REDACTED_OUTPUT_BYTES`,
  checked after redaction); oversized output is rejected with
  `CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE` rather than truncated silently.

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
WORKSPACE_ID="<your workspace id>"
JOB_ID="$1"                        # must already exist; executors do not create jobs

curl -sS -X POST "$API_BASE/certops/jobs/$JOB_ID/events" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"schemaVersion\":1,\"eventId\":\"$(uuidgen)\",\"workspaceId\":\"$WORKSPACE_ID\",\"jobId\":\"$JOB_ID\",\"status\":\"running\",\"eventType\":\"job.started\",\"occurredAt\":\"$(date -u +%FT%TZ)\"}"

# ... do the certificate work (renew/deploy/reload) out of band ...

curl -sS -X POST "$API_BASE/certops/jobs/$JOB_ID/events" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"schemaVersion\":1,\"eventId\":\"$(uuidgen)\",\"workspaceId\":\"$WORKSPACE_ID\",\"jobId\":\"$JOB_ID\",\"status\":\"succeeded\",\"eventType\":\"job.completed\",\"occurredAt\":\"$(date -u +%FT%TZ)\"}"
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
WORKSPACE_ID="<your workspace id>"
JOB_ID="<job id issued for this certificate's renewal>"

curl -sS -X POST "$API_BASE/certops/jobs/$JOB_ID/events" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"schemaVersion\":1,\"eventId\":\"$(uuidgen)\",\"workspaceId\":\"$WORKSPACE_ID\",\"jobId\":\"$JOB_ID\",\"status\":\"succeeded\",\"eventType\":\"job.completed\",\"occurredAt\":\"$(date -u +%FT%TZ)\",\"message\":\"renewed via certbot for $RENEWED_DOMAINS\"}"

curl -sS -X POST "$API_BASE/certops/jobs/$JOB_ID/evidence" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"schemaVersion\":1,\"eventId\":\"$(uuidgen)\",\"workspaceId\":\"$WORKSPACE_ID\",\"jobId\":\"$JOB_ID\",\"status\":\"accepted\",\"eventType\":\"evidence.attached\",\"occurredAt\":\"$(date -u +%FT%TZ)\",\"evidence\":[{\"schemaVersion\":1,\"evidenceId\":\"$(uuidgen)\",\"eventType\":\"deployment.updated\",\"source\":\"executor\",\"observedAt\":\"$(date -u +%FT%TZ)\",\"summary\":\"nginx reloaded after cert renewal\"}]}"
```

Do not include `$RENEWED_LINEAGE` file contents (certbot's live cert/key
directory) in any event or evidence payload; only reference paths or
fingerprints, never key material. `--deploy-hook` and `--renew-hook` scripts
run with access to the private key on disk, but nothing derived from that key
should ever be sent to TokenTimer, and if it is, the request is rejected
(section 3), not silently accepted.

## 8. Timeline in the dashboard

Reported events and evidence show up under `/certops/operations` (Executor
jobs panel + evidence timeline) for workspace managers/admins, with status
badges, redaction markers, and audit links where available. See
`apps/dashboard/src/components/certops/{JobStatusBadge,EvidenceTimeline,CertificateTimeline}.jsx`.
