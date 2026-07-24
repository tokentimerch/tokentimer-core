# COORDINATION-H1 — Registration idempotency key

## Finding

H1: Registration cannot recover from a crash between bootstrap-token
consumption and local credential persistence. The bootstrap token is
single-use server-side; if the agent receives the credential response but
crashes before writing it locally, the installation is unrecoverable.

## Contract (agent → control plane)

**Field name:** `registrationId`

**Where:** `registerBody` on `POST /api/v1/certops/agent/register`
(agent-protocol envelope `messageType: "register"`).

**Shape:**

| Property | Type | Required | Constraints |
|---|---|---|---|
| `registrationId` | string | yes (from agent v0.11+; treat as required for new installs) | 1–128 chars, pattern `^[A-Za-z0-9_.:-]+$` (UUID v4 recommended) |

Example body fragment:

```json
{
  "bootstrapTokenId": "bst_abc123",
  "agentVersion": "0.1.0",
  "registrationId": "550e8400-e29b-41d4-a716-446655440000",
  "hostname": "host-1",
  "platform": "linux",
  "nodeVersion": "v22.0.0",
  "declaredTargetSelectors": ["example.com"],
  "declaredCommandProfileNames": ["nginx-reload"]
}
```

## Server behavior required (apps/api/routes/certops-agent.js)

1. Accept `registrationId` on register requests.
2. Persist a durable map from `registrationId` → issued
   `{ agentId, credential, protocolVersion, signingKeyId?, signingPublicKeyPem? }`
   keyed also to the bootstrap token / workspace, for at least as long as
   a reasonable crash-retry window (hours to days).
3. **First** request with a given `(bootstrapToken, registrationId)` pair:
   consume the bootstrap token, mint the credential, store under
   `registrationId`, return the response.
4. **Retry** with the **same** `registrationId` after the token was already
   consumed: return the **same** registration response (idempotent replay).
   Do **not** hard-reject as “token already used” when the `registrationId`
   matches a completed registration for that token.
5. A retry with a **different** `registrationId` against an already-spent
   token remains a hard rejection (prevents minting a second agent from one
   token by inventing a new id).
6. Response shape is unchanged: still
   `{ agentId, credential, protocolVersion, signingKeyId?, signingPublicKeyPem? }`.

## Agent behavior (this branch)

1. Generate a UUID `registrationId` and persist it under the agent config
   dir (`registration-id.json`, 0600) **before** sending register.
2. Include `registrationId` on every register attempt.
3. On success, persist credential via the existing write-ahead journal, then
   clear `registration-id.json`.
4. After a crash mid-flight, restart reuses the same persisted
   `registrationId` so the server can replay the credential response.

## Owner split

| Side | Owner |
|---|---|
| Client generate / persist / send / accept replay | `packages/agent` (this worktree) |
| Server idempotent store + replay | `apps/api/routes/certops-agent.js` (parallel branch) |
