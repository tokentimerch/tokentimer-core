# COORDINATION-H3 — Signing key rotation heartbeat notice

Server-side signing-key rotation (control plane) delivers an overlapping
old/new key lifecycle. Agent-side consumption of the heartbeat notice is
owned by a parallel engineer; this document is the contract for that work.

## Lifecycle (server)

1. `beginSigningKeyRotation()` creates a new Ed25519 key as `active` and moves
   the previous key to `retiring` (still accepted for verification until
   retired).
2. Heartbeat responses include `signingKeyRotation` when the agent's pinned
   key is not yet the new active key.
3. Agents acknowledge by sending `body.pinnedSigningKeyId` equal to the new
   key id on a subsequent heartbeat. The server records an ack row in
   `certops_signing_key_acks`.
4. `completeSigningKeyRotation()` retires the `retiring` key only when every
   `active` agent has acknowledged, or when an operator forces incomplete
   rotation (`force: true`, reason logged on the key row).

## Heartbeat response field

Added alongside existing heartbeat fields (`ok`, `status`, `lastSeenAt`,
`signingKeyId`, `signingPublicKeyPem`):

```json
{
  "ok": true,
  "status": "active",
  "lastSeenAt": "2026-07-24T08:00:00.000Z",
  "signingKeyId": "ttsk_<new>",
  "signingPublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...",
  "signingKeyRotation": {
    "pendingSigningKeyId": "ttsk_<new>",
    "pendingPublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...",
    "supersedesSigningKeyId": "ttsk_<old>",
    "status": "pending_ack"
  }
}
```

When the agent has already pinned the active key, `signingKeyRotation` is
`null`.

## Agent acknowledgement

On the next heartbeat after adopting the new key, set:

```json
{
  "pinnedSigningKeyId": "<pendingSigningKeyId from signingKeyRotation>"
}
```

That value is also what the agent should use for subsequent job signature
verification (TOFU update).
