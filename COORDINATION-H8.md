# H8 — Fleet / protocol compatibility (coordination)

Control-plane implementation lives in `apps/api/services/certops/agentRegistry.js`
(`computeAgentCompatibility`, applied in `toPublicAgent` / fleet list + heartbeat).

## Fleet / agent API fields (additive)

Every agent object returned by fleet/status routes now includes:

```json
{
  "compatibilityState": "compatible",
  "clockDriftState": "ok",
  "clockDriftMs": 1200
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `compatibilityState` | `"compatible"` \| `"outdated"` \| `"blocked"` | From reported `protocolVersion` + `agentVersion` vs config |
| `clockDriftState` | `"ok"` \| `"warn"` \| `"alert"` \| `null` | `null` when offset unknown |
| `clockDriftMs` | `number` \| `null` | Absolute offset in ms |

## Config (API env)

| Env | Default role |
| --- | --- |
| `CERTOPS_AGENT_MIN_PROTOCOL_VERSION` | Prefer / require minimum protocol |
| `CERTOPS_AGENT_MAX_PROTOCOL_VERSION` | Block above this protocol |
| `CERTOPS_AGENT_MIN_AGENT_VERSION` | Prefer / require minimum agent package version |
| `CERTOPS_AGENT_MAX_AGENT_VERSION` | Block above this agent version |
| `CERTOPS_AGENT_CLOCK_DRIFT_WARN_MS` | Warn threshold |
| `CERTOPS_AGENT_CLOCK_DRIFT_ALERT_MS` | Alert/flag threshold |

## Follow-up

Full alert delivery (reuse of `renewalFailureAlerts` style dispatch) is not
wired yet; UI/ops should treat `clockDriftState: "alert"` and
`compatibilityState: "blocked"` as the primary signals.
