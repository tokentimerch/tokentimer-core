# ADR-0005: CertOps threat model

## Status

Proposed (2026-06-25). Phase 0 skeleton (P0.2). Finalize in M0.

## Context

CertOps spans a control plane that holds no private keys and an execution plane
(agent / k8s controller) that does. The boundary between them is the primary
security surface. This ADR enumerates threats and the mitigation for each, with
each mitigation expressed as something that can be tested. It is a living
document; M0 fleshes out the TODOs and links each mitigation to a test id.

Trust boundaries:

- Internet / customer infra <-> control plane API
- Control plane <-> agent (outbound-only, scoped-token)
- Agent <-> host / CA / DNS provider
- Kubernetes cluster <-> TokenTimer controller

## Decision

Adopt the threat / mitigation table below. Every mitigation must have a test.

| # | Threat | Mitigation | Testable assertion |
|---|--------|-----------|--------------------|
| T1 | Private key reaches control plane via import/body | Content detector + 422 rejection at API boundary | A request body containing any PEM private-key variant (incl. base64-wrapped, nested) is rejected 422 `PRIVATE_KEY_MATERIAL_REJECTED` (unit tests for the detector already exist in `tests/unit/secretMaterial.test.js`) |
| T2 | Key material leaks into logs | Field-name redaction + content redaction | Log records with key material render the placeholder, never the key |
| T3 | Key material persisted in evidence | `redactGenericSecrets` before storage; size limits | Stored evidence never contains a private-key block |
| T4 | Forged job dispatched to agent | Ed25519 signature, agent pins public key, HMAC rejected | Agent rejects a job whose signature fails or that is HMAC-signed |
| T5 | Job replay | nonce + jobId replay cache; expiry window | Re-submitted job (same nonce/jobId) is rejected; expired job is rejected |
| T6 | Clock skew used to widen validity | Reported clock offset; agent rejects out-of-window | Job outside `[issuedAt, expiresAt]` (offset-adjusted) is rejected |
| T7 | Control plane over-reaches agent | Agent-local allowlists win | Job referencing a non-allowlisted command/path/CA/DNS zone is refused and reported as evidence |
| T8 | DNS-01 credentials centralized | Credentials agent-local only; control plane stores references | No DNS provider secret is ever stored control-plane side |
| T9 | k8s controller reads `tls.key` | Read hierarchy (status > annotations > `tls.crt`); narrow RBAC; code-level non-access; detector scan | RBAC minimizes Secret access (cannot prove per-key denial); tests prove controller code never reads/deserializes/logs/transmits `tls.key` |
| T10 | Stolen agent token reused broadly | Scoped tokens; bounded scope per workspace/agent | A token scoped to workspace A cannot act on workspace B |
| T11 | Compromised agent supply chain | Signed/checksummed images and packages | Release artifacts carry verifiable checksums/signatures |
| T12 | Frozen/over-quota workspace still executes | Fail-closed plan/freeze guards (cloud) | Frozen workspace requests return 403 `WORKSPACE_FROZEN`; over-limit returns 402 |

## Alternatives considered

- Defer the threat model to implementation - rejected: the mitigations dictate
  contract and schema shape, so they must be fixed in Phase 0.

## Consequences

- Each row becomes one or more tests, tracked in the M1/M2 issue map.
- TODO (M0): assign a test id to every row; add abuse cases for T1 (PKCS#12),
  T6 (drift thresholds), and T10 (scope matrix).
