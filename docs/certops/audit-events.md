# AD CS and execution-console audit events

Audit action names use uppercase words separated by underscores. UUID subjects
are stored in metadata because the audit `target_id` column is an integer.
Human actions identify their actor; agent log rejection has a machine actor.
These metadata fields are available in the Audit feed and CSV/JSON export.

- `CERTOPS_ISSUER_CREATED`: `{ issuerId, kind }` records issuer creation.
- `CERTOPS_ISSUER_PREFLIGHT_DISPATCHED`: `{ issuerId, jobId, agentId }` records a CA preflight request.
- `CERTOPS_ISSUER_KEY_CONFIRMED`: `{ issuerId, version, caKeySha256 }` records confirmation of a CA public-key pin.
- `CERTOPS_ENROLLMENT_CREATED`: `{ enrollmentId, issuerId, jobId }` records a new enrollment request.
- `CERTOPS_ENROLLMENT_RECONCILE_PROPOSED`: `{ enrollmentId, requestId }` records an operator-provided CA request ID for reconciliation.
- `CERTOPS_ENROLLMENT_CANCELLED`: `{ enrollmentId }` records cancellation of an enrollment.
- `CERTOPS_ENROLLMENT_ABANDONED`: `{ enrollmentId }` records abandonment of an enrollment.
- `CERTOPS_AGENT_LOG_REJECTED`: `{ jobId, claimId, code }` records rejection of log material containing prohibited secrets. The rejected content is never recorded.
- `CERTOPS_AGENT_ALERT_SETTINGS_UPDATED`: `{ agentId, downtimeAlertsEnabled, contactGroupId }` records changes to agent downtime alert delivery.
- `CERTOPS_DIAGNOSTIC_AGENT_BOOTSTRAPPED`: `{ agentId, requestId, jobId, credentialPrefix, signingKeyId }` records diagnostic-agent bootstrap. Only the credential prefix is recorded.
- `CERTOPS_RENEWAL_PROFILE_CREATED`: `{ profileId, profileName, issuerId, reference }` records AD CS renewal-profile creation.

Audit feeds, action filters and exports recognize the earlier dotted names and
present the canonical action names. Stored events remain immutable, with their
original metadata and occurrence times. See [machine-initiated audit guarantees](../adr/0011-certops-machine-initiated-audit-events.md)
and [AD CS operations](agent/adcs.md).
