# CertOps audit events

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

## Other certificate, execution, and administration events

Optional metadata fields depend on the operation and outcome. Machine events
may have no user actor. Credentials and rejected private material are never
included in the audit metadata.

- **CERTOPS_API_TOKEN_CREATED** metadata: `{ api_token_id, token_prefix, name, scopes, status, expires_at }`.
- **CERTOPS_API_TOKEN_REVOKED** metadata: `{ api_token_id, token_prefix, name, scopes, status, revoked_at }`.
- **CERTOPS_CERTIFICATE_REGISTERED** / **CERTOPS_CERTIFICATE_IMPORTED** metadata: `{ source, count, certificate_ids, fingerprints_sha256 }`.
- **CERTOPS_CERTIFICATE_ISSUED** metadata: `{ managedCertificateId, commonName, jobId, operation, source, agentId, fingerprintSha256, serialNumber, issuer, notAfter, subjectAltNames, deployedCertPath, targetType, windowsStore, windowsBindingSite, windowsBindingPort, windowsBindingSniHost, profileId, profileDerivationReason }`.
- **CERTOPS_CERTIFICATE_ISSUANCE_UNRECONCILED** metadata: `{ managedCertificateId, commonName, jobId, operation, claimId, agentId, reconciliationReason, targetType, windowsStore, windowsBindingSite, windowsBindingPort, windowsBindingSniHost }`.
- **CERTOPS_CERTIFICATE_RENEWAL_UNRECONCILED** metadata: same shape as `CERTOPS_CERTIFICATE_ISSUANCE_UNRECONCILED` above.
- **CERTOPS_CERTIFICATE_RETIRED** metadata: `{ managedCertificateId, tokenId, status, reason, fingerprintSha256 }`.
- **CERTOPS_JOB_CREATED_MANUAL** metadata: `{ operation, subjectType, subjectId, source, targetType, windowsStore, windowsBindingSite, windowsBindingPort, windowsBindingSniHost }`.
- **CERTOPS_JOB_CREATED_AUTOMATIC** metadata: `{ jobId, operation, mode, subjectType, subjectId, commonName, notAfter, profileId, source, trigger, targetType, windowsStore, windowsBindingSite, windowsBindingPort, windowsBindingSniHost }`.
- **CERTOPS_JOB_FAILED** metadata: `{ jobId, operation, jobStatus, source, mode, agentId, claimId, errorCode, errorMessage, subjectType, subjectId, needsOperatorReconciliation, reconciliationReason, targetType, windowsStore, windowsBindingSite, windowsBindingPort, windowsBindingSniHost }`.
- **CERTOPS_EXECUTOR_EVENT_ACCEPTED** metadata: `{ apiTokenId, executorEventId, eventType, jobId, logId, status, evidenceIds }`.
- **CERTOPS_EVIDENCE_ACCEPTED** metadata: same fields as `CERTOPS_EXECUTOR_EVENT_ACCEPTED`.
- **CERTOPS_EVIDENCE_REJECTED** metadata: `{ apiTokenId, jobId, eventId, eventType, rejectionCode, routeFamily }`.
- **CERTOPS_GENERIC_SECRET_REDACTION_APPLIED** metadata: `{ ...executor event fields, redactionApplied: true, redactionCount, redactedFields }`.
- **CERTOPS_AGENT_BOOTSTRAP_TOKEN_CREATED** metadata: `{ bootstrap_token_id, token_prefix, name, status, expires_at }`.
- **CERTOPS_AGENT_BOOTSTRAP_TOKEN_REVOKED** metadata: `{ bootstrap_token_id, token_prefix, name, status, revoked_at }`.
- **CERTOPS_AGENT_REGISTERED** metadata: `{ agentId, hostname, platform, agentVersion, protocolVersion, credentialPrefix, bootstrapTokenId, signingKeyId, declaredTargetSelectors, declaredCommandProfileNames, declaredCapabilities }`.
- **CERTOPS_AGENT_CAPABILITIES_CHANGED** metadata: `{ agentId, previousCapabilities, declaredCapabilities }`.
- **CERTOPS_AGENT_RETIRED** metadata: `{ agentId, force, reason, leasedJobs }`, plus `{ cancelledJobIds, orphanedJobIds }` when the retirement fenced in-flight work.
- **CERTOPS_TRUST_ANCHOR_APPROVED** metadata: `{ trustAnchorId, fingerprintSha256, anchorType, name }`.
- **CERTOPS_TRUST_ANCHOR_RETIRED** metadata: `{ trustAnchorId, fingerprintSha256, anchorType, reason }` (`reason` present only when the caller supplied one).
- **CERTOPS_TRUST_DISTRIBUTE_JOB_CREATED** / **CERTOPS_TRUST_REVOKE_JOB_CREATED** metadata: `{ jobId, trustAnchorId, anchorName, fingerprintSha256, agentId, store, host, owner, transitionGeneration }`.
- **CERTOPS_TRUST_ANCHOR_DISTRIBUTED** / **CERTOPS_TRUST_ANCHOR_REVOKED** metadata: `{ jobId, trustAnchorId, installationId, store, host, owner, transitionState, provenance, agentId, outcome, mutationPerformed, failureCategory, observedFingerprintBefore, observedFingerprintAfter }`.
- **CERTOPS_TRUST_REFERENCE_RELEASED** metadata: `{ trustAnchorId, anchorName, fingerprintSha256, agentId, store, host, owner, transitionGeneration }`.
- **CERTOPS_RENEWAL_PROFILE_DERIVED** metadata: `{ profileId, profileName, created, managedCertificateId, renewBeforeDays, acmeKind, commandRef, caEndpoint, certPath, targetType, windowsStore, windowsBindingSite, windowsBindingPort, windowsBindingSniHost, dnsProvider, dnsZone, keyAlgorithm, keySize }`.
- **CERTOPS_RENEWAL_PROFILE_DERIVATION_DECLINED** metadata: `{ managedCertificateId, commonName, jobId, operation, agentId, derivationReason, reconciliationReason, detail, targetType }`.
- **CERTOPS_RENEWAL_PROFILE_UPDATED** metadata: `{ profileId, profileName, changes }`.
- **CERTOPS_RENEWAL_PROFILE_DETACHED** metadata: `{ managedCertificateId, commonName, profileId, profileName, invalidatedIntents }`.
- **CERTOPS_JOB_APPROVAL_GRANTED** metadata: `{ jobId, status, payloadHash, canonicalIntentHash, reason }` (`reason` present only when the approver supplied one).
- **CERTOPS_JOB_APPROVAL_REJECTED** metadata: `{ jobId, status, reason }` (`reason` present only when the approver supplied one).
- **CERTOPS_WORKSPACE_APPROVAL_POLICY_ENABLED** / **CERTOPS_WORKSPACE_APPROVAL_POLICY_DISABLED** metadata: `{ workspaceId, previousRequireApprovalAlways, certOpsRequireApprovalAlways }`.
- **CERTOPS_WORKSPACE_PAUSED** / **CERTOPS_WORKSPACE_RESUMED** metadata: `{ workspaceId, previousCertOpsPaused, certOpsPaused, certOpsEnabled, certOpsActive, reason }`.
- **CERTOPS_CONTROLLER_OBSERVATION_ACCEPTED** metadata: `{ apiTokenId, clusterId, managedCertificateId, observationId, resourceRecreated, targetId, certificateInstanceId }`.
- **CERTOPS_CONTROLLER_PROVISION_INTENT_CREATED** metadata: `{ clusterId, jobId, managedCertificateId, targetId }`.
- **CERTOPS_SIGNING_KEY_ROTATION_STARTED** metadata: `{ signing_key_id, supersedes_signing_key_id, source }`.
- **CERTOPS_SIGNING_KEY_ROTATION_COMPLETED** metadata: `{ retired_signing_key_id, active_signing_key_id, forced, force_reason, active_agents, ack_count, source }`.
- **CERTOPS_KEY_MATERIAL_REJECTED** metadata varies by caller: dashboard/API requests use `{ code, method, path, body_type }`; external executors use `{ code, method, routeFamily, apiTokenId }`; native agents use `{ code, method, routeFamily, agentId }`. The rejected key material is never recorded.

Signing-key rotation events have no workspace or user subject. They are
visible to system administrators in the organization audit view, or directly
in the audit table.
