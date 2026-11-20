# CertOps audit events

UUID subjects are stored in metadata because the audit target ID is an
integer. Human actions identify their actor. Machine events can identify an
agent or API token in metadata. These details are available in the Audit feed
and CSV/JSON export. See [Audit event catalog](../audit-events.md) for other
TokenTimer actions.

- `CERTOPS_ISSUER_CREATED`: `{ issuerId, kind }` records issuer creation.
- `CERTOPS_ISSUER_PREFLIGHT_DISPATCHED`: `{ issuerId, issuerName, jobId, agentId, caConfig, template }` records a manual or automatically requested CA check. Older entries may contain only IDs.
- `CERTOPS_ISSUER_KEY_CONFIRMED`: `{ issuerId, version, caKeySha256 }` records confirmation of a CA public-key pin.
- `CERTOPS_ENROLLMENT_CREATED`: `{ enrollmentId, issuerId, jobId }` records a new enrollment request.
- `CERTOPS_ENROLLMENT_RECONCILE_PROPOSED`: `{ enrollmentId, requestId }` records an operator-provided CA request ID for reconciliation.
- `CERTOPS_ENROLLMENT_CANCELLED`: `{ enrollmentId }` records cancellation of an enrollment.
- `CERTOPS_ENROLLMENT_ABANDONED`: `{ enrollmentId }` records abandonment of an enrollment.
- `CERTOPS_AGENT_LOG_REJECTED`: `{ agentId, jobId, claimId, code }` records rejection of log material containing prohibited secrets. The rejected content is never recorded.
- `CERTOPS_AGENT_ALERT_SETTINGS_UPDATED`: `{ agentId, downtimeAlertsEnabled, contactGroupId }` records changes to agent downtime alert delivery.
- `CERTOPS_DIAGNOSTIC_AGENT_BOOTSTRAPPED`: `{ agentId, requestId, jobId, credentialPrefix, signingKeyId }` records diagnostic-agent bootstrap. Only the credential prefix is recorded.
- `CERTOPS_RENEWAL_PROFILE_CREATED`: `{ profileId, profileName, issuerId, reference }` records AD CS renewal-profile creation.

Audit feeds, action filters, and exports normalize legacy aliases to the
uppercase names above. The aliases are `certops.issuer.created`,
`certops.issuer.preflight_dispatched`, `certops.issuer.key_confirmed`,
`certops.enrollment.created`, `certops.enrollment.reconcile_proposed`,
`certops.enrollment.cancelled`, `certops.enrollment.abandoned`, and
`certops.agent_log.rejected`. Stored events retain their original metadata
and occurrence times. See [machine-initiated audit guarantees](../adr/0011-certops-machine-initiated-audit-events.md)
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
- **CERTOPS_CERTIFICATE_RETIRED** records `{ identityId, fingerprintSha256, status, reason, cancelledJobs, reconciliationMarkedJobs }`.
- **CERTOPS_JOB_CREATED_MANUAL** metadata: `{ jobId, operation, subjectType, subjectId, source, via, targetType, windowsStore, windowsBindingSite, windowsBindingPort, windowsBindingSniHost }`.
- **CERTOPS_JOB_CREATED_AUTOMATIC** metadata: `{ jobId, operation, mode, subjectType, subjectId, commonName, notAfter, profileId, enrollmentId, issuerId, source, trigger, targetType, windowsStore, windowsBindingSite, windowsBindingPort, windowsBindingSniHost }`.
- **CERTOPS_JOB_FAILED** metadata: `{ jobId, operation, jobStatus, source, mode, agentId, claimId, errorCode, errorMessage, subjectType, subjectId, needsOperatorReconciliation, reconciliationReason, targetType, windowsStore, windowsBindingSite, windowsBindingPort, windowsBindingSniHost }`. Trust jobs can include `{ outcome, mutationPerformed, failureCategory, observedFingerprintBefore, observedFingerprintAfter, provenance }`.
- **CERTOPS_EXECUTOR_EVENT_ACCEPTED** records `{ apiTokenId, executorEventRecordId, executorEventId, eventType, jobId, logId, status, evidenceIds, certificateName, namespace, issuerRef, dnsNames }`. Certificate topology fields apply when the job targets a Kubernetes certificate.
- **CERTOPS_EVIDENCE_ACCEPTED** metadata: same fields as `CERTOPS_EXECUTOR_EVENT_ACCEPTED`.
- **CERTOPS_EVIDENCE_REJECTED** metadata: `{ workspaceId, jobId, eventId, eventType, evidenceIds, redactionApplied, redactionCount, rejectionCode, createdByApiTokenId, routeFamily }`.
- **CERTOPS_GENERIC_SECRET_REDACTION_APPLIED** metadata: `{ ...executor event fields, redactionApplied: true, redactionCount, redactedFields }`. Controller observations include `{ apiTokenId, clusterId, observationId, redactionApplied, redactionCount }`.
- **CERTOPS_AGENT_BOOTSTRAP_TOKEN_CREATED** metadata: `{ bootstrap_token_id, token_prefix, name, status, expires_at }`.
- **CERTOPS_AGENT_BOOTSTRAP_TOKEN_REVOKED** metadata: `{ bootstrap_token_id, token_prefix, name, status, revoked_at }`.
- **CERTOPS_AGENT_REGISTERED** metadata: `{ agentId, hostname, platform, agentVersion, protocolVersion, credentialPrefix, bootstrapTokenId, signingKeyId, declaredTargetSelectors, declaredCommandProfileNames, declaredCapabilities }`.
- **CERTOPS_AGENT_CAPABILITIES_CHANGED** metadata: `{ agentId, previousCapabilities, declaredCapabilities }`.
- **CERTOPS_AGENT_RETIRED** metadata: `{ agentId, force, reason, leasedJobs }`, plus `{ cancelledJobIds, orphanedJobIds }` when the retirement fenced in-flight work.
- **CERTOPS_TRUST_ANCHOR_APPROVED** metadata: `{ trustAnchorId, fingerprintSha256, anchorType, name }`.
- **CERTOPS_TRUST_ANCHOR_RETIRED** metadata: `{ trustAnchorId, fingerprintSha256, anchorType, reason }` (`reason` present only when the caller supplied one).
- **CERTOPS_TRUST_DISTRIBUTE_JOB_CREATED** / **CERTOPS_TRUST_REVOKE_JOB_CREATED** metadata: `{ jobId, trustAnchorId, anchorName, fingerprintSha256, agentId, store, host, owner, transitionGeneration }`.
- **CERTOPS_TRUST_ANCHOR_DISTRIBUTED** / **CERTOPS_TRUST_ANCHOR_REVOKED** metadata: `{ jobId, trustAnchorId, installationId, store, host, owner, transitionState, provenance, agentId, outcome, mutationPerformed, failureCategory, observedFingerprintBefore, observedFingerprintAfter }`.
- **CERTOPS_TRUST_REFERENCE_RELEASED** metadata: `{ trustAnchorId, anchorName, fingerprintSha256, agentId, store, host, owner, transitionGeneration, otherLiveReferences, provenance }`.
- **CERTOPS_RENEWAL_PROFILE_DERIVED** metadata: `{ profileId, profileName, created, managedCertificateId, renewBeforeDays, acmeKind, commandRef, caEndpoint, certPath, targetType, windowsStore, windowsBindingSite, windowsBindingPort, windowsBindingSniHost, dnsProvider, dnsZone, keyAlgorithm, keySize }`.
- **CERTOPS_RENEWAL_PROFILE_DERIVATION_DECLINED** metadata: `{ managedCertificateId, commonName, jobId, operation, agentId, derivationReason, reconciliationReason, detail, targetType }`.
- **CERTOPS_RENEWAL_PROFILE_UPDATED** metadata: `{ profileId, profileName, changes }`.
- **CERTOPS_RENEWAL_PROFILE_DETACHED** metadata: `{ managedCertificateId, commonName, profileId, profileName, invalidatedIntents }`.
- **CERTOPS_JOB_APPROVAL_GRANTED** metadata: `{ jobId, status, payloadHash, canonicalIntentHash, reason }` (`reason` present only when the approver supplied one).
- **CERTOPS_JOB_APPROVAL_REJECTED** metadata: `{ jobId, status, reason }` (`reason` present only when the approver supplied one).
- **CERTOPS_WORKSPACE_APPROVAL_POLICY_ENABLED** / **CERTOPS_WORKSPACE_APPROVAL_POLICY_DISABLED** metadata: `{ workspaceId, previousRequireApprovalAlways, certOpsRequireApprovalAlways }`.
- **CERTOPS_WORKSPACE_PAUSED** / **CERTOPS_WORKSPACE_RESUMED** metadata: `{ workspaceId, previousCertOpsPaused, certOpsPaused, certOpsEnabled, certOpsActive, reason }`.
- **CERTOPS_CONTROLLER_OBSERVATION_ACCEPTED** metadata: `{ apiTokenId, clusterId, managedCertificateId, observationId, resourceRecreated, targetId, certificateInstanceId }`.
- **CERTOPS_CONTROLLER_PROVISION_INTENT_CREATED** metadata: `{ clusterId, jobId, managedCertificateId, targetId, namespace, certificateName, secretName, issuerRef, dnsNames }`.
- **CERTOPS_SIGNING_KEY_ROTATION_STARTED** metadata: `{ signing_key_id, supersedes_signing_key_id, source }`.
- **CERTOPS_SIGNING_KEY_ROTATION_COMPLETED** metadata: `{ retired_signing_key_id, active_signing_key_id, forced, force_reason, active_agents, ack_count, source }`.
- **CERTOPS_KEY_MATERIAL_REJECTED** metadata varies by caller: dashboard/API requests use `{ code, method, path, body_type }`; external executors use `{ code, method, routeFamily, apiTokenId }`; native agents use `{ code, method, routeFamily, agentId }`. Controller rejections use the executor rejection fields listed above. The rejected key material is never recorded.

Signing-key rotation events have no workspace or user subject. They are
visible to system administrators in the organization audit view, or directly
in the audit table.

## Enrollment and certificate management

- `certops.enrollment.installation_retry_requested` records `enrollmentId`, `jobId`, and `attempt`. The action filter uses the stored dotted name.
- `certops.enrollment.recovery_requested` records `enrollmentId`, `orphanedJobId`, `jobId`, `attempt`, `acknowledgeUnknownEffect`, and `reason`. The action filter uses the stored dotted name.
- `CERTOPS_ENROLLMENT_RETRIEVAL_RECONCILIATION_REQUIRED` records `enrollmentId`, `requestId`, and `reason` after a pending retrieval with an uncertain effect times out.
- `CERTOPS_MANAGEMENT_STARTED` and `CERTOPS_MANAGEMENT_STOPPED` record `periodId`, `managedCertificateId`, `identityId`, `renewalProfileId`, and `automationEnabled`. The identity can be null before a certificate is observed, and the renewal profile can be null for tracking-only management. Stop events also record `runningJobs`, the count of claimed or running jobs at the time of the stop.

## Certificate signing requests

Each CSR event identifies the workflow in `workflow_id`.

- `CERTOPS_CSR_IMPORTED` records `csr_der_sha256` and `target_id`.
- `CERTOPS_CSR_RESTARTED` and `CERTOPS_CSR_CANCELLED` identify the workflow affected.
- `CERTOPS_CSR_SIGNED_IMPORTED` records `fingerprint_sha256`, `managed_certificate_id`, and `names_changed`.
- `CERTOPS_CSR_NAMES_ACKNOWLEDGED` records the SAN `additions` and `omissions` acknowledged by the operator.
- `CERTOPS_CSR_COMPLETED` records `method`, `managed_certificate_id`, and `observed_instance_id`.
- `CERTOPS_CSR_OBSERVED_IDENTITY_CONFLICT` records `expected_certificate_id`, `observed_certificate_id`, and `observed_instance_id`.

## Certificate distribution and verification

- `CERTOPS_DISTRIBUTION_POLICY_CHANGED` records `groupId`, `revision`, `scopeHash`, `mode`, and `approvalJobId`.
- `CERTOPS_POST_PUBLICATION_DISTRIBUTION` records `groupId`, `materialVersionId`, `outcome`, `policyRevision`, and `jobId` when applicable.
- `CERTOPS_CONSUMER_BINDING_CHANGED` records `bindingId`, `groupId`, and `authorizationRevision`.
- `CERTOPS_CONSUMER_ACTIVATION_POLICY_CHANGED` and `CERTOPS_EMERGENCY_ACTIVATION_REQUESTED` record `groupId`, `authorizationRevision`, `method`, `disruptive`, `requiresApproval`, and `emergency`.
- `CERTOPS_ROLLOUT_STATE_CHANGED` records `groupId`, `rolloutId`, `materialVersionId`, and `state`.
- `CERTOPS_DISTRIBUTION_INCIDENT_OPENED`, `CERTOPS_DISTRIBUTION_INCIDENT_UPDATED`, and `CERTOPS_DISTRIBUTION_INCIDENT_RESOLVED` record `incidentId`, `groupId`, and `code`. Opening and updating also include `evidence`.
- `CERTOPS_RECURRING_VERIFICATION_FAILED` records `groupId`, `rolloutId`, and `jobId`. `CERTOPS_RECURRING_VERIFICATION_BACKOFF` also records `sequence`, `failures`, and `retryAt`.
- `CERTOPS_MATERIAL_JOB_RETRY_REQUESTED` records `jobId`, `materialVersionId`, `previousStatus`, and `status`.
- `CERTOPS_MATERIAL_CLEANUP_REQUESTED` and `CERTOPS_MATERIAL_CLEANUP_REAUTHORIZED` record `cleanupId`, `groupId`, `materialVersionId`, `jobId`, `previousJobId`, and `policyRevision`.
- `CERTOPS_MATERIAL_CLEANUP_FENCED` records `cleanupId`, `groupId`, `materialVersionId`, `jobId`, and `agentId` when material becomes ineligible for reuse.
- `CERTOPS_MATERIAL_CLEANUP_COMPLETED` records the cleanup receipt fields `{ schemaVersion, workspaceId, cleanupId, groupId, materialVersionId, providerVersion, method, softDeleted, observedAt }`, plus `jobId` and `agentId`.
- `CERTOPS_MATERIAL_RECONCILIATION_REQUESTED` and `CERTOPS_MATERIAL_RECONCILIATION_PROVED` record `originalJobId` and `reconciliationJobId`. Proof also includes `claimId`, `agentId`, and `materialVersionId`.
- `CERTOPS_PUBLICATION_RENEWAL_PROFILE_REPAIRED` records `managedCertificateId`, `profileId`, `publishingJobId`, and `groupId`.
