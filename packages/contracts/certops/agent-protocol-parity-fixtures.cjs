"use strict";

/**
 * Shared valid/invalid agent-protocol envelope fixtures for parity tests.
 * Imported by both the agent-side and API-side validators so accept/reject
 * verdicts cannot drift independently.
 */

function envelope(messageType, body, overrides = {}) {
  return {
    schemaVersion: 1,
    protocolVersion: "1.0.0",
    messageType,
    agentId: "agent-1",
    workspaceId: "11111111-1111-4111-8111-111111111111",
    sentAt: "2026-07-20T12:00:00.000Z",
    clockOffsetMs: null,
    body,
    ...overrides,
  };
}

const FIXTURES = Object.freeze([
  {
    id: "heartbeat-valid",
    expectValid: true,
    message: envelope("heartbeat", {
      agentVersion: "0.1.0",
      ntpSynced: true,
      uptimeSeconds: 3600,
      pinnedSigningKeyId: "signing-key-1",
    }),
  },
  {
    id: "claim-valid",
    expectValid: true,
    message: envelope("claim", {
      maxJobs: 2,
      supportedActions: ["renew", "reload"],
    }),
  },
  {
    id: "result-succeeded-valid",
    expectValid: true,
    message: envelope("result", {
      jobId: "job-1",
      attemptId: "attempt-1",
      status: "succeeded",
      rejectionReason: null,
      keyRotated: false,
      errorMessage: null,
    }),
  },
  {
    id: "result-dry_run_complete-valid",
    expectValid: true,
    message: envelope("result", {
      jobId: "job-1",
      attemptId: "attempt-1",
      status: "dry_run_complete",
      rejectionReason: null,
      keyRotated: null,
      errorMessage: null,
    }),
  },
  {
    id: "result-orphaned_unknown_effect-valid",
    expectValid: true,
    message: envelope("result", {
      jobId: "job-1",
      attemptId: "attempt-1",
      status: "orphaned_unknown_effect",
      rejectionReason: null,
      keyRotated: true,
      errorMessage:
        "reload failed; needsOperatorReconciliation=true; reconciliationReason=first_deploy_reload_failed",
    }),
  },
  {
    id: "evidence-valid",
    expectValid: true,
    message: envelope("evidence", {
      jobId: "job-1",
      evidenceItems: [
        {
          evidenceId: "evidence-1",
          eventType: "policy.checked",
          observedAt: "2026-07-20T12:00:00.000Z",
          summary: "ok",
        },
      ],
    }),
  },
  {
    id: "register-valid",
    expectValid: true,
    message: envelope("register", {
      bootstrapTokenId: "bst_abc123",
      agentVersion: "0.1.0",
      hostname: "host-1",
      platform: "linux",
      nodeVersion: "v22.0.0",
      registrationId: "reg-1",
    }),
  },
  {
    id: "result-unknown-status-invalid",
    expectValid: false,
    message: envelope("result", {
      jobId: "job-1",
      attemptId: "attempt-1",
      status: "not_a_real_status",
    }),
  },
  {
    id: "result-extra-property-invalid",
    expectValid: false,
    message: envelope("result", {
      jobId: "job-1",
      attemptId: "attempt-1",
      status: "succeeded",
      unexpectedExtra: true,
    }),
  },
  {
    id: "heartbeat-extra-property-invalid",
    expectValid: false,
    message: envelope("heartbeat", {
      agentVersion: "0.1.0",
      privateKeyPem: "must-not-be-accepted",
    }),
  },
  {
    id: "claim-unknown-action-invalid",
    expectValid: false,
    message: envelope("claim", {
      maxJobs: 1,
      supportedActions: ["renew", "not_a_real_action"],
    }),
  },
  {
    id: "evidence-unknown-eventType-invalid",
    expectValid: false,
    message: envelope("evidence", {
      jobId: "job-1",
      evidenceItems: [
        {
          evidenceId: "evidence-1",
          eventType: "not.a.real.event",
          observedAt: "2026-07-20T12:00:00.000Z",
        },
      ],
    }),
  },
]);

module.exports = {
  FIXTURES,
  envelope,
};
