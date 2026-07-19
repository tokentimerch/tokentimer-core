"use strict";

/**
 * Canonical request examples for docs/certops/executor-api.md.
 *
 * These are the source of truth the markdown code blocks are meant to
 * mirror. tests/integration/certops-docs-fixtures.test.js POSTs these
 * literal bodies against the real executor routes and asserts the exact
 * documented response shape/status code, so a change to validation or
 * response shape that would make the docs wrong fails CI here first.
 *
 * workspaceId/jobId placeholders below are replaced by the test with real
 * UUIDs created for each test workspace/job; the doc keeps illustrative
 * fixed UUIDs since a reader cannot obtain real ones without calling the API.
 */

const DOC_WORKSPACE_ID = "0b8f2e2a-6e2a-4c2a-9b1a-1a2b3c4d5e6f";
const DOC_JOB_ID = "5f3a1c9e-7d21-4e11-8b2a-9c7d6e5f4a3b";

function jobCompletedEvent({ workspaceId = DOC_WORKSPACE_ID, jobId = DOC_JOB_ID } = {}) {
  return {
    schemaVersion: 1,
    eventId: "evt-2026-07-12-000001",
    workspaceId,
    jobId,
    status: "succeeded",
    eventType: "job.completed",
    occurredAt: "2026-07-12T10:00:00.000Z",
    message: "certificate renewed and reloaded",
    metadata: [{ name: "cert.serial", value: "0a1b2c" }],
  };
}

function evidenceAttachedEnvelope({ workspaceId = DOC_WORKSPACE_ID, jobId = DOC_JOB_ID } = {}) {
  return {
    schemaVersion: 1,
    eventId: "evt-2026-07-12-000002",
    workspaceId,
    jobId,
    status: "accepted",
    eventType: "evidence.attached",
    occurredAt: "2026-07-12T10:05:00.000Z",
    evidence: [
      {
        schemaVersion: 1,
        evidenceId: "ev-2026-07-12-000001",
        eventType: "certificate.observed",
        source: "executor",
        observedAt: "2026-07-12T10:05:00.000Z",
        certificateId: "cert-web-01",
        summary: "Observed public certificate fingerprint after renewal",
        metadata: [{ name: "issuer", value: "Let's Encrypt" }],
      },
    ],
  };
}

module.exports = {
  DOC_JOB_ID,
  DOC_WORKSPACE_ID,
  evidenceAttachedEnvelope,
  jobCompletedEvent,
};
