"use strict";

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");

const {
  _test: {
    executorEventIdempotencyPayload,
    mergeRedactionReport,
    normalizeExecutorEventBody,
  },
} = require("../../apps/api/routes/certops-executor");
const {
  _test: { requestHash },
} = require("../../apps/api/services/certops/executorEvents");

const WORKSPACE_ID = "11111111-1111-4111-8111-111111111111";
const JOB_ID = "22222222-2222-4222-8222-222222222222";
const OCCURRED_AT = "2026-07-12T12:00:00.000Z";

function eventBody(overrides = {}) {
  return {
    schemaVersion: 1,
    eventId: "event-stable-hash",
    jobId: JOB_ID,
    workspaceId: WORKSPACE_ID,
    certificateId: "cert-1",
    executorId: "executor-1",
    status: "accepted",
    eventType: "evidence.attached",
    occurredAt: OCCURRED_AT,
    message: "password=first-value",
    metadata: [
      { name: "issuer", value: "TokenTimer Test CA" },
      { name: "credential", value: "first-value" },
    ],
    evidence: [
      {
        schemaVersion: 1,
        evidenceId: "evidence-1",
        jobId: JOB_ID,
        workspaceId: WORKSPACE_ID,
        certificateId: "cert-1",
        eventType: "certificate.observed",
        source: "executor",
        observedAt: OCCURRED_AT,
        summary: "credential=first-value",
        metadata: [{ name: "issuer", value: "TokenTimer Test CA" }],
      },
    ],
    ...overrides,
  };
}

function normalize(body) {
  return normalizeExecutorEventBody(body, { workspaceId: WORKSPACE_ID });
}

function hash(body) {
  return requestHash(executorEventIdempotencyPayload(normalize(body)));
}

describe("CertOps executor event normalization", () => {
  it("hashes only an explicit allowlist of sanitized client semantics", () => {
    const normalized = normalize(eventBody());
    const projection = executorEventIdempotencyPayload(normalized);
    const withDerivedInternals = {
      ...normalized,
      generatedLogId: "33333333-3333-4333-8333-333333333333",
      jobStatus: "failed",
      logStatus: "failed",
      metadata: {
        ...normalized.metadata,
        redactionCount: 999,
        redactedFields: ["volatile-server-category"],
        redactedMetadata99: "[REDACTED]",
      },
    };

    assert.deepEqual(Object.keys(projection), [
      "schemaVersion",
      "eventId",
      "jobId",
      "workspaceId",
      "certificateId",
      "executorId",
      "status",
      "eventType",
      "occurredAt",
      "message",
      "metadata",
      "evidence",
    ]);
    assert.equal(
      requestHash(executorEventIdempotencyPayload(withDerivedInternals)),
      requestHash(projection),
    );
    assert.doesNotMatch(JSON.stringify(projection), /first-value/);
    assert.doesNotMatch(
      JSON.stringify(projection),
      /redactionCount|redactedFields|redactedMetadata|jobStatus|logStatus/,
    );
  });

  it("keeps sanitized retries and metadata key ordering idempotent", () => {
    const retry = eventBody({
      message: "password=second-value",
      metadata: [
        { name: "credential", value: "second-value" },
        { name: "issuer", value: "TokenTimer Test CA" },
      ],
      evidence: [
        {
          ...eventBody().evidence[0],
          summary: "credential=second-value",
          metadata: [{ value: "TokenTimer Test CA", name: "issuer" }],
        },
      ],
    });

    assert.equal(hash(eventBody()), hash(retry));
    assert.notEqual(
      hash(eventBody()),
      hash(eventBody({ certificateId: "cert-2" })),
    );
  });

  it("does not let a client redaction hint affect idempotency or server redaction state", () => {
    const marked = eventBody({
      evidence: [{ ...eventBody().evidence[0], redactionApplied: true }],
    });
    const unmarked = eventBody({
      evidence: [{ ...eventBody().evidence[0], redactionApplied: false }],
    });

    assert.equal(hash(marked), hash(unmarked));
    assert.equal(normalize(marked).evidence[0].metadata.redactionApplied, true);
    assert.equal(normalize(unmarked).evidence[0].metadata.redactionApplied, true);
  });

  it("preserves contract array ordering while canonicalizing object keys", () => {
    const firstEvidence = eventBody().evidence[0];
    const secondEvidence = {
      ...firstEvidence,
      evidenceId: "evidence-2",
      certificateId: "cert-2",
    };
    const firstOrder = eventBody({ evidence: [firstEvidence, secondEvidence] });
    const reversedOrder = eventBody({ evidence: [secondEvidence, firstEvidence] });

    assert.notEqual(hash(firstOrder), hash(reversedOrder));
  });

  it("preserves redaction categories from nested reports", () => {
    const tracker = { count: 0, fields: new Set() };
    mergeRedactionReport(
      tracker,
      {
        redactionApplied: true,
        redactionCount: 2,
        redactedFields: ["authorization", "generic-secret"],
      },
      "metadata",
    );

    assert.equal(tracker.count, 2);
    assert.deepEqual(Array.from(tracker.fields).sort(), [
      "authorization",
      "generic-secret",
    ]);
  });
});
