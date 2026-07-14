"use strict";

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");

const {
  _test: {
    executorEventIdempotencyPayload,
    EVIDENCE_SOURCES,
    EVIDENCE_STATUSES,
    createRedactionTracker,
    immutableRedactionReport,
    isReservedMetadataName,
    mergeRedactionReport,
    normalizeExecutorEventBody,
    normalizeRfc3339Timestamp,
  },
} = require("../../apps/api/routes/certops-executor");
const {
  CERTOPS_EXECUTOR_EVENT_CONFLICT,
  _test: { requestHash, storedResponseForReplay },
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
  it("never replays a malformed historical idempotency response as success", () => {
    const safeResponse = {
      ok: true,
      eventId: "event-log-1",
      logId: "event-log-1",
      jobId: JOB_ID,
      status: "running",
      evidenceIds: [],
    };

    assert.deepEqual(storedResponseForReplay(JSON.stringify(safeResponse)), safeResponse);
    for (const response of [null, "{}", "not-json", { ok: true }]) {
      assert.throws(
        () => storedResponseForReplay(response),
        (error) => error?.code === CERTOPS_EXECUTOR_EVENT_CONFLICT,
      );
    }
  });

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
      /redactionCount|redactedFields|jobStatus|logStatus/,
    );
    assert.match(JSON.stringify(projection), /redactedSecretCategories/);
  });

  it("keeps sanitized retries and metadata key ordering idempotent", () => {
    const retry = eventBody({
      message: "password=second-value",
      metadata: [
        { name: "api_token", value: "second-value" },
        { name: "issuer", value: "TokenTimer Test CA" },
      ],
      evidence: [
        {
          ...eventBody().evidence[0],
          summary: "credential=second-value",
          metadata: [
            { name: "cookie_header", value: "second-value" },
            { value: "TokenTimer Test CA", name: "issuer" },
          ],
        },
      ],
    });
    const first = eventBody({
      metadata: [
        { name: "issuer", value: "TokenTimer Test CA" },
        { name: "apiToken", value: "first-value" },
      ],
      evidence: [
        {
          ...eventBody().evidence[0],
          metadata: [
            { name: "issuer", value: "TokenTimer Test CA" },
            { name: "cookieHeader", value: "first-value" },
          ],
        },
      ],
    });

    assert.equal(hash(first), hash(retry));
    assert.notEqual(
      hash(first),
      hash({ ...first, certificateId: "cert-2" }),
    );
    assert.notEqual(
      hash(first),
      hash({
        ...first,
        metadata: [
          { name: "issuer", value: "Different public metadata" },
          { name: "apiToken", value: "first-value" },
        ],
      }),
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
    const tracker = createRedactionTracker();
    mergeRedactionReport(
      tracker,
      {
        redactionApplied: true,
        redactionCount: 2,
        redactedFields: ["authorization", "generic-secret"],
      },
    );

    assert.equal(tracker.count, 2);
    assert.deepEqual(Array.from(tracker.categories).sort(), [
      "authorization",
      "generic-secret",
    ]);
    assert.deepEqual(immutableRedactionReport(tracker), {
      count: 2,
      categories: ["authorization", "generic-secret"],
    });
  });

  it("rejects normalized server-owned metadata names before they can forge state", () => {
    for (const name of [
      "redactionApplied",
      "redaction_count",
      "REDACTED-FIELDS",
      "redactedSecretCategories",
      "redacted_secret_categories",
      "REDACTED-SECRET-CATEGORIES",
      "executorEventId",
      "job_status_transition_ignored_reason",
      "source",
      "artifactRefs",
    ]) {
      assert.equal(isReservedMetadataName(name), true);
      assert.throws(
        () => normalize(eventBody({ metadata: [{ name, value: "public" }] })),
        (error) => error?.code === "CERTOPS_EXECUTOR_EVENT_INVALID",
      );
      assert.throws(
        () =>
          normalize(
            eventBody({
              evidence: [
                {
                  ...eventBody().evidence[0],
                  metadata: [{ name, value: "public" }],
                },
              ],
            }),
          ),
        (error) => error?.code === "CERTOPS_EXECUTOR_EVENT_INVALID",
      );
    }
  });

  it("keeps client redaction hints and collidable metadata out of reports and hashes", () => {
    const withSecret = normalize(eventBody({ message: "password=first-value" }));
    assert.deepEqual(withSecret.redactionReport, {
      count: 2,
      categories: ["generic-secret"],
    });
    assert.throws(
      () =>
        normalize(
          eventBody({
            metadata: [
              { name: "redactionApplied", value: true },
              { name: "redactionCount", value: -100 },
            ],
          }),
        ),
      (error) => error?.code === "CERTOPS_EXECUTOR_EVENT_INVALID",
    );
  });

  it("keeps embedded evidence enums and fingerprints aligned with the public contract", () => {
    for (const source of EVIDENCE_SOURCES) {
      const normalized = normalize(
        eventBody({ evidence: [{ ...eventBody().evidence[0], source }] }),
      );
      assert.equal(normalized.evidence[0].metadata.source, source);
    }

    for (const status of EVIDENCE_STATUSES) {
      const normalized = normalize(
        eventBody({ evidence: [{ ...eventBody().evidence[0], status }] }),
      );
      assert.equal(normalized.evidence[0].metadata.status, status);
    }

    for (const evidenceOverrides of [
      { source: "arbitrary-source" },
      { status: "unknown-status" },
      { fingerprintSha256: "not-a-fingerprint" },
      { fingerprintSha256: "a".repeat(63) },
      { fingerprintSha256: "a".repeat(65) },
      { fingerprintSha256: "A".repeat(64) },
    ]) {
      assert.throws(
        () =>
          normalize(
            eventBody({
              evidence: [{ ...eventBody().evidence[0], ...evidenceOverrides }],
            }),
          ),
        (error) => error?.code === "CERTOPS_EXECUTOR_EVENT_INVALID",
      );
    }
  });

  it("accepts contract-valid RFC3339 timestamps and normalizes to milliseconds", () => {
    const cases = [
      ["2026-07-12T12:00:00Z", "2026-07-12T12:00:00.000Z"],
      ["2026-07-12T12:00:00.123Z", "2026-07-12T12:00:00.123Z"],
      ["2026-07-12T12:00:00.123456Z", "2026-07-12T12:00:00.123Z"],
      ["2026-07-12T12:00:00.123456789Z", "2026-07-12T12:00:00.123Z"],
      ["2024-02-29T23:59:59+02:30", "2024-02-29T21:29:59.000Z"],
      ["2024-02-29T23:59:59-02:30", "2024-03-01T02:29:59.000Z"],
      ["2000-01-01T00:00:00+14:00", "1999-12-31T10:00:00.000Z"],
      ["2100-12-31T23:59:59-14:00", "2101-01-01T13:59:59.000Z"],
    ];
    for (const [input, output] of cases) {
      assert.equal(normalizeRfc3339Timestamp(input), output);
    }
  });

  it("rejects RFC3339 timestamps outside the documented grammar and operational range", () => {
    for (const value of [
      "2026-02-29T12:00:00Z",
      "2026-13-01T12:00:00Z",
      "2026-07-12T12:00:00+14:01",
      "1999-12-31T23:59:59Z",
      "2101-01-01T00:00:00Z",
    ]) {
      assert.throws(
        () => normalizeRfc3339Timestamp(value),
        (error) => error?.code === "CERTOPS_EXECUTOR_EVENT_INVALID",
      );
    }
  });
});
