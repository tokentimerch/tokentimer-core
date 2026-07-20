"use strict";

/**
 * Tests for packages/agent/src/evidence/index.js.
 *
 * The PEM fixture below is synthetic (mirrors the fixture style already used
 * in tests/unit/certops-jobs.test.js) and is never a real key.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const evidence = require("./index.js");

const SYNTHETIC_PRIVATE_KEY_PEM =
  "-----BEGIN RSA PRIVATE KEY-----\nRkFLRS1OT1QtQS1SRUFMLUtFWQ==\n-----END RSA PRIVATE KEY-----";

const VALID_FINGERPRINT =
  "a".repeat(64);

test("buildMetadataEntry rejects a value containing PEM private key material", () => {
  assert.throws(
    () => evidence.buildMetadataEntry("note", `prefix ${SYNTHETIC_PRIVATE_KEY_PEM} suffix`),
    (err) => {
      assert.equal(err.code, "PRIVATE_KEY_MATERIAL_REJECTED");
      return true;
    },
  );
});

test("buildMetadataEntry redacts a generic secret embedded in a string value", () => {
  const entry = evidence.buildMetadataEntry("note", "connection string password=hunter2 in use");
  assert.equal(entry.name, "note");
  assert.ok(!entry.value.includes("hunter2"));
  assert.ok(entry.value.includes("[REDACTED]"));
});

test("buildMetadataEntry accepts number/boolean/null values unchanged", () => {
  assert.deepEqual(evidence.buildMetadataEntry("count", 3), { name: "count", value: 3 });
  assert.deepEqual(evidence.buildMetadataEntry("ok", true), { name: "ok", value: true });
  assert.deepEqual(evidence.buildMetadataEntry("nothing", null), { name: "nothing", value: null });
});

test("buildMetadataEntry rejects a key-material-looking name via the schema pattern", () => {
  assert.throws(() => evidence.buildMetadataEntry("privateKeyBlob", "x"));
  assert.throws(() => evidence.buildMetadataEntry("secretThing", "x"));
});

test("buildMetadataEntry rejects an oversized string value", () => {
  assert.throws(() => evidence.buildMetadataEntry("note", "a".repeat(513)));
});

test("buildEvidenceItem rejects an invalid eventType", () => {
  assert.throws(() =>
    evidence.buildEvidenceItem({
      eventType: "not.a.real.event",
      observedAt: new Date().toISOString(),
    }),
  );
});

test("buildEvidenceItem rejects an invalid fingerprintSha256", () => {
  assert.throws(() =>
    evidence.buildEvidenceItem({
      eventType: "certificate.observed",
      observedAt: new Date().toISOString(),
      fingerprintSha256: "not-a-valid-hash",
    }),
  );
});

test("buildEvidenceItem rejects an oversized summary", () => {
  assert.throws(() =>
    evidence.buildEvidenceItem({
      eventType: "validation.failed",
      observedAt: new Date().toISOString(),
      summary: "a".repeat(1025),
    }),
  );
});

test("buildEvidenceItem accepts a valid item, converts Date, and redacts summary secrets", () => {
  const observedAt = new Date("2026-01-01T00:00:00.000Z");
  const item = evidence.buildEvidenceItem({
    eventType: "certificate.observed",
    observedAt,
    fingerprintSha256: VALID_FINGERPRINT,
    summary: "issued ok, token=abc123secretvalue",
    metadata: [{ name: "issuer", value: "internal-ca" }],
  });

  assert.equal(item.eventType, "certificate.observed");
  assert.equal(item.observedAt, observedAt.toISOString());
  assert.equal(item.fingerprintSha256, VALID_FINGERPRINT);
  assert.ok(!item.summary.includes("abc123secretvalue"));
  assert.deepEqual(item.metadata, [{ name: "issuer", value: "internal-ca" }]);
  // additionalProperties:false parity - no unexpected keys
  assert.deepEqual(
    Object.keys(item).sort(),
    ["eventType", "fingerprintSha256", "metadata", "observedAt", "summary"].sort(),
  );
});

test("buildEvidenceItem rejects private key material in summary", () => {
  assert.throws(
    () =>
      evidence.buildEvidenceItem({
        eventType: "validation.failed",
        observedAt: new Date().toISOString(),
        summary: `leaked key: ${SYNTHETIC_PRIVATE_KEY_PEM}`,
      }),
    (err) => {
      assert.equal(err.code, "PRIVATE_KEY_MATERIAL_REJECTED");
      return true;
    },
  );
});

test("buildEvidenceBody enforces the 1-16 item bounds", () => {
  assert.throws(() => evidence.buildEvidenceBody({ evidenceItems: [] }));

  const tooMany = Array.from({ length: 17 }, () => ({
    eventType: "policy.checked",
    observedAt: new Date().toISOString(),
  }));
  assert.throws(() => evidence.buildEvidenceBody({ evidenceItems: tooMany }));

  const body = evidence.buildEvidenceBody({
    jobId: "job-123",
    evidenceItems: [
      { eventType: "policy.checked", observedAt: new Date().toISOString() },
    ],
  });
  assert.equal(body.jobId, "job-123");
  assert.equal(body.evidenceItems.length, 1);
});

test("buildEvidenceBody defaults jobId to null", () => {
  const body = evidence.buildEvidenceBody({
    evidenceItems: [{ eventType: "policy.checked", observedAt: new Date().toISOString() }],
  });
  assert.equal(body.jobId, null);
});

test("buildPolicyRejectionEvidence produces the right shape", () => {
  const body = evidence.buildPolicyRejectionEvidence({
    rejectionReason: "target_out_of_scope",
    detail: "target host is not within declaredTargetSelectors",
    jobId: "job-456",
  });

  assert.equal(body.jobId, "job-456");
  assert.equal(body.evidenceItems.length, 1);

  const [item] = body.evidenceItems;
  assert.equal(item.eventType, "policy.checked");
  assert.equal(typeof item.observedAt, "string");
  assert.equal(item.summary, "target host is not within declaredTargetSelectors");
  assert.deepEqual(item.metadata, [
    { name: "rejectionReason", value: "target_out_of_scope" },
  ]);
});

test("assertEvidencePayloadSafe throws on a nested private key anywhere in a deep object", () => {
  const payload = {
    jobId: "job-789",
    evidenceItems: [
      {
        eventType: "policy.checked",
        observedAt: new Date().toISOString(),
        nested: {
          deeper: [SYNTHETIC_PRIVATE_KEY_PEM],
        },
      },
    ],
  };

  assert.throws(
    () => evidence.assertEvidencePayloadSafe(payload),
    (err) => {
      assert.equal(err.code, "PRIVATE_KEY_MATERIAL_REJECTED");
      return true;
    },
  );
});

test("assertEvidencePayloadSafe passes for a clean payload", () => {
  const body = evidence.buildEvidenceBody({
    evidenceItems: [
      {
        eventType: "deployment.checked",
        observedAt: new Date().toISOString(),
        summary: "deployment looks healthy",
        metadata: [{ name: "hostCount", value: 4 }],
      },
    ],
  });

  assert.doesNotThrow(() => evidence.assertEvidencePayloadSafe(body));
});

test("EVENT_TYPES mirrors the schema enum exactly", () => {
  assert.deepEqual(evidence.EVENT_TYPES, [
    "certificate.observed",
    "deployment.checked",
    "deployment.updated",
    "validation.passed",
    "validation.failed",
    "policy.checked",
  ]);
});

test("re-exported containsPrivateKeyMaterial / assertNoPrivateKeyMaterial / redactGenericSecrets behave as expected", () => {
  assert.equal(evidence.containsPrivateKeyMaterial(SYNTHETIC_PRIVATE_KEY_PEM), true);
  assert.equal(evidence.containsPrivateKeyMaterial("just a plain string"), false);
  assert.throws(() => evidence.assertNoPrivateKeyMaterial(SYNTHETIC_PRIVATE_KEY_PEM));
  assert.equal(
    evidence.redactGenericSecrets("Authorization: Bearer abc123"),
    "Authorization: [REDACTED]",
  );
});

test("integration: the real apps/api/utils/secretMaterial.js module resolves via the relative require path used by this module", () => {
  // Guards against path-relativity mistakes: fails loudly (module not found)
  // if packages/agent/src/evidence/index.js's require path to the shared
  // detector ever drifts from the real repo layout.
  const shared = require("../../../../apps/api/utils/secretMaterial.js");
  assert.equal(typeof shared.containsPrivateKeyMaterial, "function");
  assert.equal(typeof shared.assertNoPrivateKeyMaterial, "function");
  assert.equal(typeof shared.redactGenericSecrets, "function");
  assert.equal(shared.containsPrivateKeyMaterial(SYNTHETIC_PRIVATE_KEY_PEM), true);
});
