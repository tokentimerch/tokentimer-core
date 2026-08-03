"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");

const { sanitizeLogRecord } = require(
  path.resolve(__dirname, "../../packages/log-scrub"),
);
const { redactSensitiveFields } = require(
  path.resolve(__dirname, "../../apps/api/utils/logger.js"),
);
const {
  PRIVATE_KEY_REDACTION_PLACEHOLDER,
} = require(path.resolve(__dirname, "../../apps/api/utils/secretMaterial.js"));

const workerLoggerPath = path.resolve(
  __dirname,
  "../../apps/worker/src/logger.js",
);

// Synthetic fixture only. No real key material is committed.
const FAKE_BODY = "RkFLRS1OT1QtQS1SRUFMLUtFWQ==";
const pem = (label) =>
  `-----BEGIN ${label}-----\n${FAKE_BODY}\n-----END ${label}-----`;

// C3 (ARC-08): apps/worker/src/logger.js wires Winston directly into
// @tokentimer/log-scrub's sanitizeLogRecord (an ES module import, so this
// suite exercises the same function through the CommonJS package entry
// point rather than importing the worker's ESM logger module directly).
describe("worker logger redaction parity (C3 / ARC-08)", () => {
  it("wires apps/worker/src/logger.js through @tokentimer/log-scrub's sanitizeLogRecord", () => {
    const workerLoggerSource = fs.readFileSync(workerLoggerPath, "utf8");
    assert.match(workerLoggerSource, /@tokentimer\/log-scrub/);
    assert.match(workerLoggerSource, /sanitizeLogRecord\s*\(/);
  });

  it("redacts a secret-bearing worker job failure exactly like the API logger", () => {
    const key = pem("RSA PRIVATE KEY");
    const jobFailure = {
      level: "error",
      message: "certops job execution failed",
      jobId: "job_abc123",
      password: "should-not-appear",
      apiKey: "should-not-appear-either",
      privateKey: key,
      stdout: `openssl error, dumping key for debug: ${key}`,
      headers: { authorization: "Bearer leaked-worker-token" },
    };

    const workerResult = sanitizeLogRecord(jobFailure);
    const apiResult = redactSensitiveFields(jobFailure);

    assert.equal(workerResult.password, "[REDACTED]");
    assert.equal(workerResult.apiKey, "[REDACTED]");
    // Field-name redaction is the outer defense layer: "privateKey" matches
    // the sensitive-key pattern and is redacted before content-based
    // scrubbing runs, so it comes back as the generic marker, not the
    // private-key-specific one.
    assert.equal(workerResult.privateKey, "[REDACTED]");
    assert.ok(workerResult.stdout.includes(PRIVATE_KEY_REDACTION_PLACEHOLDER));
    assert.ok(!workerResult.stdout.includes(FAKE_BODY));
    assert.equal(workerResult.headers.authorization, "[REDACTED]");
    assert.equal(workerResult.jobId, "job_abc123");
    assert.equal(workerResult.message, "certops job execution failed");

    // The worker and API loggers must agree byte-for-byte on this record:
    // both ultimately call the same shared scrubber, so any divergence here
    // is a real behavioral gap, not just a missing test.
    assert.deepEqual(workerResult, apiResult);
  });

  it("redacts a thrown Error the same way on both loggers", () => {
    const key = pem("EC PRIVATE KEY");
    const err = new Error(`deploy failed while handling ${key}`);
    err.stack = `Error: deploy failed while handling ${key}\n    at deploy (apps/worker/src/jobs/deploy.js:42:9)`;

    const workerResult = sanitizeLogRecord({ level: "error", err });
    const apiResult = redactSensitiveFields({ level: "error", err });

    assert.ok(workerResult.err.message.includes(PRIVATE_KEY_REDACTION_PLACEHOLDER));
    assert.ok(!workerResult.err.message.includes(FAKE_BODY));
    assert.ok(workerResult.err.stack.includes(PRIVATE_KEY_REDACTION_PLACEHOLDER));
    assert.match(workerResult.err.stack, /at deploy \(apps\/worker\/src\/jobs\/deploy\.js:42:9\)/);
    assert.deepEqual(workerResult, apiResult);
  });
});
