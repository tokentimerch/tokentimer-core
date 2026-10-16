"use strict";
/** Read-only public identity observation from an original signed claim response.
 * This never verifies a signature, changes signed bytes, or qualifies execution.
 * A caller must independently prove actual agent verification/current claim. */
const assert = require("node:assert/strict");
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
function observeClaimResponse(bytes) {
  assert.ok(
    Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 1048576,
    "Bounded original claim response required",
  );
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw Error("Original claim response is not bounded JSON");
  }
  assert.ok(
    value && Array.isArray(value.jobs) && value.jobs.length <= 128,
    "Bounded actual claim jobs required",
  );
  const records = [];
  for (const envelope of value.jobs) {
    assert.ok(
      envelope &&
        envelope.envelopeVersion === 2 &&
        typeof envelope.payloadB64 === "string" &&
        envelope.payloadB64.length > 0 &&
        envelope.payloadB64.length <= 1048576,
      "Original version2 signed envelope required",
    );
    const payloadBytes = Buffer.from(envelope.payloadB64, "base64");
    assert.ok(
      payloadBytes.toString("base64") === envelope.payloadB64,
      "Canonical original signed payload encoding required",
    );
    let payload;
    try {
      payload = JSON.parse(payloadBytes.toString("utf8"));
    } catch {
      throw Error("Original signed payload cannot be observed");
    }
    assert.ok(
      typeof payload.jobId === "string" && UUID.test(payload.jobId),
      "Public original job identity required",
    );
    assert.ok(
      typeof envelope.signingKeyId === "string" &&
        /^[A-Za-z0-9_.:-]{1,128}$/.test(envelope.signingKeyId),
      "Public original signing key identity required",
    );
    records.push({ jobId: payload.jobId, signingKeyId: envelope.signingKeyId });
  }
  assert.equal(
    new Set(records.map((r) => r.jobId.toLowerCase())).size,
    records.length,
    "One original envelope per claimed job required",
  );
  return records;
}
function createClaimObserver() {
  const seen = new Map();
  let responses = 0;
  return {
    observe(bytes) {
      for (const record of observeClaimResponse(bytes)) {
        const key = record.jobId.toLowerCase();
        if (seen.has(key))
          assert.equal(
            seen.get(key),
            record.signingKeyId,
            "Signing key changed for one observed native job",
          );
        else seen.set(key, record.signingKeyId);
      }
      responses++;
    },
    signingKeyFor(jobId) {
      assert.ok(typeof jobId === "string" && UUID.test(jobId));
      return seen.get(jobId.toLowerCase());
    },
    snapshot() {
      return { responseCount: responses, jobCount: seen.size };
    },
  };
}
module.exports = { observeClaimResponse, createClaimObserver };
