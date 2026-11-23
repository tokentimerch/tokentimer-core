"use strict";

const { createHash } = require("node:crypto");

const CANDIDATE_SHA256 = "f".repeat(64);

function nativeCounts({ captureId = "a".repeat(32), submissions = 1, keygens = 1, accepts = 1 } = {}) {
  const events = [];
  const append = event => events.push({ sequence: events.length + 1, ...event });
  let callId = 0;
  function observeKey(api, nameKind, pid) {
    const handleCorrelation = "1".repeat(64);
    for (const operation of ["create", "finalize", "free"]) {
      callId++;
      const common = {
        tid: 42, callId, operation: `${api}-${operation}`,
        invocationFingerprint: createHash("sha256").update(String(callId)).digest("hex"),
      };
      const process = { pid, createdFileTime: "01dc000000000000" };
      append({ kind: "cng-api-entry", evidence: { ...process,
        payload: operation === "create" ? { ...common, nameKind } : common } });
      append({ kind: "cng-api-return", evidence: { ...process,
        payload: { ...common, status: "00000000", handleCorrelation } } });
    }
  }

  observeKey("ncrypt", "ephemeral", 51);
  observeKey("bcrypt", "ephemeral", 51);
  append({ kind: "baseline" });
  for (let key = 0; key < keygens; key++) observeKey("ncrypt", "non-null", 52);
  return { captureId, coverageComplete: true, submissions, keygens, accepts,
    cngEvidence: { captureId, candidateSha256: CANDIDATE_SHA256, events } };
}

module.exports = { CANDIDATE_SHA256, nativeCounts };
