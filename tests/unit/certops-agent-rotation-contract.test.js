"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { prepareCredentialRotation } = require("../../apps/api/services/certops/agentCredentialRotation");

test("rotation operation IDs use the shared 32 lower-case hex contract", async () => {
  const options = {
    dbPool: { connect: async () => { throw new Error("VALIDATED_OPERATION_ID"); } },
    agent: {}, candidatePrefix: `ttagent_${"a".repeat(16)}`, candidateHash: "a".repeat(64),
    env: { CERTOPS_AGENT_ROTATION_ALL_API_FENCED: "true" },
  };
  await assert.rejects(prepareCredentialRotation({ ...options, operationId: "0123456789abcdef0123456789abcdef" }), /VALIDATED_OPERATION_ID/);
  for (const operationId of ["A123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcde", "01234567-89ab-4cde-8fab-0123456789ab"]) {
    await assert.rejects(prepareCredentialRotation({ ...options, operationId }), { code: "CERTOPS_AGENT_ROTATION_INVALID" });
  }
});
