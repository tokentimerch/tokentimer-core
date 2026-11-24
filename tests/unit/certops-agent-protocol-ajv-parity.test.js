"use strict";

/**
 * Parity proof: agent-side and API-side AJV validators accept/reject the
 * same shared fixture set compiled from agent-protocol.schema.json.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { FIXTURES } = require(
  path.resolve(
    __dirname,
    "../../packages/contracts/certops/agent-protocol-parity-fixtures.cjs",
  ),
);
const {
  validateAgentProtocolMessage: validateAgentSide,
} = require(
  path.resolve(
    __dirname,
    "../../packages/agent/src/protocol/schemaValidation.js",
  ),
);
const {
  validateAgentProtocolMessage: validateApiSide,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/protocolSchemaValidation.js",
  ),
);

describe("CertOps agent-protocol AJV parity (agent vs API)", () => {
  it("loads the shared fixture table covering dry_run_complete and orphaned_unknown_effect", () => {
    const ids = new Set(FIXTURES.map((fixture) => fixture.id));
    assert.ok(ids.has("result-dry_run_complete-valid"));
    assert.ok(ids.has("result-orphaned_unknown_effect-valid"));
    assert.ok(ids.has("result-unknown-status-invalid"));
    assert.ok(ids.has("result-extra-property-invalid"));
  });


  it("enforces the same closed claim-bound destination receipt on both sides", () => {
    const base = FIXTURES.find(({ id }) => id === "result-succeeded-valid").message;
    const result = structuredClone(base);
    Object.assign(result.body, {
      claimId: "claim-1",
      nonce: "destination-validation-nonce-1",
      deploymentDestinationValidation: {
        version: 1,
        validation: {
          configurationSha256: "a".repeat(64),
          trustSha256: "b".repeat(64),
          observedStateSha256: "c".repeat(64),
          planSha256: "d".repeat(64),
          affectedServiceRefs: ["service-1"],
          permittedEffects: ["replace-certificate"],
        },
        bindingSha256: "e".repeat(64),
      },
    });
    for (const validate of [validateAgentSide, validateApiSide]) {
      assert.equal(validate(result).valid, true);
      assert.equal(validate({ ...result, body: { ...result.body, status: "blocked" } }).valid, false);
      assert.equal(validate({ ...result, body: { ...result.body, claimId: null } }).valid, false);
      const unsafeResult = structuredClone(result);
      unsafeResult.body.deploymentDestinationValidation.validation.unexpected = true;
      assert.equal(validate(unsafeResult).valid, false);
    }
  });

  it("requires an authenticated claim and closed read-only facts for historical observation results", () => {
    const result = structuredClone(FIXTURES.find(({ id }) => id === "result-succeeded-valid").message);
    Object.assign(result.body, {
      claimId: "claim-2", nonce: "destination-observation-nonce-1",
      deploymentDestinationObservationReceipt: {
        version: 1, bindingSha256: "e".repeat(64),
        observation: { state: "observed", observedStateSha256: "f".repeat(64), affectedServiceRefs: ["service-1"] },
      },
    });
    for (const validate of [validateAgentSide, validateApiSide]) {
      assert.equal(validate(result).valid, true);
      assert.equal(validate({ ...result, body: { ...result.body, claimId: null } }).valid, false);
      assert.equal(validate({ ...result, body: { ...result.body, status: "blocked" } }).valid, false);
      const receipt = result.body.deploymentDestinationObservationReceipt;
      for (const observation of [
        { ...receipt.observation, state: "deployed" },
        { ...receipt.observation, observedStateSha256: null },
        { ...receipt.observation, materialRef: "private-ref" },
      ]) {
        const unsafeResult = { ...result, body: { ...result.body, deploymentDestinationObservationReceipt: { ...receipt, observation } } };
        assert.equal(validate(unsafeResult).valid, false);
      }
    }
  });

  it("keeps destination execution off claim polls and pairs each preview receipt with its outcome", () => {
    const claim = FIXTURES.find(({ id }) => id === "claim-valid").message;
    const result = FIXTURES.find(({ id }) => id === "result-succeeded-valid").message;
    for (const validate of [validateAgentSide, validateApiSide]) {
      assert.equal(validate({ ...claim, body: { ...claim.body,
        supportedActions: [...claim.body.supportedActions, "validate-deployment-destination", "observe-deployment-destination"],
      } }).valid, true);
      assert.equal(validate({ ...claim, body: { ...claim.body,
        supportedActions: [...claim.body.supportedActions, "execute-deployment-destination"],
      } }).valid, false);
      const confirmed = {
        state: "confirmed", verifiedFingerprintSha256: "a".repeat(64),
        verifiedServiceRefs: ["portal"], verificationSha256: "b".repeat(64),
      };
      for (const [status, outcome] of [["succeeded", confirmed], ["orphaned_unknown_effect", { state: "unknown" }]]) {
        const receipt = { version: 1, intendedEffectSha256: "c".repeat(64), outcome, bindingSha256: "d".repeat(64) };
        const body = {
          ...result.body, status, attemptId: "claim-1", claimId: "claim-1", nonce: "destination-execution-nonce-1",
          keyRotated: null,
          deploymentDestinationExecutionReceipt: receipt,
        };
        assert.equal(validate({ ...result, body }).valid, true);
        assert.equal(validate({ ...result, body: { ...body, status: "blocked" } }).valid, false);
        assert.equal(validate({ ...result, body: { ...body, claimId: null } }).valid, false);
        assert.equal(validate({ ...result, body: { ...body, errorMessage: "extra detail" } }).valid, false);
        assert.equal(validate({ ...result, body: { ...body, deploymentDestinationExecutionReceipt: {
          ...receipt, outcome: { ...outcome, extra: "not allowed" },
        } } }).valid, false);
      }
    }
  });

  for (const fixture of FIXTURES) {
    it(`agrees on ${fixture.id} (expectValid=${fixture.expectValid})`, () => {
      const agent = validateAgentSide(fixture.message);
      const api = validateApiSide(fixture.message);
      assert.equal(
        agent.valid,
        fixture.expectValid,
        `agent side: ${JSON.stringify(agent.errors)}`,
      );
      assert.equal(
        api.valid,
        fixture.expectValid,
        `api side: ${JSON.stringify(api.errors)}`,
      );
      assert.equal(
        agent.valid,
        api.valid,
        `parity mismatch for ${fixture.id}: agent=${agent.valid} api=${api.valid}`,
      );
    });
  }
});
