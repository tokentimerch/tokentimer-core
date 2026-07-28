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
