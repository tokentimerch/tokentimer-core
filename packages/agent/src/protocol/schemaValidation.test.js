"use strict";

/**
 * Colocated agent-side coverage using the same shared fixture table as the
 * API parity test (tests/unit/certops-agent-protocol-ajv-parity.test.js).
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { FIXTURES } = require(
  path.resolve(
    __dirname,
    "../../../../packages/contracts/certops/agent-protocol-parity-fixtures.cjs",
  ),
);
const { validateAgentProtocolMessage } = require("./schemaValidation");
const { validateEnvelopeShape } = require("./index.js");

describe("agent protocol schemaValidation fixtures", () => {
  for (const fixture of FIXTURES) {
    it(`${fixture.id}`, () => {
      const result = validateAgentProtocolMessage(fixture.message);
      assert.equal(result.valid, fixture.expectValid, JSON.stringify(result.errors));
      const problems = validateEnvelopeShape(fixture.message);
      assert.equal(problems.length === 0, fixture.expectValid, problems.join("; "));
    });
  }
});
