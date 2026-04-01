/**
 * Contract Tests - Limits Policy Baseline
 *
 * Verifies core stays oss-first with unlimited defaults.
 */

import { describe, it } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const constantsPath = resolve(process.cwd(), "apps/api/config/constants.js");
const planLimitsPath = resolve(
  process.cwd(),
  "apps/api/services/planLimits.js",
);

describe("Limits policy contract baseline", () => {
  it("defines oss token and alert defaults as unlimited", () => {
    const source = readFileSync(constantsPath, "utf8");
    assert.match(source, /oss:\s*Number\.POSITIVE_INFINITY/);
  });

  it("keeps workspace and member limits unlimited by default in core", () => {
    const source = readFileSync(planLimitsPath, "utf8");
    assert.match(source, /WORKSPACE_LIMITS/);
    assert.match(source, /MEMBER_LIMITS/);
    assert.match(source, /Number\.POSITIVE_INFINITY/);
  });

  it("always allows workspace creation in core plan logic", () => {
    const source = readFileSync(planLimitsPath, "utf8");
    assert.match(
      source,
      /function canCreateAnotherWorkspace\([^)]*\)\s*\{\s*return true;/,
    );
  });
});
