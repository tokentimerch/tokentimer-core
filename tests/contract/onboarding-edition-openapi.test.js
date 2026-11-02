/**
 * Contract Tests - onboarding extension surface vs OpenAPI
 *
 * Static assertions: the verified-summary response documents the optional,
 * free-form `edition` object, and the capability list documents that an
 * edition may add ids.
 */

import { describe, it } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const yaml = fs.readFileSync(
  path.join(repoRoot, "packages/contracts/openapi/openapi.yaml"),
  "utf8",
);

function operation(start, end) {
  const from = yaml.indexOf(start);
  const to = yaml.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `missing ${start}`);
  return yaml.slice(from, to);
}

describe("onboarding edition extension contract", () => {
  const summary = operation(
    "  /api/v1/workspaces/{id}/onboarding/{flow}/summary:",
    "  /api/v1/workspaces/{id}/onboarding/{flow}/reset:",
  );

  it("documents an optional free-form edition object on the summary", () => {
    const start = summary.indexOf("                      edition:");
    assert.ok(start >= 0, "summary.edition is not documented");
    const block = summary.slice(
      start,
      summary.indexOf("                      references:", start),
    );
    assert.match(block, /type: object/);
    assert.match(block, /additionalProperties:\s+oneOf:/);
    assert.match(block, /enum: \[unknown\]/);
    // Optional: never listed as required.
    assert.doesNotMatch(summary, /required:[^\n]*edition/);
  });

  it("keeps the core summary keys alongside the edition object", () => {
    for (const key of ["assets", "autoSync", "monitors", "certops", "alerts", "references"]) {
      assert.match(summary, new RegExp(`\\n {22}${key}:`));
    }
  });

  it("states that an edition may add capability ids", () => {
    const capabilities = operation(
      "  /api/v1/workspaces/{id}/onboarding/capabilities:",
      "  /api/v1/workspaces/{id}/onboarding/{flow}:",
    );
    assert.match(capabilities, /edition may add capability ids/);
    assert.match(capabilities, /additionalProperties: true/);
  });
});
