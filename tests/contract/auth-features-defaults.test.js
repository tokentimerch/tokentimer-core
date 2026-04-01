/**
 * Contract Tests - Runtime Extension Surface
 *
 * Verifies core default auth feature contract remains stable.
 */

import { describe, it } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const healthRoutePath = resolve(process.cwd(), "apps/api/routes/health.js");

describe("Runtime extension auth feature defaults", () => {
  it("exposes /api/auth/features default endpoint in core", () => {
    const source = readFileSync(healthRoutePath, "utf8");
    assert.match(source, /router\.get\("\/api\/auth\/features"/);
  });

  it("keeps core auth feature defaults disabled", () => {
    const source = readFileSync(healthRoutePath, "utf8");
    assert.match(source, /saml:\s*false/);
    assert.match(source, /oidc:\s*false/);
  });
});
