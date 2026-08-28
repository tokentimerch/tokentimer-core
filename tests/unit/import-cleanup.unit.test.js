"use strict";

/**
 * Unit tests for importCleanup's pure exports: request validation and the
 * dimension-filter SQL builder used by the scan-scoped anti-join. DB-backed
 * deletion behavior (claim, anti-join, observation fence, transaction) is
 * covered by integration tests since it requires a real database.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert");
const {
  KNOWN_PROVIDERS,
  validateCleanupRequest,
  buildDimensionFilterSql,
} = require("../../apps/api/services/importCleanup");

describe("importCleanup.validateCleanupRequest", () => {
  it("accepts undefined/null (cleanup not requested)", () => {
    assert.strictEqual(validateCleanupRequest(undefined), null);
    assert.strictEqual(validateCleanupRequest(null), null);
  });

  it("rejects non-object payloads", () => {
    assert.match(validateCleanupRequest("yes"), /must be an object/);
    assert.match(validateCleanupRequest([1]), /must be an object/);
  });

  it("ignores payloads with enabled !== true", () => {
    assert.strictEqual(validateCleanupRequest({ enabled: false }), null);
    assert.strictEqual(validateCleanupRequest({}), null);
    // Even a garbage provider/scanId is ignored when cleanup isn't enabled --
    // this must never be a backdoor to validate an otherwise-inert payload.
    assert.strictEqual(
      validateCleanupRequest({ enabled: false, provider: "nope" }),
      null,
    );
  });

  it("requires a known provider when enabled", () => {
    assert.match(
      validateCleanupRequest({
        enabled: true,
        provider: "bitbucket",
        scanId: "11111111-1111-1111-1111-111111111111",
      }),
      /provider must be one of/,
    );
  });

  it("requires a non-empty scanId string when enabled", () => {
    assert.match(
      validateCleanupRequest({ enabled: true, provider: "gitlab" }),
      /scanId is required/,
    );
    assert.match(
      validateCleanupRequest({
        enabled: true,
        provider: "gitlab",
        scanId: "",
      }),
      /scanId is required/,
    );
    assert.match(
      validateCleanupRequest({
        enabled: true,
        provider: "gitlab",
        scanId: "   ",
      }),
      /scanId is required/,
    );
    assert.match(
      validateCleanupRequest({
        enabled: true,
        provider: "gitlab",
        scanId: 12345,
      }),
      /scanId is required/,
    );
  });

  it("accepts a valid payload for every known provider", () => {
    for (const provider of KNOWN_PROVIDERS) {
      assert.strictEqual(
        validateCleanupRequest({
          enabled: true,
          provider,
          scanId: "11111111-1111-1111-1111-111111111111",
        }),
        null,
        `${provider} should accept a valid scanId payload`,
      );
    }
  });

  it("KNOWN_PROVIDERS covers exactly the seven supported integrations", () => {
    assert.deepStrictEqual(
      [...KNOWN_PROVIDERS].sort(),
      [
        "aws",
        "azure",
        "azure-ad",
        "gcp",
        "github",
        "gitlab",
        "vault",
      ].sort(),
    );
  });
});

describe("importCleanup.buildDimensionFilterSql", () => {
  it("returns an empty filter for no dimensions", () => {
    const { sql, params } = buildDimensionFilterSql(null, 5);
    assert.strictEqual(sql, "");
    assert.deepStrictEqual(params, []);
  });

  it("skips null/undefined/empty-string dimension values", () => {
    const { sql, params } = buildDimensionFilterSql(
      { region: null, service: undefined, mount: "" },
      5,
    );
    assert.strictEqual(sql, "");
    assert.deepStrictEqual(params, []);
  });

  it("builds an exact-match clause for a plain dimension key", () => {
    const { sql, params } = buildDimensionFilterSql({ region: "us-east-1" }, 3);
    assert.match(sql, /\(t\.source_dimensions->>'region'\) = \$3/);
    assert.deepStrictEqual(params, ["us-east-1"]);
  });

  it("builds a prefix-match clause against the token's own 'path' for pathPrefix", () => {
    const { sql, params } = buildDimensionFilterSql(
      { pathPrefix: "staging/db" },
      2,
    );
    assert.match(sql, /\(t\.source_dimensions->>'path'\) LIKE \$2/);
    assert.deepStrictEqual(params, ["staging/db%"]);
  });

  it("combines multiple dimensions with AND and sequential placeholders", () => {
    const { sql, params } = buildDimensionFilterSql(
      { mount: "secret/", pathPrefix: "app1", category: "cert" },
      1,
    );
    assert.match(sql, / AND /);
    assert.match(sql, /\$1/);
    assert.match(sql, /\$2/);
    assert.match(sql, /\$3/);
    assert.deepStrictEqual(params, ["secret/", "app1%", "cert"]);
  });

  it("sanitizes non-pathPrefix dimension keys to a safe identifier", () => {
    // Defense in depth: dimension keys ultimately come from scan-recorded
    // data, not raw user input, but the SQL builder must never interpolate
    // an unsanitized key into the query string regardless.
    const { sql } = buildDimensionFilterSql({ "bad key'; --": "x" }, 1);
    assert.doesNotMatch(sql, /'; --/);
    assert.match(sql, /badkey/);
  });

  it("builds a membership-match clause against the token's own 'category' for categories", () => {
    const { sql, params } = buildDimensionFilterSql(
      { categories: ["cert", "generic"] },
      4,
    );
    assert.match(
      sql,
      /\(t\.source_dimensions->>'category'\) = ANY\(\$4::text\[\]\)/,
    );
    assert.deepStrictEqual(params, [["cert", "generic"]]);
  });

  it("skips categories when the array is empty", () => {
    const { sql, params } = buildDimensionFilterSql({ categories: [] }, 1);
    assert.strictEqual(sql, "");
    assert.deepStrictEqual(params, []);
  });
});
