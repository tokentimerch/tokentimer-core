"use strict";

/**
 * Unit tests for importCleanup validation and scope patterns.
 * DB-dependent deletion behavior is covered by integration tests.
 * Only the pure exports are exercised here; requiring the module creates a
 * pg Pool but never connects.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert");
const {
  validateCleanupRequest,
  SOURCE_LOCATION_PATTERNS,
  PROVIDER_PREFIXES,
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
  });

  it("requires a known provider when enabled", () => {
    assert.match(
      validateCleanupRequest({ enabled: true, provider: "bitbucket" }),
      /provider must be one of/,
    );
  });

  it("requires non-empty scannedSources with known kinds", () => {
    assert.match(
      validateCleanupRequest({
        enabled: true,
        provider: "gitlab",
        scannedSources: [],
      }),
      /non-empty array/,
    );
    assert.match(
      validateCleanupRequest({
        enabled: true,
        provider: "gitlab",
        scannedSources: ["gitlab-unknown"],
      }),
      /unknown source kind/,
    );
  });

  it("requires scannedLocations array", () => {
    assert.match(
      validateCleanupRequest({
        enabled: true,
        provider: "gitlab",
        scannedSources: ["gitlab-pat"],
        scannedLocations: "gitlab:x",
      }),
      /must be an array/,
    );
  });

  it("accepts a valid payload", () => {
    assert.strictEqual(
      validateCleanupRequest({
        enabled: true,
        provider: "gitlab",
        scannedSources: ["gitlab-pat", "gitlab-deploy-token"],
        scannedLocations: ["gitlab:personal_access_tokens/1"],
      }),
      null,
    );
  });
});

describe("importCleanup.SOURCE_LOCATION_PATTERNS", () => {
  it("gitlab-pat matches both PAT location shapes", () => {
    const p = SOURCE_LOCATION_PATTERNS["gitlab-pat"];
    assert.strictEqual(p.test("gitlab:personal_access_tokens/42"), true);
    assert.strictEqual(
      p.test("gitlab:users/alice/personal_access_tokens/42"),
      true,
    );
    assert.strictEqual(p.test("gitlab:projects/7/access_tokens/42"), false);
  });

  it("gitlab token type patterns are mutually exclusive", () => {
    const samples = {
      "gitlab-project-token": "gitlab:projects/7/access_tokens/1",
      "gitlab-group-token": "gitlab:groups/3/access_tokens/1",
      "gitlab-deploy-token": "gitlab:projects/7/deploy_tokens/1",
      "gitlab-trigger-token": "gitlab:projects/7/triggers/1",
      "gitlab-ssh-key": "gitlab:user/keys/1",
    };
    for (const [kind, location] of Object.entries(samples)) {
      assert.strictEqual(
        SOURCE_LOCATION_PATTERNS[kind].test(location),
        true,
        `${kind} should match ${location}`,
      );
      for (const [otherKind, pattern] of Object.entries(
        SOURCE_LOCATION_PATTERNS,
      )) {
        if (otherKind === kind || !otherKind.startsWith("gitlab-")) continue;
        assert.strictEqual(
          pattern.test(location),
          false,
          `${otherKind} should not match ${location}`,
        );
      }
    }
  });

  it("github patterns match the integration location shapes", () => {
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["github-ssh-key"].test("github:user/keys/9"),
      true,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["github-secret"].test(
        "github:repos/org/repo/actions/secrets/MY_SECRET",
      ),
      true,
    );
    assert.strictEqual(
      SOURCE_LOCATION_PATTERNS["github-deploy-key"].test(
        "github:repos/org/repo/keys/12",
      ),
      true,
    );
  });

  it("every provider prefix has a colon suffix", () => {
    for (const prefix of Object.values(PROVIDER_PREFIXES)) {
      assert.strictEqual(prefix.endsWith(":"), true);
    }
  });
});
