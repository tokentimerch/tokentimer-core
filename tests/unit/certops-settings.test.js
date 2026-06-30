"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  dbCertOpsEnabled,
  envCertOpsEnabled,
  isCertOpsEnabled,
  parseBoolean,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/settings.js"),
);
const {
  NOT_FOUND_RESPONSE,
  createRequireCertOpsEnabled,
} = require(
  path.resolve(__dirname, "../../apps/api/middleware/require-certops-enabled.js"),
);

function poolReturning(settings) {
  return {
    async query() {
      return { rows: [{ certops_settings: settings }] };
    },
  };
}

function poolThrowing(code) {
  return {
    async query() {
      const error = new Error("database error");
      error.code = code;
      throw error;
    },
  };
}

function responseRecorder() {
  return {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
}

describe("CertOps rollout settings", () => {
  it("parses common boolean forms", () => {
    assert.equal(parseBoolean(true), true);
    assert.equal(parseBoolean(false), false);
    assert.equal(parseBoolean("true"), true);
    assert.equal(parseBoolean("1"), true);
    assert.equal(parseBoolean("enabled"), true);
    assert.equal(parseBoolean("false"), false);
    assert.equal(parseBoolean("0"), false);
    assert.equal(parseBoolean("disabled"), false);
    assert.equal(parseBoolean("maybe"), null);
    assert.equal(parseBoolean(undefined), null);
  });

  it("uses CERTOPS_ENABLED from the environment", () => {
    assert.equal(envCertOpsEnabled({ CERTOPS_ENABLED: "true" }), true);
    assert.equal(envCertOpsEnabled({ CERTOPS_ENABLED: "false" }), false);
    assert.equal(envCertOpsEnabled({}), null);
  });

  it("reads certops_settings.enabled when the DB column exists", async () => {
    assert.equal(await dbCertOpsEnabled(poolReturning({ enabled: true })), true);
    assert.equal(await dbCertOpsEnabled(poolReturning({ enabled: false })), false);
    assert.equal(await dbCertOpsEnabled(poolReturning({})), null);
  });

  it("treats a missing certops_settings column as unset", async () => {
    assert.equal(await dbCertOpsEnabled(poolThrowing("42703")), null);
    assert.equal(await dbCertOpsEnabled(poolThrowing("42P01")), null);
  });

  it("defaults to false and gives env precedence over DB", async () => {
    assert.equal(
      await isCertOpsEnabled({
        env: {},
        dbPool: poolReturning({ enabled: true }),
      }),
      true,
    );
    assert.equal(
      await isCertOpsEnabled({
        env: { CERTOPS_ENABLED: "false" },
        dbPool: poolReturning({ enabled: true }),
      }),
      false,
    );
    assert.equal(
      await isCertOpsEnabled({
        env: {},
        dbPool: poolReturning({}),
      }),
      false,
    );
  });
});

describe("requireCertOpsEnabled middleware", () => {
  it("passes through when enabled", async () => {
    const middleware = createRequireCertOpsEnabled({
      flagResolver: async () => true,
    });
    const res = responseRecorder();
    let nextCalled = false;

    await middleware({}, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, true);
    assert.equal(res.statusCode, null);
  });

  it("returns the standard not-found response when disabled", async () => {
    const middleware = createRequireCertOpsEnabled({
      flagResolver: async () => false,
    });
    const res = responseRecorder();
    let nextCalled = false;

    await middleware({}, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 404);
    assert.deepEqual(res.body, NOT_FOUND_RESPONSE);
  });
});
