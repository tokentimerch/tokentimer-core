"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const common = require("../../scripts/adcs-lab/common.cjs");
test("simulator refuses production, external APIs and non-lab databases before transport", async () => {
  const saved = { ...process.env },
    originalFetch = global.fetch;
  let requests = 0;
  global.fetch = async () => {
    requests++;
    throw Error("Unexpected transport");
  };
  try {
    for (const overrides of [
      { NODE_ENV: "production" },
      { DB_HOST: "customer.invalid" },
      { DB_NAME: "production" },
      { API_URL: "https://example.com" },
      { TT_ADCS_LOCAL_LAB: "" },
    ]) {
      Object.assign(
        process.env,
        common.environment(common.newState()),
        overrides,
      );
      await assert.rejects(
        require("../../scripts/adcs-lab/simulator.cjs").machine(
          {},
          "jobs/claim",
          "claim",
          {},
        ),
        /dedicated loopback/,
      );
    }
    assert.equal(requests, 0);
  } finally {
    process.env = saved;
    global.fetch = originalFetch;
  }
});
test("lab service environment excludes ambient SMTP and protected cloud credentials", () => {
  const saved = { ...process.env };
  try {
    Object.assign(process.env, {
      SMTP_HOST: "customer.invalid",
      SMTP_PASS: "ambient-secret",
      AZURE_CLIENT_SECRET: "protected-secret",
      DATABASE_URL: "production-url",
    });
    const env = common.environment(common.newState());
    assert.equal(env.SMTP_HOST, "127.0.0.1");
    assert.equal(env.SMTP_PASS, "");
    assert.equal(env.AZURE_CLIENT_SECRET, undefined);
    assert.equal(env.DATABASE_URL, undefined);
    assert.equal(env.DB_NAME, "tt_adcs_simulated");
  } finally {
    process.env = saved;
  }
});
