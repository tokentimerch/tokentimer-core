"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { createRequire } = require("node:module");
const yaml = createRequire(require.resolve("mocha/package.json"))("js-yaml");

for (const [file, services] of [
  ["docker-compose.yml", ["api", "worker-delivery", "worker-weekly-digest"]],
  ["docker-compose.dev.yml", ["api", "worker-delivery", "worker-weekly-digest"]],
  ["docker-compose.test.yml", ["api", "worker-delivery"]],
]) {
  test(`${file} applies the same recipient verification configuration to API and notification workers`, () => {
    const compose = yaml.load(readFileSync(join(__dirname, "../../deploy/compose", file), "utf8"));
    for (const name of services) {
      const values = compose.services[name].environment;
      const env = Array.isArray(values)
        ? Object.fromEntries(values.map(value => {
            const index = value.indexOf("=");
            return [value.slice(0, index), value.slice(index + 1)];
          }))
        : values;
      assert.equal(env.RECIPIENT_VERIFICATION_MODE, "${RECIPIENT_VERIFICATION_MODE:-off}", name);
      assert.equal(env.RECIPIENT_FINGERPRINT_SECRET, "${RECIPIENT_FINGERPRINT_SECRET:-}", name);
      assert.equal(env.PUBLIC_BASE_URL, "${PUBLIC_BASE_URL:-}", name);
      assert.equal(env.TT_DEPLOYMENT, "${TT_DEPLOYMENT:-self-hosted}", name);
    }
  });
}
