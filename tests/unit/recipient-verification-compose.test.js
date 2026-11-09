"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { createRequire } = require("node:module");
const yaml = createRequire(require.resolve("mocha/package.json"))("js-yaml");

function environment(values) {
  return Array.isArray(values)
    ? Object.fromEntries(values.map(value => {
        const index = value.indexOf("=");
        return index < 0 ? [value, null] : [value.slice(0, index), value.slice(index + 1)];
      }))
    : values;
}

for (const [file, services] of [
  ["docker-compose.yml", ["api", "worker-delivery", "worker-weekly-digest"]],
  ["docker-compose.dev.yml", ["api", "worker-delivery", "worker-weekly-digest"]],
  ["docker-compose.test.yml", ["api", "worker-delivery"]],
]) {
  test(`${file} applies the same recipient verification configuration to API and notification workers`, () => {
    const compose = yaml.load(readFileSync(join(__dirname, "../../deploy/compose", file), "utf8"));
    for (const name of services) {
      const env = environment(compose.services[name].environment);
      assert.equal(env.RECIPIENT_VERIFICATION_MODE, "${RECIPIENT_VERIFICATION_MODE:-off}", name);
      assert.equal(env.RECIPIENT_VERIFICATION_LEGACY_GRACE, "${RECIPIENT_VERIFICATION_LEGACY_GRACE:-0}", name);
      assert.equal(env.RECIPIENT_FINGERPRINT_SECRET, "${RECIPIENT_FINGERPRINT_SECRET:-}", name);
      assert.equal(env.PUBLIC_BASE_URL, "${PUBLIC_BASE_URL:-}", name);
      assert.equal(env.TT_DEPLOYMENT, "${TT_DEPLOYMENT:-self-hosted}", name);
    }
  });
}

for (const file of ["docker-compose.yml", "docker-compose.dev.yml"]) {
  test(`${file} forwards API rate tuning and digest recovery without empty-string defaults`, () => {
    const compose = yaml.load(readFileSync(join(__dirname, "../../deploy/compose", file), "utf8"));
    const api = environment(compose.services.api.environment);
    const defaults = {
      RECIPIENT_VERIFY_EMAIL_DEST_PER_DAY: 1,
      RECIPIENT_VERIFY_EMAIL_DEST_PER_WEEK: 3,
      RECIPIENT_VERIFY_WHATSAPP_DEST_PER_DAY: 1,
      RECIPIENT_VERIFY_WHATSAPP_DEST_PER_WEEK: 3,
      RECIPIENT_VERIFY_WORKSPACE_PER_DAY: 50,
      RECIPIENT_VERIFY_USER_PER_DAY: 20,
      RECIPIENT_TEST_PER_CONTACT_PER_DAY: 3,
      RECIPIENT_TEST_COOLDOWN_SECONDS: 120,
      RECIPIENT_VERIFY_PUBLIC_PER_WINDOW: 60,
      RECIPIENT_VERIFY_PUBLIC_WINDOW_SECONDS: 600,
      RECIPIENT_RESUBSCRIBE_IP_PER_DAY: 10,
      RECIPIENT_VERIFICATION_DISPATCH_LEASE_SECONDS: 120,
      RECIPIENT_VERIFY_PAGE_WINDOW_MS: 600000,
    };
    for (const [key, fallback] of Object.entries(defaults)) {
      assert.equal(api[key], "${" + key + ":-" + fallback + "}", key);
    }
    assert.ok(Object.hasOwn(api, "RECIPIENT_VERIFY_PAGE_MAX"));
    assert.equal(api.RECIPIENT_VERIFY_PAGE_MAX, null);
    const digest = environment(compose.services["worker-weekly-digest"].environment);
    assert.equal(digest.WEEKLY_DIGEST_UNCERTAIN_RETRY_SECONDS, "${WEEKLY_DIGEST_UNCERTAIN_RETRY_SECONDS:-900}");
    assert.equal(Object.hasOwn(digest, "RECIPIENT_VERIFY_PAGE_MAX"), false);
  });
}
