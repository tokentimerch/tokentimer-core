"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "../..");
const variables = [
  "SUBFINDER_BIN",
  "DOMAIN_CHECKER_TOOL_TMPDIR",
  "DOMAIN_CHECKER_TOOL_TIMEOUT_MS",
  "DOMAIN_CHECKER_OVERALL_TIMEOUT_MS",
  "DOMAIN_CHECKER_TLS_TIMEOUT_MS",
  "DOMAIN_CHECKER_IMPORT_SOCKET_TIMEOUT_MS",
  "DOMAIN_CHECKER_MAX_RESULTS",
  "DOMAIN_CHECKER_IMPORT_MAX_CERTIFICATES",
  "DOMAIN_CHECKER_DISCOVERY_LIMITS",
  "DOMAIN_CHECKER_IMPORT_LIMITS",
  "DOMAIN_CHECKER_LOOKUP_RATE_LIMIT_MAX",
  "DOMAIN_CHECKER_LOOKUP_RATE_LIMIT_WINDOW_MS",
];

function serviceBlock(file, service) {
  const yaml = readFileSync(path.join(root, "deploy/compose", file), "utf8");
  const start = yaml.indexOf(`  ${service}:`);
  assert.notEqual(start, -1);
  const rest = yaml.slice(start + service.length + 3);
  const nextService = rest.search(/^  [a-z][a-z-]+:/m);
  return nextService === -1 ? rest : rest.slice(0, nextService);
}

describe("Compose domain checker environment", () => {
  for (const file of ["docker-compose.yml", "docker-compose.dev.yml"]) {
    it(`${file} forwards every setting to the api service with an empty default`, () => {
      const block = serviceBlock(file, "api");
      for (const key of variables) {
        assert.match(
          block,
          new RegExp(`\\b${key}[:=]\\s*\\$\\{${key}:-\\}`),
          key,
        );
      }
    });
  }

  it("documents every setting in .env.example and CONFIGURATION.md", () => {
    const env = readFileSync(
      path.join(root, "deploy/compose/.env.example"),
      "utf8",
    );
    const docs = readFileSync(path.join(root, "docs/CONFIGURATION.md"), "utf8");
    for (const key of variables) {
      assert.match(
        env,
        new RegExp(`^# ${key}=`, "m"),
        `${key} in .env.example`,
      );
      const rows = docs.match(new RegExp(`^\\| \`${key}\``, "gm")) || [];
      assert.equal(rows.length, 1, `${key} listed once in CONFIGURATION.md`);
    }
  });
});
