"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "../..");
const autoSyncVariables = [
  "APP_URL",
  "SMTP_HOST",
  "SMTP_PORT",
  "SMTP_USER",
  "SMTP_PASS",
  "SMTP_SECURE",
  "SMTP_REQUIRE_TLS",
  "FROM_EMAIL",
  "FROM_EMAIL_NAME",
  "OP_NOTIFICATION_EMAIL_DAILY_CAP",
  "AUTO_SYNC_CRITICAL_THRESHOLD",
];

function serviceBlock(file, service) {
  const yaml = readFileSync(path.join(root, "deploy/compose", file), "utf8");
  const start = yaml.indexOf(`  ${service}:`);
  assert.notEqual(start, -1);
  const rest = yaml.slice(start + service.length + 3);
  const nextService = rest.search(/^  [a-z][a-z-]+:/m);
  return nextService === -1 ? rest : rest.slice(0, nextService);
}

describe("Compose operational incident worker environment", () => {
  for (const file of ["docker-compose.yml", "docker-compose.dev.yml"]) {
    it(`${file} wires auto-sync email context and tuning`, () => {
      const block = serviceBlock(file, "worker-auto-sync");
      for (const key of autoSyncVariables) {
        assert.match(block, new RegExp(`\\b${key}[:=]`), key);
      }
    });

    it(`${file} wires the delivery incident email cap`, () => {
      assert.match(
        serviceBlock(file, "worker-delivery"),
        /\bOP_NOTIFICATION_EMAIL_DAILY_CAP[:=]/,
      );
    });
  }
});
