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
    it(`${file} exposes lifecycle sweep controls and keeps cleanup opt-in`, () => {
      const worker = serviceBlock(file, "worker-certops");
      for (const key of [
        "CERTOPS_SWEEP_DISTRIBUTION_SCHEDULER_ENABLED",
        "CERTOPS_SWEEP_DISTRIBUTION_SCHEDULER_TIMEOUT_MS",
        "CERTOPS_SWEEP_DISTRIBUTION_MONITORING_ENABLED",
        "CERTOPS_SWEEP_DISTRIBUTION_MONITORING_TIMEOUT_MS",
      ]) assert.match(worker, new RegExp(`\\b${key}[:=]`), key);
      assert.ok(serviceBlock(file, "api").includes("${CERTOPS_MATERIAL_CLEANUP_ENABLED:-false}"));
      assert.match(serviceBlock(file, "worker-delivery"), /\bTWILIO_WHATSAPP_ALERT_CONTENT_SID_DISTRIBUTION[:=]/);
    });
  }
  it("makes the qualified cleanup flag and distribution template configurable in the test stack", () => {
    assert.ok(serviceBlock("docker-compose.test.yml", "api").includes("${CERTOPS_MATERIAL_CLEANUP_ENABLED:-false}"));
    assert.match(serviceBlock("docker-compose.test.yml", "worker-delivery"), /\bTWILIO_WHATSAPP_ALERT_CONTENT_SID_DISTRIBUTION[:=]/);
  });
  for (const file of ["docker-compose.yml", "docker-compose.dev.yml"]) {
    it(`${file} wires auto-sync email context and tuning`, () => {
      const block = serviceBlock(file, "worker-auto-sync");
      for (const key of autoSyncVariables) {
        assert.match(block, new RegExp(`\\b${key}[:=]`), key);
      }
    });

    it(`${file} wires the delivery incident email cap`, () => {
      const block = serviceBlock(file, "worker-delivery");
      assert.match(block, /\bOP_NOTIFICATION_EMAIL_DAILY_CAP[:=]/);
      assert.match(block, /\bALERT_DEGRADED_ATTEMPTS_THRESHOLD[:=]/);
    });
  }

  it("documents the degraded warning threshold", () => {
    assert.match(
      readFileSync(path.join(root, "deploy/compose/.env.example"), "utf8"),
      /# ALERT_DEGRADED_ATTEMPTS_THRESHOLD=5/,
    );
  });
});
