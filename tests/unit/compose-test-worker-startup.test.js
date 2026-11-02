"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "../..");

function serviceBlock(name) {
  const lines = readFileSync(path.join(root, "deploy/compose/docker-compose.test.yml"), "utf8").split(/\r?\n/);
  const start = lines.indexOf(`  ${name}:`);
  assert.ok(start >= 0, `Missing test service ${name}`);
  const next = lines.findIndex((line, index) => index > start && /^  [\w-]+:/.test(line));
  return lines.slice(start, next < 0 ? undefined : next).join("\n");
}

for (const [service, entrypoint] of [
  ["worker-endpoint-check", "endpoint-check-worker.js"],
  ["worker-delivery", "delivery-worker.js"],
  ["worker-auto-sync", "auto-sync-worker.js"],
]) {
  test(`${service} waits for migrated API health before its one-shot run`, () => {
    const block = serviceBlock(service);
    assert.match(block, /^      api:\n        condition: service_healthy$/m);
    assert.ok(block.includes(`command: ["node", "src/${entrypoint}"]`));
    assert.match(block, /^    restart: "no"$/m);
  });
}

test("the API health barrier cannot pass before migrations finish", () => {
  const api = serviceBlock("api");
  assert.ok(api.includes('dockerfile: apps/api/Dockerfile.dev'));
  assert.ok(api.includes('command: ["node", "coverage-bootstrap.cjs"]'));
  const dockerfile = readFileSync(path.join(root, "apps/api/Dockerfile.dev"), "utf8");
  assert.match(dockerfile, /HEALTHCHECK[\s\S]*http.*localhost:4000\/[\s\S]*res\.statusCode === 200/);
  const bootstrap = readFileSync(path.join(root, "apps/api/coverage-bootstrap.cjs"), "utf8");
  const bootstrapMigration = bootstrap.indexOf("await runMigrations();");
  assert.ok(bootstrapMigration >= 0 && bootstrapMigration < bootstrap.indexOf('require("./index")'));
  const source = readFileSync(path.join(root, "apps/api/index.js"), "utf8");
  const start = source.indexOf("async function main()");
  const migration = source.indexOf("await runMigrations();", start);
  const listen = source.indexOf("app.listen(", start);
  assert.ok(start >= 0 && migration > start && listen > migration);
});
