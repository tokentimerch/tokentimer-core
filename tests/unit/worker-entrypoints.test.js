"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.join(__dirname, "..", "..");

function readRepoFile(...parts) {
  return fs.readFileSync(path.join(repoRoot, ...parts), "utf8");
}

describe("worker entrypoints", () => {
  it("keeps package and Docker defaults on the long-running runner", () => {
    const workerPackage = JSON.parse(
      readRepoFile("apps", "worker", "package.json"),
    );
    const dockerfile = readRepoFile("deploy", "compose", "Dockerfile.worker");

    assert.strictEqual(workerPackage.scripts.start, "node src/runner.js all");
    assert.strictEqual(
      workerPackage.scripts["start:discovery"],
      "node src/queue-manager.js",
    );
    assert.match(
      dockerfile,
      /CMD \["node", "apps\/worker\/src\/runner\.js", "all"\]/,
    );
  });

  it("keeps Compose worker services on explicit runner commands", () => {
    const compose = readRepoFile("deploy", "compose", "docker-compose.yml");
    const composeDev = readRepoFile(
      "deploy",
      "compose",
      "docker-compose.dev.yml",
    );
    const workers = [
      "discovery",
      "delivery",
      "weekly-digest",
      "auto-sync",
      "endpoint-check",
    ];

    for (const worker of workers) {
      assert.match(
        compose,
        new RegExp(
          `command: \\["node", "/app/apps/worker/src/runner\\.js", "${worker}"\\]`,
        ),
      );
      assert.match(
        composeDev,
        new RegExp(`command: \\["node", "src/runner\\.js", "${worker}"\\]`),
      );
    }
  });
});
