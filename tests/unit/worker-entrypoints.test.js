"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.join(__dirname, "..", "..");

function readRepoFile(...parts) {
  return fs.readFileSync(path.join(repoRoot, ...parts), "utf8");
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
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
    assert.strictEqual(
      workerPackage.scripts["start:certops"],
      "node src/certops-worker.js",
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
      "certops",
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

  it("keeps Compose worker cron defaults aligned with Helm CronJobs", () => {
    const compose = readRepoFile("deploy", "compose", "docker-compose.yml");
    const composeDev = readRepoFile(
      "deploy",
      "compose",
      "docker-compose.dev.yml",
    );
    const expectedCrons = {
      WORKER_DISCOVERY_CRON: "*/5 * * * *",
      WORKER_DELIVERY_CRON: "1/5 * * * *",
      WORKER_WEEKLY_DIGEST_CRON: "0 9 * * 1",
      WORKER_AUTO_SYNC_CRON: "*/1 * * * *",
      WORKER_ENDPOINT_CHECK_CRON: "*/1 * * * *",
      WORKER_CERTOPS_CRON: "*/1 * * * *",
    };

    for (const [variable, cron] of Object.entries(expectedCrons)) {
      const escapedCron = escapeRegex(cron);
      assert.match(
        compose,
        new RegExp(`${variable}: "\\$\\{${variable}:-${escapedCron}\\}"`),
      );
      assert.match(
        composeDev,
        new RegExp(`"${variable}=\\$\\{${variable}:-${escapedCron}\\}"`),
      );
    }
  });

  it("calls the shared NODE_USE_ENV_PROXY warning from every entrypoint Helm's CronJobs invoke directly", () => {
    // Helm's CronJobs run these six scripts directly (see
    // deploy/helm/templates/cronjob-*.yaml `command:`), never through
    // runner.js, so the warning must be wired into each one individually
    // rather than relying on a single check inside runner.js.
    const entrypoints = [
      "queue-manager.js",
      "delivery-worker.js",
      "weekly-digest-runner.js",
      "auto-sync-worker.js",
      "endpoint-check-worker.js",
      "certops-worker.js",
    ];

    for (const file of entrypoints) {
      const source = readRepoFile("apps", "worker", "src", file);
      assert.match(
        source,
        /from ["']\.\/proxy-compat-check\.js["']/,
        `${file} must import the shared proxy-compat-check helper`,
      );
      assert.match(
        source,
        /warnIfNodeUseEnvProxyUnsupported\(\)/,
        `${file} must call warnIfNodeUseEnvProxyUnsupported()`,
      );
    }

    const runner = readRepoFile("apps", "worker", "src", "runner.js");
    assert.match(runner, /from ["']\.\/proxy-compat-check\.js["']/);
    assert.match(runner, /warnIfNodeUseEnvProxyUnsupported\(\)/);
  });

  it("keeps every Helm worker CronJob command pointed at one of the six standalone entrypoints", () => {
    const cronjobFiles = {
      "cronjob-discovery.yaml": "queue-manager.js",
      "cronjob-delivery.yaml": "delivery-worker.js",
      "cronjob-weekly-digest.yaml": "weekly-digest-runner.js",
      "cronjob-auto-sync.yaml": "auto-sync-worker.js",
      "cronjob-endpoint-check.yaml": "endpoint-check-worker.js",
      "cronjob-certops.yaml": "certops-worker.js",
    };

    for (const [template, entrypoint] of Object.entries(cronjobFiles)) {
      const source = readRepoFile(
        "deploy",
        "helm",
        "templates",
        template,
      );
      assert.match(
        source,
        new RegExp(
          `command:\\s*\\["node",\\s*"apps/worker/src/${escapeRegex(entrypoint)}"\\]`,
        ),
        `${template} must invoke ${entrypoint} directly (not runner.js)`,
      );
    }
  });
});
