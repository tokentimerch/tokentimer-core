#!/usr/bin/env node

// Boot each Helm CronJob entrypoint inside a built worker image.
// docker build and unit tests never load this sparse tree; v0.16.0 shipped
// Cannot find module for API files the image did not COPY. Postgres or
// metrics refusal after import is fine. MODULE_NOT_FOUND is not.

const { spawnSync } = require("node:child_process");

const BOOT_TIMEOUT_MS = 45_000;

// Keep in lockstep with tests/unit/worker-entrypoints.test.js and
// deploy/helm/templates/cronjob-*.yaml `command:`.
const WORKER_IMAGE_ENTRYPOINTS = [
  "apps/worker/src/queue-manager.js",
  "apps/worker/src/delivery-worker.js",
  "apps/worker/src/weekly-digest-runner.js",
  "apps/worker/src/auto-sync-worker.js",
  "apps/worker/src/endpoint-check-worker.js",
  "apps/worker/src/certops-worker.js",
];

const IMAGE_REF_PATTERN = /^[A-Za-z0-9_.:/-]+$/;

function fail(message) {
  console.error(`boot-worker-image-entrypoints: ${message}`);
  process.exit(1);
}

function combinedOutput(result) {
  return `${result.stdout || ""}${result.stderr || ""}`;
}

function bootEntrypoint(image, entry) {
  const result = spawnSync(
    "docker",
    ["run", "--rm", "--entrypoint", "node", image, entry],
    {
      encoding: "utf8",
      timeout: BOOT_TIMEOUT_MS,
      maxBuffer: 2 * 1024 * 1024,
    },
  );
  const output = combinedOutput(result);
  if (output) {
    process.stdout.write(output.endsWith("\n") ? output : `${output}\n`);
  }

  if (/Cannot find module|MODULE_NOT_FOUND/i.test(output)) {
    fail(`entrypoint ${entry} failed import in ${image}`);
  }
  if (result.error && result.error.code === "ETIMEDOUT") {
    fail(`entrypoint ${entry} timed out after ${BOOT_TIMEOUT_MS}ms in ${image}`);
  }
  if (result.error && result.error.code === "ENOENT") {
    fail("docker is not on PATH");
  }
  if (result.error) {
    fail(`entrypoint ${entry} failed to start in ${image}: ${result.error.message}`);
  }
}

function main(argv = process.argv.slice(2)) {
  const image = argv[0];
  if (!image) {
    fail("usage: node scripts/boot-worker-image-entrypoints.js <image>");
  }
  if (!IMAGE_REF_PATTERN.test(image)) {
    fail(`invalid image ref: ${image}`);
  }

  for (const entry of WORKER_IMAGE_ENTRYPOINTS) {
    console.log(`boot-worker-image-entrypoints: ${image} ${entry}`);
    bootEntrypoint(image, entry);
  }
  console.log(
    `boot-worker-image-entrypoints: ok (${WORKER_IMAGE_ENTRYPOINTS.length} entrypoints)`,
  );
}

if (require.main === module) {
  main();
}

module.exports = {
  WORKER_IMAGE_ENTRYPOINTS,
  BOOT_TIMEOUT_MS,
  main,
};
