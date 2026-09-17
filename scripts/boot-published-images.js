#!/usr/bin/env node

// Run the published start path of each image CI already builds.
// docker build and Grype never execute it. Fail on MODULE_NOT_FOUND.
// Config/DB refusal after import is fine. Dashboard is nginx -t, not Node.

const { spawnSync } = require("node:child_process");

const BOOT_TIMEOUT_MS = 45_000;
const API_BOOT_TIMEOUT_MS = 25_000;

const IMAGE_REF_PATTERN = /^[A-Za-z0-9_.:/-]+$/;
const MISSING_MODULE_RE = /Cannot find module|MODULE_NOT_FOUND/i;
const API_IMPORTED_RE =
  /Waiting for database|Database connection attempt|Startup configuration error|Startup failed/;

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

const ROLES = ["api", "dashboard", "worker", "controller"];

function fail(message) {
  console.error(`boot-published-images: ${message}`);
  process.exit(1);
}

function assertImageRef(image) {
  if (!image) {
    fail(
      "usage: node scripts/boot-published-images.js <api|dashboard|worker|controller> <image>",
    );
  }
  if (!IMAGE_REF_PATTERN.test(image)) {
    fail(`invalid image ref: ${image}`);
  }
}

function combinedOutput(result) {
  return `${result.stdout || ""}${result.stderr || ""}`;
}

function runContainer(image, argsAfterImage, timeoutMs = BOOT_TIMEOUT_MS) {
  const result = spawnSync("docker", ["run", "--rm", ...argsAfterImage], {
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: 2 * 1024 * 1024,
  });
  const output = combinedOutput(result);
  if (output) {
    process.stdout.write(output.endsWith("\n") ? output : `${output}\n`);
  }
  if (result.error && result.error.code === "ENOENT") {
    fail("docker is not on PATH");
  }
  return { result, output };
}

function rejectMissingModule(output, label, image) {
  if (MISSING_MODULE_RE.test(output)) {
    fail(`${label} failed import in ${image}`);
  }
}

function bootWorker(image) {
  assertImageRef(image);
  for (const entry of WORKER_IMAGE_ENTRYPOINTS) {
    console.log(`boot-published-images: worker ${image} ${entry}`);
    const { result, output } = runContainer(image, [
      "--entrypoint",
      "node",
      image,
      entry,
    ]);
    rejectMissingModule(output, `entrypoint ${entry}`, image);
    if (result.error && result.error.code === "ETIMEDOUT") {
      fail(
        `entrypoint ${entry} timed out after ${BOOT_TIMEOUT_MS}ms in ${image}`,
      );
    }
    if (result.error) {
      fail(
        `entrypoint ${entry} failed to start in ${image}: ${result.error.message}`,
      );
    }
  }
  console.log(
    `boot-published-images: worker ok (${WORKER_IMAGE_ENTRYPOINTS.length} entrypoints)`,
  );
}

function bootApi(image) {
  assertImageRef(image);
  console.log(`boot-published-images: api ${image} apps/api/index.js`);
  const { result, output } = runContainer(
    image,
    ["--entrypoint", "node", image, "apps/api/index.js"],
    API_BOOT_TIMEOUT_MS,
  );
  rejectMissingModule(output, "API", image);
  if (result.error && result.error.code === "ETIMEDOUT") {
    if (!API_IMPORTED_RE.test(output)) {
      fail(
        `API timed out after ${API_BOOT_TIMEOUT_MS}ms before import completed in ${image}`,
      );
    }
    console.log(
      "boot-published-images: api ok (import reached database wait; process stopped)",
    );
    return;
  }
  if (result.error) {
    fail(`API failed to start in ${image}: ${result.error.message}`);
  }
  if (!API_IMPORTED_RE.test(output)) {
    fail(
      `API exited ${result.status} before database wait or config check in ${image}`,
    );
  }
  console.log("boot-published-images: api ok");
}

function bootDashboard(image) {
  assertImageRef(image);
  console.log(`boot-published-images: dashboard ${image} nginx -t`);
  const { result, output } = runContainer(image, [
    "--entrypoint",
    "sh",
    image,
    "-lc",
    "nginx -t && test -f /usr/share/nginx/html/index.html && test -x /docker-entrypoint.sh",
  ]);
  rejectMissingModule(output, "dashboard", image);
  if (result.error && result.error.code === "ETIMEDOUT") {
    fail(`dashboard timed out in ${image}`);
  }
  if (result.error) {
    fail(`dashboard failed to start in ${image}: ${result.error.message}`);
  }
  if (result.status !== 0) {
    fail(`dashboard nginx -t or asset check failed in ${image}`);
  }
  console.log("boot-published-images: dashboard ok");
}

function bootController(image) {
  assertImageRef(image);
  // require.main is not the controller file, so runController() does not start.
  // The require graph still loads the sparse API COPY (parser, limits, secrets).
  console.log(`boot-published-images: controller ${image} src/index.js`);
  const { result, output } = runContainer(image, [
    "--entrypoint",
    "node",
    image,
    "-e",
    "require('./src/index.js'); console.log('import-ok')",
  ]);
  rejectMissingModule(output, "controller", image);
  if (result.error && result.error.code === "ETIMEDOUT") {
    fail(`controller timed out in ${image}`);
  }
  if (result.error) {
    fail(`controller failed to start in ${image}: ${result.error.message}`);
  }
  if (result.status !== 0 || !/import-ok/.test(output)) {
    fail(`controller import did not complete in ${image}`);
  }
  console.log("boot-published-images: controller ok");
}

const BOOTERS = {
  api: bootApi,
  dashboard: bootDashboard,
  worker: bootWorker,
  controller: bootController,
};

function main(argv = process.argv.slice(2)) {
  const role = argv[0];
  const image = argv[1];
  if (!ROLES.includes(role)) {
    fail(
      "usage: node scripts/boot-published-images.js <api|dashboard|worker|controller> <image>",
    );
  }
  BOOTERS[role](image);
}

if (require.main === module) {
  main();
}

module.exports = {
  API_BOOT_TIMEOUT_MS,
  BOOT_TIMEOUT_MS,
  ROLES,
  WORKER_IMAGE_ENTRYPOINTS,
  bootApi,
  bootController,
  bootDashboard,
  bootWorker,
  main,
};
