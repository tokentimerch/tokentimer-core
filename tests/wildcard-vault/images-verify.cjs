"use strict";

// Verify actual production image files and dependency resolution, rather than
// only checking the staging directory or a development/test-runner image.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const core = path.resolve(__dirname, "../..");
const variant = process.argv[2];
assert.ok(["core", "cloud", "enterprise"].includes(variant));
const cloud = variant === "cloud";
const source = cloud ? path.resolve(core, "../tokentimer-cloud") : core;
const apiSource = cloud ? "apps/saas" : "apps/api";
const images = {
  core: [
    "localhost:58600/core-api:20261008",
    "localhost:58600/core-worker:20261008",
  ],
  cloud: [
    "cloud-saas-runtime:wildcard-vault-20261008",
    "cloud-worker-runtime:wildcard-vault-20261008",
  ],
  enterprise: [
    "enterprise-api:wildcard-vault-20261008",
    "enterprise-worker:wildcard-vault-20261008",
  ],
}[variant];
const checks = [];
for (const [index, image] of images.entries()) {
  const worker = index === 1;
  const root = cloud
    ? worker
      ? "/app/saas"
      : "/workspace/apps/saas"
    : "/app/apps/api";
  const contracts = cloud
    ? worker
      ? "/packages/contracts"
      : "/workspace/packages/contracts"
    : "/app/packages/contracts";
  const files = [
    ...[
      "materialDistribution",
      "distributionOperations",
      "agentDispatch",
      "jobApprovals",
      "outbox",
      "issuance",
      "renewalProfile",
      cloud ? "renewalSchedulerSweep" : "renewalScheduler",
    ].map((name) => [
      `${apiSource}/services/certops/${name}.js`,
      `${root}/services/certops/${name}.js`,
    ]),
    [
      "packages/contracts/certops/material-distribution.schema.json",
      `${contracts}/certops/material-distribution.schema.json`,
    ],
    [
      "packages/contracts/certops/validate-material-distribution.cjs",
      `${contracts}/certops/validate-material-distribution.cjs`,
    ],
  ];
  if (cloud)
    files.push(
      ["apps/saas/services/certops/distributionPolicy.js", `${root}/services/certops/distributionPolicy.js`],
      ["apps/saas/services/certops/renewalScheduler.js", `${root}/services/certops/renewalScheduler.js`],
    );
  if (!worker) {
    const scanner = cloud ? "integrations" : "services";
    files.push([
      `${apiSource}/${scanner}/vaultIntegration.js`,
      `${root}/${scanner}/vaultIntegration.js`,
    ]);
    if (cloud)
      files.push([
        "compatibility.manifest.json",
        "/workspace/compatibility.manifest.json",
      ]);
    if (variant === "enterprise")
      files.push([
        "src/license/default-public-key.pem",
        "/app/src/license/default-public-key.pem",
        path.resolve(core, "../tokentimer-enterprise"),
      ]);
  } else {
    files.push(
      cloud
        ? [
            "apps/worker/src/certops-scheduler-placeholder.js",
            "/app/src/certops-scheduler-placeholder.js",
          ]
        : [
            "apps/worker/src/certops-worker.js",
            "/app/apps/worker/src/certops-worker.js",
          ],
    );
  }
  const expected = files.map(([local, remote, sourceRoot = source]) => ({
    remote,
    hash: crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.join(sourceRoot, local)))
      .digest("hex"),
  }));
  const probe = `(async()=>{const fs=require('fs'),crypto=require('crypto');for(const f of ${JSON.stringify(expected)}){if(crypto.createHash('sha256').update(fs.readFileSync(f.remote)).digest('hex')!==f.hash)throw Error('Image source mismatch: '+f.remote);}require(${JSON.stringify(`${root}/services/certops/materialDistribution.js`)});require(${JSON.stringify(`${root}/services/certops/distributionOperations.js`)});require(${JSON.stringify(`${contracts}/certops/validate-material-distribution.cjs`)});await require(${JSON.stringify(`${root}/db/database.js`)}).pool.end();console.log('production-file-and-dependency-check-passed');})().catch(e=>{console.error(e.message);process.exitCode=1;})`;
  const output = execFileSync(
    "docker",
    [
      "run",
      "--rm",
      "--name",
      `tt-wildcard-${variant}-${worker ? "worker" : "api"}-verify-20261008`,
      "--cpus",
      "0.5",
      "--memory",
      "384m",
      "--network",
      "tt-wildcard-vault-20261008_default",
      "--env-file",
      path.join(core, ".scratch/wildcard/runtime.env"),
      "-e",
      `DB_NAME=wildcard_candidate_${variant}_image`,
      "--entrypoint",
      "node",
      image,
      "-e",
      probe,
    ],
    { encoding: "utf8", timeout: 120_000, maxBuffer: 1024 * 1024 },
  );
  assert.match(output, /production-file-and-dependency-check-passed/);
  const id = execFileSync(
    "docker",
    ["image", "inspect", "--format", "{{.Id}}", image],
    { encoding: "utf8" },
  ).trim();
  checks.push({
    image,
    id,
    checkedFiles: files.length,
    dependenciesLoaded: true,
  });
}
console.log(JSON.stringify({ passed: true, variant, checks }));
