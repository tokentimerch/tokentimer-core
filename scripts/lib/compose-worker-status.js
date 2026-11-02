"use strict";

const { spawnSync } = require("node:child_process");

const WORKER_SERVICES = [
  "worker-endpoint-check",
  "worker-auto-sync",
  "worker-delivery",
];

function assertComposeWorkerStates({
  composeFile,
  cwd,
  env,
  run = spawnSync,
  workerServices = WORKER_SERVICES,
}) {
  if (!workerServices.length) return;
  const options = { cwd, env, encoding: "utf8", timeout: 15000 };
  const listed = run("docker", ["compose", "-f", composeFile, "ps", "--all", "--quiet"], options);
  if (listed.status !== 0) throw new Error("Cannot inspect Compose worker status: service listing failed");
  const ids = String(listed.stdout || "").trim().split(/\s+/).filter(Boolean);
  if (!ids.length) return;
  if (ids.some((id) => !/^[a-f0-9]{12,64}$/i.test(id))) {
    throw new Error("Cannot inspect Compose worker status: invalid container ID");
  }
  const inspected = run("docker", ["inspect", ...ids], options);
  if (inspected.status !== 0) throw new Error("Cannot inspect Compose worker status: container inspection failed");
  const containers = JSON.parse(String(inspected.stdout || ""));
  if (!Array.isArray(containers)) throw new Error("Cannot inspect Compose worker status: invalid inspection result");
  const failures = [];
  for (const container of containers) {
    if (!ids.some((id) => String(container.Id || "").startsWith(id))) continue;
    const service = container.Config?.Labels?.["com.docker.compose.service"];
    if (!workerServices.includes(service)) continue;
    const state = container.State;
    if (!state) throw new Error(`Cannot inspect Compose worker status: missing state for ${service}`);
    if (state.OOMKilled || state.Dead || state.Status === "dead" ||
        (state.Status === "exited" && Number(state.ExitCode) !== 0)) {
      failures.push(`${service}: ${state.Status}, exit ${state.ExitCode}, OOM ${Boolean(state.OOMKilled)}`);
    }
  }
  if (failures.length) throw new Error("Compose worker failure: " + failures.join("; "));
}

module.exports = { assertComposeWorkerStates };

if (require.main === module) {
  try {
    if (!process.argv[2]) throw new Error("Usage: node compose-worker-status.js <compose-file>");
    assertComposeWorkerStates({ composeFile: process.argv[2], cwd: process.cwd(), env: process.env });
  } catch (error) {
    console.error(error.message || error);
    process.exitCode = 1;
  }
}
