"use strict";
const fs = require("node:fs"),
  path = require("node:path"),
  assert = require("node:assert/strict"),
  { spawnSync } = require("node:child_process");
function audit(project, output) {
  assert.match(project || "", /^tt-wildcard-ux-(?:ci|qual)-[a-z0-9-]+$/);
  const run = (args, input) => {
    const r = spawnSync("docker", args, {
      input,
      encoding: "utf8",
      timeout: 30000,
      windowsHide: true,
      maxBuffer: 32 * 1024 * 1024,
    });
    assert.equal(r.status, 0, "Owned privacy audit subprocess failed");
    return r.stdout;
  };
  for (const service of ["postgres", "api", "worker", "customers"]) {
    const name = project + "-" + service + "-1";
    assert.equal(
      run([
        "inspect",
        "--format",
        '{{index .Config.Labels "com.docker.compose.project"}}',
        name,
      ]).trim(),
      project,
    );
  }
  const database = run([
    "exec",
    project + "-postgres-1",
    "pg_dump",
    "-U",
    "wildcard_ux_lab",
    "-d",
    "wildcard_ux_lab",
    "--data-only",
    "--no-owner",
    "--no-privileges",
  ]);
  let logs = "";
  for (const service of ["api", "worker"]) {
    const r = spawnSync("docker", ["logs", project + "-" + service + "-1"], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 30000,
      maxBuffer: 16 * 1024 * 1024,
    });
    assert.equal(r.status, 0);
    logs += (r.stdout || "") + (r.stderr || "");
  }
  const result = JSON.parse(
    run(
      [
        "exec",
        "-i",
        project + "-customers-1",
        "node",
        "/repo/tests/wildcard-vault/ux-lab/privacy-audit.cjs",
      ],
      database + logs,
    ),
  );
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n");
  return result;
}
if (require.main === module) {
  try {
    console.log(JSON.stringify(audit(process.argv[2], process.argv[3])));
  } catch {
    console.error("Owned distribution zero-custody audit failed");
    process.exitCode = 1;
  }
}
module.exports = { audit };
