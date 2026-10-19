"use strict";
// Reuse the established adapter tests, including both opt-in real Vault tests,
// without publishing a port or attaching to an existing audit network.
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { spawnSync } = require("node:child_process");
const { verify } = require("./certops-stack-report");
const root = path.resolve(__dirname, ".."),
  nonce = crypto.randomBytes(12).toString("hex"),
  name = "tt-certops-distribution-vault-" + nonce;
const output = path.join(
  root,
  "qualification-results",
  "distribution-vault-" + nonce,
);
function run(args, options = {}) {
  const r = spawnSync("docker", args, {
    cwd: root,
    encoding: "utf8",
    windowsHide: true,
    timeout: 180000,
    maxBuffer: 16 * 1024 * 1024,
    ...options,
  });
  if (r.status !== 0 || r.error)
    throw new Error("Owned Vault qualification command failed");
  return r.stdout;
}
async function main() {
  fs.mkdirSync(output, { recursive: true });
  let created = false;
  const summary = {
    schemaVersion: 1,
    scope: "distribution-functional-support",
    kind: "vault",
    qualificationStatus: "not-qualified",
    startedAt: new Date().toISOString(),
    fixtureSources: require("./certops-distribution-functional-summary").sourceInventory("vault"),
    tests: [],
    status: "failed",
    evidenceLevel: "integration",
    nativeAgentQualified: false,
  };
  try {
    const candidate = spawnSync("git", ["rev-parse", "HEAD"], {
      cwd: root,
      encoding: "utf8",
    });
    if (candidate.status !== 0)
      throw new Error("Candidate identity unavailable");
    summary.candidateSha = candidate.stdout.trim();
    let image = process.env.TT_CERTOPS_DISTRIBUTION_FIXTURE_IMAGE;
    if (!image) {
      image = name + "-fixture";
      run([
        "build",
        "-t",
        image,
        "-f",
        "tests/wildcard-vault/Dockerfile.fixture",
        "tests/wildcard-vault",
      ]);
    }
    run([
      "run",
      "-d",
      "--name",
      name,
      "--label",
      "tokentimer.qualification-owner=" + nonce,
      "--cpus=0.5",
      "--memory=384m",
      "-e",
      "VAULT_DEV_ROOT_TOKEN_ID=isolated-vault-fixture-only",
      "hashicorp/vault:1.21",
      "server",
      "-dev",
      "-dev-listen-address=0.0.0.0:58200",
    ]);
    created = true;
    let ready = false;
    for (let i = 0; i < 60; i++) {
      const probe = spawnSync(
        "docker",
        [
          "exec",
          "-e",
          "VAULT_ADDR=http://127.0.0.1:58200",
          name,
          "vault",
          "status",
        ],
        { encoding: "utf8", windowsHide: true, timeout: 10000 },
      );
      if (probe.status === 0) {
        ready = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    if (!ready) throw new Error("Owned Vault never became ready");
    const file = "packages/agent/src/material-store/material-store.test.js",
      report =
        "qualification-results/" + path.basename(output) + "/adapter.jsonl";
    // Only this report subdirectory is writable. Customer fixture keys live in
    // the disposable process's /tmp, never in the mounted repository.
    run([
      "run",
      "--rm",
      "--name",
      name + "-tests",
      "--cpus=1",
      "--memory=512m",
      "--network",
      "container:" + name,
      "--mount",
      "type=bind,source=" + root + ",target=/repo,readonly",
      "--mount",
      "type=bind,source=" +
        output +
        ",target=/repo/qualification-results/" +
        path.basename(output),
      "--workdir",
      "/repo",
      "-e",
      "TT_WILDCARD_VAULT_REAL=1",
      "-e",
      "GITHUB_SHA=" + summary.candidateSha,
      "-e",
      "GITHUB_ACTIONS=" + (process.env.GITHUB_ACTIONS === "true" ? "true" : "false"),
      "-e",
      "CERTOPS_REPORT_SCOPE=distribution-vault-adapter",
      image,
      "node",
      "--test",
      "--test-concurrency=1",
      "--test-reporter=./scripts/certops-stack-reporter.js",
      "--test-reporter-destination=" + report,
      file,
    ]);
    const slot =
      require("../docs/certops/qualification-suites.json").slots.find(
        (s) => s.id === "distribution-vault-adapter",
      );
    verify(
      fs.readFileSync(path.join(output, "adapter.jsonl"), "utf8"),
      slot.requiredTests,
      path.basename(file),
      slot.suite,
      summary.candidateSha,
    );
    summary.tests.push({suite:"distribution-vault-adapter",status:"passed",report:"adapter.jsonl"});
    summary.status = "passed";
    console.log(
      "PASS real Vault adapter/CAS/ACL and fault tests; native release not qualified",
    );
  } finally {
    if (created) {
      const owner = run([
        "inspect",
        "--format",
        '{{index .Config.Labels "tokentimer.qualification-owner"}}',
        name,
      ]).trim();
      if (owner !== nonce)
        throw new Error("Vault ownership changed; cleanup refused");
      run(["rm", "-f", name]);
      summary.cleanup = "passed";
    }
    summary.finishedAt = new Date().toISOString();
    fs.writeFileSync(
      path.join(output, "summary.json"),
      JSON.stringify(summary, null, 2) + "\n",
    );
    console.log("Vault evidence: " + output);
  }
}
if (require.main === module)
  main().catch(() => {
    console.error(
      "Owned Vault qualification failed; inspect its bounded execution report",
    );
    process.exitCode = 1;
  });
