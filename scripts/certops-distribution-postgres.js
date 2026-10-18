"use strict";
// Disposable server controller. No inherited DB endpoint, no .env loading, no
// fixed project name, and cleanup targets only the container created here.
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { verify } = require("./certops-stack-report");
const root = path.resolve(__dirname, ".."),
  nonce = crypto.randomBytes(16).toString("hex"),
  name = "tt-certops-distribution-pg-" + nonce;
const output = path.join(
  root,
  "qualification-results",
  "distribution-postgres-" + nonce,
);
const tests = [
  ["postgres", "wildcard_candidate"],
  ["pr329-review", "pr329_review"],
  ["transfer", "pr329_final"],
];
function run(cmd, args, env, log) {
  const r = spawnSync(cmd, args, {
    cwd: root,
    env: env || process.env,
    encoding: "utf8",
    windowsHide: true,
    timeout: 180000,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (log)
    fs.writeFileSync(log, (r.stdout || "") + (r.stderr || ""), { mode: 0o600 });
  if (r.error || r.status !== 0)
    throw new Error(
      "Distribution qualification subprocess failed: " +
        cmd +
        " (inspect local diagnostic log)",
    );
  return r.stdout;
}
async function main() {
  fs.mkdirSync(output, { recursive: true });
  const summary = {
    schemaVersion: 1,
    scope: "distribution-functional-support",
    kind: "postgres",
    qualificationStatus: "not-qualified",
    startedAt: new Date().toISOString(),
    fixtureSources: require("./certops-distribution-functional-summary").sourceInventory("postgres"),
    candidateSha: run("git", ["rev-parse", "HEAD"]).trim(),
    evidenceLevel: "integration",
    nativeAgentQualified: false,
    tests: [],
    status: "running",
  };
  let created = false;
  try {
    run("docker", [
      "run",
      "-d",
      "--name",
      name,
      "--label",
      "tokentimer.qualification-owner=" + nonce,
      "--cpus=0.5",
      "--memory=256m",
      "-p",
      "127.0.0.1::5432",
      "-e",
      "POSTGRES_USER=distribution_qualification",
      "-e",
      "POSTGRES_PASSWORD=synthetic-disposable-only",
      "-e",
      "POSTGRES_DB=postgres",
      "postgres:17-alpine",
    ]);
    created = true;
    const port = run("docker", ["port", name, "5432/tcp"])
      .trim()
      .match(/^127\.0\.0\.1:([0-9]+)$/)?.[1];
    if (!port) throw new Error("Owned loopback PostgreSQL port unavailable");
    let ready = false;
    for (let i = 0; i < 60; i++) {
      const r = spawnSync(
        "docker",
        ["exec", name, "pg_isready", "-U", "distribution_qualification"],
        { encoding: "utf8", windowsHide: true, timeout: 10000 },
      );
      if (r.status === 0) {
        ready = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    if (!ready) throw new Error("Owned PostgreSQL did not become ready");
    for (const [suite, prefix] of tests) {
      const database = prefix + "_qualification_" + nonce;
      run("docker", [
        "exec",
        name,
        "createdb",
        "-U",
        "distribution_qualification",
        database,
      ]);
      const env = {
        ...process.env,
        NODE_ENV: "test",
        CERTOPS_ENABLED: "true",
        DB_HOST: "127.0.0.1",
        DB_PORT: port,
        DB_NAME: database,
        DB_USER: "distribution_qualification",
        DB_PASSWORD: "synthetic-disposable-only",
        TT_CERTOPS_DISTRIBUTION_DISPOSABLE: "1",
        TT_CERTOPS_DISTRIBUTION_DB_PORT: port,
        GITHUB_SHA: summary.candidateSha,
        CERTOPS_REPORT_SCOPE: "distribution-postgres-" + suite,
      };
      // A fresh key belongs solely to this server/database. Never reuse audit keys.
      env.CERTOPS_SIGNING_ENCRYPTION_KEY = crypto
        .randomBytes(32)
        .toString("hex");
      env.CERTOPS_REGISTRATION_ENCRYPTION_KEY = crypto
        .randomBytes(32)
        .toString("hex");
      delete env.TT_WILDCARD_API_ROOT;
      const file = "tests/wildcard-vault/" + suite + ".test.cjs";
      run(
        process.execPath,
        ["apps/api/migrations/migrate.js"],
        env,
        path.join(output, suite + "-migration.log"),
      );
      const report = path.join(output, suite + ".jsonl");
      run(
        process.execPath,
        [
          "--test",
          "--test-force-exit",
          "--test-concurrency=1",
          "--test-reporter=./scripts/certops-stack-reporter.js",
          "--test-reporter-destination=" + report,
          "--test-reporter=spec",
          "--test-reporter-destination=" +
            path.join(output, suite + "-local-only.log"),
          file,
        ],
        env,
        path.join(output, suite + "-execution.log"),
      );
      const slot =
        require("../docs/certops/qualification-suites.json").slots.find(
          (s) => s.id === "distribution-postgres-" + suite,
        );
      verify(
        fs.readFileSync(report, "utf8"),
        slot.requiredTests,
        path.basename(file),
        slot.suite,
        summary.candidateSha,
      );
      summary.tests.push({
        suite: "distribution-postgres-" + suite,
        status: "passed",
        report: path.basename(report),
      });
      console.log("PASS distribution-postgres-" + suite);
    }
    summary.status = "passed";
  } catch (error) {
    summary.status = "failed";
    throw error;
  } finally {
    if (created) {
      const owner = run("docker", [
        "inspect",
        "--format",
        '{{index .Config.Labels "tokentimer.qualification-owner"}}',
        name,
      ]).trim();
      if (owner !== nonce)
        throw new Error("PostgreSQL ownership changed; refusing cleanup");
      run("docker", ["rm", "-f", name]);
      summary.cleanup = "passed";
    }
    summary.finishedAt = new Date().toISOString();
    fs.writeFileSync(
      path.join(output, "summary.json"),
      JSON.stringify(summary, null, 2) + "\n",
    );
    console.log("Distribution PostgreSQL evidence: " + output);
  }
}
if (require.main === module)
  main().catch((e) => {
    console.error(e.message);
    process.exitCode = 1;
  });
module.exports = { tests };
