"use strict";

// Independent disposable PostgreSQL + real Vault. Never loads .env, never
// connects to an old lab, and removes only containers carrying this run's label.
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const provider = process.argv.includes("--openbao") ? "openbao-kv2" : "vault-kv2";
const keepLab = process.argv.includes("--keep-lab");
const nonce = crypto.randomBytes(8).toString("hex");
const output = path.join(root, "qualification-results", `cleanup-completion-${nonce}`);
fs.mkdirSync(output, { recursive: true });

function fixtureState(container) {
  const result = spawnSync("docker", ["inspect", "--format", "{{json .State}}", container],
    { encoding: "utf8", windowsHide: true, timeout: 10000 });
  if (result.status !== 0) return { container, inspected: false };
  const state = JSON.parse(result.stdout);
  return { container, status: state.Status, oomKilled: state.OOMKilled, exitCode: state.ExitCode, error: state.Error };
}

function run(command, args, { env = process.env, log, timeout = 180000 } = {}) {
  const result = spawnSync(command, args, { cwd: root, env, encoding: "utf8", windowsHide: true,
    timeout, maxBuffer: 32 * 1024 * 1024 });
  if (log) fs.writeFileSync(path.join(output, log), (result.stdout || "") + (result.stderr || ""));
  if (result.status !== 0 || result.error) {
    const error = new Error(`${command} failed; ${log ? `diagnostics: ${path.join(output, log)}` : "owned fixture command failed"}`);
    error.exitCode = result.status;
    throw error;
  }
  return result.stdout;
}

async function main() {
  const containers = [];
  const summary = { schemaVersion: 1, scope: "cleanup-completion-functional-support", nativeAgentQualified: false,
    provider, candidateSha: run("git", ["rev-parse", "HEAD"]).trim(), dirty: Boolean(run("git", ["status", "--porcelain"]).trim()),
    startedAt: new Date().toISOString(), status: "running", logs: ["migration.log", "tests.log"] };
  try {
    const pg = `tt-cleanup-pg-${nonce}`, vault = `tt-cleanup-vault-${nonce}`;
    const database = `distribution_lifecycle_${nonce}_test`;
    for (const [name, args] of [
      [pg, ["--memory=512m", "-p", "127.0.0.1::5432", "-e", "POSTGRES_USER=certops_fixture", "-e",
        "POSTGRES_PASSWORD=synthetic-completion-only", "-e", `POSTGRES_DB=${database}`, "postgres:16-alpine"]],
      // Vault 1.21 dev was OOM-killed at 384m on GitHub-hosted runners before health returned.
      [vault, ["--memory=1024m", "-p", "127.0.0.1::8200", "-e", `${provider === "openbao-kv2" ? "BAO" : "VAULT"}_DEV_ROOT_TOKEN_ID=isolated-completion-fixture-only`,
        provider === "openbao-kv2" ? "openbao/openbao:2.4.1" : "hashicorp/vault:1.21", "server", "-dev", "-dev-listen-address=0.0.0.0:8200"]],
    ]) {
      run("docker", ["run", "-d", "--name", name, "--label", `tokentimer.cleanup-completion-owner=${nonce}`, ...args]);
      containers.push(name);
    }
    const port = name => {
      const result = run("docker", ["port", name]).match(/-> 127\.0\.0\.1:(\d+)/)?.[1];
      if (!result) throw new Error("Owned loopback port unavailable");
      return result;
    };
    const pgPort = port(pg), vaultAddress = `http://127.0.0.1:${port(vault)}`;
    let ready = false;
    const deadline = Date.now() + 60000;
    while (Date.now() < deadline) {
      const pgReady = spawnSync("docker", ["exec", pg, "pg_isready", "-h", "127.0.0.1", "-U", "certops_fixture"],
        { windowsHide: true, stdio: "ignore", timeout: 10000 }).status === 0;
      let vaultReady = false;
      try { vaultReady = (await fetch(`${vaultAddress}/v1/sys/health`, { signal: AbortSignal.timeout(2000) })).status === 200; } catch { /* startup */ }
      if (pgReady && vaultReady) { ready = true; break; }
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    if (!ready) {
      const states = containers.map(fixtureState);
      const detail = states.map(state => state.inspected === false
        ? `${state.container}:uninspected`
        : `${state.container}:${state.status}${state.oomKilled ? ",oom" : ""}`).join("; ");
      const error = new Error(`Owned PostgreSQL/Vault startup failed (${detail})`);
      error.fixtureStates = states;
      throw error;
    }
    const env = { ...process.env, NODE_ENV: "test", CERTOPS_ENABLED: "true", CERTOPS_MATERIAL_CLEANUP_ENABLED: "true",
      DB_HOST: "127.0.0.1", DB_PORT: pgPort, DB_NAME: database, DB_USER: "certops_fixture", DB_PASSWORD: "synthetic-completion-only",
      CERTOPS_SIGNING_ENCRYPTION_KEY: crypto.randomBytes(32).toString("hex"), CERTOPS_REGISTRATION_ENCRYPTION_KEY: crypto.randomBytes(32).toString("hex"),
      TT_CLEANUP_COMPLETION_DISPOSABLE: "1", TT_CLEANUP_VAULT_ADDRESS: vaultAddress, TT_CLEANUP_PROVIDER: provider, TT_CLEANUP_EVIDENCE_DIR: output };
    if (keepLab) {
      const config = path.join(root, ".tmp", `cleanup-ui-${nonce}`, "private.json");
      require("../packages/agent/src/material-store/index").writeProtectedJson(config, {
        owner: nonce, containers: [...containers], env: Object.fromEntries(Object.entries(env).filter(([key]) =>
          key.startsWith("DB_") || key.startsWith("CERTOPS_") || key.startsWith("TT_CLEANUP_") || key === "NODE_ENV")), output,
      });
      summary.retainedLabConfig = config;
    }
    run(process.execPath, ["apps/api/migrations/migrate.js"], { env, log: "migration.log" });
    const tests = ["tests/postgres/distribution-cleanup.test.js", "tests/postgres/distribution-cleanup-provider.test.js"];
    summary.tests = tests;
    summary.command = `node --test --test-force-exit --test-concurrency=1 ${tests.join(" ")}`;
    const log = run(process.execPath, ["--test", "--test-force-exit", "--test-concurrency=1", ...tests], { env, log: "tests.log", timeout: 300000 });
    summary.status = "passed";
    const counts = {};
    for (const key of ["tests", "pass", "fail", "skipped", "cancelled"]) {
      const value = log.match(new RegExp(`(?:ℹ|#) ${key} (\\d+)`))?.[1];
      if (value !== undefined) counts[key] = Number(value);
    }
    summary.counts = counts;
    console.log(log);
  } catch (error) {
    summary.status = "failed";
    summary.failure = error.message;
    // Provider dev-server logs include bootstrap credentials. Export only
    // container state so startup/resource failures are diagnosable safely.
    summary.fixtureStates = error.fixtureStates || containers.map(fixtureState);
    throw error;
  } finally {
    for (const container of [...containers].reverse()) {
      const owner = run("docker", ["inspect", "--format", '{{index .Config.Labels "tokentimer.cleanup-completion-owner"}}', container]).trim();
      if (owner !== nonce) throw new Error("Fixture ownership changed; refusing container removal");
      if (!keepLab) run("docker", ["rm", "--force", "--volumes", container]);
    }
    summary.finishedAt = new Date().toISOString();
    summary.cleanup = keepLab ? "owned-fixtures-retained-for-operator-ui" : "passed";
    fs.writeFileSync(path.join(output, "summary.json"), JSON.stringify(summary, null, 2) + "\n");
    console.log(`Cleanup completion evidence: ${output}`);
  }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
