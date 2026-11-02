"use strict";

// Disposable PostgreSQL + real local SMTP sink, native API and Vite dashboard.
// No external mail or Twilio credentials are read from a developer's .env.
const path = require("node:path");
const fs = require("node:fs");
const { spawnSync } = require("node:child_process");
const { spawnCommand, killProcessTree } = require("./process-utils");
const { assertDevPortsAvailable } = require("./check-dev-ports");

const root = path.resolve(__dirname, "..");
const output = path.join(root, "test-results", "recipient-verification");
fs.mkdirSync(output, { recursive: true });
const env = {
  ...process.env,
  NODE_ENV: "development",
  DB_HOST: "127.0.0.1", DB_PORT: "54339", DB_NAME: "recipient_browser_test",
  DB_USER: "tokentimer", DB_PASSWORD: "browser-test-only", DB_SSL: "",
  PGSSLROOTCERT: "", PORT: "44061", HOST: "127.0.0.1",
  APP_URL: "http://localhost:5173", API_URL: "http://localhost:44061",
  PUBLIC_BASE_URL: "http://localhost:44061", VITE_API_URL: "http://localhost:44061",
  SESSION_SECRET: "recipient-browser-test-session-secret",
  RECIPIENT_FINGERPRINT_SECRET: "recipient-browser-test-fingerprint-secret",
  ADMIN_EMAIL: "admin@recipient.test", ADMIN_PASSWORD: "BrowserTest123!", ADMIN_NAME: "Browser Admin",
  SMTP_HOST: "127.0.0.1", SMTP_PORT: "11025", SMTP_USER: "", SMTP_PASS: "",
  SMTP_SECURE: "false", SMTP_REQUIRE_TLS: "false", FROM_EMAIL: "notifications@recipient.test",
  TWILIO_ACCOUNT_SID: "AC00000000000000000000000000000000",
  TWILIO_AUTH_TOKEN: "browser-test-signature-secret", TWILIO_WHATSAPP_FROM: "whatsapp:+14155550999",
  WHATSAPP_DRY_RUN: "true", ENABLE_METRICS: "false",
  RECIPIENT_VERIFY_PUBLIC_PER_WINDOW: "1000", RECIPIENT_VERIFY_WORKSPACE_PER_DAY: "500",
  RECIPIENT_VERIFY_USER_PER_DAY: "500", RECIPIENT_VERIFICATION_CLOUD_SHADOW: "",
  RV_BROWSER_TEST: "1", RV_BROWSER_OUTPUT: output,
};
const compose = ["compose", "-p", "tt-recipient-browser", "-f", "tests/e2e/recipient-verification.compose.yml"];
const children = new Set();

function service(command, args, name, serviceEnv = env) {
  const log = fs.openSync(path.join(output, `${name}.log`), "w");
  const child = spawnCommand(command, args, { cwd: root, env: serviceEnv, stdio: ["ignore", log, log], windowsHide: true });
  fs.closeSync(log);
  children.add(child);
  child.on("error", (error) => console.error(error.message));
  return child;
}

async function stopped(child) {
  killProcessTree(child);
  await new Promise((resolve) => {
    if (child.exitCode !== null) return resolve();
    child.once("exit", resolve);
    setTimeout(resolve, 6000).unref();
  });
  children.delete(child);
}

async function ready(url, child) {
  const until = Date.now() + 120000;
  while (Date.now() < until) {
    if (child.exitCode !== null) throw new Error(`${url} process exited; see ${output}`);
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(2000) });
      if (response.ok) return;
    } catch { /* service is starting */ }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`${url} did not become ready; see ${output}`);
}

async function run(command, args, commandEnv = env) {
  const child = spawnCommand(command, args, { cwd: root, env: commandEnv, stdio: "inherit", windowsHide: true });
  children.add(child);
  const code = await new Promise((resolve, reject) => { child.once("exit", resolve); child.once("error", reject); });
  children.delete(child);
  if (code !== 0) throw new Error(`${command} ${args.join(" ")} exited ${code}`);
}

async function main() {
  await assertDevPortsAvailable({ apiPort: Number(env.PORT), dashboardPort: 5173 });
  try {
    await run("docker", [...compose, "up", "-d", "--wait"]);
    const dashboard = service("pnpm", ["dev:dashboard"], "dashboard");
    await ready(env.APP_URL, dashboard);
    const selected = process.argv.find((arg) => arg.startsWith("--mode="))?.slice(7);
    for (const mode of selected ? [selected] : ["enforce", "off", "cloud"]) {
      if (!["enforce", "off", "cloud"].includes(mode)) throw new Error(`Unknown mode ${mode}`);
      const modeEnv = { ...env, RV_BROWSER_MODE: mode, TT_DEPLOYMENT: mode === "cloud" ? "cloud" : "self-hosted", RECIPIENT_VERIFICATION_MODE: mode === "cloud" ? "off" : mode };
      const api = service("pnpm", ["dev:api"], `api-${mode}`, modeEnv);
      await ready(`${env.API_URL}/health`, api);
      console.log(`Browser validation: ${mode} (real UI/API/PostgreSQL, local SMTP, synthetic signed Twilio inbound)`);
      await run(process.execPath, ["--test", "--test-concurrency=1", "tests/e2e/recipient-verification.browser.test.cjs"], modeEnv);
      await stopped(api);
    }
    const integrationEnv = {
      ...env, NODE_ENV: "test", TT_DEPLOYMENT: "self-hosted", RECIPIENT_VERIFICATION_MODE: "enforce",
      TEST_API_URL: env.API_URL, API_BASE_URL: env.API_URL, TT_TEST_DB_PORT: env.DB_PORT,
      CONTRACT_API_REQUIRED: "1",
    };
    const integrationApi = service("pnpm", ["dev:api"], "api-integration", integrationEnv);
    await ready(`${env.API_URL}/health`, integrationApi);
    await run(process.execPath, [require.resolve("mocha/bin/mocha.js"),
      "tests/integration/api-test-whatsapp.test.js", "tests/integration/contacts-crud.test.js",
      "tests/integration/contact-groups-settings.test.js", "tests/integration/contact-group-reassignment.test.js",
      "--timeout", "60000", "--exit"], integrationEnv);
    await run(process.execPath, ["--test", "tests/contract/api-endpoints.test.js"], integrationEnv);
    await stopped(integrationApi);
  } finally {
    await Promise.all([...children].map(stopped));
    if (process.env.RV_BROWSER_KEEP_STACK !== "1") {
      const result = spawnSync("docker", [...compose, "down", "-v", "--remove-orphans"], { cwd: root, env, stdio: "inherit", windowsHide: true });
      if (result.status !== 0) process.exitCode = 1;
    }
  }
}

main().catch((error) => { console.error(error.message); process.exitCode = 1; });
