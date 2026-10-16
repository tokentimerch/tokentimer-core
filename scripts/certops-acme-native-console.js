"use strict";
/** Dedicated trusted-manual Ubuntu browser/native-agent qualification. The
 * dashboard is the actual built application, served by a retained Vite HTTP
 * server in this process. The child owns its existing Pebble/agent fixtures.
 * This wrapper never kills a process by a rediscovered PID or emits raw logs. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const { spawn } = require("node:child_process"),
  { pathToFileURL } = require("node:url");
const { createHostGate } = require("../packages/agent/scripts/host-gate");
const report = require("./certops-acme-native-console-report");
const ROOT = path.resolve(__dirname, "..");
const REQUIRED_SOURCES = Object.freeze([
  ...new Set([
    ...require("../tests/e2e/helpers/certops-acme-lease-loss").REQUIRED_SOURCES,
    ...require("../tests/e2e/helpers/certops-acme-certificate-outbox").REQUIRED_SOURCES,
    ...require("../tests/e2e/helpers/certops-acme-disabled-profile").REQUIRED_SOURCES,
    "scripts/certops-acme-disabled-profile-report.js",
    "scripts/certops_acme_disabled_profile_proof.py",
    "scripts/certops-acme-certificate-outbox-report.js",
    "scripts/certops_acme_certificate_outbox_proof.py",
    ...require("../tests/e2e/helpers/certops-acme-native-adoption").REQUIRED_SOURCES,
    "scripts/certops-acme-native-adoption-report.js",
    "scripts/certops_acme_native_adoption_proof.py",
    ...require("../tests/e2e/helpers/certops-acme-bulk-renewal").REQUIRED_SOURCES,
    "scripts/certops-acme-bulk-report.js",
    "scripts/certops_acme_bulk_proof.py",
    ...require("../tests/e2e/helpers/certops-acme-browser-console")
      .REQUIRED_SOURCES,
    ...require("../tests/e2e/helpers/certops-acme-stage-faults")
      .REQUIRED_SOURCES,
    ...require("../tests/e2e/helpers/certops-acme-background-renewals")
      .REQUIRED_SOURCES,
    "scripts/certops-acme-native-console.js",
    "scripts/certops-acme-native-console-report.js",
    "scripts/certops_acme_native_console_proof.py",
    "apps/api/routes/certops-executor.js",
    "apps/dashboard/src/App.jsx",
    "apps/dashboard/src/pages/Login.jsx",
    "apps/dashboard/src/pages/certops/CertOpsRoutes.jsx",
    "apps/dashboard/src/pages/certops/CertOpsLayout.jsx",
    "apps/dashboard/src/pages/certops/CertOpsJobs.jsx",
    "apps/dashboard/src/components/RequireManagerRoute.jsx",
    "apps/dashboard/src/hooks/useCertOpsUrlState.js",
    "apps/dashboard/src/utils/WorkspaceContext.jsx",
    ".github/workflows/certops-acme-native-console.yml",
    "apps/dashboard/vite.config.js",
    "packages/agent/scripts/host-gate.js",
    "scripts/certops-stack-report.js",
  ]),
]);
function checkScope(
  env = process.env,
  platform = process.platform,
  release = fs.readFileSync("/etc/os-release", "utf8"),
  container = fs.existsSync("/.dockerenv") ||
    fs.existsSync("/run/.containerenv"),
) {
  assert.equal(platform, "linux");
  assert.match(release, /^ID=ubuntu$/m);
  assert.match(release, /^VERSION_ID="24\.04"$/m);
  assert.equal(env.CERTOPS_PROTOCOL_DISPOSABLE_STACK, "1");
  assert.equal(env.CERTOPS_REAL_ACME_CLIENT, "certbot");
  assert.equal(env.CERTOPS_REAL_ACME_EAB, "none");
  assert.equal(env.CERTOPS_NATIVE_ACME_CONSOLE, "1");
  assert.equal(env.GITHUB_ACTIONS, "true");
  assert.equal(env.GITHUB_REF, "refs/heads/main");
  assert.equal(env.GITHUB_EVENT_NAME, "workflow_dispatch");
  assert.match(env.GITHUB_SHA, /^[a-f0-9]{40}$/);
  assert.ok(container === false, "Native Ubuntu host required");
  return true;
}
function runChild(env) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [path.join(ROOT, "scripts/certops-real-acme.js")],
      { cwd: ROOT, env, stdio: "inherit" },
    );
    child.once("error", () =>
      reject(new Error("Native console journey could not launch")),
    );
    child.once("close", (code, signal) => {
      if (code === 0 && signal === null) resolve();
      else
        reject(new Error("Native console journey did not close successfully"));
    });
  });
}
async function closePreview(server) {
  let closed = false;
  server.once("close", () => {
    closed = true;
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("Owned dashboard HTTP server did not close")),
      30000,
    );
    timer.unref();
    server.close((error) => {
      clearTimeout(timer);
      if (error) reject(new Error("Owned dashboard close failed"));
      else resolve();
    });
    server.closeAllConnections();
  });
  assert.equal(closed, true);
  assert.equal(server.listening, false);
}
async function main() {
  checkScope();
  const fingerprint = (file) => ({
    file,
    sha256: crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.join(ROOT, file)))
      .digest("hex"),
  });
  let preview, primary;
  const gate = createHostGate({
    suite: report.SUITE,
    strict: true,
    evidenceLevel: "e2e",
    reportPath: "qualification-results/acme-native-console.json",
    requiredCapabilities: ["linux", "api", "browser"],
    fixtureSource: fingerprint("scripts/certops-acme-native-console.js"),
    probeCapabilities: async () => {
      const pin = require("../package.json").devDependencies.playwright,
        playwright = require("playwright");
      const response = await fetch("http://localhost:4000/", {
        signal: AbortSignal.timeout(10000),
      });
      const apiAvailable = response.ok;
      await response.body?.cancel();
      return {
        linux: { available: process.platform === "linux" },
        api: { available: apiAvailable },
        browser: {
          available:
            require("playwright/package.json").version === pin &&
            fs.lstatSync(playwright.chromium.executablePath()).isFile(),
        },
      };
    },
  });
  try {
    await gate.preflight();
    await gate.scenario(report.SCENARIO, async () => {
      const vite = await import(
        pathToFileURL(
          require.resolve("vite", {
            paths: [path.join(ROOT, "apps/dashboard")],
          }),
        ).href
      );
      preview = await vite.preview({
        root: path.join(ROOT, "apps/dashboard"),
        configFile: path.join(ROOT, "apps/dashboard/vite.config.js"),
        preview: { host: "127.0.0.1", port: 5173, strictPort: true },
      });
      assert.equal(preview.httpServer.listening, true);
      const address = preview.httpServer.address();
      assert.equal(address.address, "127.0.0.1");
      assert.equal(address.port, 5173);
      assert.equal(
        fs.existsSync(path.join(ROOT, report.SIDECAR)),
        false,
        "Fresh native console sidecar required",
      );
      await runChild({
        ...process.env,
        CERTOPS_NATIVE_ACME_CONSOLE_URL: "http://localhost:5173",
        CERTOPS_NATIVE_ACME_CONSOLE_API_URL: "http://localhost:4000",
      });
      const proof = report.readProof(ROOT),
        events = fs.readFileSync(
          path.join(ROOT, "qualification-results/real-acme.jsonl"),
          "utf8",
        );
      report.verifyActualJourney(events, proof, process.env.GITHUB_SHA);
      gate.report.nativeAcmeBrowserConsole = proof;
      gate.report.fixtureSources = REQUIRED_SOURCES.map(fingerprint);
    });
  } catch (error) {
    primary = error;
  } finally {
    if (preview) {
      try {
        await closePreview(preview.httpServer);
      } catch {
        primary = new Error(
          "Native console dashboard ownership cleanup incomplete",
        );
      }
    }
  }
  if (primary) {
    gate.report.status = "failed";
    gate.report.failure = "Native browser/agent console qualification failed";
    await gate.finish({
      requiredScenarios: [report.SCENARIO],
      cleanup: { status: "failed" },
    });
    throw new Error("Native browser/agent console qualification failed");
  }
  await gate.finish({
    requiredScenarios: [report.SCENARIO],
    cleanup: { status: "passed" },
  });
}
module.exports = { REQUIRED_SOURCES, checkScope, runChild, closePreview, main };
if (require.main === module)
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
