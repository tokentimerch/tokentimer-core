"use strict";
/** Manual Azure-free stopped/offline producer. The installed native journey writes
 * facts only after its owned native/API/database cleanup succeeds. This producer
 * cannot turn an interrupted run or a partial sidecar into a passing report. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const proof = require("../tests/e2e/helpers/certops-windows-stop-offline-proof");
const SOURCES = require("./certops-windows-stop-offline-sources");
const SOURCE = "scripts/certops-windows-stop-offline.js";
const SUITE = "windows-installed-stop-offline-renewal";
const CAPABILITIES = Object.freeze([
  "windows",
  "system",
  "iis",
  "api",
  "nativeAcme",
]);
function sha(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}
function readFacts(file) {
  const retained =
    require("../tests/e2e/helpers/certops-windows-stop-offline").readPrivate(
      file,
      16384,
    );
  const facts = JSON.parse(retained.bytes.toString("utf8"));
  proof.verifyProof(facts);
  return facts;
}
async function main() {
  assert.equal(process.platform, "win32");
  assert.equal(process.arch, "x64");
  assert.equal(process.env.CERTOPS_WINDOWS_STOP_OFFLINE_REQUIRED, "1");
  assert.equal(process.env.CERTOPS_WINDOWS_KEY_PROFILE, "rsa-2048");
  assert.ok(
    !process.env.CERTOPS_WINDOWS_HISTORICAL_PACKAGE,
    "Stop/offline scope requires only current candidate",
  );
  const root = path.resolve(__dirname, "..");
  const output = path.join(root, "qualification-results");
  fs.mkdirSync(output, { recursive: true });
  const factsFile = path.join(output, "windows-stop-offline-native-facts.json");
  const reportPath = path.join(output, "windows-installed-stop-offline.json");
  assert.equal(fs.existsSync(factsFile), false, "Refuse stale native facts");
  assert.equal(
    fs.existsSync(reportPath),
    false,
    "Refuse stale qualification report",
  );
  const gate = require("../packages/agent/scripts/host-gate").createHostGate({
    suite: SUITE,
    strict: true,
    reportPath,
    requiredCapabilities: CAPABILITIES.filter(
      (x) => x !== "api" && x !== "nativeAcme",
    ),
    fixtureSource: { file: SOURCE, sha256: sha(fs.readFileSync(__filename)) },
    probeCapabilities: () => {
      const result = spawnSync(
        "powershell.exe",
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);@{sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;iis=[bool](Get-Module -ListAvailable WebAdministration);language=(Get-WinSystemLocale).Name}|ConvertTo-Json -Compress",
        ],
        { encoding: "utf8", timeout: 15000, windowsHide: true },
      );
      assert.ifError(result.error);
      assert.equal(result.status, 0);
      const observed = JSON.parse(result.stdout);
      assert.equal(observed.language, "en-US");
      return {
        windows: { available: process.platform === "win32" },
        system: { available: observed.sid === "S-1-5-18" },
        iis: { available: observed.iis === true },
        api: { available: false },
        nativeAcme: { available: false },
      };
    },
  });
  // API/ACME capabilities become measured only inside the actual scenario;
  // host preflight must not manufacture their availability from environment flags.
  assert.equal(await gate.preflight(), true);
  gate.report.requiredCapabilities = [...CAPABILITIES];
  gate.report.qualificationEnvironment.identity = "LocalSystem";
  gate.report.qualificationEnvironment.nativeLanguage = "en-US";
  gate.report.qualificationEnvironment.architecture = "x64";
  assert.ok(
    ["2022", "2025"].includes(gate.report.qualificationEnvironment.osVersion),
  );
  gate.report.fixtureSources = SOURCES.map((file) => ({
    file,
    sha256: sha(fs.readFileSync(path.join(root, file))),
  }));
  await gate.scenario(proof.SCENARIO, async () => {
    await require("./certops-real-acme").withPebble((fixtureEnv) => {
      const result = spawnSync(
        process.execPath,
        [
          "--test",
          "--test-name-pattern=real Windows:",
          "tests/e2e/certops-agent-e2e.test.js",
        ],
        {
          cwd: root,
          stdio: "inherit",
          timeout: 2520000,
          windowsHide: true,
          env: {
            ...process.env,
            ...fixtureEnv,
            CERTOPS_E2E_REQUIRED: "1",
            CERTOPS_REAL_WINDOWS_REQUIRED: "1",
            CERTOPS_CSR_DISPOSABLE_STACK: "1",
            CERTOPS_WINDOWS_STOP_OFFLINE_REQUIRED: "1",
            CERTOPS_REPORT_SCOPE: "real-agent-windows-stop-offline/rsa-2048",
          },
        },
      );
      assert.ifError(result.error);
      assert.equal(
        result.status,
        0,
        "Installed stopped/offline journey failed",
      );
    });
    gate.report.nativeWindowsStoppedOffline = readFacts(factsFile);
    gate.report.capabilities.api = { available: true };
    gate.report.capabilities.nativeAcme = { available: true };
  });
  await gate.finish({
    requiredScenarios: [proof.SCENARIO],
    cleanup: {
      status: "passed",
      summary:
        "Actual installed fixture and API/database cleanup completed before native facts publication",
    },
  });
}
if (require.main === module)
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
module.exports = {
  main,
  readFacts,
  SOURCE,
  SUITE,
  CAPABILITIES,
  REQUIRED_SOURCES: SOURCES,
};
