"use strict";
/** Dedicated manual Azure-free Windows WebHosting retention qualification.
 * One genuine expiry+300s wait; no service install/CA/domain infrastructure.
 * The existing My24/168/720 cases remain separate. Failed native ownership
 * preserves local state for runner disposal instead of broad cleanup.
 */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os"),
  crypto = require("node:crypto"),
  { spawnSync } = require("node:child_process");
const fixture = require("../packages/agent/scripts/host/retention-webhosting-fixture"),
  replacement = require("../packages/agent/scripts/host/retention-webhosting-replacement");
const SOURCE = "scripts/certops-windows-webhosting-retention.js",
  SUITE = "windows-webhosting-retention",
  SCENARIOS = [
    ...fixture.SCENARIOS,
    "windows-webhosting-retention-owned-cleanup",
  ];
const REQUIRED_SOURCES = Object.freeze([
  ...new Set([
    SOURCE,
    ...fixture.REQUIRED_SOURCES,
    ...replacement.REQUIRED_SOURCES,
    "packages/agent/scripts/host-gate.js",
    "packages/agent/scripts/build-windows-chain-helper.js",
    ".github/workflows/certops-windows-webhosting-retention.yml",
    "packages/agent/reference/adcs-chain/main.go",
    "packages/agent/reference/adcs-chain/keyrefs/scan_windows.go",
    "packages/agent/reference/adcs-chain/keyrefs/result.go",
    "packages/agent/reference/adcs-chain/chaincore/chain_windows.go",
    "packages/agent/reference/adcs-chain/chaincore/result.go",
    "packages/agent/reference/adcs-chain/chaincore/trust_map.go",
    "packages/agent/reference/adcs-chain/go.mod",
    "packages/agent/reference/adcs-chain/go.sum",
    "packages/agent/reference/adcs-chain/build.cjs",
    "packages/agent/src/windows-cert-store/exclusive-lock-worker.js",
    "packages/agent/src/windows-cert-store/exclusive-lock-reclaim-gate.js",
    "packages/agent/src/issuers/chain-helper.js",
    "packages/agent/src/platform/durability.js",
    "packages/agent/src/windows-discovery/index.js",
    "packages/agent/src/verify/index.js",
    "packages/agent/vendor/log-scrub/secret-material.js",
  ]),
]);
function command(file, args) {
  const env = { ...process.env };
  if (path.basename(file).toLowerCase() === "powershell.exe")
    for (const key of Object.keys(env))
      if (key.toLowerCase() === "psmodulepath") delete env[key];
  const result = spawnSync(file, args, {
    env,
    encoding: "utf8",
    timeout: 180000,
    windowsHide: true,
  });
  assert.ifError(result.error);
  assert.equal(
    result.status,
    0,
    "Owned WebHosting prerequisite/native command failed",
  );
  return result.stdout.trim();
}
function powershell(script) {
  const full =
    "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);" +
    script;
  return command("powershell.exe", [
    "-NoProfile",
    "-NonInteractive",
    "-EncodedCommand",
    Buffer.from(full, "utf16le").toString("base64"),
  ]);
}
async function main() {
  assert.equal(process.platform, "win32");
  assert.equal(process.arch, "x64");
  assert.equal(process.env.CERTOPS_HOST_TESTS, "1");
  assert.equal(process.env.CERTOPS_QUALIFICATION_STRICT, "1");
  const root = path.resolve(__dirname, ".."),
    reportPath = path.join(
      root,
      "qualification-results",
      "windows-webhosting-retention.json",
    );
  assert.equal(
    fs.existsSync(reportPath),
    false,
    "Refuse stale WebHosting report",
  );
  const gate = require("../packages/agent/scripts/host-gate").createHostGate({
    suite: SUITE,
    strict: true,
    reportPath,
    requiredCapabilities: [
      "windows",
      "optIn",
      "elevated",
      "iis",
      "openssl",
      "noInstalledAgent",
    ],
    fixtureSource: {
      file: SOURCE,
      sha256: crypto
        .createHash("sha256")
        .update(fs.readFileSync(__filename))
        .digest("hex"),
    },
    probeCapabilities: () => ({
      windows: { available: process.platform === "win32" },
      optIn: { available: process.env.CERTOPS_HOST_TESTS === "1" },
      elevated: {
        available:
          powershell(
            "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
          ) === "True",
      },
      iis: {
        available:
          powershell("[bool](Get-Module -ListAvailable WebAdministration)") ===
          "True",
      },
      noInstalledAgent: {
        available:
          powershell(
            "[string](@(Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\").Count)",
          ) === "0",
      },
      openssl: {
        available:
          spawnSync("openssl", ["version"], {
            encoding: "utf8",
            windowsHide: true,
          }).status === 0,
      },
    }),
  });
  assert.equal(await gate.preflight(), true);
  gate.report.fixtureSources = REQUIRED_SOURCES.map((file) => ({
    file,
    sha256: crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.join(root, file)))
      .digest("hex"),
  }));
  const workDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "certops-webhosting-expiry-"),
    ),
    identity = fs.lstatSync(workDir, { bigint: true }),
    started = performance.now();
  let owner,
    primaryError,
    caseCompleted = false;
  try {
    await gate.scenario(
      fixture.SCENARIOS[0],
      async () => {
        owner = await replacement.prepareReplacement({
          workDir,
          powershell,
          run: command,
        });
        assert.ok(
          performance.now() - started < 180000,
          "Preparation exceeded reviewed three-minute setup budget; preserve fixture",
        );
        gate.report.nativeWebHostingRetention =
          await fixture.qualifyWebHostingRetention({
            gate,
            workDir,
            powershell,
            run: command,
            replacementPem: owner.replacementPem,
            replacementThumbprint: owner.replacementThumbprint,
            replacementOwner: owner,
          });
        fixture.verifyProof(gate.report.nativeWebHostingRetention);
        assert.ok(
          performance.now() - started < 900000,
          "Native WebHosting qualification exceeded fifteen-minute budget",
        );
        caseCompleted = true;
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "Actual WebHosting CNG A→B→C, real expiry+300s, retained child interruption/default collector recovery, independent store/IIS/trustedTLS and borrowed My key/certificate preservation",
      },
    );
  } catch (error) {
    primaryError = error;
  }
  try {
    await require("../packages/agent/scripts/host/retention-interrupted-process").drainBeforeCleanup(
      workDir,
    );
    await gate.scenario(
      SCENARIOS[2],
      () => {
        assert.equal(
          caseCompleted,
          true,
          "Failed native ownership must preserve fixture",
        );
        replacement.assertCleanupSafe(workDir);
        const current = fs.lstatSync(workDir, { bigint: true });
        assert.ok(
          current.isDirectory() &&
            !current.isSymbolicLink() &&
            current.dev === identity.dev &&
            current.ino === identity.ino,
        );
        const entries = [workDir];
        let ownedEntries = 0,
          ownedBytes = 0;
        while (entries.length) {
          const directory = entries.pop();
          for (const item of fs.readdirSync(directory, {
            withFileTypes: true,
          })) {
            const file = path.join(directory, item.name),
              stat = fs.lstatSync(file);
            ownedEntries += 1;
            ownedBytes += stat.isFile() ? stat.size : 0;
            assert.ok(
              ownedEntries <= 1024 && ownedBytes <= 33554432,
              "Bounded owned temporary inventory required",
            );
            assert.ok(
              stat.isFile() || stat.isDirectory(),
              "Unexpected owned temporary entry type",
            );
            assert.ok(
              !stat.isSymbolicLink(),
              "Refuse reparse entry during owned temporary cleanup",
            );
            if (stat.isDirectory()) entries.push(file);
          }
        }
        fs.rmSync(workDir, { recursive: true });
        assert.equal(fs.existsSync(workDir), false);
        gate.report.cleanup = { status: "passed" };
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "Exact retained child drainage, original root identity, successful owned certificate/key/root removal and no recursive cleanup of unresolved native state",
      },
    );
  } catch (error) {
    gate.report.cleanup = { status: "failed" };
    primaryError = primaryError
      ? new AggregateError(
          [primaryError, error],
          "WebHosting native ownership/cleanup failed",
        )
      : error;
  }
  await gate.finish({ requiredScenarios: SCENARIOS });
  if (primaryError) throw primaryError;
}
if (require.main === module)
  main().catch(() => {
    console.error(
      "WebHosting retention qualification failed; preserve unresolved owned state",
    );
    process.exitCode = 1;
  });
module.exports = { SOURCE, SUITE, SCENARIOS, REQUIRED_SOURCES, main };
