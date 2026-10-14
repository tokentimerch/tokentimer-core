"use strict";
/** Canonical-root lifecycle on a fresh disposable hosted Windows Server.
 * Executes the byte-identical packed installer CLI, not extracted functions or
 * a root-rewritten script. Owns only a previously absent canonical service/root.
 * This lane qualifies candidate reapplication, not distinct-version migration,
 * certificate issuance, second-rename rollback or Windows dump containment.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const canonicalRoot = "C:\\ProgramData\\TokenTimerAgent";
const suite = "windows-canonical-root-lifecycle";
const requiredScenarios = ["windows-canonical-root-owned", "windows-canonical-unmodified-install", "windows-canonical-authenticated-registration", "windows-canonical-service-restart", "windows-canonical-candidate-reapplication", "windows-canonical-unmodified-uninstall", "windows-canonical-owned-cleanup"];
const fields = ["initialRootAbsent", "initialServiceAbsent", "ownershipRecordedBeforeInstall", "originalInstallerBytesUnchanged", "canonicalInstalledHostVerified", "localSystemServiceVerified", "authenticatedRegistration", "bootstrapRegistryScrubbed", "restartChangedServicePid", "freshHeartbeatAfterRestart", "candidateReapplicationSucceeded", "configurationCredentialAndPinPreserved", "freshHeartbeatAfterReapplication", "unmodifiedUninstallerSucceeded", "serviceAndAppRemoved", "uninstallPreservedState", "exactOwnedRootRemoved"];
const requiredSources = ["tests/e2e/helpers/certops-windows-fixed-root.js", "tests/e2e/certops-agent-e2e.test.js", "packages/agent/scripts/install-agent.ps1", "packages/agent/scripts/pack-release.js", "packages/agent/scripts/build-windows-chain-helper.js", "packages/agent/scripts/build-windows-service-host.js", "scripts/certops-windows-fixed-root.js", "scripts/certops-windows-fixed-root-cleanup.js"];
function verifyProof(proof) {
  assert.ok(proof && typeof proof === "object" && !Array.isArray(proof));
  assert.deepEqual(Object.keys(proof).sort(), [...fields, "scope"].sort());
  assert.equal(proof.scope, "unmodified-candidate-cli-canonical-root-same-version-reapplication");
  for (const field of fields) assert.equal(proof[field], true, field);
  return true;
}
function assertCanonicalOwnership({ root, token, receipt, fileId, serviceAbsent }) {
  assert.equal(path.win32.normalize(root).toLowerCase(), canonicalRoot.toLowerCase());
  assert.match(token, /^[a-f0-9]{32}$/);
  assert.equal(receipt.token, token);
  assert.equal(receipt.root, canonicalRoot);
  assert.equal(receipt.fileId, String(fileId));
  assert.equal(serviceAbsent, true, "Owned root must remain while the service exists");
  return true;
}
async function qualifyFixedRoot({ pool, baseUrl, workspaceId, createBootstrap, repoRoot }) {
  assert.equal(process.platform, "win32");
  assert.equal(process.arch, "x64");
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.equal(process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST, "1");
  assert.equal(process.env.CERTOPS_REAL_WINDOWS_FIXED_ROOT_REQUIRED, "1");
  const powershell = path.join(process.env.SystemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe");
  const environment = { ...process.env };
  for (const key of Object.keys(environment)) if (key.toLowerCase() === "psmodulepath") delete environment[key];
  const run = (program, args, additions = {}) => {
    const result = spawnSync(program, args, { encoding: "utf8", timeout: 180000, windowsHide: true, maxBuffer: 131072, env: { ...environment, ...additions } });
    assert.ifError(result.error); assert.equal(result.status, 0, "Owned native operation failed"); return result.stdout.trim();
  };
  const ps = script => run(powershell, ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from("$ErrorActionPreference='Stop';" + script, "utf16le").toString("base64")]);
  const service = () => JSON.parse(ps("$s=Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\";if($s){@{pid=$s.ProcessId;state=$s.State;path=$s.PathName;startName=$s.StartName}|ConvertTo-Json -Compress}else{'null'}"));
  const absent = () => service() === null;
  const wait = async check => { const deadline = Date.now() + 120000; while (Date.now() < deadline) { const value = await check(); if (value) return value; await new Promise(resolve => setTimeout(resolve, 500)); } throw new Error("Canonical Windows lifecycle deadline exceeded"); };
  assert.equal(ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"), "S-1-5-18");
  assert.equal(path.win32.resolve(fs.realpathSync("C:\\ProgramData")).toLowerCase(), "c:\\programdata", "Canonical parent must not redirect");
  assert.equal(fs.existsSync(canonicalRoot), false, "Refuse any existing canonical install root");
  assert.equal(absent(), true, "Refuse any existing agent service");
  assert.ok(process.env.RUNNER_TEMP && fs.statSync(process.env.RUNNER_TEMP).isDirectory());
  const token = process.env.CERTOPS_FIXED_ROOT_OWNER_TOKEN, agentId = `fixed-root-${crypto.randomUUID()}`;
  assert.match(token, /^[a-f0-9]{32}$/);
  const externalReceipt = path.resolve(process.env.CERTOPS_FIXED_ROOT_RECEIPT || "");
  assert.ok(externalReceipt.startsWith(path.resolve(process.env.RUNNER_TEMP) + path.sep));
  assert.equal(fs.existsSync(externalReceipt), false, "Refuse stale external ownership receipt");
  const workDir = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP, "certops-fixed-root-"));
  const configDir = path.join(canonicalRoot, "state"), receiptPath = path.join(canonicalRoot, ".qualification-ownership.json");
  const expectedHost = path.join(canonicalRoot, "app/bin/tokentimer-agent-host-amd64.exe");
  const proof = { scope: "unmodified-candidate-cli-canonical-root-same-version-reapplication", initialRootAbsent: true, initialServiceAbsent: true };
  let rootOwned = false, fileId, installer, originalBytes, primary;
  const errors = [];
  const hash = file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(repoRoot, file))).digest("hex") });
  const gate = require("../../../packages/agent/scripts/host-gate").createHostGate({ suite, strict: true, evidenceLevel: "e2e", reportPath: "qualification-results/windows-canonical-root.json", fixtureSource: hash(requiredSources[0]), requiredCapabilities: ["windows", "system", "disposableHost", "api"], probeCapabilities: () => ({ windows: { available: process.platform === "win32" }, system: { available: ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value") === "S-1-5-18" }, disposableHost: { available: process.env.RUNNER_ENVIRONMENT === "github-hosted" }, api: { available: true } }) });
  gate.report.fixtureSources = requiredSources.map(hash);
  await gate.preflight(); gate.report.qualificationEnvironment.identity = "LocalSystem";
  const assertRoot = () => {
    assert.equal(fs.lstatSync(canonicalRoot).isSymbolicLink(), false);
    assert.equal(fs.statSync(canonicalRoot, { bigint: true }).ino, fileId);
    const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    assert.equal(receipt.token, token); assert.equal(receipt.fileId, String(fileId)); assert.equal(receipt.root, canonicalRoot);
    assert.equal(path.win32.resolve(fs.realpathSync(canonicalRoot)).toLowerCase(), canonicalRoot.toLowerCase());
    return receipt;
  };
  const assertService = () => { assertRoot(); const value = service(); assert.ok(value); assert.ok(value.path.toLowerCase().startsWith(('"' + expectedHost + '" ').toLowerCase()), "Refuse a service outside the owned canonical app"); assert.equal(value.startName, "LocalSystem"); return value; };
  const install = async () => { assertRoot(); assert.deepEqual(fs.readFileSync(installer), originalBytes); const bootstrap = await createBootstrap(); run(powershell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", installer, "--api-url", baseUrl, "--workspace-id", String(workspaceId), "--allow-insecure-local-http", "--no-trust-store"], { TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: bootstrap.plaintextToken }); assert.deepEqual(fs.readFileSync(installer), originalBytes); assert.deepEqual(fs.readFileSync(path.join(canonicalRoot, "app/scripts/install-agent.ps1")), originalBytes); };
  const seen = async () => (await pool.query("SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2 AND retired_at IS NULL", [workspaceId, agentId])).rows[0]?.last_seen_at;
  const freshHeartbeat = async () => { const baseline = await seen(); assert.ok(baseline); await wait(async () => new Date(await seen()).getTime() > new Date(baseline).getTime()); };
  const stateFiles = ["config.json", "credential", "signing-key-pin.json"];
  const readState = () => stateFiles.map(file => fs.readFileSync(path.join(configDir, file)));
  try {
    await gate.scenario(requiredScenarios[0], () => {
      assert.equal(fs.existsSync(canonicalRoot), false); assert.equal(absent(), true);
      fs.mkdirSync(canonicalRoot); rootOwned = true; fileId = fs.statSync(canonicalRoot, { bigint: true }).ino; assert.ok(fileId > 0n);
      fs.writeFileSync(receiptPath, JSON.stringify({ root: canonicalRoot, token, fileId: String(fileId) }), { flag: "wx" });
      fs.writeFileSync(externalReceipt, fs.readFileSync(receiptPath), { flag: "wx" });
      assertRoot(); proof.ownershipRecordedBeforeInstall = true;
      fs.mkdirSync(configDir);
      fs.writeFileSync(path.join(configDir, "config.json"), JSON.stringify({ serverUrl: baseUrl, agentId, allowInsecureLocalHttp: true, heartbeatIntervalMs: 5000, pollIntervalMs: 5000, execution: { enabled: false, dryRun: true } }));
      const platform = require(path.join(repoRoot, "packages/agent/src/platform")); platform.applyRestrictivePermissions(configDir, { kind: "directory" }); platform.applyRestrictivePermissions(path.join(configDir, "config.json"), { kind: "file" });
    });
    await gate.scenario(requiredScenarios[1], async () => {
      const packaged = require(path.join(repoRoot, "packages/agent/scripts/pack-release")).main(["--out-dir", path.join(workDir, "release-package")]);
      require(path.join(repoRoot, "packages/agent/scripts/host/package-fixture")).verifyArchiveDigest(packaged.tarballPath, packaged.checksumPath);
      const extract = path.join(workDir, "candidate"); fs.mkdirSync(extract); run(path.join(process.env.SystemRoot, "System32/tar.exe"), ["-xzf", packaged.tarballPath, "-C", extract]);
      const candidate = path.join(extract, "package"); installer = path.join(candidate, "scripts/install-agent.ps1"); originalBytes = fs.readFileSync(path.join(repoRoot, "packages/agent/scripts/install-agent.ps1"));
      assert.deepEqual(fs.readFileSync(installer), originalBytes); assert.ok(originalBytes.toString("utf8").includes('$InstallRoot = "C:\\ProgramData\\TokenTimerAgent"'));
      await install(); const value = assertService(); assert.equal(value.state, "Running");
      assert.deepEqual(fs.readFileSync(expectedHost), fs.readFileSync(path.join(candidate, "bin/tokentimer-agent-host-amd64.exe")));
      Object.assign(proof, { originalInstallerBytesUnchanged: true, canonicalInstalledHostVerified: true, localSystemServiceVerified: true });
    });
    await gate.scenario(requiredScenarios[2], async () => {
      await wait(seen); await wait(() => stateFiles.every(file => fs.existsSync(path.join(configDir, file))));
      const registry = run("reg.exe", ["query", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent", "/v", "Environment"]);
      assert.equal(/TOKENTIMER_AGENT_BOOTSTRAP_TOKEN(?:=|_ID=)/.test(registry), false);
      Object.assign(proof, { authenticatedRegistration: true, bootstrapRegistryScrubbed: true });
    });
    await gate.scenario(requiredScenarios[3], async () => {
      const before = assertService(); assert.ok(before.pid > 0); const state = readState();
      ps("Restart-Service -Name TokenTimerAgent -ErrorAction Stop");
      await wait(() => { const after = assertService(); return after.state === "Running" && after.pid > 0 && after.pid !== before.pid; });
      assert.deepEqual(readState(), state); await freshHeartbeat(); Object.assign(proof, { restartChangedServicePid: true, freshHeartbeatAfterRestart: true });
    });
    await gate.scenario(requiredScenarios[4], async () => {
      const state = readState(); await install(); assert.equal(assertService().state, "Running"); assert.deepEqual(readState(), state); await freshHeartbeat();
      Object.assign(proof, { candidateReapplicationSucceeded: true, configurationCredentialAndPinPreserved: true, freshHeartbeatAfterReapplication: true });
    });
    await gate.scenario(requiredScenarios[5], async () => {
      const state = readState(); assertService(); assert.deepEqual(fs.readFileSync(installer), originalBytes);
      run(powershell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", installer, "--uninstall"]);
      await wait(absent); assert.equal(fs.existsSync(path.join(canonicalRoot, "app")), false); assert.deepEqual(readState(), state); assertRoot();
      Object.assign(proof, { unmodifiedUninstallerSucceeded: true, serviceAndAppRemoved: true, uninstallPreservedState: true });
    });
  } catch (error) { primary = error; }
  finally {
    await gate.scenario(requiredScenarios[6], async () => {
      if (rootOwned) {
        assertRoot();
        if (!absent()) {
          assertService(); ps("$s=Get-Service TokenTimerAgent;if($s.Status -ne 'Stopped'){Stop-Service TokenTimerAgent -ErrorAction Stop};$s.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))");
          run("sc.exe", ["delete", "TokenTimerAgent"]); await wait(absent);
        }
        const receipt = assertRoot(); assertCanonicalOwnership({ root: canonicalRoot, token, receipt, fileId, serviceAbsent: absent() });
        fs.rmSync(canonicalRoot, { recursive: true }); assert.equal(fs.existsSync(canonicalRoot), false); proof.exactOwnedRootRemoved = true;
      }
      const tempRoot = path.resolve(process.env.RUNNER_TEMP), target = path.resolve(workDir);
      assert.ok(target.startsWith(tempRoot + path.sep) && path.basename(target).startsWith("certops-fixed-root-"));
      assert.equal(absent(), true); fs.rmSync(target, { recursive: true });
      if (!primary) { verifyProof(proof); gate.report.nativeCanonicalRoot = proof; }
    }).catch(error => errors.push(error));
    await gate.finish({ requiredScenarios }).catch(error => errors.push(error));
  }
  if (primary || errors.length) throw new AggregateError([...(primary ? [primary] : []), ...errors], "Canonical root qualification or owned cleanup failed");
  return gate.report;
}
module.exports = { qualifyFixedRoot, verifyProof, assertCanonicalOwnership, requiredScenarios, requiredSources, fields, suite, canonicalRoot };
