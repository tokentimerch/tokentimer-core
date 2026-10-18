"use strict";
// Operator acceptance on a disposable domain member: verified archive -> real
// default-root installer -> local policy -> browser profile -> worker -> TLS.
// SQL creates only the isolated login/workspace; certificate state is observed,
// never inserted or advanced by the journey. Native keys survive until VM teardown.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const net = require("node:net");
const { spawnSync } = require("node:child_process");
const { extractVerified, verifyInstalled, digest, ADCS_ACCEPTANCE_SCENARIOS } = require("../../scripts/certops-agent-package");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const browserJourney = require("./helpers/certops-adcs-browser-journey");
const { applyRestrictivePermissions } = require("../../packages/agent/src/platform");
function command(file, args, additions = {}) {
  const env = { ...process.env, ...additions };
  if (path.basename(file).toLowerCase() === "powershell.exe") {
    for (const key of Object.keys(env)) if (key.toLowerCase() === "psmodulepath") delete env[key];
  }
  const result = spawnSync(file, args, { encoding: "utf8", windowsHide: true, timeout: 180000, env });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${path.basename(file)} failed (${result.status}); private output withheld`);
  return result.stdout.trim();
}
const ps = source => command("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop';${source}`]);
async function until(check, timeout = 240000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { const value = await check(); if (value) return value; await new Promise(resolve => setTimeout(resolve, 500)); }
  throw new Error("Operator acceptance condition timed out");
}
test("AD CS operator journey uses the verified package and documented installer", { timeout: 1200000 }, async () => {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  const runtime = JSON.parse(fs.readFileSync("C:\\ttqualification\\runtime.json", "utf8"));
  const artifact = JSON.parse(fs.readFileSync(runtime.agentPackageReceipt, "utf8"));
  assert.equal(artifact.candidateSha, process.env.GITHUB_SHA);
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-package-acceptance-"));
  applyRestrictivePermissions(workDir, { kind: "directory" });
  const installedRoot = "C:\\ProgramData\\TokenTimerAgent", configDir = path.join(installedRoot, "state");
  assert.equal(fs.existsSync(installedRoot), false, "Refuse any pre-existing canonical installation");
  assert.notEqual(spawnSync("sc.exe", ["query", "TokenTimerAgent"]).status, 0);
  const fixture = await createApiFixture(process.env.CERTOPS_ADCS_API_URL);
  const readonlyFixture = { ...fixture, pool: { query(sql, args) {
    assert.match(sql, /^\s*SELECT\b/i, "Acceptance certificate state must be observation-only");
    return fixture.pool.query(sql, args);
  } } };
  const gate = createHostGate({ suite: "adcs-package-operator-acceptance", strict: true,
    reportPath: "C:\\ttqualification\\adcs-package-acceptance.json", candidateSha: artifact.candidateSha,
    requiredCapabilities: ["disposable-domain", "candidate-package"],
    probeCapabilities: async () => ({ "disposable-domain": { available: ps("(Get-CimInstance Win32_ComputerSystem).Domain") === "lab.certops.test" }, "candidate-package": { available: digest(runtime.agentPackage) === artifact.sha256 } }) });
  Object.assign(gate.report, { qualificationStatus: "not-qualified", buildMode: artifact.buildMode,
    packageSha256: artifact.sha256, operatorRunbooks: ["docs/certops/agent/install-windows.md", "docs/certops/agent/adcs.md"],
    certificateDatabaseInjection: false, workerDriven: true, publishedReleaseQualified: false });
  const ownedEnrollmentIds = [], ownedThumbprints = new Set(), ownedBrowserResources = [], ownedBrowserPreflightJobIds = [], ownedTlsProbes = [];
  const run = crypto.randomBytes(5).toString("hex"), site = `TTADCS-${run}-rsa2048`, domain = `certops-adcs-${run}-rsa2048.example.test`;
  const port = await new Promise(resolve => { const server = net.createServer(); server.listen(0, "127.0.0.1", () => { const value = server.address().port; server.close(() => resolve(value)); }); });
  const api = `/api/v1/workspaces/${fixture.workspaceId}/certops`;
  let packageRoot, files, credential, installed = false, siteOwned = false, primary;
  await gate.preflight();
  try {
    await gate.scenario("adcs-package-checksum-and-extraction", async () => {
      ({ root: packageRoot, files } = extractVerified({ tarball: runtime.agentPackage, expectedSha256: artifact.sha256, destination: path.join(workDir, "extracted") }));
    });
    const installer = path.join(packageRoot, "scripts/install-agent.ps1");
    await gate.scenario("adcs-package-documented-default-root-install", async () => {
      const bootstrap = await fixture.request(`${api}/agent-bootstrap-tokens`, "POST", { name: "Package acceptance", expiresAt: new Date(Date.now() + 3600000).toISOString() });
      assert.equal(bootstrap.status, 201);
      const args = ["-NoProfile", "-NonInteractive", "-File", installer, "--api-url", process.env.CERTOPS_ADCS_API_URL, "--workspace-id", fixture.workspaceId, "--ca-bundle", "C:\\ttqualification\\api-public.pem"];
      command("powershell.exe", [...args, "--dry-run"]);
      assert.equal(fs.existsSync(installedRoot), false, "Installer dry run must not create the installation");
      installed = true; // Retain cleanup responsibility even if installation fails halfway.
      command("powershell.exe", args, { TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: bootstrap.body.plaintextToken });
      verifyInstalled(files, path.join(installedRoot, "app"));
      await until(async () => (await fixture.request(`${api}/agents`)).body.items?.some(row => row.lastSeenAt));
      assert.equal(ps("(Get-Service TokenTimerAgent).Status"), "Running");
    });
    const agentRow = await until(async () => (await fixture.request(`${api}/agents`)).body.items?.[0]);
    const settingsFile = path.join(configDir, "config.json"), settings = JSON.parse(fs.readFileSync(settingsFile, "utf8"));
    credential = fs.readFileSync(path.join(configDir, "credential"));
    await gate.scenario("adcs-package-local-policy-and-signed-dry-run", async () => {
      Object.assign(settings, { heartbeatIntervalMs: 5000, pollIntervalMs: 2000,
        windowsDiscovery: { enabled: true, intervalMs: 5000, stores: ["My"] }, declaredTargetSelectors: [domain],
        execution: { enabled: true, dryRun: true }, policy: { allowedPaths: [workDir], allowedCommands: {}, allowedCaEndpoints: [], allowedDnsZones: [], allowedDnsProviders: [] },
        adcs: { enrollmentRules: [{ caConfig: "tt-ca.lab.certops.test\\TTQualificationRoot", template: "TTQualificationRSAShort", dnsScopes: ["example.test"], keyAlgorithms: ["rsa"], operatorAttested: false }] } });
      fs.writeFileSync(settingsFile, JSON.stringify(settings)); applyRestrictivePermissions(settingsFile);
      ps("Restart-Service TokenTimerAgent -Force");
      const created = await fixture.request(`${api}/jobs`, "POST", { operation: "noop", mode: "dry_run", assignedAgentId: agentRow.id });
      assert.equal(created.status, 201);
      assert.equal(created.body.job.payload.mode, "dry_run", "Public API must retain the signed preview mode");
      await until(async () => (await fixture.request(`${api}/jobs/${created.body.job.id}`)).body.job?.status === "dry_run_complete");
      settings.execution.dryRun = false;
      fs.writeFileSync(settingsFile, JSON.stringify(settings)); applyRestrictivePermissions(settingsFile);
      ps("Restart-Service TokenTimerAgent -Force");
      assert.deepEqual(fs.readFileSync(path.join(configDir, "credential")), credential);
    });
    // Existing IIS content is an operator prerequisite, not a fabricated managed
    // source. The agent must discover it before the browser can attach a profile.
    const seed = JSON.parse(ps(`Import-Module WebAdministration;$c=New-SelfSignedCertificate -DnsName '${domain}' -CertStoreLocation Cert:\\LocalMachine\\My -NotAfter (Get-Date).AddDays(1);New-Website -Name '${site}' -PhysicalPath '${workDir.replace(/'/g,"''")}' -Port ${port}|Out-Null;Remove-WebBinding -Name '${site}' -Protocol http;New-WebBinding -Name '${site}' -Protocol https -Port ${port} -HostHeader '${domain}' -SslFlags 1;(Get-WebBinding -Name '${site}' -Protocol https).AddSslCertificate($c.Thumbprint,'My');@{pem=[Convert]::ToBase64String($c.RawData);thumb=$c.Thumbprint}|ConvertTo-Json -Compress`));
    siteOwned = true;
    ownedThumbprints.add(seed.thumb);
    const caDer = ps("$roots=@(Get-ChildItem Cert:\\LocalMachine\\Root|Where-Object {$_.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -eq 'TTQualificationRoot'});if($roots.Count -ne 1){throw 'Ambiguous owned CA root'};[Convert]::ToBase64String($roots[0].RawData)");
    const ca = new crypto.X509Certificate(Buffer.from(caDer, "base64"));
    const authority = { keySha256: crypto.createHash("sha256").update(ca.publicKey.export({ type: "spki", format: "der" })).digest("hex") };
    await browserJourney.qualifyAdcsBrowserJourney({ gate, fixture: readonlyFixture, api, agentRowId: agentRow.id, configDir, workDir, run,
      renewalFixture: { item: { id: "rsa2048", domain }, site, port, authority }, until, workerDriven: true,
      jobFinished: id => until(async () => { const row = (await fixture.request(`${api}/jobs/${id}`)).body.job; assert.ok(!["failed", "rejected", "cancelled"].includes(row?.status)); return row?.status === "succeeded"; }),
      ps, command, tlsAuthority: () => [ca.toString(), new crypto.X509Certificate(Buffer.from(seed.pem, "base64")).toString()],
      ownedEnrollmentIds, ownedThumbprints, ownedBrowserResources, ownedBrowserPreflightJobIds, ownedTlsProbes });
    await gate.scenario("adcs-package-service-restart-preserves-custody", async () => {
      ps("Restart-Service TokenTimerAgent -Force");
      assert.deepEqual(fs.readFileSync(path.join(configDir, "credential")), credential);
      verifyInstalled(files, path.join(installedRoot, "app"));
      assert.equal(ps("(Get-Service TokenTimerAgent).Status"), "Running");
    });
  } catch (error) { primary = error; throw error; }
  finally {
    let cleanup = "passed";
    try {
      for (const probe of ownedTlsProbes) await probe.drain();
      for (const browser of ownedBrowserResources) await browser.close();
      if (installed && packageRoot) await gate.scenario("adcs-package-documented-uninstall-preserves-state", async () => {
        command("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", path.join(packageRoot, "scripts/install-agent.ps1"), "--uninstall"]);
        assert.notEqual(spawnSync("sc.exe", ["query", "TokenTimerAgent"]).status, 0);
        assert.equal(fs.existsSync(path.join(installedRoot, "app")), false);
        if (credential) assert.deepEqual(fs.readFileSync(path.join(configDir, "credential")), credential);
      });
      if (siteOwned) ps(`Import-Module WebAdministration;Remove-Website -Name '${site}'`);
      await fixture.cleanup();
      // The documented uninstall preserves custody state. Do not delete a key
      // or erase its journal; the outer workflow destroys this whole owned VM.
    } catch (error) { cleanup = "failed"; if (!primary) throw error; }
    finally { await gate.finish({ cleanup: { status: cleanup }, requiredScenarios: ADCS_ACCEPTANCE_SCENARIOS }); }
  }
});
