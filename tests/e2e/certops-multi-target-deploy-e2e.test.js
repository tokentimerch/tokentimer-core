"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path"), crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { createApiFixture } = require("./helpers/certops-api-fixture");
const { createRegisteredAgent } = require("./helpers/certops-registered-agent");
const { createHostGate } = require("../../packages/agent/scripts/host-gate");
const { runDeployReloadVerifyForTargets } = require("../../packages/agent/src");
const { createPolicyEngine, loadPolicyConfig } = require("../../packages/agent/src/policy");
const scenarios = ["multi-deploy-owned-context", "multi-deploy-real-destinations", "multi-deploy-preflight-refusal", "multi-deploy-second-target-rollback", "multi-deploy-first-install-rollback", "multi-deploy-lost-backup-uncertainty", "multi-deploy-cleanup", "multi-deploy-idempotent-permissions"];
test("production multi-target coordinator preserves files and exposes uncertain rollback", { timeout: 120000 }, async (t) => {
  const baseUrl = process.env.CERTOPS_CSR_API_URL;
  if (!baseUrl && process.env.CERTOPS_E2E_REQUIRED !== "1") {
    // skip-reason: no-host - requires disposable API PostgreSQL OpenSSL and native temporary filesystem
    t.skip("Disposable API and OpenSSL required"); return;
  }
  assert.ok(baseUrl);
  const fixture = await createApiFixture(baseUrl), root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-multi-deploy-"));
  const gate = createHostGate({ suite: "multi-target-deploy-api", evidenceLevel: "integration", strict: process.env.CERTOPS_E2E_REQUIRED === "1", reportPath: process.env.CERTOPS_MULTI_TARGET_DEPLOY_REPORT, requiredCapabilities: ["api", "postgres", "openssl", "native-filesystem"], fixtureSource: { file: "tests/e2e/certops-multi-target-deploy-e2e.test.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ api: { available: true }, postgres: { available: true }, openssl: { available: spawnSync("openssl", ["version"]).status === 0 }, "native-filesystem": { available: fs.statSync(root).isDirectory() } }) });
  gate.report.executionScope = "Production deployment coordinator on actual temporary files with real authenticated claim-bound evidence ingestion; no public deploy dispatch, daemon reload, served TLS or issuer completion claimed. Uncertainty deliberately deletes owned local backups";
  let ready = false, failure, agent, owned, first, second, destinations;
  const engine = createPolicyEngine(loadPolicyConfig({ allowedPaths: [root] }));
  const name = "multi-deploy.example.test";
  function material(label) {
    const key = path.join(root, `${label}.key`), cert = path.join(root, `${label}.crt`);
    assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-subj", `/CN=${name}`, "-addext", `subjectAltName=DNS:${name}`, "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature,keyEncipherment", "-addext", "extendedKeyUsage=serverAuth", "-days", "2"], { timeout: 20000 }).status, 0);
    return { key, pem: fs.readFileSync(cert, "utf8") };
  }
  function targets(prefix) {
    return [1, 2].map((index) => {
      const directory = path.join(root, `${prefix}-${index}`); fs.mkdirSync(directory);
      const backupDir = path.join(directory, "backups"); fs.mkdirSync(backupDir);
      return { type: "domain", reference: name, certPath: path.join(directory, "leaf.pem"), keyPath: path.join(directory, "leaf.key"), backupDir };
    });
  }
  const capture = (rows) => rows.map((target) => [target.certPath, target.keyPath].map((file) => fs.readFileSync(file)));
  function observe(rows, expected) {
    for (const target of rows) {
      const leaf = new crypto.X509Certificate(fs.readFileSync(target.certPath));
      assert.equal(leaf.fingerprint256, new crypto.X509Certificate(expected.pem).fingerprint256); assert.equal(leaf.checkHost(name), name);
      assert.equal(leaf.checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(target.keyPath))), true);
      if (process.platform !== "win32") assert.equal(fs.statSync(target.keyPath).mode & 0o777, 0o600);
      else {
        const aclEnvironment = { ...process.env, CERTOPS_FIXTURE_KEY: target.keyPath };
        for (const key of Object.keys(aclEnvironment)) if (key.toLowerCase() === "psmodulepath") delete aclEnvironment[key];
        const acl = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; $acl=Get-Acl -LiteralPath $env:CERTOPS_FIXTURE_KEY; if(-not $acl.AreAccessRulesProtected){throw 'Inherited key ACL'}; $allowed=@('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value); foreach($rule in $acl.Access){$sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;if($rule.AccessControlType -eq 'Allow' -and $sid -notin $allowed){throw 'Unexpected key ACL trustee'}}; 'restricted'"], { encoding: "utf8", env: aclEnvironment, timeout: 15000 });
        assert.equal(acl.status, 0, "Independent private-key ACL oracle failed; raw output withheld"); assert.equal(acl.stdout.trim(), "restricted");
      }
    }
  }
  function deploy(rows, source, onBeforeMutation) {
    const staging = path.join(root, `staging-${crypto.randomUUID()}.key`); fs.copyFileSync(source.key, staging);
    const client = { async reportEvidence(body) {
      const response = await agent.machine("jobs/results", "evidence", { ...body, claimId: owned.claimId, evidenceItems: body.evidenceItems.map(item => ({ ...item, evidenceId: crypto.randomUUID() })) }); assert.equal(response.status, 200);
    } };
    return runDeployReloadVerifyForTargets({ job: { action: "deploy", mode: "real", target: { type: "domain", reference: name } }, jobId: owned.jobId, policyEngine: engine, client, certificatePem: source.pem, deployTargets: rows, stagedKeyPath: staging, keyRotated: true, requestedSans: [name], onBeforeMutation });
  }
  const failingSecond = (rows) => {
    const directory = path.join(root, `existing-directory-${crypto.randomUUID()}`); fs.mkdirSync(directory);
    return [rows[0], { ...rows[1], certPath: directory }];
  };
  try {
    assert.equal(await gate.preflight(), true); ready = true;
    await gate.scenario(scenarios[0], async () => {
      agent = await createRegisteredAgent(fixture, baseUrl); owned = await agent.claimNoop(); first = material("first"); second = material("second"); destinations = targets("existing");
    });
    await gate.scenario(scenarios[1], async () => {
      const result = await deploy(destinations, first); assert.equal(result.status, "succeeded"); assert.equal(result.targetOutcomes.length, 2); observe(destinations, first);
      for (const target of destinations) assert.deepEqual(fs.readdirSync(target.backupDir), []);
    });
    await gate.scenario("multi-deploy-idempotent-permissions", async () => {
      const before = capture(destinations), mtimes = destinations.map(target => fs.statSync(target.keyPath).mtimeMs);
      if (process.platform === "win32") {
        const tool = require("../../packages/agent/src/platform").windowsSystem32Tool("icacls");
        for (const target of destinations) assert.equal(spawnSync(tool, [target.keyPath, "/grant", "*S-1-1-0:(R)"], { encoding: "utf8", timeout: 15000 }).status, 0, "Owned key ACL fault setup failed");
      }
      const result = await deploy(destinations, first); assert.equal(result.status, "succeeded");
      assert.deepEqual(capture(destinations), before); assert.deepEqual(destinations.map(target => fs.statSync(target.keyPath).mtimeMs), mtimes); observe(destinations, first);
    }, { oracle: "Idempotent real-file replay preserves bytes and modification times; actual foreign Windows Everyone grant is removed and independently checked" });
    await gate.scenario(scenarios[2], async () => {
      const before = capture(destinations), outside = path.join(os.tmpdir(), `outside-certops-${crypto.randomUUID()}.pem`);
      const result = await deploy([destinations[0], { ...destinations[1], certPath: outside }], second);
      assert.equal(result.status, "rejected"); assert.deepEqual(capture(destinations), before); assert.equal(fs.existsSync(outside), false);
    });
    await gate.scenario(scenarios[3], async () => {
      const before = capture(destinations), result = await deploy(failingSecond(destinations), second);
      assert.equal(result.status, "failed"); assert.equal(result.targetOutcomes.length, 2); assert.deepEqual(capture(destinations), before); observe(destinations, first);
    });
    await gate.scenario(scenarios[4], async () => {
      const fresh = targets("fresh"), result = await deploy(failingSecond(fresh), second);
      assert.equal(result.status, "failed"); assert.equal(fs.existsSync(fresh[0].certPath), false); assert.equal(fs.existsSync(fresh[0].keyPath), false);
    });
    await gate.scenario(scenarios[5], async () => {
      let deployments = 0;
      const result = await deploy(failingSecond(destinations), second, (phase) => {
        assert.equal(phase, "deploy"); deployments++;
        if (deployments === 2) {
          const files = fs.readdirSync(destinations[0].backupDir); assert.ok(files.length >= 2, "Actual retained predecessor backups must exist before the deliberate loss");
          for (const file of files) fs.unlinkSync(path.join(destinations[0].backupDir, file));
        }
      });
      assert.equal(result.status, "orphaned_unknown_effect"); assert.match(result.errorMessage, /needsOperatorReconciliation=true/); assert.match(result.errorMessage, /multi_target_rollback_uncertain/);
      observe([destinations[0]], second);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [fixture.workspaceId, owned.jobId])).rows[0].count > 0, true);
    });
  } catch (error) { failure = error; }
  finally {
    const cleanup = async () => {
      const errors = [];
      try { await fixture.cleanup(); } catch (error) { errors.push(error); }
      try { assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir())); assert.ok(path.basename(root).startsWith("certops-multi-deploy-")); fs.rmSync(root, { recursive: true, force: true }); assert.equal(fs.existsSync(root), false); } catch (error) { errors.push(error); }
      if (errors.length) throw new AggregateError(errors, "Multi-target fixture cleanup failed");
    };
    try { if (ready) await gate.scenario(scenarios[6], cleanup); else await cleanup(); } catch (error) { failure = failure ? new AggregateError([failure, error], "Multi-target cleanup failed") : error; }
    try { if (ready) await gate.finish({ requiredScenarios: scenarios }); } catch (error) { failure = failure ? new AggregateError([failure, error], "Multi-target qualification incomplete") : error; }
  }
  if (failure) throw failure;
});
