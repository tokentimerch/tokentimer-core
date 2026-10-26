"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");
const tls = require("node:tls");
const { readProtectedFile, writeProtectedJson } = require("./index");
const { applyRestrictivePermissions } = require("../platform");
const { computeCertificateFingerprint, parseDnsSans } = require("../verify");
const { executePinnedDeployment, reconcilePinnedDeployment, deployWroteNothing } = require("./lifecycle");

async function fixture(t, platform = "linux") {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tt-binding-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const tokenFile = path.join(directory, "token");
  fs.writeFileSync(tokenFile, "isolated-vault-fixture-only", { mode: 0o600 });
  applyRestrictivePermissions(tokenFile);
  const cert = fs.readFileSync(
    path.join(__dirname, "../verify/fixtures/leaf.crt.pem"),
    "utf8",
  );
  const key = fs.readFileSync(
    path.join(__dirname, "../verify/fixtures/leaf.key.pem"),
    "utf8",
  );
  const x509 = new crypto.X509Certificate(cert);
  const ids = {
    workspaceId: crypto.randomUUID(),
    groupId: crypto.randomUUID(),
    materialVersionId: crypto.randomUUID(),
  };
  const bundle = {
    schemaVersion: 1,
    ...ids,
    certificatePem: cert,
    privateKeyPem: key,
    fingerprintSha256: computeCertificateFingerprint(cert),
    sans: parseDnsSans(x509.subjectAltName),
  };
  const server = http.createServer((req, res) => {
    res.setHeader("Connection", "close");
    res.end(
      JSON.stringify({
        data: {
          data: bundle,
          metadata: { version: 1, deletion_time: "", destroyed: false },
        },
      }),
    );
  });
  server.keepAliveTimeout=60000;
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const scope = {
    workspaceId: ids.workspaceId,
    prefix: `${ids.workspaceId}/${ids.groupId}`,
    sans: bundle.sans,
    keyAlgorithm: x509.publicKey.asymmetricKeyType,
  };
  const stores = {
    customer: {
      address: `http://127.0.0.1:${server.address().port}`,
      mount: "secret",
      tokenFile,
      timeoutMs: 10000,
      groups: { [ids.groupId]: scope },
    },
  };
  const bindingId = crypto.randomUUID();
  const deployDir = path.join(directory, "service");
  fs.mkdirSync(deployDir, { recursive: true });
  const target = {
    type: "endpoint",
    reference: "fixture",
    certPath: path.join(deployDir, "cert.pem"),
    keyPath: path.join(deployDir, "cert.pem.key"),
  };
  const bindings = {
    [bindingId]: {
      ...ids,
      agentId: "consumer-agent",
      materialStoreRef: "customer",
      deploymentProfileRef: "fixture",
      profileRevision: 1,
      authorizationRevision: 1,
      verificationPolicy: "served",
      reloadService: "fixture",
      target,
      probes: [{ dialAddress: "127.0.0.1", port: 9, sni: bundle.sans.find(san => !san.includes("*")) }],
    },
  };
  const record = path.join(
    directory,
    "state",
    "material-bindings",
    `${bindingId}.json`,
  );
  function options({ generation = 1, reload = async () => true, policy = bindings[bindingId].verificationPolicy, verificationOnly = false, checkLease = async () => {}, recoveryOnly = false, windowsConnector, onBeforeMutation, intent = {}, platform: executionPlatform = platform } = {}) {
    return {
      job: {
        workspaceId: ids.workspaceId,
        agentId: "consumer-agent",
        materialDeployment: {
          ...ids,
          bindingId,
          materialStoreRef: "customer",
          providerVersion: 1,
          fingerprintSha256: bundle.fingerprintSha256,
          generation,
          deploymentProfileRef: "fixture",
          profileRevision: 1,
          authorizationRevision: 1,
          verificationPolicy: policy,
          ...(verificationOnly ? { verificationOnly: true } : {}),
          ...intent,
        },
      },
      stores,
      bindings,
      stateDir: path.join(directory, "state"),
      policyEngine: { checkPath: () => ({ allowed: true }), checkTargetScope: () => ({allowed:true}) },
      checkLease,
      windowsConnector,
      onBeforeMutation,
      reload,
      recoveryOnly,
      fixtureLoopbackHttp: true,
      platform: executionPlatform,
    };
  }
  const deploy = (input) => executePinnedDeployment(options(input));
  return { deploy, options, binding: bindings[bindingId], record, target, deployDir, bindings, bindingId, bundle, ids, directory };
}

const readRecord = (file) => JSON.parse(readProtectedFile(file, 16384));

function filesOnly(f) {
  f.binding.verificationPolicy = "installed";
  delete f.binding.reloadService;
  f.binding.probes = [];
}

function fullChain(f) {
  f.bundle.certificatePem = fs.readFileSync(path.join(__dirname, "../verify/fixtures/chain-leaf-fullchain.crt.pem"), "utf8");
  f.bundle.privateKeyPem = fs.readFileSync(path.join(__dirname, "../verify/fixtures/chain-leaf.key.pem"), "utf8");
  f.bundle.fingerprintSha256 = computeCertificateFingerprint(f.bundle.certificatePem);
  f.bundle.sans.splice(0, f.bundle.sans.length, ...parseDnsSans(new crypto.X509Certificate(f.bundle.certificatePem).subjectAltName));
}

test("files-only delivery writes and reads back the actual pair without reload or TLS", async (t) => {
  const f = await fixture(t);
  filesOnly(f);
  delete f.binding.probes;
  t.mock.method(require("node:tls"), "connect", () => assert.fail("files-only must not probe TLS"));
  const result = await f.deploy({ reload: () => assert.fail("files-only must not reload") });
  assert.equal(result.status, "succeeded");
  assert.ok(new crypto.X509Certificate(fs.readFileSync(f.target.certPath)).checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(f.target.keyPath))));
  for (const key of ["fetched", "installed"]) assert.equal(result.deploymentReceipt[key], true);
  for (const key of ["bound", "servedVerified", "trustValidated"]) assert.equal(result.deploymentReceipt[key], false);
  assert.equal(readRecord(f.record).uncertain, false);
  assert.equal((await f.deploy({ recoveryOnly: true })).status, "succeeded");
});

for (const splitChain of [false, true]) {
  test(`installed-only reconciliation rejects an incomplete ${splitChain ? "separate" : "combined"} chain without clearing uncertainty`, async t => {
    const f = await fixture(t);
    filesOnly(f); fullChain(f);
    if (splitChain) f.target.chainPath = path.join(f.deployDir, "chain.pem");
    let leases = 0;
    const interrupted = await f.deploy({ checkLease: async () => { if (++leases === 3) throw new Error("interrupted after readback"); } });
    assert.equal(interrupted.status, "orphaned_unknown_effect");
    assert.equal(readRecord(f.record).uncertain, true);
    const leaf = f.bundle.certificatePem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)[0];
    fs.writeFileSync(splitChain ? f.target.chainPath : f.target.certPath, splitChain ? "\n" : leaf);
    await assert.rejects(reconcilePinnedDeployment(f.options()), { code: "material_reconciliation_mismatch" });
    assert.equal(readRecord(f.record).uncertain, true);
    await assert.rejects(f.deploy({ generation: 2, verificationOnly: true }), { code: "material_binding_uncertain" });
  });
}

test("legacy file-only journals use the exact provider pin to recover public chain proof", async t => {
  const f = await fixture(t); filesOnly(f); fullChain(f);
  let leases = 0;
  await f.deploy({ checkLease: async () => { if (++leases === 3) throw new Error("interrupted after readback"); } });
  const saved = readRecord(f.record);
  delete saved.certificatePem;
  writeProtectedJson(f.record, saved);
  assert.equal((await reconcilePinnedDeployment(f.options())).reconciled, true);
  assert.equal(readRecord(f.record).uncertain, false);
  assert.equal((await f.deploy({ recoveryOnly: true })).status, "succeeded");
});

test("files-only rejects mismatched local policy, service hooks, and stale generations before writing", async (t) => {
  const f = await fixture(t);
  filesOnly(f);
  await assert.rejects(f.deploy({ policy: "trust" }), { code: "material_binding_policy_denied" });
  for (const extra of [{ reloadService: "nginx" }, { reloadCommandRefs: [] }, { probes: [{ dialAddress: "localhost" }] }]) {
    const original = { ...f.binding };
    Object.assign(f.binding, extra);
    await assert.rejects(f.deploy(), { code: "material_binding_policy_denied" });
    for (const key of Object.keys(extra)) delete f.binding[key];
    Object.assign(f.binding, original);
  }
  assert.equal(fs.existsSync(f.target.certPath), false);
  assert.equal((await f.deploy({ generation: 2 })).status, "succeeded");
  await assert.rejects(f.deploy({ generation: 1 }), { code: "material_stale_generation" });
});

test("files-only reconcile proves the pair after uncertainty and recovery keeps file-only assurance", async (t) => {
  const f = await fixture(t);
  filesOnly(f);
  let leases = 0;
  const result = await f.deploy({ checkLease: async () => { if (++leases === 3) throw new Error("lost lease after install"); } });
  assert.equal(result.status, "orphaned_unknown_effect");
  assert.equal(readRecord(f.record).uncertain, true);
  await assert.rejects(f.deploy({ recoveryOnly: true }), { code: "material_binding_uncertain" });
  t.mock.method(require("node:tls"), "connect", () => assert.fail("reconcile must not probe"));
  assert.equal((await reconcilePinnedDeployment(f.options())).reconciled, true);
  assert.equal(readRecord(f.record).uncertain, false);
  assert.equal((await f.deploy({ recoveryOnly: true })).status, "succeeded");
  fs.writeFileSync(f.target.keyPath, "not a key");
  await assert.rejects(reconcilePinnedDeployment(f.options()));
});

test("files-only verification checks the disk without repairing missing or altered files", async (t) => {
  const f = await fixture(t);
  filesOnly(f);
  assert.equal((await f.deploy()).status, "succeeded");
  assert.equal((await f.deploy({ generation: 2, verificationOnly: true })).status, "succeeded");
  fs.unlinkSync(f.target.certPath);
  const result = await f.deploy({ generation: 3, verificationOnly: true });
  assert.equal(result.status, "failed");
  assert.equal(result.errorMessage, "material_drift_detected");
  assert.equal(result.deploymentReceipt.installed, false);
  assert.equal(fs.existsSync(f.target.certPath), false);
});

test("a deploy rejected before any write leaves no uncertain marker and can be retried", async (t) => {
  const f = await fixture(t);
  const missingDir = path.join(f.deployDir, "absent");
  const goodCert = f.target.certPath;
  f.target.certPath = path.join(missingDir, "cert.pem");
  const rejected = await f.deploy();
  assert.equal(rejected.status, "failed");
  assert.equal(rejected.errorMessage, "material_install_failed");
  assert.equal(
    fs.existsSync(f.record),
    false,
    "no marker may outlive a deploy that wrote nothing",
  );

  f.target.certPath = goodCert;
  const retried = await f.deploy({ reload: async () => false });
  // The retry reached the destination instead of stopping at the marker check.
  assert.equal(retried.errorMessage, "material_reload_failed");
  assert.equal(fs.existsSync(goodCert), true);
});

test("a read failure on the existing destination restores the previous binding record", async (t) => {
  const f = await fixture(t);
  fs.mkdirSync(f.target.certPath);
  const previous = {
    generation: 1,
    intentHash: "0".repeat(64),
    intent: {},
    uncertain: false,
    receipt: { schemaVersion: 1 },
  };
  fs.mkdirSync(path.dirname(f.record), { recursive: true });
  writeProtectedJson(f.record, previous);
  const rejected = await f.deploy({ generation: 2 });
  assert.equal(rejected.status, "failed");
  assert.deepEqual(readRecord(f.record), previous);
});

test("a failure after files were written stays uncertain and blocks later jobs", async (t) => {
  const f = await fixture(t);
  const ambiguous = await f.deploy({ reload: async () => false });
  assert.equal(ambiguous.status, "orphaned_unknown_effect");
  assert.equal(readRecord(f.record).uncertain, true);
  await assert.rejects(f.deploy(), { code: "material_binding_uncertain" });
});

test("only deploy failures that provably wrote nothing are treated as clean", () => {
  for (const stage of [
    "validate",
    "realpath",
    "realpath-policy",
    "read-key",
    "read-existing",
    "backup",
    "permissions",
  ]) {
    assert.equal(deployWroteNothing({ deployed: false, stage }), true, stage);
  }
  assert.equal(
    deployWroteNothing({ deployed: false, stage: "write", rolledBack: true }),
    true,
  );
  assert.equal(
    deployWroteNothing({ deployed: false, stage: "write", rolledBack: false }),
    false,
  );
  assert.equal(deployWroteNothing({ deployed: false, stage: "write" }), false);
  assert.equal(deployWroteNothing({ deployed: false }), false);
  assert.equal(deployWroteNothing(undefined), false);
});

async function windowsFixture(t) {
  const f=await fixture(t,"win32"),binding=f.bindings[f.bindingId];
  const listener=tls.createServer({cert:f.bundle.certificatePem,key:f.bundle.privateKeyPem},socket=>socket.end());
  await new Promise(resolve=>listener.listen(0,"127.0.0.1",resolve));t.after(()=>new Promise(resolve=>listener.close(resolve)));
  Object.assign(binding,{connector:"windows-material-iis-v1",serviceAccountSids:["S-1-5-82-123-456"],
    target:{type:"windows-iis",reference:"iis-web-01",store:"My",binding:{site:"Qualification",address:"127.0.0.1",port:listener.address().port,store:"My",sniHost:binding.probes[0].sni}},
    probes:[{...binding.probes[0],port:listener.address().port}]});
  let installed=false,bound=false,interrupted=false,imports=0,activations=0;
  const connector={withLock:work=>work(),preflight:()=>Promise.resolve(),
    import:()=>{imports++;installed=true;return Promise.resolve();},
    activate:()=>{activations++;if(interrupted)throw Object.assign(new Error(),{code:"material_windows_activation_failed"});bound=true;return Promise.resolve();},
    verify:()=>Promise.resolve(installed&&bound)};
  return {...f,binding,connector,interrupt:()=>{interrupted=true;},repair:()=>{bound=true;interrupted=false;},get imports(){return imports;},get activations(){return activations;}};
}
test("Windows consumer state is independent and a pinned retry verifies the actual TLS listener",async t=>{
  const f=await windowsFixture(t);let markers=0;
  const first=await f.deploy({windowsConnector:f.connector,onBeforeMutation:()=>{markers++;}});
  assert.equal(first.status,"succeeded");assert.equal(first.deploymentReceipt.servedVerified,true);assert.equal(markers,1);
  const duplicate=await f.deploy({windowsConnector:f.connector});assert.equal(duplicate.status,"succeeded");
  assert.equal(readRecord(f.record).uncertain,false);
  const otherId=crypto.randomUUID();f.bindings[otherId]={...f.binding,deploymentProfileRef:"other-site"};
  const other=await f.deploy({windowsConnector:f.connector,intent:{bindingId:otherId,deploymentProfileRef:"other-site"}});
  assert.equal(other.status,"succeeded");assert.equal(other.deploymentReceipt.materialVersionId,first.deploymentReceipt.materialVersionId);
  assert.notEqual(other.deploymentReceipt.bindingId,first.deploymentReceipt.bindingId);
  assert.equal(JSON.stringify(first).includes("PRIVATE KEY"),false);
  // A new, approved generation can explicitly select the same retained
  // material; generation order, rather than version order, fences rollback.
  assert.equal((await f.deploy({generation:3,windowsConnector:f.connector})).status,"succeeded");
  await assert.rejects(f.deploy({generation:2,windowsConnector:f.connector}),{code:"material_stale_generation"});
});
test("Windows interrupted activation requires verified local reconciliation and original signed intent retry",async t=>{
  const f=await windowsFixture(t);f.interrupt();
  const failed=await f.deploy({windowsConnector:f.connector});
  assert.equal(failed.status,"orphaned_unknown_effect");assert.equal(failed.deploymentReceipt.installed,true);assert.equal(failed.deploymentReceipt.servedVerified,false);
  await assert.rejects(f.deploy({windowsConnector:f.connector}),{code:"material_binding_uncertain"});
  const saved=readRecord(f.record);
  const options={job:{workspaceId:f.ids.workspaceId,agentId:"consumer-agent",materialDeployment:saved.intent},bindings:f.bindings,stateDir:path.join(f.directory,"state"),policyEngine:{checkTargetScope:()=>({allowed:true})},windowsConnector:f.connector,platform:"win32"};
  await assert.rejects(reconcilePinnedDeployment(options),{code:"material_reconciliation_mismatch"});
  f.repair();assert.equal((await reconcilePinnedDeployment(options)).reconciled,true);
  assert.equal((await f.deploy({windowsConnector:f.connector})).status,"succeeded");
});
test("Windows verification-only detects drift without import, activation, or a mutation marker",async t=>{
  const f=await windowsFixture(t);
  const result=await f.deploy({windowsConnector:f.connector,intent:{verificationOnly:true},onBeforeMutation:()=>assert.fail("mutation")});
  assert.equal(result.status,"failed");assert.equal(f.imports,0);assert.equal(f.activations,0);
});

test("Windows IIS refuses installed-only assurance before helpers, staging or reload", async t => {
  const f = await windowsFixture(t);
  filesOnly(f);
  await assert.rejects(f.deploy({ windowsConnector: f.connector, onBeforeMutation: () => assert.fail("mutation"),
    reload: () => assert.fail("reload") }), { code: "material_windows_policy_denied" });
  assert.equal(f.imports, 0); assert.equal(f.activations, 0);
  assert.equal(fs.existsSync(path.join(f.directory, "state")), false);
});

for (const [platform, type] of [["win32", "endpoint"], ["linux", "windows-iis"], ["darwin", "endpoint"], ["darwin", "windows-iis"]]) {
  test(`${platform} rejects shared ${type} before staging, reload or native mutation`, async t => {
    const f = await fixture(t, platform);
    f.bindings[f.bindingId].target.type = type;
    const untouched = () => assert.fail("unsupported combination reached execution");
    for (const verificationOnly of [false, true]) {
      await assert.rejects(f.deploy({ intent: { verificationOnly }, checkLease: untouched,
        reload: untouched, onBeforeMutation: untouched,
        windowsConnector: { withLock: untouched, import: untouched, activate: untouched } }),
      { code: "material_platform_unqualified" });
    }
    assert.equal(fs.existsSync(path.join(f.directory, "state")), false);
    assert.deepEqual(fs.readdirSync(f.deployDir), []);
    await assert.rejects(reconcilePinnedDeployment({
      job: { workspaceId: f.ids.workspaceId, agentId: "consumer-agent", materialDeployment: {
        ...f.ids, bindingId: f.bindingId, generation: 1, materialStoreRef: "customer",
        deploymentProfileRef: "fixture", profileRevision: 1, authorizationRevision: 1,
        verificationPolicy: "served",
      } }, bindings: f.bindings, stateDir: path.join(f.directory, "state"), policyEngine: {}, platform,
    }), { code: "material_platform_unqualified" });
    assert.equal(fs.existsSync(path.join(f.directory, "state")), false);
  });
}

test("Linux endpoint deployment still installs the pair, reloads and verifies served TLS", async t => {
  const f = await fixture(t);
  const listener = tls.createServer({ cert: f.bundle.certificatePem, key: f.bundle.privateKeyPem }, socket => socket.end());
  await new Promise(resolve => listener.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise(resolve => listener.close(resolve)));
  f.bindings[f.bindingId].probes[0].port = listener.address().port;
  let reloads = 0;
  const result = await f.deploy({ reload: async () => { reloads++; return true; } });
  assert.equal(result.status, "succeeded");
  assert.equal(result.deploymentReceipt.servedVerified, true);
  assert.equal(reloads, 1);
  assert.equal(fs.readFileSync(f.target.keyPath, "utf8"), f.bundle.privateKeyPem);
  assert.equal(readRecord(f.record).uncertain, false);
});

test("Linux trust deployment requires the pinned listener and its trusted full chain", async t => {
  const f = await fixture(t); fullChain(f);
  f.binding.verificationPolicy = "trust";
  const blocks = f.bundle.certificatePem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  assert.ok(blocks.length > 1);
  const caFile = path.join(f.directory, "trusted-ca.pem");
  const roots = fs.readFileSync(path.join(__dirname, "../verify/fixtures/leaf-fullchain.crt.pem"), "utf8").match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  fs.writeFileSync(caFile, roots.at(-1));
  const listener = tls.createServer({ cert: f.bundle.certificatePem, key: f.bundle.privateKeyPem }, socket => socket.end());
  await new Promise(resolve => listener.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise(resolve => listener.close(resolve)));
  f.binding.probes = [{ dialAddress: "127.0.0.1", port: listener.address().port,
    sni: f.bundle.sans.find(name => !name.includes("*")), trustCaFile: caFile }];
  const deployed = await f.deploy();
  assert.equal(deployed.status, "succeeded", deployed.errorMessage);
  assert.equal(deployed.deploymentReceipt.trustValidated, true);
  fs.writeFileSync(caFile, fs.readFileSync(path.join(__dirname, "../verify/fixtures/leaf.crt.pem")));
  const failed = await f.deploy({ generation: 2, verificationOnly: true });
  assert.equal(failed.status, "failed");
  assert.equal(failed.deploymentReceipt.installed, true);
  assert.equal(failed.deploymentReceipt.trustValidated, false);
});

test("Windows shared IIS refuses an untyped connector before any helper or filesystem effects", async t => {
  const f = await fixture(t, "win32");
  const binding = f.bindings[f.bindingId];
  Object.assign(binding, { connector: "powershell", serviceAccountSids: [],
    target: { type: "windows-iis", reference: "site", store: "My", binding: {
      site: "Review", address: "127.0.0.1", port: 9, store: "My", sniHost: binding.probes[0].sni,
    } } });
  const untouched = () => assert.fail("untyped connector reached execution");
  await assert.rejects(f.deploy({ checkLease: untouched, reload: untouched,
    windowsConnector: { withLock: untouched }, onBeforeMutation: untouched }),
  { code: "material_windows_policy_denied" });
  assert.equal(fs.existsSync(path.join(f.directory, "state")), false);
  assert.deepEqual(fs.readdirSync(f.deployDir), []);
});
test("Windows rejects wrong authorization, wrong hostname, broad ACLs and lease loss before import",async t=>{
  const f=await windowsFixture(t);
  await assert.rejects(f.deploy({windowsConnector:f.connector,intent:{authorizationRevision:2}}),{code:"material_binding_policy_denied"});
  const good=f.binding.probes[0].sni;f.binding.probes[0].sni="wrong-identity.test";f.binding.target.binding.sniHost="wrong-identity.test";
  await assert.rejects(f.deploy({windowsConnector:f.connector}),{code:"material_probe_identity_mismatch"});
  f.binding.probes[0].sni=good;f.binding.target.binding.sniHost=good;
  f.binding.serviceAccountSids=["S-1-1-0"];
  await assert.rejects(f.deploy({windowsConnector:f.connector}),{code:"material_windows_policy_denied"});
  f.binding.serviceAccountSids=[];
  await assert.rejects(f.deploy({windowsConnector:f.connector,checkLease:()=>{throw Object.assign(new Error(),{code:"material_lease_unavailable"});}}),{code:"material_lease_unavailable"});
  assert.equal(f.imports,0);assert.equal(fs.existsSync(f.record),false);
  let leases=0;
  const expired=await f.deploy({windowsConnector:f.connector,checkLease:()=>{
    if(++leases===3)throw Object.assign(new Error(),{code:"material_lease_unavailable"});
  }});
  assert.equal(expired.status,"failed");assert.equal(expired.errorMessage,"material_lease_unavailable");
  assert.equal(f.imports,0);assert.equal(fs.existsSync(f.record),false,"a revoked lease after native preflight still causes no import");
});
