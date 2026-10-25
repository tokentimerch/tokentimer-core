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

async function fixture(t) {
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
  function deploy({ generation = 1, reload = async () => true, windowsConnector, onBeforeMutation, intent = {}, checkLease = async () => {} } = {}) {
    return executePinnedDeployment({
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
          verificationPolicy: "served",
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
      fixtureLoopbackHttp: true,
    });
  }
  return { deploy, record, target, deployDir, bindings, bindingId, bundle, ids, directory };
}

const readRecord = (file) => JSON.parse(readProtectedFile(file, 16384));

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
  const f=await fixture(t),binding=f.bindings[f.bindingId];
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
  const options={job:{workspaceId:f.ids.workspaceId,agentId:"consumer-agent",materialDeployment:saved.intent},bindings:f.bindings,stateDir:path.join(f.directory,"state"),policyEngine:{checkTargetScope:()=>({allowed:true})},windowsConnector:f.connector};
  await assert.rejects(reconcilePinnedDeployment(options),{code:"material_reconciliation_mismatch"});
  f.repair();assert.equal((await reconcilePinnedDeployment(options)).reconciled,true);
  assert.equal((await f.deploy({windowsConnector:f.connector})).status,"succeeded");
});
test("Windows verification-only detects drift without import, activation, or a mutation marker",async t=>{
  const f=await windowsFixture(t);
  const result=await f.deploy({windowsConnector:f.connector,intent:{verificationOnly:true},onBeforeMutation:()=>assert.fail("mutation")});
  assert.equal(result.status,"failed");assert.equal(f.imports,0);assert.equal(f.activations,0);
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
