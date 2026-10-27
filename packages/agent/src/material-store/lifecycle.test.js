"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");
const { readProtectedFile, writeProtectedJson } = require("./index");
const { applyRestrictivePermissions } = require("../platform");
const { computeCertificateFingerprint, parseDnsSans } = require("../verify");
const { executePinnedDeployment, reconcilePinnedDeployment, deployWroteNothing } = require("./lifecycle");

test("calendar enforcement refuses a delayed deployment before material fetch or service writes", async t=>{
  const f=await fixture(t),options=f.options();
  options.job.materialDeployment.activationPolicy={method:"reload",disruptive:true,requiresApproval:true,timezone:"UTC",windows:[],blackouts:[],validUntil:null,emergency:null};
  await assert.rejects(()=>executePinnedDeployment(options),{code:"material_maintenance_window_closed"});
  assert.equal(fs.existsSync(f.record),false);
});

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
      probes: [{ dialAddress: "127.0.0.1", port: 9, sni: "fixture.test" }],
    },
  };
  const record = path.join(
    directory,
    "state",
    "material-bindings",
    `${bindingId}.json`,
  );
  function options({ generation = 1, reload = async () => true, policy = bindings[bindingId].verificationPolicy, verificationOnly = false, checkLease = async () => {}, recoveryOnly = false } = {}) {
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
        },
      },
      stores,
      bindings,
      stateDir: path.join(directory, "state"),
      policyEngine: { checkPath: () => ({ allowed: true }) },
      checkLease,
      reload,
      recoveryOnly,
      fixtureLoopbackHttp: true,
    };
  }
  const deploy = (input) => executePinnedDeployment(options(input));
  return { deploy, options, binding: bindings[bindingId], record, target, deployDir };
}

const readRecord = (file) => JSON.parse(readProtectedFile(file, 16384));

function filesOnly(f) {
  f.binding.verificationPolicy = "installed";
  delete f.binding.reloadService;
  f.binding.probes = [];
}

test("files-only delivery writes and reads back the actual pair without reload or TLS", async (t) => {
  const f = await fixture(t);
  filesOnly(f);
  t.mock.method(require("node:tls"), "connect", () => assert.fail("files-only must not probe TLS"));
  const result = await f.deploy({ reload: () => assert.fail("files-only must not reload") });
  assert.equal(result.status, "succeeded");
  assert.ok(new crypto.X509Certificate(fs.readFileSync(f.target.certPath)).checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(f.target.keyPath))));
  for (const key of ["fetched", "installed"]) assert.equal(result.deploymentReceipt[key], true);
  for (const key of ["bound", "servedVerified", "trustValidated"]) assert.equal(result.deploymentReceipt[key], false);
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
