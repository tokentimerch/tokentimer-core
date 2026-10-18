/**
 * Regression coverage: Windows profile evidence binds actual recovery journey and output-privacy sources.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const test = require("node:test"),
  assert = require("node:assert/strict"),
  crypto = require("node:crypto"),
  fs = require("node:fs"),
  path = require("node:path");
const { supplementalSources } = require("./certops-stack-reporter");

test("installed verification rollback reporter requires actual bounded sidecar for all five profiles",()=>{
 const h=require("../tests/e2e/helpers/certops-windows-installed-verify-rollback"),{fixture}=require("./fixtures/certops-windows-installed-verify-rollback.cjs"),{installedVerifyRollbackProof:read}=require("./certops-stack-reporter");
 const root=fs.mkdtempSync(path.join(path.resolve(__dirname,"../.build"),"verify-rollback-reporter-")),name="real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence";
 try{fs.mkdirSync(path.join(root,"qualification-results"));for(const profile of ["rsa-2048","rsa-3072","rsa-4096","ec-p256","ec-p384"]){const scope="real-agent-windows-acme-iis/"+profile,file=path.join(root,"qualification-results",`windows-installed-verify-rollback-${profile}.json`);assert.throws(()=>read(scope,name,root));fs.writeFileSync(file,JSON.stringify(fixture()));assert.deepEqual(read(scope,name,root),fixture());for(const patch of [{[h.FLAGS[0]]:false},{privateNative:"sentinel"},{transientNewBindingObservationQualified:true}]){fs.writeFileSync(file,JSON.stringify({...fixture(),...patch}));assert.throws(()=>read(scope,name,root));}fs.unlinkSync(file);}
 assert.equal(read("real-agent-acme-filesystem",name,root),undefined);assert.throws(()=>read("real-agent-windows-acme-iis/unknown",name,root));
 }finally{fs.rmSync(root,{recursive:true});}
});
test("Windows profile evidence binds public admission, recovery and output-privacy sources", () => {
  const sources = supplementalSources("real-agent-windows-acme-iis/rsa-2048");
  assert.equal(new Set(sources.map((item) => item.file)).size, sources.length);
  for (const item of sources)
    assert.equal(
      item.sha256,
      crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.resolve(__dirname, "..", item.file)))
        .digest("hex"),
    );
  for (const file of [
    "scripts/certops-installer-pe.test.ps1",
    ...require("../tests/e2e/helpers/certops-windows-key-reuse-refusal")
      .requiredSources,
    ...require("../tests/e2e/helpers/certops-windows-installed-iis-refusal")
      .REQUIRED_SOURCES,
    "tests/e2e/helpers/certops-windows-public-issuance.js",
    "tests/e2e/helpers/certops-windows-installed-handoff.js",
    "tests/e2e/helpers/certops-windows-registration-job.ps1",
    ".github/workflows/certops-windows-e2e.yml",
    "tests/e2e/helpers/certops-api-fixture.js",
    "tests/e2e/helpers/certops-windows-reregistration.js",
    "tests/e2e/helpers/certops-windows-capability-refresh.js",
    "tests/e2e/helpers/certops-windows-output-child.js",
    "tests/e2e/helpers/certops-windows-output-privacy.js",
    "tests/e2e/windows-real-journey.js",
  ])
    assert.ok(
      sources.some((item) => item.file === file),
      `Required Windows admission/recovery source missing: ${file}`,
    );
});
test("unrelated and environment-supplied scope paths cannot select arbitrary source", () => {
  assert.equal(supplementalSources("agent-protocol-api-worker"), undefined);
  assert.equal(supplementalSources("../../secret"), undefined);
});
test("Every committed Linux ACME scope binds current actual journey and Pebble producer", () => {
  for (const scope of [
    "real-agent-acme-filesystem",
    "real-agent-acme-eab-filesystem",
    "real-agent-acmesh-filesystem",
    "real-agent-acmesh-eab-filesystem",
    "real-agent-alpine-certbot",
    "real-agent-alpine-acmesh",
  ]) {
    const sources = supplementalSources(scope);
    const declared = require("./certops-qualification-manifest").slots.find(slot=>slot.suite===scope).requiredSources;
    assert.deepEqual(sources.map(item=>item.file).sort(),[...declared].sort());
    for(const file of require("../tests/e2e/helpers/certops-acme-background-renewals").REQUIRED_SOURCES)assert.ok(sources.some(item=>item.file===file));
    for (const item of sources)
      assert.equal(
        item.sha256,
        crypto
          .createHash("sha256")
          .update(fs.readFileSync(path.resolve(__dirname, "..", item.file)))
          .digest("hex"),
      );
  }
  assert.equal(
    supplementalSources("real-agent-acme-filesystem/../../secret"),
    undefined,
  );
});

test("installed IIS sidecar reporter validates real public file lookup for every key profile", () => {
  const h = require("../tests/e2e/helpers/certops-windows-installed-iis-refusal"),
    { installedIisRefusalProof } = require("./certops-stack-reporter"),
    base = path.resolve(__dirname, "../.build");
  fs.mkdirSync(base, { recursive: true });
  const root = fs.mkdtempSync(path.join(base, "iis-refusal-reporter-"));
  assert.ok(
    path.relative(base, root) && !path.relative(base, root).startsWith(".."),
  );
  fs.mkdirSync(path.join(root, "qualification-results"));
  const proof = {
      scope: h.SCOPE,
      jobId: "11111111-1111-1111-1111-111111111111",
      claimId: "22222222-2222-2222-2222-222222222222",
      ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
    },
    name =
      "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence";
  try {
    for (const profile of [
      "rsa-2048",
      "rsa-3072",
      "rsa-4096",
      "ec-p256",
      "ec-p384",
    ]) {
      const scope = `real-agent-windows-acme-iis/${profile}`,
        file = path.join(
          root,
          "qualification-results",
          `windows-installed-iis-refusal-${profile}.json`,
        );
      assert.throws(() => installedIisRefusalProof(scope, name, root));
      fs.writeFileSync(file, JSON.stringify(proof), { flag: "wx" });
      assert.deepEqual(installedIisRefusalProof(scope, name, root), proof);
      for (const change of [
        { claimBoundFailureAudit: false },
        { scope: "direct-executor" },
        { privateCngReceipt: "must-not-qualify" },
      ]) {
        fs.writeFileSync(file, JSON.stringify({ ...proof, ...change }));
        assert.throws(() => installedIisRefusalProof(scope, name, root));
      }
      fs.unlinkSync(file);
    }
    assert.equal(
      installedIisRefusalProof("real-agent-acme-filesystem", name, root),
      undefined,
    );
    assert.throws(() =>
      installedIisRefusalProof(
        "real-agent-windows-acme-iis/unknown",
        name,
        root,
      ),
    );
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});

test("installed Unicode paths sidecar reporter validates real public file lookup for every key profile", () => {
  const h = require("../tests/e2e/helpers/certops-windows-installed-paths"),
    { installedPathsProof } = require("./certops-stack-reporter"),
    base = path.resolve(__dirname, "../.build");
  fs.mkdirSync(base, { recursive: true });
  const root = fs.mkdtempSync(path.join(base, "unicode-paths-reporter-"));
  assert.ok(
    path.relative(base, root) && !path.relative(base, root).startsWith(".."),
  );
  fs.mkdirSync(path.join(root, "qualification-results"));
  const proof = {
      scope: h.SCOPE,
      ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
    },
    name =
      "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence";
  try {
    for (const profile of [
      "rsa-2048",
      "rsa-3072",
      "rsa-4096",
      "ec-p256",
      "ec-p384",
    ]) {
      const scope = `real-agent-windows-acme-iis/${profile}`,
        file = path.join(
          root,
          "qualification-results",
          `windows-installed-paths-${profile}.json`,
        );
      assert.throws(() => installedPathsProof(scope, name, root));
      fs.writeFileSync(file, JSON.stringify(proof), { flag: "wx" });
      assert.deepEqual(installedPathsProof(scope, name, root), proof);
      for (const change of [
        { actualSystemHostAndChild: false },
        { scope: "direct-executor" },
        { privateCngReceipt: "must-not-qualify" },
      ]) {
        fs.writeFileSync(file, JSON.stringify({ ...proof, ...change }));
        assert.throws(() => installedPathsProof(scope, name, root));
      }
      fs.unlinkSync(file);
    }
    assert.equal(
      installedPathsProof("real-agent-acme-filesystem", name, root),
      undefined,
    );
    assert.throws(() =>
      installedPathsProof("real-agent-windows-acme-iis/unknown", name, root),
    );
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});

test('installed native crash reporter requires bounded current facts for every key profile',()=>{
 const os=require('node:os'),h=require('../tests/e2e/helpers/certops-windows-owned-process'),reporter=require('./certops-stack-reporter');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'certops-crash-reporter-')),name='real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence';
 try{fs.mkdirSync(path.join(root,'qualification-results'));for(const profile of ['rsa-2048','rsa-3072','rsa-4096','ec-p256','ec-p384']){
 const scope='real-agent-windows-acme-iis/'+profile,file=path.join(root,'qualification-results',`windows-native-crash-${profile}.json`);
 assert.throws(()=>reporter.installedCrashProof(scope,name,root));const proof={scope:'installed-system-native-handle-crash-fixture-lease-recovery',...Object.fromEntries(h.PUBLIC_FLAGS.map(flag=>[flag,true])),atomicTreeContainmentQualified:false,productionLeaseGraceQualified:false};fs.writeFileSync(file,JSON.stringify(proof));assert.deepEqual(reporter.installedCrashProof(scope,name,root),proof);
 for(const key of Object.keys(proof)){const bad={...proof};delete bad[key];fs.writeFileSync(file,JSON.stringify(bad));assert.throws(()=>reporter.installedCrashProof(scope,name,root));}
 }assert.equal(reporter.installedCrashProof('real-agent-acme-filesystem',name,root),undefined);}finally{fs.rmSync(root,{recursive:true});}
});
