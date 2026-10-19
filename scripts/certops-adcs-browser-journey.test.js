"use strict";
/** Pure native-browser proof checks; no browser/domain/certificate mutation. */
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  crypto = require("node:crypto"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");
const helper = require("../tests/e2e/helpers/certops-adcs-browser-journey");
function valid() {
  return {
    scope: helper.SCOPE,
    lifecycle: "renew-existing-inventory-not-first-issue-or-manual-job",
    scheduler: "production-default-sweep-not-background-worker-loop",
    browserEngine: "chromium",
    browserMutationCount: 6,
    successfulEnrollments: 1,
    fingerprints: ["a".repeat(64), "b".repeat(64)],
    spkiFingerprints: ["c".repeat(64), "d".repeat(64)],
    requestId: "123",
    enrollmentId: crypto.randomUUID(),
    jobId: crypto.randomUUID(),
    profileId: crypto.randomUUID(),
    issuerId: crypto.randomUUID(),
    ...Object.fromEntries(helper.FLAGS.map((flag) => [flag, true])),
  };
}
test("native browser proof requires every UI, scheduler, native and cleanup fact", () => {
  assert.equal(helper.verifyProof(valid()), true);
  for (const flag of helper.FLAGS) {
    const missing = valid();
    delete missing[flag];
    assert.throws(() => helper.verifyProof(missing));
    assert.throws(() => helper.verifyProof({ ...valid(), [flag]: false }));
  }
});
test("native browser proof rejects scope promotion, duplicate leaves and private artifacts", () => {
  for (const change of [
    { lifecycle: "browser-first-issuance" },
    { scheduler: "background-worker-loop" },
    { browserEngine: "mock" },
    { browserMutationCount: 0 },
    { successfulEnrollments: 0 },
    { requestId: "0" },
    { requestId: "4294967296" },
    { enrollmentId: "foreign" },
    { fingerprints: ["a".repeat(64), "a".repeat(64)] },
    { spkiFingerprints: ["a".repeat(64)] },
    { cookies: "private-browser-state" },
    { screenshot: "raw-browser-image" },
  ])
    assert.throws(() => helper.verifyProof({ ...valid(), ...change }));
});
test("owned browser failure preserves trust receipt and state for parent cleanup retry", async () => {
  const directory = fs.mkdtempSync(
      path.join(os.tmpdir(), "certops-browser-resource-"),
    ),
    receipt = path.join(directory, "browser-api-trust.json");
  try {
    fs.writeFileSync(receipt, "owned public trust receipt");
    const child = { pid: 123, exitCode: null, signalCode: null };
    let removals = 0;
    const server = {
      process: () => child,
      close: () => {
        return Promise.reject(new Error("controlled close failure"));
      },
      kill: () => {
        return Promise.reject(new Error("controlled kill failure"));
      },
    };
    const resource = helper.createOwnedBrowserResource({
      getServer: () => server,
      receipt,
      removeTrust: () => {
        removals++;
        fs.unlinkSync(receipt);
      },
    });
    await assert.rejects(resource.close(), /preserve browser trust receipt/);
    assert.equal(resource.hasLiveChild(), true);
    assert.equal(resource.hasOwnershipReceipt(), true);
    assert.equal(removals, 0);
    child.exitCode = 0;
    await resource.close();
    assert.equal(resource.hasLiveChild(), false);
    assert.equal(resource.hasOwnershipReceipt(), false);
    assert.equal(removals, 1);
  } finally {
    assert.equal(
      path.dirname(path.resolve(directory)),
      path.resolve(os.tmpdir()),
    );
    assert.ok(path.basename(directory).startsWith("certops-browser-resource-"));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
test("owned browser forced drain completes before exact trust cleanup", async () => {
  const directory = fs.mkdtempSync(
      path.join(os.tmpdir(), "certops-browser-resource-"),
    ),
    receipt = path.join(directory, "browser-api-trust.json");
  try {
    fs.writeFileSync(receipt, "owned public trust receipt");
    const child = { pid: 123, exitCode: null, signalCode: null },
      events = [];
    const server = {
      process: () => child,
      close: () => {
        events.push("close");
        return Promise.reject(new Error("controlled close failure"));
      },
      kill: () => {
        events.push("kill-and-drain");
        child.signalCode = "SIGKILL";
        return Promise.resolve();
      },
    };
    const resource = helper.createOwnedBrowserResource({
      getServer: () => server,
      receipt,
      removeTrust: () => {
        assert.equal(resource.hasLiveChild(), false);
        events.push("remove-owned-trust");
        fs.unlinkSync(receipt);
      },
    });
    await resource.close();
    assert.deepEqual(events, ["close", "kill-and-drain", "remove-owned-trust"]);
    assert.equal(resource.hasOwnershipReceipt(), false);
  } finally {
    assert.equal(
      path.dirname(path.resolve(directory)),
      path.resolve(os.tmpdir()),
    );
    assert.ok(path.basename(directory).startsWith("certops-browser-resource-"));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
test("native browser sources exist and optional bootstrap scripts preserve owned-lab boundaries", () => {
  assert.equal(helper.REQUIRED_SCENARIOS.length, 6);
  assert.equal(new Set(helper.REQUIRED_SCENARIOS).size, 6);
  for (const file of helper.REQUIRED_SOURCES)
    assert.equal(
      fs.statSync(path.resolve(__dirname, "..", file)).isFile(),
      true,
      file,
    );
  const control = fs.readFileSync(
    path.resolve(__dirname, "../infra/certops-adcs/browser-control-plane.sh"),
    "utf8",
  );
  assert.ok(control.includes("127.0.0.1:5173:8080"));
  assert.ok(control.includes('git -C "$workspace" rev-parse HEAD'));
  assert.ok(control.includes("--read-only"));
  assert.equal(control.includes("az vm create"), false);
  const guest = fs.readFileSync(
    path.resolve(__dirname, "../infra/certops-adcs/browser-windows-tools.ps1"),
    "utf8",
  );
  assert.ok(guest.includes("--frozen-lockfile"));
  assert.ok(guest.includes("playwright install chromium"));
  const trust = fs.readFileSync(
    path.resolve(__dirname, "../infra/certops-adcs/browser-api-trust.ps1"),
    "utf8",
  );
  assert.ok(trust.includes("'Root','LocalMachine'"));
  assert.ok(trust.includes("$env:CERTOPS_ADCS_DISPOSABLE_LAB -ne '1'"));
  assert.ok(trust.includes("User.Value -ne 'S-1-5-18'"));
  assert.ok(trust.includes("$owned.storeLocation -cne 'LocalMachine'"));
  assert.ok(trust.includes("if($owned.added)"));
  assert.ok(trust.includes("$store.Remove($entry)"));
});

test("comprehensive browser integration is mandatory outside isolated issuer, elapsed and retention profiles", () => {
  const root=path.resolve(__dirname,"..");
  const producer=fs.readFileSync(path.join(root,"tests/e2e/certops-adcs-real-e2e.test.js"),"utf8");
  assert.ok(producer.includes('if(!elapsedPending && !issuerSwitch)assert.equal(process.env.CERTOPS_ADCS_BROWSER,"1"'));
  assert.ok(producer.includes('assert.ok(++primaryPreflightCount<=18'));
  assert.ok(producer.includes('assert.equal(ownedBrowserPreflightJobIds.length,2)'));
  assert.ok(producer.includes("operation='adcs-preflight' AND id=ANY($2::uuid[])"));
  assert.ok(producer.includes('resource.hasLiveChild()||resource.hasOwnershipReceipt()'));
  const provision=fs.readFileSync(path.join(root,"infra/certops-adcs/provision-lab.ps1"),"utf8");
  assert.ok(provision.includes("if($IssuerReassignment -ne '1' -and $PendingElapsedQualification -ne '1' -and $Retention24hPrepare -ne '1' -and $AdcsTtl24hPrepare -ne '1' -and $RetentionCadencePrepare -ne '1'){Invoke-Stage 'windows-agent'"));
  assert.match(provision, /if\(\$IssuerReassignment -ne '1' -and \$PendingElapsedQualification -ne '1' -and \$Retention24hPrepare -ne '1' -and \$AdcsTtl24hPrepare -ne '1' -and \$RetentionCadencePrepare -ne '1'\)\{\s+Refresh-LabAuthentication/);
  assert.ok(provision.includes("Only the core AD CS lab is included"));
  assert.ok(!provision.includes("run-retention-cadence-prepare.ps1"));
  assert.ok(!provision.includes("run-ttl24h-prepare.ps1"));
});

test("CA confirmation uses public metadata without DER and verifies the independently observed native key", () => {
  const ca=new crypto.X509Certificate(fs.readFileSync(path.join(__dirname,"../packages/agent/reference/adcs-cmc/testdata/ca.cer")));
  const current=crypto.createHash("sha256").update(ca.publicKey.export({type:"spki",format:"der"})).digest("hex");
  const native={certificateB64:ca.raw.toString("base64")};
  const old={keySha256:"b".repeat(64),thumbprintSha1:"b".repeat(40),notBefore:"2030-01-01"};
  const first={keySha256:current,thumbprintSha1:"c".repeat(40),notBefore:"2025-01-01"};
  const latest={keySha256:current,thumbprintSha1:crypto.createHash("sha1").update(ca.raw).digest("hex").toUpperCase(),notBefore:"2026-01-01"};
  assert.equal(latest.certificateB64,undefined,"Actual public issuer shape contains no DER");
  assert.equal(helper.currentAuthorityGroup([old,first,latest],current,native),latest);
  assert.throws(()=>helper.currentAuthorityGroup([old],current,native));
  assert.throws(()=>helper.currentAuthorityGroup([{...latest,thumbprintSha1:"0".repeat(40)}],current,native));
  assert.throws(()=>helper.currentAuthorityGroup([latest],"0".repeat(64),native));
  assert.throws(()=>helper.currentAuthorityGroup([latest],current,{certificateB64:Buffer.from("wrong DER").toString("base64")}));
  assert.throws(()=>helper.currentAuthorityGroup([latest],current,{}));
});

test("package worker proof stays distinct from focused default-sweep qualification", () => {
  const proof = { ...valid(), scheduler: "production-maintenance-worker" };
  assert.throws(() => helper.verifyProof(proof));
  assert.equal(helper.verifyProof(proof, { workerDriven: true }), true);
  assert.throws(() => helper.verifyProof(valid(), { workerDriven: true }));
  assert.throws(() => helper.verifyProof({ ...proof, scheduler: "background-worker-loop" }, { workerDriven: true }));
});

test("native CA isolation runs before package acceptance adds another pass's requests",()=>{
  const provision=fs.readFileSync(path.resolve(__dirname,"../infra/certops-adcs/provision-lab.ps1"),"utf8");
  const focused=provision.indexOf("'CERTOPS_STAGE=real-enterprise-adcs-tests-passed'");
  const packaged=provision.indexOf("'CERTOPS_STAGE=operator-package-acceptance-passed'");
  assert.ok(focused>0 && focused<packaged);
  assert.ok(fs.readFileSync(path.resolve(__dirname,"../infra/certops-adcs/owned-ca-checkpoint.ps1"),"utf8").includes("Foreign agent request encountered in isolated checkpoint"));
});

test("actual native cleanup accounts for only dispatched browser preflights after an earlier failure",async()=>{
 const source=fs.readFileSync(path.join(__dirname,"../tests/e2e/certops-adcs-real-e2e.test.js"),"utf8");
 const body=source.match(/await clean\(async\(\)=>\{(const measured=Number[\s\S]*?gate\.report\.primaryNativePreflightDispatchCount=measured;)\}\);/)[1];
 const execute=new (Object.getPrototypeOf(async function(){}).constructor)("fixture","assert","primaryPreflightCount","elapsedPending","issuerSwitch","ownedBrowserPreflightJobIds","gate",body);
 const ids=["11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222"];
 async function check({count,failed=true,orphan=false,foreign=false,duplicate=false}){
  const owned=ids.slice(0,count);if(duplicate)owned.push(owned[0]);const gate={report:failed?{originalFailure:{errorClass:"AssertionError"}}:{}};
  const fixture={workspaceId:"owned",pool:{async query(sql,args){assert.equal(args[0],"owned");if(sql.includes("count(*)"))return {rows:[{count:2+owned.length+(orphan?1:0)}]};assert.deepEqual(args[1],owned);return {rows:owned.map(id=>({id:foreign?"33333333-3333-4333-8333-333333333333":id}))};}}};
  await execute(fixture,assert,2,false,false,owned,gate);return gate.report;
 }
 for(const count of [0,1,2]){const report=await check({count});assert.equal(report.browserNativePreflightDispatch.count,count);assert.equal(report.primaryNativePreflightDispatchCount,2+count);assert.ok(report.originalFailure);}
 await assert.rejects(check({count:0,failed:false}));await assert.rejects(check({count:1,failed:false}));
 assert.equal((await check({count:2,failed:false})).browserNativePreflightDispatch.count,2);
 await assert.rejects(check({count:0,orphan:true}));await assert.rejects(check({count:1,foreign:true}));await assert.rejects(check({count:1,duplicate:true}));
});
