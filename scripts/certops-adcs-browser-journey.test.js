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
  assert.ok(trust.includes("'Root','CurrentUser'"));
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

test("CA confirmation selects the independently current visible key group despite historical ordering", () => {
  const certificate=(key,body,date)=>({keySha256:key,certificateB64:Buffer.from(body).toString("base64"),thumbprintSha1:crypto.createHash("sha1").update(body).digest("hex").toUpperCase(),notBefore:date});
  const current="a".repeat(64),historical="b".repeat(64);
  const old=certificate(historical,"historical-public-der","2030-01-01"),first=certificate(current,"current-earlier-public-der","2025-01-01"),latest=certificate(current,"current-renewed-public-der","2026-01-01");
  assert.equal(helper.currentAuthorityGroup([old,first,latest],current),latest);
  assert.throws(()=>helper.currentAuthorityGroup([old],current));
  assert.throws(()=>helper.currentAuthorityGroup([{...latest,thumbprintSha1:"0".repeat(40)}],current));
});
