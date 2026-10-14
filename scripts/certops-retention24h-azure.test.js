"use strict";
/** Controlled adapter decisions and workflow contracts only. No Azure, GitHub,
 * ScheduledTask, service, certificate, key or workflow operation runs here. */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const adapter = require("./certops-retention24h-azure");
const contract = require("./certops-retention24h-contract");
const root = path.resolve(__dirname, "..");
test("owned deletion polling can outlive three minutes and independently proves absence", () => {
  const name = "tt-certops-123-2", calls = [];
  adapter.waitForOwnedDeletion(name, {
    execute: (...args) => calls.push(args),
    query: args => { assert.deepEqual(args, ["group", "exists", "--name", name]); return false; },
  });
  assert.equal(calls.length, 1);
  const [file, args, binary, timeout] = calls[0];
  assert.equal(file, "az"); assert.equal(binary, false);
  assert.deepEqual(args, ["group", "wait", "--name", name, "--deleted", "--timeout", "600", "--interval", "15"]);
  assert.equal(timeout, 660000); assert.ok(timeout > Number(args[args.indexOf("--timeout") + 1]) * 1000);
});
test("owned deletion refuses timeout, failed transport, surviving groups and coerced absence", () => {
  const name = "tt-certops-123-2";
  for (const answer of [true, "false", null, undefined]) assert.throws(() => adapter.waitForOwnedDeletion(name, { execute() {}, query: () => answer }));
  let queried = false;
  assert.throws(() => adapter.waitForOwnedDeletion(name, { execute() { throw new Error("bounded poll timeout"); }, query() { queried = true; return false; } }), /bounded poll timeout/);
  assert.equal(queried, false);
  assert.throws(() => adapter.waitForOwnedDeletion(name, { execute() {}, query() { throw new Error("transport unavailable"); } }), /transport unavailable/);
  assert.throws(() => adapter.waitForOwnedDeletion("foreign", { execute() { throw new Error("must not invoke"); } }), { code: "ERR_ASSERTION" });
});
const created = "2026-10-14T00:00:00.000Z";
const at = (hours) =>
  new Date(Date.parse(created) + hours * contract.HOUR).toISOString();
const owner = {
  candidateSha: "a".repeat(40),
  runId: "123",
  runAttempt: "1",
  nonce: "b".repeat(64),
  vmResourceId:
    "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/tt-certops-123-1/providers/Microsoft.Compute/virtualMachines/windows-agent",
  vmId: "22222222-2222-2222-2222-222222222222",
  taskName: `TokenTimer-Retention24h-${"b".repeat(64)}`,
  nodeSha256: "c".repeat(64),
  keeperSha256: "d".repeat(64),
};
function observation() {
  return {
    ...owner,
    replacementCngCustodyVerified: true,
    replacementIisSniBindingVerified: true,
    actualPredecessorCertificateAbsent: false,
    actualPredecessorKeyAbsent: false,
    ...Object.fromEntries(
      [
        "taskXmlVerified",
        "vmIdentityVerified",
        "nodeHashVerified",
        "keeperHashVerified",
        "residentProcessVerified",
        "soleAgentStoppedAndDrained",
        "productionCutoverVerified",
        "nativeCustodyVerified",
        "trustedTlsVerified",
        "ledgerUnmodified",
      ].map((field) => [field, true]),
    ),
    principalSid: "S-1-5-18",
    taskState: "Running",
    processId: 1234,
    bootTime: created,
    processCreatedAt: at(1),
    nativeVerificationStartedAt: at(1.1),
    nativeVerificationFinishedAt: at(1.2),
    monotonicElapsedMs: 1000,
    verifiedCutoverAt: at(1),
    oldNotAfter: at(48),
    cleanupDeadline: at(25),
    taskXmlSha256: "e".repeat(64),
    configSha256: "f".repeat(64),
  };
}
function fixture() {
  const preparedLease = contract.createLease(owner, created),
    observed = observation();
  const lease = contract.attestHandoff(preparedLease, observed, at(2));
  const group = {
    name: "tt-certops-123-1",
    id: owner.vmResourceId.split("/providers/")[0],
    tags: {
      purpose: "certops-adcs-qualification",
      retentionPrepareKind: "certops-native-retention24h",
      retentionPrepareNonce: owner.nonce,
      retentionPrepareRunId: owner.runId,
      retentionPrepareRunAttempt: owner.runAttempt,
      candidateSha: owner.candidateSha,
      createdAt: created,
      ...adapter.leaseTags(lease),
    },
  };
  const vm = {
    id: owner.vmResourceId,
    vmId: owner.vmId,
    provisioningState: "Succeeded",
    timeCreated: at(0.1),
    tags: {
      purpose: "certops-adcs-qualification",
      candidateSha: owner.candidateSha,
    },
  };
  const run = {
    id: 123,
    run_attempt: 1,
    repository: { full_name: adapter.REPOSITORY },
    head_repository: { full_name: adapter.REPOSITORY },
    path: adapter.WORKFLOW,
    event: "workflow_dispatch",
    head_branch: "main",
    head_sha: owner.candidateSha,
    status: "completed",
    conclusion: "success",
    created_at: created,
    updated_at: at(3),
  };
  const deployment = {
    id: `${group.id}/providers/Microsoft.Resources/deployments/qualification`,
    name: "qualification",
    candidateSha: owner.candidateSha,
    provisioningState: "Succeeded",
    timestamp: at(0.2),
  };
  const jobs = {
    total_count: 1,
    jobs: [
      {
        id: 456,
        name: "prepare",
        run_id: 123,
        run_attempt: 1,
        head_sha: owner.candidateSha,
        status: "completed",
        conclusion: "success",
        started_at: created,
        completed_at: at(3),
      },
    ],
  };
  return { preparedLease, lease, observed, group, vm, run, deployment, jobs };
}
test("exact owned Azure identity/phase and immutable expiry are required", () => {
  const value = fixture();
  assert.equal(
    adapter.verifyAzure(value.lease, value.group, value.vm, "keeper-owned"),
    true,
  );
  for (const mutate of [
    (v) => (v.group.name = "tt-certops-999-1"),
    (v) => (v.group.tags.purpose = "other"),
    (v) => (v.group.tags.candidateSha = "f".repeat(40)),
    (v) => (v.group.tags.createdAt = at(1)),
    (v) => (v.group.tags.expiresAt = at(33)),
    (v) => (v.group.tags.retentionNonce = "f".repeat(64)),
    (v) => (v.vm.vmId = "33333333-3333-3333-3333-333333333333"),
    (v) => (v.vm.id = v.vm.id.replace("windows-agent", "foreign")),
    (v) => (v.vm.provisioningState = "Failed"),
  ]) {
    const bad = fixture();
    mutate(bad);
    assert.throws(() =>
      adapter.verifyAzure(bad.lease, bad.group, bad.vm, "keeper-owned"),
    );
  }
});
test("missing-artifact cleanup uses authenticated prepare job clock and native deployment chronology", () => {
  const value = fixture();
  assert.equal(
    adapter.taggedCleanupDecision(
      value.group,
      value.run,
      value.vm,
      value.deployment,
      Date.parse(at(31)),
      value.jobs,
    ),
    "retain",
  );
  value.group.tags.createdAt = at(100);
  value.group.tags.expiresAt = at(200);
  assert.equal(
    adapter.taggedCleanupDecision(
      value.group,
      value.run,
      value.vm,
      value.deployment,
      Date.parse(at(32)),
      value.jobs,
    ),
    "delete-conservative-orphan-cap",
  );
  value.run.conclusion = "cancelled";
  assert.equal(
    adapter.taggedCleanupDecision(
      value.group,
      value.run,
      value.vm,
      value.deployment,
      Date.parse(at(3)),
      value.jobs,
    ),
    "delete-failed-owner",
  );
  for (const mutate of [
    (v) => (v.run.repository.full_name = "foreign/core"),
    (v) => (v.run.run_attempt = 2),
    (v) => (v.run.event = "pull_request"),
    (v) => (v.run.head_branch = "feature"),
    (v) => (v.run.created_at = at(40)),
    (v) => (v.deployment.name = "foreign"),
    (v) => (v.deployment.candidateSha = "f".repeat(40)),
    (v) => (v.deployment.provisioningState = "Failed"),
    (v) => (v.deployment.timestamp = at(5)),
    (v) => (v.vm.timeCreated = at(-1)),
    (v) => (v.vm.tags.candidateSha = "f".repeat(40)),
  ]) {
    const bad = fixture();
    mutate(bad);
    assert.throws(() =>
      adapter.taggedCleanupDecision(
        bad.group,
        bad.run,
        bad.vm,
        bad.deployment,
        Date.parse(at(32)),
        bad.jobs,
      ),
    );
  }
});
test("signed artifact redirects refuse non-HTTPS, credentials, local and lookalike hosts", () => {
  assert.equal(
    adapter.allowedBlobUrl(
      "https://productionresultssa0.blob.core.windows.net/x?sig=public-fixture",
    ),
    "https://productionresultssa0.blob.core.windows.net/x?sig=public-fixture",
  );
  for (const value of [
    null,
    "http://productionresultssa0.blob.core.windows.net/x",
    "https://127.0.0.1/x",
    "https://blob.core.windows.net.attacker.test/x",
    "https://user:secret@fixture.blob.core.windows.net/x",
    "https://fixture.blob.core.windows.net:444/x",
    "https://api.github.com/x",
  ]) {
    assert.throws(() => adapter.allowedBlobUrl(value));
  }
});
test("artifact transport strips auth on manual signed redirect and enforces body bounds", async () => {
  // Controlled transport fixture, never a real GitHub response or native proof.
  const calls = [];
  const token = "controlled-transport-fixture";
  const bytes = await adapter.downloadArtifactZip(123, {
    token,
    fetchImpl: (url, options) => {
      calls.push({ url, options });
      return calls.length === 1
        ? new Response(null, {
            status: 302,
            headers: {
              location: "https://fixture.blob.core.windows.net/archive",
            },
          })
        : new Response(Buffer.from("bounded fixture"), { status: 200 });
    },
  });
  assert.equal(bytes.toString(), "bounded fixture");
  assert.equal(calls.length, 2);
  assert.equal(calls[0].options.headers.Authorization, `Bearer ${token}`);
  assert.equal(calls[0].options.redirect, "manual");
  assert.equal(calls[1].options.headers, undefined);
  assert.equal(calls[1].options.redirect, "manual");
  for (const variant of [
    "foreign-redirect",
    "redirect-chain",
    "oversized-header",
    "oversized-stream",
  ]) {
    let count = 0;
    await assert.rejects(() =>
      adapter.downloadArtifactZip(123, {
        token,
        fetchImpl: () => {
          count++;
          if (count === 1)
            return new Response(null, {
              status: 302,
              headers: {
                location:
                  variant === "foreign-redirect"
                    ? "https://attacker.example/archive"
                    : "https://fixture.blob.core.windows.net/archive",
              },
            });
          if (variant === "redirect-chain")
            return new Response(null, {
              status: 302,
              headers: { location: "https://foreign.example/archive" },
            });
          if (variant === "oversized-header")
            return new Response("x", {
              status: 200,
              headers: { "content-length": String(3 * 1024 * 1024) },
            });
          return new Response(Buffer.alloc(3 * 1024 * 1024), { status: 200 });
        },
      }),
    );
    assert.equal(count, variant === "foreign-redirect" ? 1 : 2);
  }
});
function sealedReceiptFixture() {
  const value = fixture();
  const generations = [
    "11111111-1111-1111-1111-111111111111",
    "22222222-2222-2222-2222-222222222222",
  ].map((id, i) => ({
    thumbprint: (i ? "B" : "A").repeat(40),
    containerName: `tokentimer-enr-${id}`,
    requestId: String(101 + i),
    enrollmentId: id,
    jobId: i
      ? "44444444-4444-4444-4444-444444444444"
      : "33333333-3333-3333-3333-333333333333",
    serial: i ? "02" : "01",
    spkiSha256: (i ? "b" : "a").repeat(64),
  }));
  const fixtureSources =
    require("./certops-retention24h-runtime").REQUIRED_SOURCES.map((file) => ({
      file,
      sha256: "a".repeat(64),
    }));
  const prep = {
    scope: "prepared-real-domain-adcs-retention24h-not-elapsed-qualified",
    startedAt: at(0.1),
    finishedAt: at(1.3),
    lease: value.preparedLease,
    configSha256: "f".repeat(64),
    verifiedCutoverAt: at(1),
    oldNotAfter: at(48),
    cleanupDeadline: at(25),
    task: value.observed,
    fixtureSources,
    collectorHelper: {
      file: "packages/agent/bin/tokentimer-adcs-chain-amd64.exe",
      sha256: "a".repeat(64),
    },
    ledgerIdentitySha256: "b".repeat(64),
    generations,
    sourceCount: fixtureSources.length,
    actualRequestIds: ["101", "102"],
    fingerprints: ["a".repeat(64), "b".repeat(64)],
    soleAgentStoppedAndDrained: true,
  };
  const receipt = {
    schemaVersion: 1,
    scope:
      "host-verified-original-four-hour-retention24h-not-elapsed-qualified",
    preparedLease: value.preparedLease,
    configSha256: prep.configSha256,
    observed: value.observed,
    observedAt: at(2),
    publicPreparation: prep,
  };
  return receipt;
}
test("sealed original receipt binds full public native manifest and refuses private extras", () => {
  const receipt = sealedReceiptFixture();
  assert.equal(adapter.verifyOriginalReceipt(receipt), true);
  for (const mutate of [
    (v) => (v.publicPreparation.rawConfig = "private"),
    (v) => (v.publicPreparation.generations[0].privateKey = "private"),
    (v) => (v.publicPreparation.task.rawTaskXml = "private"),
    (v) => (v.publicPreparation.lease.secret = "private"),
    (v) => v.publicPreparation.fixtureSources.pop(),
    (v) => (v.publicPreparation.collectorHelper.file = "../../private"),
    (v) => (v.observed.configSha256 = "0".repeat(64)),
    (v) => (v.publicPreparation.startedAt = "secret"),
  ]) {
    const bad = structuredClone(receipt);
    mutate(bad);
    assert.throws(() => adapter.verifyOriginalReceipt(bad));
  }
});
test("changing native producer executes once while a stable multi-chunk snapshot is assembled", () => {
  const lease = fixture().preparedLease;
  for (const corrupt of [false, true]) {
    const bytes = Buffer.from(
      JSON.stringify({
        scope: "controlled-transport-only",
        data: "x".repeat(3500),
      }),
    );
    const hash = crypto.createHash("sha256").update(bytes).digest("hex");
    let produced = 0,
      removed = 0,
      chunks = 0;
    const execute = (_lease, script) => {
      if (script.includes("CERTOPS_OBSERVATION_CREATE")) {
        produced++;
        assert.ok(script.includes("CONTROLLED_CHANGING_NATIVE_PRODUCER"));
        assert.equal(produced, 1);
        return { length: bytes.length, sha256: hash, fileIdentity: "123:456" };
      }
      assert.equal(
        script.includes("CONTROLLED_CHANGING_NATIVE_PRODUCER"),
        false,
      );
      if (script.includes("CERTOPS_OBSERVATION_CLEANUP")) {
        removed++;
        assert.match(script, /123:456/);
        assert.match(script, /Remove-Item -LiteralPath/);
        assert.doesNotMatch(script, /-Recurse/);
        return { removed: true };
      }
      const match = /ToBase64String\(\$b,([0-9]+),/.exec(script);
      assert.ok(match);
      const offset = Number(match[1]);
      chunks++;
      return {
        length: bytes.length,
        sha256: corrupt && offset > 0 ? "f".repeat(64) : hash,
        chunk: bytes
          .subarray(offset, Math.min(bytes.length, offset + 1024))
          .toString("base64"),
      };
    };
    const action = () =>
      adapter.readOwnedObservation(
        lease,
        "# CONTROLLED_CHANGING_NATIVE_PRODUCER",
        { execute, requestNonce: "9".repeat(64) },
      );
    if (corrupt) assert.throws(action);
    else assert.deepEqual(action(), JSON.parse(bytes));
    assert.equal(produced, 1);
    assert.equal(removed, 1);
    assert.ok(chunks >= 2);
  }
});
test("malformed snapshot receipt cannot authorize cleanup or enter generated commands", () => {
  const lease = fixture().preparedLease;
  for (const patch of [
    { length: "1; Invoke-UntrustedCommand" },
    { length: -1 },
    { length: 65537 },
    { fileIdentity: "123:456; evil" },
    { sha256: "not a digest" },
    { extra: "private" },
  ]) {
    let calls = 0;
    assert.throws(() =>
      adapter.readOwnedObservation(lease, "# controlled producer", {
        requestNonce: "9".repeat(64),
        execute: () => {
          calls++;
          return {
            length: 100,
            sha256: "a".repeat(64),
            fileIdentity: "123:456",
            ...patch,
          };
        },
      }),
    );
    assert.equal(
      calls,
      1,
      "Unvalidated receipt must preserve unknown snapshot instead of cleanup",
    );
  }
});
test("deallocation targets only the two actual owned infrastructure VMs and preserves member", () => {
  function data() {
    const value = fixture();
    const vms = ["domain-ca", "control-plane"].map((name, i) => ({
      ...structuredClone(value.vm),
      name,
      id: `${value.group.id}/providers/Microsoft.Compute/virtualMachines/${name}`,
      vmId: i
        ? "44444444-4444-4444-4444-444444444444"
        : "33333333-3333-3333-3333-333333333333",
    }));
    value.deployment.outputResources = [value.vm, ...vms].map((vm) => ({
      id: vm.id,
    }));
    return { ...value, vms };
  }
  const value = data();
  const selected = adapter.ownedDeallocationTargets(
    value.lease,
    value.group,
    value.vm,
    value.vms,
    value.deployment,
  );
  assert.deepEqual(
    selected.map((vm) => vm.name),
    ["domain-ca", "control-plane"],
  );
  assert.equal(
    selected.some((vm) => vm.resourceId === value.vm.id),
    false,
  );
  for (const mutate of [
    (v) => (v.vms[0].name = "windows-agent"),
    (v) => (v.vms[0].id = v.vm.id),
    (v) =>
      (v.vms[0].id = v.vms[0].id.replace("tt-certops-123-1", "foreign-group")),
    (v) => (v.vms[0].tags.candidateSha = "f".repeat(40)),
    (v) => (v.vms[0].tags.purpose = "foreign"),
    (v) => (v.vms[0].vmId = v.vm.vmId),
    (v) => (v.vms[0].timeCreated = at(-1)),
    (v) => (v.group.tags.retentionPrepareNonce = "f".repeat(64)),
    (v) => v.deployment.outputResources.pop(),
    (v) => (v.deployment.candidateSha = "f".repeat(40)),
    (v) => v.vms.pop(),
  ]) {
    const bad = data();
    mutate(bad);
    assert.throws(() =>
      adapter.ownedDeallocationTargets(
        bad.lease,
        bad.group,
        bad.vm,
        bad.vms,
        bad.deployment,
        undefined,
        bad.jobs,
      ),
    );
  }
});
test("abort permits exact current in-progress owner across partial handoff and refuses foreign/preexisting groups", () => {
  const value = fixture();
  value.run.status = "in_progress";
  value.run.conclusion = null;
  assert.equal(
    adapter.verifyAbortOwnership(
      value.group,
      value.run,
      owner.nonce,
      value.vm,
      value.deployment,
      undefined,
      value.jobs,
    ),
    true,
  );
  const original = sealedReceiptFixture();
  assert.equal(
    adapter.verifyAbortOwnership(
      value.group,
      value.run,
      owner.nonce,
      value.vm,
      value.deployment,
      original,
      value.jobs,
    ),
    true,
  );
  value.group.tags.expiresAt = at(4);
  delete value.group.tags.retentionPhase;
  value.deployment.provisioningState = "Failed";
  assert.equal(
    adapter.verifyAbortOwnership(
      value.group,
      value.run,
      owner.nonce,
      value.vm,
      value.deployment,
      undefined,
      value.jobs,
    ),
    true,
  );
  for (const mutate of [
    (v) => (v.group.tags.retentionPrepareNonce = "f".repeat(64)),
    (v) => delete v.group.tags.retentionPrepareKind,
    (v) => (v.group.tags.retentionPrepareRunAttempt = "2"),
    (v) => (v.group.tags.createdAt = at(-24)),
    (v) => (v.group.tags.candidateSha = "f".repeat(40)),
    (v) => (v.group.name = "tt-certops-999-1"),
    (v) => (v.run.path = ".github/workflows/ci.yml"),
    (v) => (v.run.event = "pull_request"),
    (v) => (v.run.head_branch = "feature"),
    (v) => (v.vm.id = v.vm.id.replace("windows-agent", "foreign")),
    (v) => (v.vm.tags.purpose = "foreign"),
    (v) => (v.vm.timeCreated = at(-1)),
    (v) =>
      (v.deployment.id = v.deployment.id.replace("qualification", "foreign")),
    (v) => (v.deployment.candidateSha = "f".repeat(40)),
    (v) => (v.deployment.timestamp = at(5)),
  ]) {
    const bad = fixture();
    mutate(bad);
    assert.throws(() =>
      adapter.verifyAbortOwnership(
        bad.group,
        bad.run,
        owner.nonce,
        bad.vm,
        bad.deployment,
        undefined,
        bad.jobs,
      ),
    );
  }
  assert.throws(() =>
    adapter.verifyAbortOwnership(
      fixture().group,
      fixture().run,
      owner.nonce,
      fixture().vm,
      fixture().deployment,
      {
        ...original,
        preparedLease: {
          ...original.preparedLease,
          vmId: "55555555-5555-5555-5555-555555555555",
        },
      },
      fixture().jobs,
    ),
  );
});
test("public observation and full-day result refuse extras and incomplete native/timing facts", () => {
  const observed = observation();
  assert.equal(adapter.publicObservation(observed), observed);
  for (const field of Object.keys(observed)) {
    const missing = { ...observed };
    delete missing[field];
    assert.throws(() => adapter.publicObservation(missing));
  }
  assert.throws(() =>
    adapter.publicObservation({ ...observed, rawCredential: "private" }),
  );
  const result = {
    scope: "resident-timing-only-native-oracles-required",
    startedAt: at(1),
    finishedAt: at(25.1),
    monotonicElapsedMs: contract.DAY + 1000,
    keptSweepCount: 24,
    maximumSweepGapMs: 3600000,
    preDeadlineObservedAt: at(24.9),
    collector: "production-default-clock",
    retentionHours: 24,
    candidateSha: owner.candidateSha,
    nonce: owner.nonce,
    pid: 1234,
    processCreatedAt: at(1),
    bootTime: created,
    configSha256: "f".repeat(64),
    nativeCustodyVerified: true,
    trustedTlsVerified: true,
    actualProductionLedgerVerified: true,
  };
  assert.equal(adapter.publicResidentResult(result), result);
  for (const patch of [
    { monotonicElapsedMs: contract.DAY - 1 },
    { maximumSweepGapMs: 65 * 60000 + 1 },
    { nativeCustodyVerified: false },
    { rawCsr: "private" },
    { retentionHours: 1 },
    { keptSweepCount: 0 },
  ])
    assert.throws(() => adapter.publicResidentResult({ ...result, ...patch }));
});
test("prepare workflows seal original artifact before extension and keep independent shared cleanup", () => {
  const workflow = fs.readFileSync(
    path.join(root, ".github/workflows/certops-retention24h-prepare.yml"),
    "utf8",
  );
  const seal = workflow.indexOf("-azure.js seal"),
    upload = workflow.indexOf("name: retention24h-original-"),
    handoff = workflow.indexOf("-azure.js handoff");
  assert.ok(seal > 0 && seal < upload && upload < handoff);
  assert.match(workflow, /if: failure\(\) \|\| cancelled\(\)/);
  for (const name of [
    "retention24h-prepare",
    "retention24h-finalize",
    "retention24h-janitor",
    "adcs-lab-janitor",
  ]) {
    const text = fs.readFileSync(
      path.join(root, `.github/workflows/certops-${name}.yml`),
      "utf8",
    );
    assert.ok(text.includes(name === "retention24h-prepare" ? "group: certops-retention24h-prepare-${{ github.run_id }}-${{ github.run_attempt }}" : "group: certops-retention24h-owned-azure-lifecycle"));
    assert.match(text, /cancel-in-progress: false/);
  }
  for (const name of ["finalize", "janitor"]) {
    const text = fs.readFileSync(
      path.join(root, `.github/workflows/certops-retention24h-${name}.yml`),
      "utf8",
    );
    assert.match(text, /environment: certops-adcs-cleanup/);
    assert.match(text, /schedule:/);
  }
  // Same copy is visible to helper/public fixture validation, not executable code.
  assert.match(
    crypto.createHash("sha256").update(workflow).digest("hex"),
    /^[a-f0-9]{64}$/,
  );
});

test("actual prepare job clock supports delayed approval and rejects ambiguous or foreign lifecycle", () => {
  const value = fixture();
  value.run.created_at = at(-24);
  const job = adapter.verifyPrepareJob(value.run, value.jobs);
  assert.equal(job.startedAt, created);
  assert.equal(
    adapter.verifyJobCreation(created, value.run, job),
    Date.parse(created),
  );
  assert.equal(
    adapter.verifyAbortOwnership(
      value.group,
      value.run,
      owner.nonce,
      value.vm,
      value.deployment,
      undefined,
      value.jobs,
    ),
    true,
  );
  assert.equal(
    adapter.taggedCleanupDecision(
      value.group,
      value.run,
      value.vm,
      value.deployment,
      Date.parse(at(31)),
      value.jobs,
    ),
    "retain",
  );
  assert.equal(
    adapter.taggedCleanupDecision(
      value.group,
      value.run,
      value.vm,
      value.deployment,
      Date.parse(at(32)),
      value.jobs,
    ),
    "delete-conservative-orphan-cap",
  );
  const omitted = structuredClone(value.jobs);
  delete omitted.jobs[0].run_attempt;
  assert.equal(adapter.verifyPrepareJob(value.run, omitted).startedAt, created);
  for (const mutate of [
    (v) => (v.jobs.total_count = 2),
    (v) => (v.jobs.jobs = []),
    (v) => v.jobs.jobs.push(v.jobs.jobs[0]),
    (v) => (v.jobs.jobs[0].name = "other"),
    (v) => (v.jobs.jobs[0].run_id = 999),
    (v) => (v.jobs.jobs[0].run_attempt = 2),
    (v) => (v.jobs.jobs[0].head_sha = "f".repeat(40)),
    (v) => (v.jobs.jobs[0].started_at = null),
    (v) => (v.jobs.jobs[0].started_at = at(-25)),
    (v) => (v.jobs.jobs[0].completed_at = at(-1)),
    (v) => (v.jobs.jobs[0].completed_at = at(4)),
    (v) => (v.jobs.jobs[0].status = "queued"),
    (v) => (v.jobs.jobs[0].conclusion = "failure"),
    (v) => {
      v.jobs.jobs[0].status = "in_progress";
      v.jobs.jobs[0].completed_at = null;
    },
  ]) {
    const bad = structuredClone(value);
    mutate(bad);
    assert.throws(() => adapter.verifyPrepareJob(bad.run, bad.jobs));
  }
  for (const timestamp of [at(-0.01), at(4.01)])
    assert.throws(() => adapter.verifyJobCreation(timestamp, value.run, job));
  const precision = structuredClone(value);
  precision.run.updated_at = at(5);
  precision.jobs.jobs[0].completed_at = at(5);
  const prepared = adapter.verifyPrepareJob(precision.run, precision.jobs);
  assert.equal(
    adapter.verifyJobCreation(at(-0.001), precision.run, prepared),
    Date.parse(at(-0.001)),
  );
  assert.equal(
    adapter.verifyJobCreation(at(4.001), precision.run, prepared),
    Date.parse(at(4.001)),
  );
  const active = structuredClone(value);
  active.run.status = "in_progress";
  active.run.conclusion = null;
  active.jobs.jobs[0].status = "in_progress";
  active.jobs.jobs[0].completed_at = null;
  assert.equal(
    adapter.verifyPrepareJob(active.run, active.jobs).completedAt,
    null,
  );
});
