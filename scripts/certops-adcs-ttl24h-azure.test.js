"use strict";
/** Offline public-controller contracts only. No Azure/GitHub/native action. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  crypto = require("node:crypto");
const adapter = require("./certops-adcs-ttl24h-azure"),
  contract = require("./certops-adcs-ttl24h-contract");
const { prepared, iso, uuid } = require("./fixtures/certops-adcs-ttl24h.cjs");
function observed(p = prepared()) {
  return {
    ...Object.fromEntries(
      contract.IDENTITIES.map((key) => [key, p.lease[key]]),
    ),
    preparedSha256: contract.preparedDigest(p),
    taskXmlSha256: "c".repeat(64),
    processId: 1001,
    processCreatedAt: iso(31000),
    bootTime: p.bootTime,
    principalSid: "S-1-5-18",
    taskState: "Running",
    nativeVerificationStartedAt: iso(32000),
    nativeVerificationFinishedAt: iso(33000),
    monotonicElapsedMs: 1000,
    ...Object.fromEntries(
      adapter.OBSERVED_KEYS.slice(-5).map((key) => [key, true]),
    ),
  };
}
function original() {
  const p = prepared(),
    infrastructureOwnership = ["domain-ca", "control-plane"].map(
      (name, index) => ({
        name,
        resourceId: p.lease.vmResourceId.replace("windows-agent", name),
        vmId: uuid(String(index + 3)),
        createdAt: iso(1000),
      }),
    );
  const control = infrastructureOwnership[1];
  return {
    schemaVersion: 1,
    kind: contract.KIND,
    lease: p.lease,
    publicPreparation: p,
    taskObserved: observed(p),
    infrastructureOwnership,
    controlPlaneObserved: {
      resourceId: control.resourceId,
      vmId: control.vmId,
      candidateSha: p.lease.candidateSha,
      observedAt: iso(35000),
      composeServices: ["api", "mailhog", "postgres"],
      noStandaloneCertOpsWorker: true,
      containerIds: ["api", "mailhog", "postgres"].map((service, i) => ({
        service,
        id: String(i + 1).repeat(64),
      })),
    },
  };
}
function owner(p = prepared()) {
  return {
    id: Number(p.lease.runId),
    run_attempt: Number(p.lease.runAttempt),
    repository: { full_name: adapter.REPOSITORY },
    head_repository: { full_name: adapter.REPOSITORY },
    path: adapter.WORKFLOW,
    event: "workflow_dispatch",
    head_branch: "main",
    head_sha: p.lease.candidateSha,
    status: "in_progress",
    conclusion: null,
    created_at: iso(-2 * contract.DAY),
    updated_at: iso(100000),
  };
}
test("TTL original custody has exact closed native/task/control identities", () => {
  const value = original();
  assert.equal(adapter.verifyOriginal(value), true);
  for (const key of Object.keys(value)) {
    const bad = structuredClone(value);
    delete bad[key];
    assert.throws(() => adapter.verifyOriginal(bad), key);
  }
  for (const patch of [
    { kind: "certops-native-retention24h" },
    { credential: "private" },
  ])
    assert.throws(() => adapter.verifyOriginal({ ...value, ...patch }));
  for (const patch of [
    { principalSid: "S-1-5-32-544" },
    { processId: 0 },
    { taskState: "Ready" },
    { deferredUnacceptedNativeCustodyVerified: false },
    { preparedSha256: "f".repeat(64) },
  ])
    assert.throws(() =>
      adapter.verifyObserved(
        { ...value.taskObserved, ...patch },
        value.publicPreparation,
      ),
    );
});
test("TTL handoff preserves exact original creation, deadline and resident process", () => {
  const value = original(),
    lease = adapter.extendLease(value, value.taskObserved, iso(36000));
  assert.equal(lease.phase, "resident-owned");
  assert.equal(lease.expiresAt, value.lease.hardExpiresAt);
  for (const patch of [
    { processId: 1002 },
    { taskXmlSha256: "f".repeat(64) },
    { bootTime: iso(0) },
  ])
    assert.throws(() =>
      adapter.extendLease(
        value,
        { ...value.taskObserved, ...patch },
        iso(36000),
      ),
    );
  assert.throws(() =>
    adapter.extendLease(value, value.taskObserved, value.lease.expiresAt),
  );
});
test("actual prepare job start permits delayed protected approval and refuses wrong attempt or head", () => {
  const run = owner(),
    job = {
      id: 99,
      run_id: run.id,
      head_sha: run.head_sha,
      name: "prepare",
      status: "in_progress",
      started_at: iso(-1000),
      completed_at: null,
    },
    response = { total_count: 1, jobs: [job] };
  const verified = adapter.verifyPrepareJob(run, response);
  assert.equal(
    adapter.verifyJobCreation(iso(0), run, verified),
    Date.parse(iso(0)),
  );
  for (const patch of [
    { run_id: 999 },
    { head_sha: "f".repeat(40) },
    { run_attempt: 3 },
    { name: "other" },
    { started_at: iso(-3 * contract.DAY) },
  ])
    assert.throws(() =>
      adapter.verifyPrepareJob(run, {
        ...response,
        jobs: [{ ...job, ...patch }],
      }),
    );
  assert.throws(() =>
    adapter.verifyPrepareJob(run, { total_count: 2, jobs: [job, job] }),
  );
  assert.throws(() =>
    adapter.verifyOwner(
      { ...run, path: ".github/workflows/other.yml" },
      prepared().lease,
    ),
  );
  assert.throws(() =>
    adapter.verifyJobCreation(iso(contract.INITIAL + 10000), run, verified),
  );
});
test("original infrastructure and control plane cannot be replaced or gain scheduler services", () => {
  const value = original();
  for (const mutate of [
    (v) => (v.infrastructureOwnership[0].vmId = v.lease.vmId),
    (v) => (v.infrastructureOwnership[0].resourceId += "foreign"),
    (v) => (v.controlPlaneObserved.vmId = uuid("f")),
    (v) => v.controlPlaneObserved.composeServices.push("worker"),
    (v) =>
      (v.controlPlaneObserved.containerIds[1].id =
        v.controlPlaneObserved.containerIds[0].id),
    (v) => (v.controlPlaneObserved.noStandaloneCertOpsWorker = false),
  ]) {
    const bad = structuredClone(value);
    mutate(bad);
    assert.throws(() => adapter.verifyOriginal(bad));
  }
});
test("changing native producer executes once while a stable multi-chunk snapshot is assembled", () => {
  const lease = prepared().lease;
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

test("native finalization cannot begin without full bounded phase and deletion headroom", () => {
  const lease = prepared().lease,
    end = Date.parse(lease.hardExpiresAt);
  assert.equal(adapter.NATIVE_FINISH_TIMEOUT, 20 * 60000);
  for (const minutes of [40, 45]) {
    adapter.requireFinalizationBudget(
      lease,
      minutes,
      end - minutes * 60000 - 1,
    );
    assert.throws(() =>
      adapter.requireFinalizationBudget(lease, minutes, end - minutes * 60000),
    );
    assert.throws(() => adapter.requireFinalizationBudget(lease, minutes, end));
  }
  assert.throws(() =>
    adapter.requireFinalizationBudget(lease, 1, end - 600000),
  );
  const fs = require("node:fs"),
    yaml = require("node:module").createRequire(
      require.resolve(
        require("node:path").join(
          __dirname,
          "../node_modules/mocha/package.json",
        ),
      ),
    )("js-yaml");
  const workflow = yaml.load(
    fs.readFileSync(
      require("node:path").join(
        __dirname,
        "../.github/workflows/certops-adcs-ttl24h-finalize.yml",
      ),
      "utf8",
    ),
  );
  assert.equal(workflow.jobs.finalize["timeout-minutes"], 60);
});

test("cleanup uses immutable lease authority and conservative job-start fallback, never mutable expiry tags", () => {
  const value = original(),
    run = owner(),
    job = { startedAt: iso(0) },
    reference = {
      id: 17,
      name: `adcs-ttl24h-original-${value.lease.runAttempt}-${value.lease.nonce}`,
      archiveSha256: "a".repeat(64),
    };
  const handed = {
    ...structuredClone(value),
    lease: adapter.extendLease(value, value.taskObserved, iso(36000)),
    originalArtifact: reference,
    handoffObserved: value.taskObserved,
  };
  assert.equal(
    adapter.cleanupDecision(
      value,
      null,
      run,
      job,
      Date.parse(iso(contract.INITIAL)) - 1,
    ).delete,
    false,
  );
  assert.equal(
    adapter.cleanupDecision(
      value,
      null,
      run,
      job,
      Date.parse(iso(contract.INITIAL)),
    ).delete,
    true,
  );
  assert.equal(
    adapter.cleanupDecision(
      value,
      handed,
      run,
      job,
      Date.parse(iso(contract.DAY)),
    ).delete,
    false,
  );
  assert.equal(
    adapter.cleanupDecision(
      value,
      handed,
      run,
      job,
      Date.parse(iso(contract.MAX)),
    ).delete,
    true,
  );
  assert.equal(
    adapter.cleanupDecision(
      null,
      null,
      run,
      job,
      Date.parse(iso(contract.MAX)) - 1,
    ).delete,
    false,
  );
  assert.equal(
    adapter.cleanupDecision(null, null, run, job, Date.parse(iso(contract.MAX)))
      .delete,
    true,
  );
  assert.equal(
    adapter.cleanupDecision(
      null,
      null,
      { ...run, status: "completed", conclusion: "failure" },
      job,
      Date.parse(iso(0)),
    ).delete,
    true,
  );
  const changed = structuredClone(handed);
  changed.lease.hardExpiresAt = iso(contract.MAX + 1000);
  assert.throws(() =>
    adapter.cleanupDecision(
      value,
      changed,
      run,
      job,
      Date.parse(iso(contract.DAY)),
    ),
  );
});

test("actual controller wrapper binds full sources, completed task and native proof into the strict release cell", () => {
  const fs = require("node:fs"),
    path = require("node:path"),
    root = path.resolve(__dirname, ".."),
    value = original(),
    p = value.publicPreparation;
  p.sources = require("./certops-adcs-ttl24h-sources").REQUIRED_SOURCES.map(
    (file) => ({
      file,
      sha256: crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.join(root, file)))
        .digest("hex"),
    }),
  );
  value.taskObserved = observed(p);
  const reference = {
      id: 17,
      name: `adcs-ttl24h-original-${value.lease.runAttempt}-${value.lease.nonce}`,
      archiveSha256: "a".repeat(64),
    },
    handoff = {
      ...structuredClone(value),
      lease: adapter.extendLease(value, value.taskObserved, iso(36000)),
      originalArtifact: reference,
      handoffObserved: value.taskObserved,
    };
  const proof = {
    ...require("./fixtures/certops-adcs-ttl24h-proof.cjs").fixture().proof,
    preparedSha256: contract.preparedDigest(p),
    processId: value.taskObserved.processId,
    processCreatedAt: value.taskObserved.processCreatedAt,
    taskXmlSha256: value.taskObserved.taskXmlSha256,
  };
  const timing = {
    scope: "resident-adcs-ttl24h-timing-only-native-oracles-required",
    candidateSha: p.lease.candidateSha,
    nonce: p.lease.nonce,
    vmId: p.lease.vmId,
    processId: proof.processId,
    bootTime: p.bootTime,
    processCreatedAt: new Date(proof.processCreatedAt).toISOString(),
    startedAt: proof.residentStartedAt,
    finishedAt: proof.residentFinishedAt,
    monotonicElapsedMs: proof.monotonicElapsedMs,
    preDeadlineObservedAt: proof.preDeadlineObservedAt,
    keptObservationCount: proof.keptObservationCount,
    maximumObservationGapMs: proof.maximumObservationGapMs,
    preparedSha256: proof.preparedSha256,
  };
  const completed = {
    ...value.taskObserved,
    taskState: "Ready",
    nativeVerificationStartedAt: iso(contract.DAY + 40000),
    nativeVerificationFinishedAt: iso(contract.DAY + 41000),
    residentTiming: timing,
  };
  const args = {
    original: value,
    handoff,
    originalArtifact: reference,
    handoffArtifact: {
      ...reference,
      id: 18,
      name: reference.name.replace("-original-", "-ownership-"),
    },
    completed,
    proof,
    cleanupFinishedAt: iso(contract.DAY + 600000),
    finalizer: {},
  };
  const report = adapter.qualificationReport(args),
    slot =
      require("./certops-qualification-manifest").slots.find(
        (row) => row.suite === report.suite,
      );
  assert.deepEqual(
    require("./certops-release-qualification").verifyMatrix(
      [
        {
          kind: "host",
          suite: report.suite,
          environment: report.qualificationEnvironment,
          report,
        },
      ],
      {
        candidateSha: p.lease.candidateSha,
        specification: { schemaVersion: 1, slots: [slot] },
      },
    ),
    [],
  );
  assert.throws(() =>
    adapter.qualificationReport({
      ...args,
      completed: { ...completed, taskState: "Running" },
    }),
  );
  const missing = structuredClone(value);
  missing.publicPreparation.sources.pop();
  assert.throws(() =>
    adapter.qualificationReport({ ...args, original: missing }),
  );
});

test("provisioning passes the actual dedicated bootstrap parameter contract with canonical lease time", () => {
  const fs = require("node:fs"),
    path = require("node:path"),
    infra = path.join(__dirname, "../infra/certops-adcs");
  const provision = fs.readFileSync(
      path.join(infra, "provision-lab.ps1"),
      "utf8",
    ),
    bootstrap = fs.readFileSync(
      path.join(infra, "run-ttl24h-prepare.ps1"),
      "utf8",
    );
  const invoke = provision
    .split(/\r?\n/)
    .find(
      (line) =>
        line.includes("Invoke-Stage 'windows-agent'") &&
        line.includes("run-ttl24h-prepare.ps1"),
    );
  assert.ok(invoke);
  for (const name of [
    "DomainPassword",
    "AdcsTtl24hNonce",
    "AdcsTtl24hCreatedAt",
    "AdcsTtl24hRunId",
    "AdcsTtl24hRunAttempt",
  ]) {
    assert.ok(invoke.includes(`"${name}=`), name);
    assert.ok(bootstrap.includes(`$${name}`), name);
  }
  assert.ok(invoke.includes("yyyy-MM-ddTHH:mm:ss.fffZ"));
  assert.ok(invoke.includes("CERTOPS_STAGE=adcs-ttl24h-prepared"));
});

test("CA readiness waits are bounded and read-only before opening the CA database", () => {
  const fs = require("node:fs"),
    path = require("node:path"),
    source = fs.readFileSync(
      path.join(__dirname, "../infra/certops-adcs/ttl24h-ca-observe.ps1"),
      "utf8",
    );
  assert.ok(source.includes("$readyClock.ElapsedMilliseconds -ge 120000"));
  assert.ok(source.includes("Start-Sleep -Milliseconds 500"));
  assert.ok(
    source.indexOf("$readyClock.Stop()") <
      source.indexOf("New-Object -ComObject CertificateAuthority.View"),
  );
  assert.equal(
    /\b(?:Start-Service|Restart-Service|Stop-Service|Set-Service)\b/.test(
      source,
    ),
    false,
  );
  assert.equal(
    /\b(?:Submit|ResubmitRequest|DenyRequest|PublishCRL)\s*\(/.test(source),
    false,
  );
});

test("fresh native CA RequestId resolves exact issued DER rather than an optional journal field", () => {
 const fs=require("node:fs"),path=require("node:path");
 const base=path.join(__dirname,"../packages/agent/reference/adcs-cmc/testdata");
 const leaf=new crypto.X509Certificate(fs.readFileSync(path.join(base,"issued.cer")));
 const ca=new crypto.X509Certificate(fs.readFileSync(path.join(base,"ca.cer")));
 const rows=[{requestId:"11",certificateB64:ca.raw.toString("base64")},{requestId:"12",certificateB64:ca.raw.toString("base64")},{requestId:"13",certificateB64:leaf.raw.toString("base64")}];
 const facts={requestIds:["11","12",null],fingerprints:["a".repeat(64),"b".repeat(64),crypto.createHash("sha256").update(leaf.raw).digest("hex")]};
 assert.equal(adapter.resolveFreshRequestId(rows,facts),"13");
 assert.equal(adapter.resolveFreshRequestId(rows,{...facts,requestIds:["11","12","13"]}),"13");
 assert.throws(()=>adapter.resolveFreshRequestId(rows,{...facts,requestIds:["11","12","14"]}));
 for(const changed of [rows.slice(0,2),[...rows.slice(0,2),{...rows[2],requestId:"11"}],[rows[2],rows[1],rows[2]],[...rows.slice(0,2),{...rows[2],requestId:"4294967296"}]])assert.throws(()=>adapter.resolveFreshRequestId(changed,facts));
 assert.throws(()=>adapter.resolveFreshRequestId(rows,{...facts,fingerprints:[...facts.fingerprints.slice(0,2),"f".repeat(64)]}));
});
