"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  assertForwardTransition,
  assertIssuerKind,
  attachEnrollmentDispatch,
  confirmedKeyAllowed,
  decideContinuation,
  freezeSnapshot,
  storedAdcsPayload,
} = require("../../apps/api/services/certops/enrollmentLifecycle");
const {
  abandonEnrollment,
  cancelEnrollment,
  confirmIssuerKey,
  createEnrollment,
  dispatchPreflight,
  proposeReconcileRequestId,
  recordEnrollmentResult,
  recordPreflightResult,
  discardUnconfiguredIssuer,
  listEnrollments,
  listIssuers,
  scheduleDueEnrollments,
  retryEnrollmentInstallation,
} = require("../../apps/api/services/certops/certificateEnrollments");
const { PREFLIGHT_PER_HOUR } = require("../../apps/api/services/certops/enrollmentLifecycle");
const { validateSignedJob } = require("../../packages/contracts/certops/validate-signed-job.cjs");
const { migrations } = require("../../apps/api/migrations/migrate");
const { claimJobs } = require("../../apps/api/services/certops/agentDispatch");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");
const jobPayloadSchema = require("../../packages/contracts/certops/job-payload.schema.json");
const signedDispatchPayloadSchema = require("../../packages/contracts/certops/signed-dispatch-payload.schema.json");
const signedDispatchWireV1Schema = require("../../packages/contracts/certops/signed-dispatch-wire-v1.schema.json");
const signedDispatchWireV2Schema = require("../../packages/contracts/certops/signed-dispatch-wire-v2.schema.json");
const enrollmentSnapshotSchema = require("../../packages/contracts/certops/enrollment-snapshot.schema.json");

const ISSUER = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const ENROLLMENT = "5f0c2a8e-3b1d-4c6e-9a7f-1e2d3c4b5a69";
const JOB_ID = "6a1f0d2e-7c3b-4e8a-9f1d-2b3c4d5e6f70";
const CLAIM_ID = "0b7c2f7e-1d2a-4c3b-8e4f-5a6b7c8d9e0f";

function snapshotInput() {
  return {
    issuerId: ISSUER,
    issuerVersion: 1,
    caConfig: "ca01.corp.example.com\\Corp Issuing CA 01",
    caKeySha256: "ab".repeat(32),
    template: "TokenTimerWebServer",
    authorizedDnsNames: ["app.example.com"],
    keyAlgorithm: "rsa",
    keySize: 2048,
  };
}

describe("AD CS enrollment lifecycle", () => {
  it("fails closed on an unknown issuer kind", () => {
    assert.equal(assertIssuerKind("acme"), "acme");
    assert.equal(assertIssuerKind("adcs"), "adcs");
    assert.throws(() => assertIssuerKind("venafi"), (error) => error.code === "CERTOPS_ISSUER_KIND_INVALID");
  });

  it("freezes snapshot bytes and refuses a backwards enrollment move", () => {
    const frozen = freezeSnapshot(snapshotInput());
    assert.equal(frozen.sha256, require("node:crypto").createHash("sha256").update(frozen.bytes).digest("hex"));
    assert.doesNotThrow(() => assertForwardTransition("submitting", "submission_uncertain"));
    for(const state of ["pending_issuance","issued","validation_deferred","validated"])assert.doesNotThrow(()=>assertForwardTransition(state,"refused"));
    for(const state of ["installing","install_failed","installed"])assert.throws(()=>assertForwardTransition(state,"refused"));
    assert.doesNotThrow(() => assertForwardTransition("installing", "install_failed"));
    assert.throws(
      () => assertForwardTransition("installed", "submitting"),
      (error) => error.code === "CERTOPS_ENROLLMENT_TRANSITION_INVALID",
    );
  });

  it("attaches terminal cleanup only from the durable enrollment state", () => {
    const frozen = freezeSnapshot(snapshotInput());
    for (const state of ["expired", "cancelled", "abandoned", "pending_issuance", "installed"]) {
      const result = attachEnrollmentDispatch({ certificateId: "cert-1" }, {
        id: ENROLLMENT, attempt: 2, snapshotB64: frozen.b64,
        snapshotSha256: frozen.sha256, state,
      });
      assert.equal(result.enrollment.terminalState,
        ["expired", "cancelled", "abandoned"].includes(state) ? state : undefined);
    }
  });

  it("replaces stale reconcile metadata with the current durable operator proposal", () => {
    const frozen = freezeSnapshot(snapshotInput());
    const signed = attachEnrollmentDispatch({ metadata: [{ name: "adcs.reconcileRequestId", value: 12 }] }, {
      id: ENROLLMENT, state: "submission_uncertain", attempt: 2, operatorRequestId: 77,
      snapshotB64: frozen.b64, snapshotSha256: frozen.sha256,
    });
    assert.equal(signed.enrollment.reconcileRequestId, 77);
    assert.deepEqual(signed.metadata, [{ name: "adcs.reconcileRequestId", value: 77 }]);
  });

  it("builds a signed adcs renew payload without storing issuer fields", () => {
    const frozen = freezeSnapshot(snapshotInput());
    const stored = storedAdcsPayload({
      certificateId: "cert-1",
      target: {
        type: "windows-iis",
        reference: "iis-01/default-web-site",
        store: "My",
        binding: { site: "Default Web Site", port: 443, sniHost: "app.example.com" },
      },
    });
    assert.equal(stored.issuerKind, undefined);
    const signed = {
      ...attachEnrollmentDispatch(stored, {
        id: ENROLLMENT,
        attempt: 1,
        snapshotB64: frozen.b64,
        snapshotSha256: frozen.sha256,
        operatorRequestId: 42,
      }),
      schemaVersion: 1,
      jobId: "job-adcs-1",
      workspaceId: "11111111-1111-4111-8111-111111111111",
      agentId: "22222222-2222-4222-8222-222222222222",
      action: "renew",
      mode: "real",
      requestedAt: "2026-01-01T00:00:00.000Z",
    };
    const validated = validateSignedJob(signed);
    assert.equal(validated.valid, true, JSON.stringify(validated.errors));
    assert.equal(signed.metadata[0].name, "adcs.reconcileRequestId");
    assert.equal(signed.metadata[0].value, 42);
    for (const terminalState of ["expired", "cancelled", "abandoned"]) {
      const cleanup = { ...signed, action: "continue-enrollment",
        enrollment: { ...signed.enrollment, terminalState } };
      assert.equal(validateSignedJob(cleanup).valid, true);
      assert.equal(validateSignedJob({ ...cleanup, action: "renew" }).valid, false);
    }
    assert.equal(validateSignedJob({ ...signed, action: "continue-enrollment",
      enrollment: { ...signed.enrollment, terminalState: "installed" } }).valid, false);
    const reconcile = { ...signed, action: "continue-enrollment",
      enrollment: { ...signed.enrollment, reconcileRequestId: 4294967295 } };
    assert.equal(validateSignedJob(reconcile).valid, true);
    assert.equal(validateSignedJob({ ...reconcile, action: "renew" }).valid, false);
    assert.equal(validateSignedJob({ ...reconcile,
      enrollment: { ...reconcile.enrollment, terminalState: "expired" } }).valid, false);
    assert.equal(validateSignedJob({ ...reconcile,
      enrollment: { ...reconcile.enrollment, reconcileRequestId: 4294967296 } }).valid, false);
  });

  it("polls a pending enrollment and retries an unreachable submit", () => {
    const now = new Date("2026-10-11T12:00:00.000Z");
    const snapshot = { pollInterval: 900, pendingTimeout: 3600 };
    assert.deepEqual(
      decideContinuation(
        {
          state: "pending_issuance",
          pendingSince: new Date("2026-10-11T10:00:00.000Z"),
          nextPollAt: new Date("2026-10-11T11:00:00.000Z"),
          activeJob: false,
        },
        snapshot,
        now,
      ),
      { state: "expired", reason: "pending_timeout" },
    );
    assert.equal(
      decideContinuation(
        {
          state: "submitting",
          lastErrorCode: "ADCS_CA_UNREACHABLE",
          nextPollAt: new Date("2026-10-11T11:00:00.000Z"),
          activeJob: false,
        },
        snapshot,
        now,
      ).reason,
      "ADCS_CA_UNREACHABLE",
    );
    assert.equal(
      decideContinuation(
        { state: "pending_issuance", nextPollAt: now, activeJob: true },
        snapshot,
        now,
      ),
      null,
    );
  });

  it("does not dispatch a blind resubmit for submission_uncertain without a RequestId", () => {
    const now = new Date("2026-10-11T12:00:00.000Z");
    const snapshot = { pollInterval: 900, pendingTimeout: 3600 };
    assert.equal(
      decideContinuation(
        {
          state: "submission_uncertain",
          operatorRequestId: null,
          nextPollAt: now,
          activeJob: false,
        },
        snapshot,
        now,
      ),
      null,
    );
    assert.deepEqual(
      decideContinuation(
        {
          state: "submission_uncertain",
          operatorRequestId: 77,
          nextPollAt: now,
          activeJob: false,
        },
        snapshot,
        now,
      ),
      { dispatch: true, reason: "reconcile" },
    );
  });

  it("confirms only a key from a safe preflight", () => {
    const key = "cd".repeat(32);
    const safe = {
      templateCheck: { verdict: "safe", reasons: [] },
      caCheck: { verdict: "safe", reasons: [], operatorAttested: true },
      caCertificates: [{ keySha256: key }],
    };
    assert.equal(confirmedKeyAllowed(safe, key), true);
    assert.equal(confirmedKeyAllowed({ ...safe, caCheck: { verdict: "unsafe", reasons: ["schema_version_1"], operatorAttested: false } }, key), false);
    assert.equal(confirmedKeyAllowed({ templateCheck: { verdict: "unsafe", reasons: ["schema_version_1"] }, caCheck: safe.caCheck, caCertificates: [{ keySha256: key }] }, key), false);
  });
});

describe("migration 70 certificate enrollments", () => {
  const migration = migrations.find((entry) => entry.name === "certops_certificate_enrollments");

  it("creates the issuer and enrollment tables and allows adcs-preflight", () => {
    assert.ok(migration);
    assert.equal(migration.version, 70);
    assert.match(migration.sql, /certificate_enrollments/);
    assert.match(migration.sql, /certificate_issuer_versions/);
    assert.match(migration.sql, /'adcs-preflight'/);
    assert.match(migration.sql, /enrollment_id/);
    assert.match(migration.sql, /deploy_target/);
    assert.match(migration.sql, /last_preflight_job_id/);
    assert.match(migration.sql, /preflight_seq/);
  });
});

const WORKSPACE = "11111111-1111-4111-8111-111111111111";
const WEBHOSTING = {
  type: "windows-iis",
  reference: "iis-01/webhosting",
  store: "WebHosting",
  binding: { site: "Shop", port: 443, sniHost: "app.example.com" },
};

function profileEnrollmentDb(versionRow) {
  return {
    async query(sql) {
      if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") return { rows: [] };
      if (sql.includes("FROM certificate_profiles")) return { rows: [{ issuer_id: ISSUER }] };
      if (sql.includes("FROM certificate_issuer_versions")) {
        return { rows: versionRow ? [versionRow] : [] };
      }
      throw new Error(sql);
    },
  };
}

function enrollThroughProfile(db) {
  return createEnrollment({
    client: db,
    workspaceId: WORKSPACE,
    issuerId: ISSUER,
    profileId: "33333333-3333-4333-8333-333333333333",
    certificateId: "33333333-3333-4333-8333-333333333333",
    agentId: "22222222-2222-4222-8222-222222222222",
    target: WEBHOSTING,
    authorizedDnsNames: ["app.example.com"],
    keyAlgorithm: "rsa",
    keySize: 2048,
    audit: async () => {},
    createJob: async () => ({ id: "job-should-not-exist" }),
  });
}

function rowDb() {
  const enrollments = new Map();
  const issuers = new Map();
  let preflightCount = 0;
  let checkpoint = null;
  function cloneRows() {
    return new Map([...enrollments.entries()].map(([id, row]) => [id, { ...row }]));
  }
  function cloneIssuers() {
    return new Map([...issuers.entries()].map(([id, row]) => [id, {
      ...row,
      confirmed: row.confirmed ? { ...row.confirmed } : undefined,
    }]));
  }
  function restore(saved) {
    enrollments.clear();
    for (const [id, row] of saved.enrollments) enrollments.set(id, row);
    issuers.clear();
    for (const [id, row] of saved.issuers) issuers.set(id, row);
    preflightCount = saved.preflightCount;
  }
  return {
    enrollments,
    issuers,
    get preflightCount() {
      return preflightCount;
    },
    set preflightCount(value) {
      preflightCount = value;
    },
    putEnrollment(row) {
      enrollments.set(row.id, { ...row });
    },
    putIssuer(row) {
      issuers.set(row.id, { ...row });
    },
    async query(sql, params = []) {
      const text = sql.replace(/\s+/g, " ").trim();
      if (text.includes("FROM workspaces") && text.includes("certops_paused")) {
        return { rows: [{id: WORKSPACE, certops_paused: this.paused === true, certops_require_approval_always: false}] };
      }
      if (text.startsWith("SELECT status FROM certificate_jobs") && text.includes("enrollment_id=$3")) {
        const row=enrollments.get(params[2]);
        return {rows:row?.current_job_id===params[1] ? [{status:row.job_status}] : []};
      }
      if (text === "BEGIN") {
        checkpoint = {
          enrollments: cloneRows(),
          issuers: cloneIssuers(),
          preflightCount,
        };
        return { rows: [] };
      }
      if (text === "COMMIT") {
        checkpoint = null;
        return { rows: [] };
      }
      if (text === "ROLLBACK") {
        if (checkpoint) restore(checkpoint);
        checkpoint = null;
        return { rows: [] };
      }
      if (text.includes("pg_advisory_xact_lock")) return { rows: [] };
      if (text.includes("operation = 'adcs-preflight'") && text.includes("count")) {
        return { rows: [{ n: preflightCount }] };
      }
      if (text.includes("SELECT e.workspace_id, e.id") && text.includes("e.next_poll_at <= $1")) {
        const now = params[0];
        const rows = [...enrollments.values()]
          .filter((row) => row.next_poll_at && row.next_poll_at.getTime() <= now.getTime())
          .map((row) => ({ workspace_id: row.workspace_id, id: row.id }));
        return { rows };
      }
      if (text.startsWith("SELECT status FROM certificate_jobs")) {
        const row = [...enrollments.values()].find((r) => r.current_job_id === params[1]);
        return { rows: row ? [{ status: row.job_status }] : [] };
      }
      if (text.includes("FROM certificate_enrollments e")) {
        const row = enrollments.get(params[1]);
        if (!row || row.workspace_id !== params[0]) return { rows: [] };
        return { rows: [{ ...row, job_status: row.job_status || null }] };
      }
      if (text.includes("SET next_poll_at = NULL") && text.includes("RETURNING id")) {
        const row = enrollments.get(params[1]);
        const now = params[2];
        if (
          !row ||
          row.workspace_id !== params[0] ||
          !row.next_poll_at ||
          row.next_poll_at.getTime() > now.getTime()
        ) {
          return { rows: [] };
        }
        row.next_poll_at = null;
        return { rows: [{ id: row.id }] };
      }
      if (text.includes("SET state = $3")) {
        const row = enrollments.get(params[1]);
        row.state = params[2];
        row.request_id = params[3] || row.request_id;
        row.last_error_code = params[4];
        row.pending_since = params[5];
        row.next_poll_at = params[6];
        return { rows: [] };
      }
      if (text.includes("SET state = 'expired'")) {
        enrollments.get(params[1]).state = "expired";
        return { rows: [] };
      }
      if (text.includes("SET operator_request_id")) {
        const row = enrollments.get(params[1]);
        row.operator_request_id = params[2];
        row.next_poll_at = new Date();
        return { rows: [] };
      }
      if (text.includes("SET attempt = $3, current_job_id = $4")) {
        const row = enrollments.get(params[1]);
        row.attempt = params[2];
        row.current_job_id = params[3];
        row.job_status = "pending";
        return { rows: [] };
      }
      if (text.includes("FROM certificate_issuers") && text.includes("FOR UPDATE")) {
        const row = issuers.get(params[1]);
        return { rows: row && row.workspace_id === params[0] ? [row] : [] };
      }
      if (text.includes("FROM certificate_issuer_versions")) {
        const issuer = issuers.get(params[1]);
        if (!issuer || issuer.workspace_id !== params[0] || !issuer.ca_key_sha256) return { rows: [] };
        return {
          rows: [{
            version: issuer.version,
            ca_config: issuer.ca_config,
            template: issuer.template,
            ca_key_sha256: issuer.ca_key_sha256,
            kind: issuer.kind,
            revalidation_required: issuer.revalidation_required === true,
          }],
        };
      }
      if (text.includes("INSERT INTO certificate_enrollments")) {
        const id = require("node:crypto").randomUUID();
        enrollments.set(id, {
          id,
          workspace_id: params[0],
          certificate_id: params[1],
          issuer_id: params[2],
          state: "requested",
          attempt: 0,
          snapshot_bytes: params[5],
          snapshot_sha256: params[6],
          deploy_target: JSON.parse(params[7]),
          operator_request_id: null,
          pending_since: null,
          next_poll_at: null,
          last_error_code: null,
          current_job_id: null,
          job_status: null,
          agent_id: params[4],
        });
        return { rows: [{ id }] };
      }
      if (text.includes("SET current_job_id = $3")) {
        const row = enrollments.get(params[1]);
        row.current_job_id = params[2];
        row.job_status = "pending";
        return { rows: [] };
      }
      if (text.includes("SET state = 'abandoned'")) {
        const row = enrollments.get(params[1]);
        row.state = "abandoned";
        row.next_poll_at = new Date();
        return { rows: [] };
      }
      if (text.includes("SET state = 'cancelled'")) {
        const row = enrollments.get(params[1]);
        row.state = "cancelled";
        row.next_poll_at = params[2];
        return { rows: [] };
      }
      if (text.includes("UPDATE certificate_enrollments SET next_poll_at = $3")) {
        enrollments.get(params[1]).next_poll_at = params[2];
        return { rows: [] };
      }
      if (text.includes("UPDATE certificate_jobs")) return { rows: [] };
      if (text.includes("INSERT INTO certificate_issuer_versions")) {
        const issuer = issuers.get(params[1]);
        issuer.confirmed = {
          caConfig: params[3],
          template: params[4],
          caKeySha256: params[5],
        };
        return { rows: [] };
      }
      if (text.includes("SET current_version")) {
        return { rows: [] };
      }
      throw new Error(`unexpected enrollment query: ${text}`);
    },
  };
}

function storedEnrollment(id, state, extra = {}) {
  const frozen = freezeSnapshot(snapshotInput());
  return {
    id,
    workspace_id: WORKSPACE,
    state,
    attempt: 0,
    snapshot_bytes: frozen.bytes,
    snapshot_sha256: frozen.sha256,
    operator_request_id: null,
    pending_since: null,
    next_poll_at: null,
    last_error_code: null,
    current_job_id: null,
    job_status: null,
    certificate_id: "cert-1",
    agent_id: "22222222-2222-4222-8222-222222222222",
    deploy_target: WEBHOSTING,
    ...extra,
  };
}

describe("installation recovery dispatch", () => {
  const env = { CERTOPS_ENABLED: "true" };
  it("retries only the frozen failed installation and reuses an active retry", async () => {
    const db = rowDb(); const original = storedEnrollment(ENROLLMENT,"install_failed",{attempt:2}); db.putEnrollment(original);
    const jobs=[]; const audits=[];
    const options={client:db,workspaceId:WORKSPACE,enrollmentId:ENROLLMENT,actorUserId:"operator",env,
      createJob:async input=>{jobs.push(input);return {id:JOB_ID};},audit:async input=>audits.push(input)};
    assert.deepEqual(await retryEnrollmentInstallation(options),{jobId:JOB_ID,created:true});
    assert.deepEqual(await retryEnrollmentInstallation(options),{jobId:JOB_ID,created:false});
    assert.equal(jobs.length,1); assert.equal(audits.length,1); assert.equal(audits[0].actorUserId,"operator");
    assert.equal(jobs[0].operation,"continue-enrollment"); assert.equal(jobs[0].source,"api");
    assert.equal(jobs[0].requestedByUserId,"operator");
    assert.equal(jobs[0].allowEnrollmentContinuation,true); assert.equal(jobs[0].enrollmentId,ENROLLMENT);
    assert.equal(jobs[0].assignedAgentId,original.agent_id); assert.deepEqual(jobs[0].payload.target,original.deploy_target);
    const row=db.enrollments.get(ENROLLMENT); assert.equal(row.attempt,3); assert.equal(row.state,"install_failed");
    assert.deepEqual(row.snapshot_bytes,original.snapshot_bytes); assert.equal(row.snapshot_sha256,original.snapshot_sha256);
  });
  it("refuses other phases and a paused workspace without creating or auditing a job", async () => {
    for(const state of ["pending_issuance","submission_uncertain","installed","installing"]){
      const db=rowDb();db.putEnrollment(storedEnrollment(ENROLLMENT,state));
      await assert.rejects(retryEnrollmentInstallation({client:db,workspaceId:WORKSPACE,enrollmentId:ENROLLMENT,env,
        createJob:async()=>{throw Error("must not create");},audit:async()=>{throw Error("must not audit");}}),e=>e.code==="CERTOPS_ENROLLMENT_TRANSITION_INVALID");
    }
    const db=rowDb();db.paused=true;db.putEnrollment(storedEnrollment(ENROLLMENT,"install_failed"));
    await assert.rejects(retryEnrollmentInstallation({client:db,workspaceId:WORKSPACE,enrollmentId:ENROLLMENT,env}),e=>e.code==="CERTOPS_WORKSPACE_PAUSED");
  });
  it("automatically resumes an interrupted installing phase but leaves install_failed for operator decision",()=>{
    const now=new Date(); const snapshot=snapshotInput();
    assert.deepEqual(decideContinuation({state:"installing",activeJob:false,nextPollAt:now},snapshot,now),{dispatch:true,reason:"resume_installation"});
    assert.equal(decideContinuation({state:"installing",activeJob:true,nextPollAt:now},snapshot,now),null);
    assert.equal(decideContinuation({state:"install_failed",activeJob:false,nextPollAt:now},snapshot,now),null);
  });
  it("retains installing eligibility until its signed recovery acknowledges completion",async()=>{
    const db=rowDb();db.putEnrollment(storedEnrollment(ENROLLMENT,"issued",{attempt:1}));
    await recordEnrollmentResult(db,{workspaceId:WORKSPACE,job:{enrollment_id:ENROLLMENT},
      enrollmentResult:{enrollmentId:ENROLLMENT,attempt:1,state:"installing",requestId:42}});
    const due=db.enrollments.get(ENROLLMENT).next_poll_at;assert.ok(due instanceof Date);
    const jobs=await scheduleDueEnrollments({client:db,now:new Date(due.getTime()+1000),
      createJob:async input=>{assert.equal(input.operation,"continue-enrollment");assert.equal(input.enrollmentId,ENROLLMENT);return {id:JOB_ID};}});
    assert.equal(jobs.length,1);assert.ok(db.enrollments.get(ENROLLMENT).next_poll_at>due);
    await recordEnrollmentResult(db,{workspaceId:WORKSPACE,job:{enrollment_id:ENROLLMENT},
      enrollmentResult:{enrollmentId:ENROLLMENT,attempt:2,state:"installed",requestId:42}});
    assert.equal(db.enrollments.get(ENROLLMENT).next_poll_at,null);
  });
});

describe("enrollment rows", () => {
  const audit = async () => {};

  it("accepts a first renew result that skips unreported states and schedules the poll", async () => {
    const db = rowDb();
    const pendingId = ENROLLMENT;
    const uncertainId = "5f0c2a8e-3b1d-4c6e-9a7f-1e2d3c4b5a70";
    const installedId = "5f0c2a8e-3b1d-4c6e-9a7f-1e2d3c4b5a71";
    const deferredId = "5f0c2a8e-3b1d-4c6e-9a7f-1e2d3c4b5a72";
    for (const id of [pendingId, uncertainId, installedId, deferredId]) {
      db.putEnrollment(storedEnrollment(id, "requested"));
    }
    await recordEnrollmentResult(db, {
      workspaceId: WORKSPACE,
      job: { enrollment_id: pendingId },
      enrollmentResult: { enrollmentId: pendingId, attempt: 1, state: "pending_issuance", requestId: 42 },
    });
    await recordEnrollmentResult(db, {
      workspaceId: WORKSPACE,
      job: { enrollment_id: uncertainId },
      enrollmentResult: { enrollmentId: uncertainId, attempt: 1, state: "submission_uncertain" },
    });
    await recordEnrollmentResult(db, {
      workspaceId: WORKSPACE,
      job: { enrollment_id: installedId },
      enrollmentResult: { enrollmentId: installedId, attempt: 1, state: "installed" },
    });
    await recordEnrollmentResult(db, {
      workspaceId: WORKSPACE,
      job: { enrollment_id: deferredId },
      enrollmentResult: { enrollmentId: deferredId, attempt: 1, state: "validation_deferred" },
    });
    assert.ok(db.enrollments.get(pendingId).next_poll_at instanceof Date);
    assert.equal(db.enrollments.get(uncertainId).next_poll_at, null);
    assert.equal(db.enrollments.get(installedId).state, "installed");
    assert.ok(db.enrollments.get(deferredId).next_poll_at instanceof Date);
  });

  it("records stricter local-rule refusal from every still-unaccepted server phase",async()=>{
    for(const state of ["pending_issuance","issued","validation_deferred","validated"]){const db=rowDb();db.putEnrollment(storedEnrollment(ENROLLMENT,state,{next_poll_at:new Date()}));await recordEnrollmentResult(db,{workspaceId:WORKSPACE,job:{enrollment_id:ENROLLMENT},enrollmentResult:{enrollmentId:ENROLLMENT,attempt:1,state:"refused",errorCode:"ADCS_CA_CONFIG_UNSAFE"}});assert.equal(db.enrollments.get(ENROLLMENT).state,"refused");assert.equal(db.enrollments.get(ENROLLMENT).next_poll_at,null);}
  });

  it("clears a leftover poll date when a pending attempt ends in a terminal result", async () => {
    const db = rowDb();
    const id = ENROLLMENT;
    const row = storedEnrollment(id, "pending_issuance");
    row.next_poll_at = new Date(Date.now() + 60_000);
    db.putEnrollment(row);
    await recordEnrollmentResult(db, {
      workspaceId: WORKSPACE,
      job: { enrollment_id: id },
      enrollmentResult: {
        enrollmentId: id,
        attempt: 1,
        state: "denied",
        requestId: 42,
        caHresult: "0x80094012",
      },
    });
    assert.equal(db.enrollments.get(id).state, "denied");
    assert.equal(db.enrollments.get(id).next_poll_at, null);
  });

  it("keeps the original IIS target on the first continuation", async () => {
    const db = rowDb();
    const id = ENROLLMENT;
    const due = new Date("2026-10-11T12:00:00.000Z");
    db.putEnrollment(storedEnrollment(id, "pending_issuance", {
      attempt: 1,
      pending_since: new Date("2026-10-11T11:00:00.000Z"),
      next_poll_at: due,
    }));
    const jobs = [];
    const created = await scheduleDueEnrollments({
      client: db,
      now: new Date("2026-10-11T12:05:00.000Z"),
      createJob: async ({ payload }) => {
        jobs.push(payload);
        return { id: "job-cont-1" };
      },
    });
    assert.equal(created.length, 1);
    assert.equal(jobs[0].target.store, "WebHosting");
    assert.equal(jobs[0].target.binding.site, "Shop");
    assert.equal(jobs[0].issuerKind, undefined);
  });

  it("dispatches a scheduled AD CS continuation with issuer fields attached and a schema-valid payload", async () => {
    const db = rowDb();
    db.putEnrollment(storedEnrollment(ENROLLMENT, "pending_issuance", {
      attempt: 1,
      pending_since: new Date("2026-10-11T11:00:00.000Z"),
      next_poll_at: new Date("2026-10-11T12:00:00.000Z"),
    }));
    const scheduled = [];
    const created = await scheduleDueEnrollments({
      client: db,
      now: new Date("2026-10-11T12:05:00.000Z"),
      createJob: async (args) => {
        scheduled.push(args);
        return { id: JOB_ID };
      },
    });
    assert.equal(created.length, 1);
    const [request] = scheduled;
    assert.equal(request.operation, "continue-enrollment");
    assert.equal(request.payload.issuerKind, undefined, "stored payload must not carry issuerKind");
    assert.equal(request.payload.enrollment, undefined, "stored payload must not carry enrollment");

    const stored = db.enrollments.get(ENROLLMENT);
    const agent = {
      id: "agent-row-1",
      workspaceId: WORKSPACE,
      agentId: "agent-01",
      name: "Windows agent",
      status: "active",
      protocolVersion: "1.0.0",
      agentVersion: "0.1.0",
      pinnedSigningKeyId: null,
      lastSeenAt: null,
      retiredAt: null,
    };
    const claimRow = {
      id: JOB_ID,
      workspace_id: WORKSPACE,
      status: "claimed",
      claim_id: CLAIM_ID,
      lease_expires_at: new Date(Date.now() + 15 * 60 * 1000),
      attempt_count: 1,
      operation: "continue-enrollment",
      subject_type: "managed_certificate",
      subject_id: request.subjectId,
      payload: request.payload,
      mode: "real",
      executor_kind: "agent",
      assigned_agent_id: agent.id,
      enrollment_id: ENROLLMENT,
      subject_is_provisioning: false,
      created_at: new Date("2026-10-11T12:05:00.000Z"),
    };
    const claimDb = {
      async connect() {
        return this;
      },
      release() {},
      async query(text, params = []) {
        const sql = text.replace(/\s+/g, " ").trim();
        if (["BEGIN", "COMMIT", "ROLLBACK"].includes(sql)) return { rows: [] };
        if (sql.includes("SAVEPOINT") || sql.includes("RELEASE SAVEPOINT")) return { rows: [] };
        if (sql.includes("FROM certificate_enrollments e")) return db.query(text, params);
        if (sql.includes("SELECT last_sequence")) return { rows: [{ last_sequence: 0 }] };
        if (sql.includes("SET last_seen_at = NOW()")) return { rows: [] };
        if (sql.includes("SELECT declared_target_selectors")) {
          return {
            rows: [{
              declared_target_selectors: [],
              declared_command_profile_names: [],
              supported_dns_providers: [],
              declared_capabilities: ["adcs-enroll-v1"],
              capabilities_updated_at: new Date().toISOString(),
            }],
          };
        }
        if (sql.includes("FOR UPDATE SKIP LOCKED")) return { rows: [claimRow] };
        if (sql.includes("SET status = 'claimed'")) return { rows: [claimRow] };
        throw new Error(`unexpected claim query: ${sql}`);
      },
    };
    const result = await claimJobs({
      dbPool: claimDb,
      agent,
      body: { maxJobs: 1, supportedActions: ["continue-enrollment"] },
      envelope: {},
      env: {},
      deps: {
        lockWorkspaceForCertOpsSideEffect: async () => ({ locked: true }),
        enforceAgentSequence: async () => {},
        invalidateApprovalForClaim: async () => {},
        signJobForDispatch: async ({ job }) => ({
          ...job,
          nonce: require("node:crypto").randomBytes(24).toString("base64url"),
          issuedAt: "2026-10-11T12:05:00.000Z",
          expiresAt: "2026-10-11T12:10:00.000Z",
          signingKeyId: "key-1",
          signature: require("node:crypto").randomBytes(64).toString("base64"),
        }),
      },
    });

    assert.equal(result.jobs.length, 1);
    const job = result.jobs[0];
    assert.equal(job.action, "continue-enrollment");
    assert.equal(job.issuerKind, "adcs");
    assert.equal(job.enrollment.enrollmentId, ENROLLMENT);
    assert.equal(job.enrollment.attempt, 2);
    assert.equal(job.enrollment.snapshotSha256, stored.snapshot_sha256);
    assert.equal(
      require("node:crypto").createHash("sha256")
        .update(Buffer.from(job.enrollment.snapshotB64, "base64"))
        .digest("hex"),
      stored.snapshot_sha256,
    );
    for (const key of [
      "commandRef", "caEndpoint", "acmeKind", "eabRef", "accountRef", "preferredChain",
      "dnsZone", "dnsProvider", "keyRotation", "keyAlgorithm", "keySize", "sans",
      "certificatePem", "certificatePemSha256", "renewalProfile", "deploymentTargets",
    ]) {
      assert.equal(job[key], undefined, `ACME-only field ${key} must be absent`);
    }

    const ajv = new Ajv({ allErrors: true, strict: false });
    addFormats(ajv);
    for (const schema of [
      signedDispatchPayloadSchema,
      signedDispatchWireV1Schema,
      signedDispatchWireV2Schema,
      enrollmentSnapshotSchema,
    ]) {
      ajv.addSchema(schema);
    }
    const validate = ajv.compile(jobPayloadSchema);
    assert.equal(validate(job), true, JSON.stringify(validate.errors));
  });

  it("dispatches a continuation after an uncertain RequestId is proposed", async () => {
    const db = rowDb();
    const id = ENROLLMENT;
    db.putEnrollment(storedEnrollment(id, "submission_uncertain", { attempt: 1 }));
    await proposeReconcileRequestId({
      client: db,
      workspaceId: WORKSPACE,
      enrollmentId: id,
      requestId: 77,
      audit,
    });
    const jobs = [];
    const created = await scheduleDueEnrollments({
      client: db,
      now: new Date(Date.now() + 1000),
      createJob: async ({ payload }) => {
        jobs.push(payload);
        return { id: "job-reconcile-1" };
      },
    });
    assert.equal(created.length, 1);
    assert.equal(jobs[0].target.store, "WebHosting");
    assert.equal(jobs[0].metadata[0].value, 77);
    assert.ok(db.enrollments.get(id).next_poll_at > new Date());
    const signed = attachEnrollmentDispatch(jobs[0], {
      id, state: "submission_uncertain", attempt: 2, operatorRequestId: 77,
      snapshotB64: Buffer.from(db.enrollments.get(id).snapshot_bytes).toString("base64"),
      snapshotSha256: db.enrollments.get(id).snapshot_sha256,
    });
    assert.equal(signed.enrollment.reconcileRequestId, 77);
    await recordEnrollmentResult(db, { workspaceId: WORKSPACE, job: { enrollment_id: id },
      enrollmentResult: { enrollmentId: id, attempt: 2, state: "submission_uncertain", errorCode: "ADCS_DISPOSITION_UNKNOWN" } });
    assert.ok(db.enrollments.get(id).next_poll_at > new Date(), "unissued proposed candidates must remain scheduled");
  });

  it("restores the due date when continuation job creation fails", async () => {
    const db = rowDb();
    const id = ENROLLMENT;
    const due = new Date("2026-10-11T12:00:00.000Z");
    db.putEnrollment(storedEnrollment(id, "pending_issuance", {
      attempt: 1,
      next_poll_at: due,
    }));
    const now = new Date("2026-10-11T12:05:00.000Z");
    await assert.rejects(
      scheduleDueEnrollments({
        client: db,
        now,
        createJob: async () => {
          throw new Error("job insert failed");
        },
      }),
      /job insert failed/,
    );
    assert.equal(db.enrollments.get(id).next_poll_at, due);
    assert.equal(db.enrollments.get(id).current_job_id, null);
    const created = await scheduleDueEnrollments({
      client: db,
      now,
      createJob: async () => ({ id: "job-retry-1" }),
    });
    assert.equal(created.length, 1);
    assert.equal(created[0].jobId, "job-retry-1");
    assert.equal(db.enrollments.get(id).current_job_id, "job-retry-1");
  });

  it("lets only one scheduler claim a due enrollment", async () => {
    const db = rowDb();
    const id = ENROLLMENT;
    db.putEnrollment(storedEnrollment(id, "validation_deferred", {
      attempt: 1,
      next_poll_at: new Date("2026-10-11T12:00:00.000Z"),
    }));
    let calls = 0;
    const createJob = async () => {
      calls += 1;
      await new Promise((resolve) => setTimeout(resolve, 20));
      return { id: `job-${calls}` };
    };
    const now = new Date("2026-10-11T12:05:00.000Z");
    const [first, second] = await Promise.all([
      scheduleDueEnrollments({ client: db, now, createJob }),
      scheduleDueEnrollments({ client: db, now, createJob }),
    ]);
    assert.equal(first.length + second.length, 1);
    assert.equal(calls, 1);
  });

  it("confirms the preflight CA and template, not caller substitutes", async () => {
    const db = rowDb();
    const key = "cd".repeat(32);
    db.putIssuer({
      id: ISSUER,
      workspace_id: WORKSPACE,
      kind: "adcs",
      current_version: 0,
      last_preflight: {
        caConfig: "ca01.corp.example.com\\Corp Issuing CA 01",
        template: "TokenTimerWebServer",
        templateCheck: { verdict: "safe", reasons: [] },
        caCheck: { verdict: "safe", reasons: [], operatorAttested: true },
        caCertificates: [{ keySha256: key }],
      },
    });
    await assert.rejects(
      confirmIssuerKey({
        client: db,
        workspaceId: WORKSPACE,
        issuerId: ISSUER,
        caKeySha256: key,
        caConfig: "other.example.com\\Other CA",
        template: "TokenTimerWebServer",
        audit,
      }),
      (error) => error.code === "CERTOPS_SNAPSHOT_INVALID",
    );
    const confirmed = await confirmIssuerKey({
      client: db,
      workspaceId: WORKSPACE,
      issuerId: ISSUER,
      caKeySha256: key,
      audit,
    });
    assert.equal(confirmed.version, 1);
    assert.equal(db.issuers.get(ISSUER).confirmed.caConfig, "ca01.corp.example.com\\Corp Issuing CA 01");
    assert.equal(db.issuers.get(ISSUER).confirmed.template, "TokenTimerWebServer");
  });

  it("schedules reconciliation when PostgreSQL returns the RequestId as a string", async () => {
    const db = rowDb();
    db.putEnrollment(storedEnrollment(ENROLLMENT, "submission_uncertain", {
      attempt: 1,
      operator_request_id: "77",
      next_poll_at: new Date("2026-10-11T12:00:00.000Z"),
    }));
    const jobs = [];
    const created = await scheduleDueEnrollments({
      client: db,
      now: new Date("2026-10-11T12:05:00.000Z"),
      createJob: async ({ payload }) => {
        jobs.push(payload);
        return { id: "job-bigint-1" };
      },
    });
    assert.equal(created.length, 1);
    assert.equal(jobs[0].metadata[0].value, 77);
    assert.equal(typeof jobs[0].metadata[0].value, "number");
  });

  it("does not schedule a RequestId outside uint32", async () => {
    const db = rowDb();
    db.putEnrollment(storedEnrollment(ENROLLMENT, "submission_uncertain", {
      attempt: 1,
      operator_request_id: "4294967296",
      next_poll_at: new Date("2026-10-11T12:00:00.000Z"),
    }));
    const created = await scheduleDueEnrollments({
      client: db,
      now: new Date("2026-10-11T12:05:00.000Z"),
      createJob: async () => ({ id: "job-should-not-exist" }),
    });
    assert.equal(created.length, 0);
  });

  it("preserves enrollment requester identity for four-eyes approval", async () => {
    const { assertNonRequester } = require("../../apps/api/services/certops/jobApprovals")._test;
    const actor = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    for (const actorUserId of [actor, undefined]) {
      const db = rowDb();
      db.putIssuer({
        id: ISSUER, workspace_id: WORKSPACE, kind: "adcs", version: 1,
        ca_config: "ca01.corp.example.com\\Corp Issuing CA 01",
        template: "TokenTimerWebServer", ca_key_sha256: "ab".repeat(32),
        revalidation_required: false,
      });
      let job;
      await createEnrollment({
        client: db, workspaceId: WORKSPACE, issuerId: ISSUER,
        certificateId: "33333333-3333-4333-8333-333333333333",
        agentId: "22222222-2222-4222-8222-222222222222",
        target: WEBHOSTING, authorizedDnsNames: ["app.example.com"],
        keyAlgorithm: "rsa", keySize: 2048, actorUserId, audit,
        createJob: async (options) => { job = options; return { id: "job-approval" }; },
      });
      assert.equal(job.requestedByUserId, actorUserId || null);
      if (actorUserId) {
        assert.throws(() => assertNonRequester(job, actor),
          (error) => error.code === "CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN");
      }
      assert.doesNotThrow(() => assertNonRequester(job, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"));
    }
  });

  it("rolls back the enrollment when the first job cannot be created", async () => {
    const db = rowDb();
    db.putIssuer({
      id: ISSUER,
      workspace_id: WORKSPACE,
      kind: "adcs",
      version: 1,
      ca_config: "ca01.corp.example.com\\Corp Issuing CA 01",
      template: "TokenTimerWebServer",
      ca_key_sha256: "ab".repeat(32),
      revalidation_required: false,
    });
    await assert.rejects(
      createEnrollment({
        client: db,
        workspaceId: WORKSPACE,
        issuerId: ISSUER,
        certificateId: "33333333-3333-4333-8333-333333333333",
        agentId: "22222222-2222-4222-8222-222222222222",
        target: WEBHOSTING,
        authorizedDnsNames: ["app.example.com"],
        keyAlgorithm: "rsa",
        keySize: 2048,
        audit,
        createJob: async () => {
          throw new Error("job insert failed");
        },
      }),
      /job insert failed/,
    );
    assert.equal(db.enrollments.size, 0);
  });

  it("refuses a new enrollment while the issuer requires revalidation", async () => {
    const db = rowDb();
    db.putIssuer({
      id: ISSUER,
      workspace_id: WORKSPACE,
      kind: "adcs",
      version: 1,
      ca_config: "ca01.corp.example.com\\Corp Issuing CA 01",
      template: "TokenTimerWebServer",
      ca_key_sha256: "ab".repeat(32),
      revalidation_required: true,
    });
    await assert.rejects(
      createEnrollment({
        client: db,
        workspaceId: WORKSPACE,
        issuerId: ISSUER,
        certificateId: "33333333-3333-4333-8333-333333333333",
        agentId: "22222222-2222-4222-8222-222222222222",
        target: WEBHOSTING,
        authorizedDnsNames: ["app.example.com"],
        keyAlgorithm: "rsa",
        keySize: 2048,
        audit,
        createJob: async () => ({ id: "job-should-not-exist" }),
      }),
      (error) => error.code === "CERTOPS_ISSUER_REVALIDATION_REQUIRED",
    );
    assert.equal(db.enrollments.size, 0);
  });

  it("refuses a snapshot the agent would reject before inserting an enrollment", () => {
    assert.throws(
      () => freezeSnapshot({ ...snapshotInput(), keySize: 1024 }),
      (error) => error.code === "CERTOPS_SNAPSHOT_INVALID",
    );
  });

  it("dispatches a cleanup continuation after abandonment", async () => {
    const db = rowDb();
    db.putEnrollment(storedEnrollment(ENROLLMENT, "submission_uncertain", { attempt: 1 }));
    await abandonEnrollment({
      client: db,
      workspaceId: WORKSPACE,
      enrollmentId: ENROLLMENT,
      audit,
    });
    assert.equal(db.enrollments.get(ENROLLMENT).state, "abandoned");
    const created = await scheduleDueEnrollments({
      client: db,
      now: new Date(Date.now() + 1000),
      createJob: async () => ({ id: "job-free-key" }),
    });
    assert.equal(created.length, 1);
    assert.equal(created[0].jobId, "job-free-key");
    assert.ok(db.enrollments.get(ENROLLMENT).next_poll_at > new Date(),
      "failed or interrupted native cleanup must retain a bounded retry date");
  });

  it("refuses to abandon an enrollment that has not reached an uncertain submission", async () => {
    const db = rowDb();
    db.putEnrollment(storedEnrollment(ENROLLMENT, "pending_issuance", { attempt: 1 }));
    await assert.rejects(
      abandonEnrollment({
        client: db,
        workspaceId: WORKSPACE,
        enrollmentId: ENROLLMENT,
        audit,
      }),
      (error) => error.code === "CERTOPS_ENROLLMENT_TRANSITION_INVALID",
    );
    assert.equal(db.enrollments.get(ENROLLMENT).state, "pending_issuance");
    for (const state of ["requested", "prepared", "submitting"]) {
      const early = rowDb();
      early.putEnrollment(storedEnrollment(ENROLLMENT, state, { attempt: 1 }));
      await assert.rejects(
        abandonEnrollment({
          client: early,
          workspaceId: WORKSPACE,
          enrollmentId: ENROLLMENT,
          audit,
        }),
        (error) => error.code === "CERTOPS_ENROLLMENT_TRANSITION_INVALID",
      );
      assert.equal(early.enrollments.get(ENROLLMENT).state, state);
    }
  });

  it("cancels an enrollment that never reached the CA without scheduling key cleanup", async () => {
    const db = rowDb();
    db.putEnrollment(storedEnrollment(ENROLLMENT, "requested", {
      attempt: 1,
      job_status: "failed",
      current_job_id: "job-1",
    }));
    await cancelEnrollment({
      client: db,
      workspaceId: WORKSPACE,
      enrollmentId: ENROLLMENT,
      audit,
    });
    const row = db.enrollments.get(ENROLLMENT);
    assert.equal(row.state, "cancelled");
    assert.equal(row.next_poll_at, null);
  });

  it("refuses to cancel an enrollment while the agent is still running the attempt", async () => {
    const db = rowDb();
    db.putEnrollment(storedEnrollment(ENROLLMENT, "requested", {
      attempt: 1,
      job_status: "running",
    }));
    await assert.rejects(
      cancelEnrollment({
        client: db,
        workspaceId: WORKSPACE,
        enrollmentId: ENROLLMENT,
        audit,
      }),
      (error) => error.code === "CERTOPS_ENROLLMENT_JOB_ACTIVE",
    );
  });

  it("refuses a profile enrollment while that issuer requires revalidation", async () => {
    const db = profileEnrollmentDb({
      version: 1,
      ca_config: "ca01.corp.example.com\\Corp Issuing CA 01",
      template: "TokenTimerWebServer",
      ca_key_sha256: "ab".repeat(32),
      kind: "adcs",
      revalidation_required: true,
    });
    await assert.rejects(
      enrollThroughProfile(db),
      (error) => error.code === "CERTOPS_ISSUER_REVALIDATION_REQUIRED",
    );
  });

  it("refuses a profile enrollment when the issuer key is not confirmed", async () => {
    const db = profileEnrollmentDb(null);
    await assert.rejects(
      enrollThroughProfile(db),
      (error) => error.code === "CERTOPS_ISSUER_NOT_FOUND",
    );
  });

  it("keeps ACME profiles off the AD CS enrollment path", async () => {
    const db = {
      async query(sql) {
        if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") return { rows: [] };
        if (sql.includes("FROM certificate_profiles")) return { rows: [{ issuer_id: null }] };
        throw new Error(sql);
      },
    };
    await assert.rejects(
      createEnrollment({
        client: db,
        workspaceId: WORKSPACE,
        issuerId: ISSUER,
        profileId: "33333333-3333-4333-8333-333333333333",
        certificateId: "33333333-3333-4333-8333-333333333333",
        agentId: "22222222-2222-4222-8222-222222222222",
        target: WEBHOSTING,
        authorizedDnsNames: ["app.example.com"],
        keyAlgorithm: "rsa",
        keySize: 2048,
        audit,
        createJob: async () => ({ id: "job-should-not-exist" }),
      }),
      (error) => error.code === "CERTOPS_PROFILE_ISSUER_NOT_SELECTED",
    );
  });

  it("refuses an enrollment whose issuer does not match the profile", async () => {
    const other = "99999999-9999-4999-8999-999999999999";
    const db = {
      async query(sql) {
        if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") return { rows: [] };
        if (sql.includes("FROM certificate_profiles")) return { rows: [{ issuer_id: other }] };
        throw new Error(sql);
      },
    };
    await assert.rejects(
      createEnrollment({
        client: db,
        workspaceId: WORKSPACE,
        issuerId: ISSUER,
        profileId: "33333333-3333-4333-8333-333333333333",
        certificateId: "33333333-3333-4333-8333-333333333333",
        agentId: "22222222-2222-4222-8222-222222222222",
        target: WEBHOSTING,
        authorizedDnsNames: ["app.example.com"],
        keyAlgorithm: "rsa",
        keySize: 2048,
        audit,
        createJob: async () => ({ id: "job-should-not-exist" }),
      }),
      (error) => error.code === "CERTOPS_PROFILE_ISSUER_MISMATCH",
    );
  });

  it("rolls back an issuer version when confirmation audit fails", async () => {
    const db = rowDb();
    const key = "cd".repeat(32);
    db.putIssuer({
      id: ISSUER,
      workspace_id: WORKSPACE,
      kind: "adcs",
      current_version: 0,
      last_preflight: {
        caConfig: "ca01.corp.example.com\\Corp Issuing CA 01",
        template: "TokenTimerWebServer",
        templateCheck: { verdict: "safe", reasons: [] },
        caCheck: { verdict: "safe", reasons: [], operatorAttested: false },
        caCertificates: [{ keySha256: key }],
      },
    });
    await assert.rejects(
      confirmIssuerKey({
        client: db,
        workspaceId: WORKSPACE,
        issuerId: ISSUER,
        caKeySha256: key,
        audit: async () => {
          throw new Error("audit failed");
        },
      }),
      /audit failed/,
    );
    assert.equal(db.issuers.get(ISSUER).confirmed, undefined);
  });

  it("stops preflight dispatch at the workspace hourly limit", async () => {
    const db = rowDb();
    db.preflightCount = PREFLIGHT_PER_HOUR;
    await assert.rejects(
      dispatchPreflight({
        client: db,
        workspaceId: WORKSPACE,
        issuerId: ISSUER,
        agentId: "22222222-2222-4222-8222-222222222222",
        caConfig: "ca01.corp.example.com\\Corp Issuing CA 01",
        template: "TokenTimerWebServer",
        audit,
        createJob: async () => {
          throw new Error("should not create a job");
        },
      }),
      (error) => error.code === "CERTOPS_PREFLIGHT_RATE_LIMITED",
    );
  });

  it("stores a preflight result only for the succeeded job's CA and template", async () => {
    const caConfig = "ca01.corp.example.com\\Corp Issuing CA 01";
    const template = "TokenTimerWebServer";
    const stored = { last: null };
    const db = {
      async query(sql, params) {
        if (sql.includes("SET last_preflight")) {
          stored.last = JSON.parse(params[2]);
          return { rows: [] };
        }
        throw new Error(sql);
      },
    };
    const matching = {
      caConfig,
      template,
      templateCheck: {
        verdict: "safe",
        reasons: [],
        schemaVersion: 2,
        templateOid: "1.3.6.1.4.1.311.21.8.1.2.3.4.5.6",
        minimalKeySize: 2048,
        asymmetricAlgorithm: null,
        enrolleeSuppliesSubject: true,
      },
      caCheck: { verdict: "safe", reasons: [], operatorAttested: false },
      caCertificates: [{
        certificateB64: "MIIB",
        keySha256: "ab".repeat(32),
        thumbprintSha1: "AABBCCDDEEFF00112233445566778899AABBCCDD",
        notBefore: "2026-01-01T00:00:00.000Z",
        notAfter: "2031-01-01T00:00:00.000Z",
      }],
    };
    const job = {
      id: "66666666-6666-4666-8666-666666666666",
      subject_id: ISSUER,
      operation: "adcs-preflight",
      payload: { caConfig, template },
    };
    await recordPreflightResult(db, {
      workspaceId: WORKSPACE,
      job,
      preflightResult: matching,
      resultStatus: "succeeded",
    });
    assert.equal(stored.last.template, template);
    await assert.rejects(
      recordPreflightResult(db, {
        workspaceId: WORKSPACE,
        job,
        preflightResult: { ...matching, template: "OtherTemplate" },
        resultStatus: "succeeded",
      }),
      (error) => error.code === "CERTOPS_SNAPSHOT_INVALID",
    );
    await assert.rejects(
      recordPreflightResult(db, {
        workspaceId: WORKSPACE,
        job: { ...job, payload: { caConfig, template: "OtherTemplate" } },
        preflightResult: matching,
        resultStatus: "succeeded",
      }),
      (error) => error.code === "CERTOPS_SNAPSHOT_INVALID",
    );
    await assert.rejects(
      recordPreflightResult(db, {
        workspaceId: WORKSPACE,
        job,
        preflightResult: matching,
        resultStatus: "failed",
      }),
      (error) => error.code === "CERTOPS_AGENT_RESULT_STATUS_INVALID",
    );
    assert.equal(stored.last.template, template);
    assert.equal(stored.last.caConfig, caConfig);
  });

  it("lists issuers without certificate bytes and marks a stale enrollment snapshot", async () => {
    const frozen = freezeSnapshot(snapshotInput());
    const db = {
      async query(sql) {
        if (sql.includes("ORDER BY i.name")) {
          return {
            rows: [{
              id: ISSUER,
              kind: "adcs",
              name: "Issuing CA",
              current_version: 2,
              revalidation_required: true,
              last_preflight: {
                caConfig: "ca01.corp.example.com\\Corp Issuing CA 01",
                template: "TokenTimerWebServer",
                templateCheck: { verdict: "safe", reasons: [] },
                caCheck: { verdict: "safe", reasons: [], operatorAttested: false },
                caCertificates: [{
                  keySha256: "ab".repeat(32),
                  certificateB64: "MIIB",
                  thumbprintSha1: "AABBCCDDEEFF00112233445566778899AABBCCDD",
                  notBefore: "2026-01-01T00:00:00.000Z",
                  notAfter: "2031-01-01T00:00:00.000Z",
                }],
              },
              updated_at: new Date("2026-10-11T12:00:00.000Z"),
            }],
          };
        }
        if (sql.includes("FROM certificate_enrollments e")) {
          return {
            rows: [{
              id: ENROLLMENT,
              state: "pending_issuance",
              attempt: 1,
              snapshot_bytes: frozen.bytes,
              operator_request_id: "77",
              request_id: "42",
              last_error_code: "ADCS_CA_KEY_CHANGED",
              issuer_id: ISSUER,
              issuer_version: 1,
              certificate_id: null,
              updated_at: new Date("2026-10-11T12:00:00.000Z"),
              issuer_name: "Issuing CA",
              revalidation_required: true,
              current_version: 2,
            }],
          };
        }
        if (sql.includes("count(*)")) return { rows: [{ n: 1 }] };
        throw new Error(sql);
      },
    };
    const issuers = await listIssuers({ client: db, workspaceId: WORKSPACE });
    assert.equal(issuers.items[0].revalidationRequired, true);
    assert.equal(issuers.items[0].lastPreflight.caCertificates[0].certificateB64, undefined);
    assert.equal(issuers.items[0].lastPreflight.caCertificates[0].keySha256, "ab".repeat(32));
    const enrollments = await listEnrollments({ client: db, workspaceId: WORKSPACE });
    assert.equal(enrollments.items[0].state, "pending_issuance");
    assert.equal(enrollments.items[0].requestId, 42);
    assert.equal(enrollments.items[0].operatorRequestId, 77);
    assert.equal(enrollments.items[0].snapshotStale, true);
    assert.equal(enrollments.items[0].template, "TokenTimerWebServer");
  });

  it("normalizes a negative list limit to 1", async () => {
    const db = {
      async query(sql, params) {
        if (sql.includes("ORDER BY i.name")) {
          assert.equal(params[1], 1);
          return { rows: [] };
        }
        if (sql.includes("count(*)")) return { rows: [{ n: 0 }] };
        throw new Error(sql);
      },
    };
    const page = await listIssuers({ client: db, workspaceId: WORKSPACE, limit: -5 });
    assert.equal(page.pagination.limit, 1);
  });

  it("hides unconfigured AD CS issuers unless the caller asks for drafts", async () => {
    const seen = [];
    const db = {
      async query(sql) {
        seen.push(sql);
        if (sql.includes("count(*)")) return { rows: [{ n: 0 }] };
        return { rows: [] };
      },
    };
    await listIssuers({ client: db, workspaceId: WORKSPACE });
    assert.ok(
      seen.some((sql) => sql.includes("i.kind <> 'adcs' OR i.current_version > 0")),
    );
    seen.length = 0;
    await listIssuers({
      client: db,
      workspaceId: WORKSPACE,
      includeUnconfigured: true,
    });
    assert.equal(
      seen.some((sql) => sql.includes("current_version > 0")),
      false,
    );
  });

  it("discards only a version-0 issuer that has no enrollments", async () => {
    const db = {
      async query(sql) {
        assert.match(sql, /current_version = 0/);
        assert.match(sql, /NOT EXISTS/);
        assert.match(sql, /certificate_enrollments/);
        return { rows: [{ id: ISSUER }] };
      },
    };
    const discarded = await discardUnconfiguredIssuer({
      client: db,
      workspaceId: WORKSPACE,
      issuerId: ISSUER,
    });
    assert.equal(discarded.issuerId, ISSUER);

    const missing = {
      async query() {
        return { rows: [] };
      },
    };
    await assert.rejects(
      () =>
        discardUnconfiguredIssuer({
          client: missing,
          workspaceId: WORKSPACE,
          issuerId: ISSUER,
        }),
      (error) => error?.code === "CERTOPS_ISSUER_NOT_FOUND",
    );
  });
});

describe("bounded immutable AD CS enrollment policy options",()=>{
  it("preserves omitted defaults and freezes explicit supported options into distinct canonical bytes",()=>{const defaults=freezeSnapshot(snapshotInput());assert.equal(defaults.snapshot.pollInterval,900);assert.equal(defaults.snapshot.pendingTimeout,1209600);assert.equal(defaults.snapshot.minimumRemainingValidity,0);assert.equal(defaults.snapshot.requireLaterNotAfter,false);const options={pollInterval:60,pendingTimeout:3600,minimumRemainingValidity:86400,requireLaterNotAfter:true};const chosen=freezeSnapshot({...snapshotInput(),...options});for(const [key,value] of Object.entries(options))assert.equal(chosen.snapshot[key],value);assert.notEqual(chosen.sha256,defaults.sha256);assert.equal(chosen.sha256,require("node:crypto").createHash("sha256").update(chosen.bytes).digest("hex"));});
  it("rejects explicit null strings fractional values and out-of-contract bounds instead of coercing defaults",()=>{for(const options of [{pollInterval:0},{pollInterval:59},{pollInterval:86401},{pollInterval:60.5},{pollInterval:"900"},{pollInterval:null},{pendingTimeout:3599},{pendingTimeout:7776001},{pendingTimeout:null},{minimumRemainingValidity:-1},{minimumRemainingValidity:31536001},{minimumRemainingValidity:"0"},{minimumRemainingValidity:null},{requireLaterNotAfter:"true"},{requireLaterNotAfter:1},{requireLaterNotAfter:null}])assert.throws(()=>freezeSnapshot({...snapshotInput(),...options}),error=>error.code==="CERTOPS_SNAPSHOT_INVALID");});
  it("public creation service persists the policy with first-job enrollment binding",async()=>{const db=rowDb();db.putIssuer({id:ISSUER,workspace_id:WORKSPACE,kind:"adcs",version:1,ca_config:snapshotInput().caConfig,template:snapshotInput().template,ca_key_sha256:snapshotInput().caKeySha256,revalidation_required:false});const options={pollInterval:120,pendingTimeout:7200,minimumRemainingValidity:300,requireLaterNotAfter:true};let jobOptions;const created=await createEnrollment({client:db,workspaceId:WORKSPACE,issuerId:ISSUER,certificateId:"33333333-3333-4333-8333-333333333333",agentId:"22222222-2222-4222-8222-222222222222",target:WEBHOSTING,authorizedDnsNames:["app.example.com"],keyAlgorithm:"rsa",keySize:2048,...options,audit:async()=>{},createJob:async args=>{jobOptions=args;return {id:JOB_ID};}});const stored=db.enrollments.get(created.enrollmentId);for(const [key,value]of Object.entries(options))assert.equal(JSON.parse(stored.snapshot_bytes)[key],value);assert.equal(stored.snapshot_sha256,created.snapshotSha256);assert.equal(jobOptions.enrollmentId,created.enrollmentId);});
});
