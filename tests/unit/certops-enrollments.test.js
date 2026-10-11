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
  confirmIssuerKey,
  proposeReconcileRequestId,
  recordEnrollmentResult,
  scheduleDueEnrollments,
} = require("../../apps/api/services/certops/certificateEnrollments");
const { validateSignedJob } = require("../../packages/contracts/certops/validate-signed-job.cjs");
const { migrations } = require("../../apps/api/migrations/migrate");

const ISSUER = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const ENROLLMENT = "5f0c2a8e-3b1d-4c6e-9a7f-1e2d3c4b5a69";

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
    assert.doesNotThrow(() => assertForwardTransition("installing", "install_failed"));
    assert.throws(
      () => assertForwardTransition("installed", "submitting"),
      (error) => error.code === "CERTOPS_ENROLLMENT_TRANSITION_INVALID",
    );
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
  });
});

const WORKSPACE = "11111111-1111-4111-8111-111111111111";
const WEBHOSTING = {
  type: "windows-iis",
  reference: "iis-01/webhosting",
  store: "WebHosting",
  binding: { site: "Shop", port: 443, sniHost: "app.example.com" },
};

function rowDb() {
  const enrollments = new Map();
  const issuers = new Map();
  let checkpoint = null;
  function cloneRows() {
    return new Map([...enrollments.entries()].map(([id, row]) => [id, { ...row }]));
  }
  function restore(saved) {
    enrollments.clear();
    for (const [id, row] of saved) enrollments.set(id, row);
  }
  return {
    enrollments,
    issuers,
    putEnrollment(row) {
      enrollments.set(row.id, { ...row });
    },
    putIssuer(row) {
      issuers.set(row.id, { ...row });
    },
    async query(sql, params = []) {
      const text = sql.replace(/\s+/g, " ").trim();
      if (text === "BEGIN") {
        checkpoint = cloneRows();
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
      if (text.includes("FROM certificate_enrollments e") && text.includes("FOR UPDATE OF e SKIP LOCKED")) {
        const now = params[0];
        const rows = [...enrollments.values()].filter(
          (row) => row.next_poll_at && row.next_poll_at.getTime() <= now.getTime(),
        );
        return { rows };
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
});
