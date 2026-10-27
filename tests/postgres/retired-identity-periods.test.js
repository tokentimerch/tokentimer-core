"use strict";
const { test, after } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.match(process.env.DB_NAME || "", /^pr329_.*_test$/);
assert.equal(process.env.NODE_ENV, "test");
const { pool } = require("../../apps/api/db/database");
const { retireCertificateIdentity, readdManagingSource, listCertificateIdentities } = require("../../apps/api/services/certops/certificateIdentity");
const { claimJobs } = require("../../apps/api/services/certops/agentDispatch");
const { cancelEnrollment } = require("../../apps/api/services/certops/certificateEnrollments");
after(() => pool.end());

for (const status of ["revoked", "decommissioned"]) {
  for (const legacy of [false, true]) {
  test(`${status}, legacy=${legacy}: closes current source periods and retains history`, async () => {
    const workspaceId = crypto.randomUUID();
    const fingerprint = crypto.randomBytes(32).toString("hex");
    const user = (await pool.query(`INSERT INTO users(email,display_name,password_hash,auth_method)
      VALUES($1,'Retirement test','synthetic-fixture','local') RETURNING id`, [`retire-${workspaceId}@example.test`])).rows[0].id;
    await pool.query("INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'Retirement fixture',$2,'team')", [workspaceId, user]);
    for (let i = 0; i < 2; i++) {
      await pool.query(`INSERT INTO managed_certificates(workspace_id,name,status,source,fingerprint_sha256)
        VALUES($1,$2,'active','agent_filesystem',$3)`, [workspaceId, `source-${i}`, fingerprint]);
    }
    const identityId = (await pool.query("SELECT id FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2", [workspaceId, fingerprint])).rows[0].id;
    const rotated = (await pool.query(`INSERT INTO managed_certificates(workspace_id,name,status,source,fingerprint_sha256)
      VALUES($1,'rotated','active','agent_filesystem',$2) RETURNING id`, [workspaceId, fingerprint])).rows[0].id;
    await pool.query("UPDATE managed_certificates SET fingerprint_sha256=$2,identity_observed_at=clock_timestamp() WHERE id=$1", [rotated, crypto.randomBytes(32).toString("hex")]);
    await pool.query(`INSERT INTO managed_certificates(workspace_id,name,status,source,fingerprint_sha256)
      VALUES($1,'other','active','agent_filesystem',$2)`, [workspaceId, crypto.randomBytes(32).toString("hex")]);
    const before = (await pool.query("SELECT id FROM certops_management_periods WHERE workspace_id=$1 AND current_identity_id=$2 AND ended_at IS NULL", [workspaceId, identityId])).rows;
    assert.equal(before.length, 2);
    if (legacy) await pool.query("UPDATE certops_certificate_identities SET lifecycle_status=$3 WHERE workspace_id=$1 AND id=$2", [workspaceId, identityId, status]);
    const result = await retireCertificateIdentity({ workspaceId, identityId, expectedFingerprintSha256: fingerprint,
      status, reason: "Certificate intentionally retired", acknowledgeUncertainty: true, actorUserId: user });
    assert.equal(result.managed, false);
    const rows = (await pool.query("SELECT * FROM certops_management_periods WHERE workspace_id=$1 AND current_identity_id=$2", [workspaceId, identityId])).rows;
    assert.equal(rows.length, 2);
    for (const row of rows) {
      assert.ok(row.ended_at);
      assert.equal(row.ended_reason, `certificate_${status}`);
      assert.equal(row.automation_enabled, false);
    }
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM certops_management_associations WHERE workspace_id=$1 AND identity_id=$2", [workspaceId, identityId])).rows[0].n, 3);
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM certops_management_periods WHERE workspace_id=$1 AND ended_at IS NULL", [workspaceId])).rows[0].n, 2);
    // Repeating retirement is idempotent and repairs open periods left by older builds.
    await retireCertificateIdentity({ workspaceId, identityId, expectedFingerprintSha256: fingerprint, status,
      reason: "Repeat retirement", acknowledgeUncertainty: true, actorUserId: user });
    assert.equal((await pool.query("SELECT ended_at FROM certops_management_periods WHERE id=$1", [rows[0].id])).rows[0].ended_at.toISOString(), rows[0].ended_at.toISOString());
    const sourceId = rows[0].managed_certificate_id;
    const readd = () => readdManagingSource({ workspaceId, managedCertificateId: sourceId,
      renewalProfileId: null, automationEnabled: false });
    await assert.rejects(readd(), { code: "CERTOPS_CERTIFICATE_RETIRED" });
    const replacement = crypto.randomBytes(32).toString("hex");
    await pool.query("UPDATE managed_certificates SET fingerprint_sha256=$2,identity_observed_at=clock_timestamp(),status='active' WHERE id=$1", [sourceId, replacement]);
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM certops_management_periods WHERE managed_certificate_id=$1 AND ended_at IS NULL", [sourceId])).rows[0].n, 0,
      "a fresh observation does not implicitly resume management");
    const replacementIdentity = (await pool.query("SELECT id FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2", [workspaceId, replacement])).rows[0].id;
    const detail = (await listCertificateIdentities({ workspaceId, identityId: replacementIdentity })).items[0];
    assert.equal(detail.managed, false);
    assert.deepEqual(detail.sources, [], "a replacement has no invented management history");
    assert.deepEqual(detail.restartableSources.map(source => source.managedCertificateId), [sourceId]);
    assert.deepEqual((await listCertificateIdentities({ workspaceId, identityId })).items[0].restartableSources, []);
    const started = await readd();
    assert.deepEqual((await listCertificateIdentities({ workspaceId, identityId: replacementIdentity })).items[0].restartableSources, []);
    assert.notEqual(started.periodId, rows[0].id);
    assert.equal((await pool.query("SELECT current_identity_id FROM certops_management_periods WHERE id=$1", [started.periodId])).rows[0].current_identity_id,
      (await pool.query("SELECT id FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2", [workspaceId, replacement])).rows[0].id);
  });
  }
}

async function claimFixture({ enrollmentState = null, createJob = true, lateIdentity = false, enrollmentOperation = "continue-enrollment" } = {}) {
  const workspaceId = crypto.randomUUID();
  const fingerprint = crypto.randomBytes(32).toString("hex");
  const user = (await pool.query(`INSERT INTO users(email,display_name,password_hash,auth_method)
    VALUES($1,'Claim regression','synthetic-fixture','local') RETURNING id`, [`claim-${workspaceId}@example.test`])).rows[0].id;
  await pool.query("INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'Claim fixture',$2,'team')", [workspaceId, user]);
  const certificateId = (await pool.query(`INSERT INTO managed_certificates(workspace_id,name,status,source,fingerprint_sha256)
    VALUES($1,'Claim source','active','agent_filesystem',$2) RETURNING id`, [workspaceId, lateIdentity ? null : fingerprint])).rows[0].id;
  const period = (await pool.query("SELECT id,current_identity_id FROM certops_management_periods WHERE managed_certificate_id=$1", [certificateId])).rows[0];
  const agentId = (await pool.query(`INSERT INTO certops_agents(workspace_id,agent_id,name,agent_version,protocol_version,
    credential_prefix,credential_hash,status,declared_capabilities,capabilities_updated_at)
    VALUES($1,$2,'Claim agent','0.18.1','1.0.0',$3,$4,'active','["adcs-enroll-v1"]',NOW()) RETURNING id`,
  [workspaceId, crypto.randomUUID(), "ttagent_" + crypto.randomBytes(8).toString("hex"), crypto.randomBytes(32).toString("hex")])).rows[0].id;
  const f = { workspaceId, fingerprint, user, certificateId, periodId: period.id, identityId: period.current_identity_id, agentId, enrollmentOperation };
  if (enrollmentState) {
    const issuerId = (await pool.query("INSERT INTO certificate_issuers(workspace_id,kind,name,current_version) VALUES($1,'adcs','Claim CA',1) RETURNING id", [workspaceId])).rows[0].id;
    f.enrollmentId = (await pool.query(`INSERT INTO certificate_enrollments(workspace_id,certificate_id,issuer_id,issuer_version,
      agent_id,state,snapshot_bytes,snapshot_sha256,deploy_target,attempt)
      VALUES($1,$2,$3,1,$4,'pending_issuance',$5,$6,'{}',1) RETURNING id`,
    [workspaceId, certificateId, issuerId, agentId, Buffer.from("{}"), crypto.createHash("sha256").update("{}").digest("hex")])).rows[0].id;
  }
  if (createJob) await addClaimJob(f);
  if (lateIdentity) {
    // Historical jobs can predate the first observed fingerprint. Their own
    // immutable identity remains NULL; admission must lock the period's one.
    await pool.query("UPDATE managed_certificates SET fingerprint_sha256=$2 WHERE id=$1", [certificateId, fingerprint]);
    f.identityId = (await pool.query("SELECT current_identity_id FROM certops_management_periods WHERE id=$1", [f.periodId])).rows[0].current_identity_id;
    assert.equal((await pool.query("SELECT certificate_identity_id FROM certificate_jobs WHERE id=$1", [f.jobId])).rows[0].certificate_identity_id, null);
  }
  if (enrollmentState) await pool.query("UPDATE certificate_enrollments SET state=$2 WHERE id=$1", [f.enrollmentId, enrollmentState]);
  return f;
}

async function addClaimJob(f) {
  f.jobId = (await pool.query(`INSERT INTO certificate_jobs(workspace_id,operation,subject_type,subject_id,executor_kind,assigned_agent_id,enrollment_id)
    VALUES($1,$2,'managed_certificate',$3,'agent',$4,$5) RETURNING id`,
  [f.workspaceId, f.enrollmentId ? f.enrollmentOperation : "renew", f.certificateId, f.agentId, f.enrollmentId || null])).rows[0].id;
  if (f.enrollmentId) await pool.query("UPDATE certificate_enrollments SET current_job_id=$2 WHERE id=$1", [f.enrollmentId, f.jobId]);
}

function retireFixture(f, status, client = pool) {
  return retireCertificateIdentity({ client, workspaceId: f.workspaceId, identityId: f.identityId,
    expectedFingerprintSha256: f.fingerprint, status, reason: "Retirement claim regression",
    acknowledgeUncertainty: true, actorUserId: f.user });
}

function pollFixture(f, dbPool = pool) {
  return claimJobs({ dbPool, agent: { id: f.agentId, agentId: f.agentId, workspaceId: f.workspaceId,
    status: "active", protocolVersion: "1.0.0", agentVersion: "0.18.1" },
  body: { maxJobs: 16, supportedActions: ["renew", "continue-enrollment"] },
  env: { CERTOPS_ENABLED: "true" }, deps: { signJobForDispatch: async ({ job }) => job } });
}

for (const status of ["revoked", "decommissioned"]) {
  for (const lateIdentity of [false, true]) {
  test(`${status}, late identity=${lateIdentity}: real dispatch skips a concurrent retirement and SQL guards never wait for its identity`, { timeout: 10000 }, async () => {
    const f = await claimFixture({ lateIdentity, enrollmentState: lateIdentity ? "pending_issuance" : null });
    const retirementClient = await pool.connect();
    const directClaim = await pool.connect();
    const locked = Promise.withResolvers(), resume = Promise.withResolvers();
    let retirement;
    try {
      await retirementClient.query("BEGIN");
      await directClaim.query("BEGIN; SET LOCAL statement_timeout='1500ms'");
      retirement = retireFixture(f, status, { async query(sql, params) {
        const result = await retirementClient.query(sql, params);
        if (sql.includes("FOR NO KEY UPDATE")) { locked.resolve(); await resume.promise; }
        return result;
      } });
      await locked.promise;
      // The candidate is visible as active, but its identity is locked by the
      // actual retirement transaction. The complete poll must still commit.
      assert.deepEqual((await pollFixture(f)).jobs, []);
      assert.equal((await pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [f.jobId])).rows[0].status, "pending");
      await assert.rejects(directClaim.query("UPDATE certificate_jobs SET status='claimed' WHERE id=$1", [f.jobId]),
        { code: "55P03" }, "direct writers fail immediately instead of waiting while holding the period");
      await directClaim.query("ROLLBACK");
      resume.resolve();
      await retirement;
      await retirementClient.query("COMMIT");
      const period = (await pool.query("SELECT ended_at,ended_reason FROM certops_management_periods WHERE id=$1", [f.periodId])).rows[0];
      assert.ok(period.ended_at);
      assert.equal(period.ended_reason, `certificate_${status}`);
      assert.equal((await pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [f.jobId])).rows[0].status, lateIdentity ? "pending" : "cancelled");
      assert.deepEqual((await pollFixture(f)).jobs, [], "a preserved continuation cannot install after retirement");
    } finally {
      resume.resolve();
      if (retirement) await retirement.catch(() => {});
      await Promise.all([retirementClient.query("ROLLBACK"), directClaim.query("ROLLBACK")]);
      retirementClient.release(); directClaim.release();
    }
  });
  }

  for (const state of ["cancelled", "expired", "abandoned"]) {
    test(`${status}: real dispatch signs ${state} cleanup after closing its management period`, async () => {
      const f = await claimFixture({ enrollmentState: state });
      await retireFixture(f, status);
      const result = await pollFixture(f);
      assert.equal(result.jobs.length, 1);
      assert.equal(result.jobs[0].jobId, f.jobId);
      assert.equal(result.jobs[0].enrollment.enrollmentId, f.enrollmentId);
      assert.equal(result.jobs[0].enrollment.terminalState, state);
      assert.equal((await pool.query("SELECT ended_at FROM certops_management_periods WHERE id=$1", [f.periodId])).rows[0].ended_at != null, true);
    });
  }

  test(`${status}: cleanup created after retirement is claimable without invented period attribution`, async () => {
    const f = await claimFixture({ enrollmentState: "cancelled", createJob: false });
    await retireFixture(f, status);
    await addClaimJob(f);
    const job = (await pool.query("SELECT management_period_id,certificate_identity_id FROM certificate_jobs WHERE id=$1", [f.jobId])).rows[0];
    assert.equal(job.management_period_id, null);
    assert.equal(job.certificate_identity_id, null);
    assert.equal((await pollFixture(f)).jobs[0].enrollment.terminalState, "cancelled");
  });

  test(`${status}: an installation continuation remains fenced`, async () => {
    const f = await claimFixture({ enrollmentState: "issued" });
    await retireFixture(f, status);
    assert.deepEqual((await pollFixture(f)).jobs, []);
  });
}

for (const binding of ["current_job_id", "agent_id", "certificate_id"]) {
  test(`terminal cleanup cannot bypass retirement with a missing ${binding} binding`, async () => {
    const f = await claimFixture({ enrollmentState: "cancelled" });
    await retireFixture(f, "revoked");
    await pool.query(`UPDATE certificate_enrollments SET ${binding}=NULL WHERE id=$1`, [f.enrollmentId]);
    assert.deepEqual((await pollFixture(f)).jobs, []);
  });
}

test("cleanup skips an enrollment locked by cancellation and succeeds on the next poll", { timeout: 10000 }, async () => {
  const f = await claimFixture({ enrollmentState: "cancelled" });
  await retireFixture(f, "revoked");
  const cancellation = await pool.connect();
  try {
    await cancellation.query("BEGIN");
    await cancellation.query("SELECT id FROM certificate_enrollments WHERE id=$1 FOR UPDATE", [f.enrollmentId]);
    assert.deepEqual((await pollFixture(f)).jobs, []);
    await cancellation.query("COMMIT");
    assert.equal((await pollFixture(f)).jobs[0].enrollment.terminalState, "cancelled");
  } finally {
    await cancellation.query("ROLLBACK");
    cancellation.release();
  }
});

test("cleanup rechecks its current-job binding after candidate selection", async () => {
  const f = await claimFixture({ enrollmentState: "cancelled" });
  await retireFixture(f, "revoked");
  let selected = false;
  const dbPool = { async connect() {
    const client = await pool.connect();
    return { release: () => client.release(), async query(sql, params) {
      const result = await client.query(sql, params);
      if (sql.includes("FROM certificate_jobs cj") && sql.includes("FOR UPDATE SKIP LOCKED")) {
        assert.equal(result.rows[0].id, f.jobId);
        selected = true;
        await pool.query("UPDATE certificate_enrollments SET current_job_id=NULL WHERE id=$1", [f.enrollmentId]);
      }
      return result;
    } };
  } };
  assert.deepEqual((await pollFixture(f, dbPool)).jobs, []);
  assert.equal(selected, true);
});

test("an initial enrollment claim skips concurrent cancellation before initializing its attempt", { timeout: 10000 }, async () => {
  const f = await claimFixture({ enrollmentState: "prepared", enrollmentOperation: "renew" });
  await pool.query("UPDATE certificate_enrollments SET attempt=0 WHERE id=$1", [f.enrollmentId]);
  const cancellationClient = await pool.connect();
  const locked = Promise.withResolvers(), resume = Promise.withResolvers();
  let cancellation;
  try {
    cancellation = cancelEnrollment({ workspaceId: f.workspaceId, enrollmentId: f.enrollmentId, actorUserId: f.user,
      audit: async () => {}, client: { async query(sql, params) {
        const result = await cancellationClient.query(sql, params);
        if (sql.includes("FOR UPDATE OF e")) { locked.resolve(); await resume.promise; }
        return result;
      } } });
    await locked.promise;
    assert.deepEqual((await pollFixture(f)).jobs, []);
    resume.resolve();
    await cancellation;
    const enrollment = (await pool.query("SELECT state,attempt FROM certificate_enrollments WHERE id=$1", [f.enrollmentId])).rows[0];
    assert.equal(enrollment.state, "cancelled");
    assert.equal(enrollment.attempt, 0);
    assert.equal((await pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [f.jobId])).rows[0].status, "cancelled");
  } finally {
    resume.resolve();
    if (cancellation) await cancellation.catch(() => {});
    await cancellationClient.query("ROLLBACK");
    cancellationClient.release();
  }
});
