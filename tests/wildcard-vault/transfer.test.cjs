"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.equal(process.env.DB_PORT, "60470");
assert.match(process.env.DB_NAME || "", /^pr329_final/);
process.env.NODE_ENV = "test";
process.env.CERTOPS_ENABLED = "true";
const api = createRequire(require.resolve("../../apps/api/package.json"));
const { pool } = api("./db/database");
const operations = api("./services/certops/distributionOperations");
const material = api("./services/certops/materialDistribution");
const { createCertificateIssuanceJob } = api("./services/certops/issuance");
const { approveJob } = api("./services/certops/jobApprovals");
const { transferTokenAssociations } = api("./services/workspaceTokenTransfer");
const health = api("./services/certops/renewalPathHealth");
const request = require("supertest");
const uuid = () => crypto.randomUUID();
const pem = fs.readFileSync(
  path.join(__dirname, "../../packages/agent/src/verify/fixtures/leaf.crt.pem"),
  "utf8",
);
const cert = api("./services/certops/parser").parsePublicCertificateMaterial(
  pem,
)[0];
test.after(() => pool.end());

async function fixture({ ordinary = false, published = true } = {}) {
  const actor = (
    await pool.query(
      "INSERT INTO users(email,display_name,password_hash,auth_method) VALUES($1,'Transfer review','fixture-only','local') RETURNING id",
      [`${uuid()}@example.test`],
    )
  ).rows[0].id;
  const approver = (
    await pool.query(
      "INSERT INTO users(email,display_name,password_hash,auth_method) VALUES($1,'Approver','fixture-only','local') RETURNING id",
      [`${uuid()}@example.test`],
    )
  ).rows[0].id;
  const workspaceId = uuid(),
    destination = uuid();
  for (const id of [workspaceId, destination]) {
    await pool.query(
      "INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'Isolated transfer',$2,'oss')",
      [id, actor],
    );
    await pool.query(
      "INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'admin')",
      [id, actor],
    );
  }
  const issuer = (
    await pool.query(
      `INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash)
    VALUES($1,$2,'0.17.3','1.0.0',$3,$4) RETURNING id`,
      [
        workspaceId,
        uuid(),
        `ttagent_${crypto.randomBytes(8).toString("hex")}`,
        crypto.randomBytes(32).toString("hex"),
      ],
    )
  ).rows[0].id;
  let certificateId,
    groupId,
    materialVersionId,
    managementPeriodId,
    publishingJob;
  if (ordinary) {
    certificateId = (
      await pool.query(
        `INSERT INTO managed_certificates(workspace_id,source,source_ref,fingerprint_sha256,key_mode,status)
      VALUES($1,'manual',$2,$3,'external-unknown','active') RETURNING id`,
        [workspaceId, uuid(), cert.fingerprintSha256],
      )
    ).rows[0].id;
    managementPeriodId = (
      await pool.query(
        "SELECT id FROM certops_management_periods WHERE managed_certificate_id=$1 AND ended_at IS NULL",
        [certificateId],
      )
    ).rows[0].id;
  } else {
    const issued = await operations.transaction((client) =>
      createCertificateIssuanceJob({
        client,
        workspaceId,
        idempotencyKey: uuid(),
        requestedByUserId: actor,
        assignedAgentId: issuer,
        payload: {
          target: { type: "domain", reference: cert.commonName },
          sans: cert.subjectAltNames,
          caEndpoint: "https://acme.example.test/directory",
          commandRef: "certbot",
          dnsProvider: "cloudflare",
          dnsZone: "example.com",
          keyAlgorithm: "rsa",
          keySize: 2048,
          publicationDestination: {
            materialStoreRef: "source_only",
            issuanceProfileRef: "shared",
            profileRevision: 1,
          },
        },
      }),
    );
    certificateId = issued.job.subjectId;
    ({ groupId, materialVersionId, managementPeriodId } =
      issued.job.payload.publication);
    publishingJob = (
      await pool.query(
        "UPDATE certificate_jobs SET status='running',attempt_count=1,claim_id=gen_random_uuid(),claimed_by_agent_id=$2,lease_expires_at=clock_timestamp()+interval '5 minutes' WHERE id=$1 RETURNING *",
        [issued.job.id, issuer],
      )
    ).rows[0];
    if (published)
      await operations.transaction(async (client) => {
        await material.acceptPublicationReceipt({
          client,
          workspaceId,
          agentId: issuer,
          job: publishingJob,
          certificatePem: pem,
          receipt: {
            schemaVersion: 1,
            workspaceId,
            groupId,
            materialVersionId,
            materialStoreRef: "source_only",
            providerVersion: 1,
            fingerprintSha256: cert.fingerprintSha256,
            validTo: cert.notAfter,
          },
        });
        await client.query(
          "UPDATE certificate_jobs SET status='succeeded',completed_at=NOW() WHERE id=$1",
          [publishingJob.id],
        );
      });
  }
  let tokenId = (
    await pool.query("SELECT token_id FROM managed_certificates WHERE id=$1", [
      certificateId,
    ])
  ).rows[0].token_id;
  if (!tokenId) {
    tokenId = (
      await pool.query(
        "INSERT INTO tokens(user_id,workspace_id,created_by,name,expiration,type,category) VALUES($1,$2,$1,'Transfer certificate','2030-01-01','other','general') RETURNING id",
        [actor, workspaceId],
      )
    ).rows[0].id;
    await pool.query(
      "UPDATE managed_certificates SET token_id=$2 WHERE id=$1",
      [certificateId, tokenId],
    );
  }
  const bindingId = uuid(),
    binding = {
      agentId: issuer,
      deploymentProfileRef: "source_web",
      profileRevision: 1,
      required: true,
      wave: 0,
      verificationPolicy: "served",
      freshnessSeconds: 3600,
      state: "active",
    };
  if (!ordinary)
    await operations.putBinding({
      workspaceId,
      groupId,
      bindingId,
      binding,
      actorUserId: actor,
    });
  const app = api("express")();
  app.use(api("express").json());
  app.use((req, _res, next) => {
    if (req.get("X-Test-User") === String(actor)) {
      req.user = { id: actor, auth_method: "local" };
      req.isAuthenticated = () => true;
    }
    next();
  });
  const rbac = api("./services/rbac");
  app.use(
    "/api/v1/workspaces/:id",
    api("./middleware/auth").requireAuth,
    rbac.loadWorkspace,
    rbac.requireWorkspaceMembership,
  );
  app.use(api("./routes/workspaces"));
  app.use(api("./routes/certops"));
  async function transfer() {
    return request(app)
      .post(`/api/v1/workspaces/${destination}/transfer-tokens`)
      .set("X-Test-User", String(actor))
      .send({ from_workspace_id: workspaceId, token_ids: [tokenId] });
  }
  async function rollout() {
    const job = await operations.requestRollout({
      workspaceId,
      groupId,
      materialVersionId,
      actorUserId: actor,
      idempotencyKey: uuid(),
    });
    await approveJob({ workspaceId, jobId: job.id, approverUserId: approver });
    await operations.transaction((client) =>
      operations.processDistributionIntent({
        client,
        row: {
          workspace_id: workspaceId,
          event_type: "distribution_approval_granted",
        },
        payload: { jobId: job.id },
      }),
    );
    return (
      await pool.query(
        "SELECT * FROM certops_distribution_rollouts WHERE approval_job_id=$1",
        [job.id],
      )
    ).rows[0];
  }
  return {
    actor,
    approver,
    workspaceId,
    destination,
    issuer,
    certificateId,
    groupId,
    materialVersionId,
    managementPeriodId,
    publishingJob,
    tokenId,
    bindingId,
    binding,
    app,
    transfer,
    rollout,
  };
}

async function assertMoved(f) {
  const mc = (
    await pool.query("SELECT * FROM managed_certificates WHERE id=$1", [
      f.certificateId,
    ])
  ).rows[0];
  assert.equal(mc.workspace_id, f.destination);
  assert.equal(mc.profile_id, null);
  assert.equal(
    (
      await pool.query("SELECT workspace_id FROM tokens WHERE id=$1", [
        f.tokenId,
      ])
    ).rows[0].workspace_id,
    f.destination,
  );
  assert.equal(
    (
      await pool.query(
        "SELECT COUNT(*)::int n FROM certops_management_periods WHERE managed_certificate_id=$1 AND ended_at IS NULL",
        [f.certificateId],
      )
    ).rows[0].n,
    1,
  );
  const current = (
    await pool.query(
      "SELECT * FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL",
      [f.destination, f.certificateId],
    )
  ).rows[0];
  assert.equal(current.automation_enabled, false);
  assert.equal(current.renewal_profile_id, null);
  assert.equal(
    (
      await pool.query(
        "SELECT COUNT(*)::int n FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2",
        [f.destination, cert.fingerprintSha256],
      )
    ).rows[0].n,
    1,
  );
  if (f.groupId) {
    assert.equal(mc.deployed_agent_id, null);
    assert.equal(mc.deployed_cert_path, null);
    assert.equal(mc.key_reference, null);
    assert.deepEqual(mc.public_metadata, {});
    assert.equal(
      (
        await pool.query(
          "SELECT COUNT(*)::int n FROM certops_distribution_groups WHERE workspace_id=$1",
          [f.destination],
        )
      ).rows[0].n,
      0,
    );
    assert.equal(
      (
        await pool.query(
          "SELECT COUNT(*)::int n FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2",
          [f.destination, f.certificateId],
        )
      ).rows[0].n,
      0,
    );
    assert.equal(
      (
        await pool.query(
          "SELECT state FROM certops_distribution_groups WHERE id=$1",
          [f.groupId],
        )
      ).rows[0].state,
      "retired",
    );
    assert.equal(
      (
        await health.resolveRenewalPathForCertificate({
          db: pool,
          workspaceId: f.destination,
          certificateId: f.certificateId,
        })
      ).dependencies.length,
      0,
    );
    await assert.rejects(
      operations.requestRollout({
        workspaceId: f.destination,
        groupId: f.groupId,
        materialVersionId: f.materialVersionId,
        actorUserId: f.actor,
        idempotencyKey: uuid(),
      }),
      { code: "CERTOPS_DISTRIBUTION_NOT_FOUND" },
    );
  }
}

test("ordinary certificate/token transfer remains functional", async () => {
  const f = await fixture({ ordinary: true });
  const result = await f.transfer();
  assert.equal(result.status, 200, JSON.stringify(result.body));
  await assertMoved(f);
});

test("published Vault certificate transfers public inventory without source authorizations or a destination integration", async () => {
  const f = await fixture();
  const before = (
    await pool.query("SELECT * FROM certops_material_versions WHERE id=$1", [
      f.materialVersionId,
    ])
  ).rows[0];
  const result = await f.transfer();
  assert.equal(result.status, 200, JSON.stringify(result.body));
  await assertMoved(f);
  assert.deepEqual(
    (
      await pool.query("SELECT * FROM certops_material_versions WHERE id=$1", [
        f.materialVersionId,
      ])
    ).rows[0],
    before,
  );
  assert.equal(
    (
      await pool.query(
        "SELECT workspace_id FROM certificate_jobs WHERE id=$1",
        [f.publishingJob.id],
      )
    ).rows[0].workspace_id,
    f.workspaceId,
  );
  assert.equal(
    (await f.transfer()).body.moved,
    0,
    "replay must not create another management period",
  );
  assert.equal(
    (
      await pool.query(
        "SELECT COUNT(*)::int n FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL",
        [f.destination, f.certificateId],
      )
    ).rows[0].n,
    1,
  );
});

test("historical groups, completed rollouts and their approval/evidence retain source provenance", async () => {
  const f = await fixture(),
    rollout = await f.rollout();
  await pool.query(
    "UPDATE certops_distribution_rollouts SET state='verified' WHERE id=$1",
    [rollout.id],
  );
  await pool.query(
    "INSERT INTO certificate_job_log(workspace_id,job_id,event_type,status,message) VALUES($1,$2,'job.completed','succeeded','Retained publication evidence')",
    [f.workspaceId, f.publishingJob.id],
  );
  await pool.query(
    "UPDATE certops_management_periods SET ended_at=NOW(),ended_reason='stopped' WHERE id=$1",
    [f.managementPeriodId],
  );
  const period = (
    await pool.query(
      "INSERT INTO certops_management_periods(workspace_id,managed_certificate_id,current_identity_id) SELECT $1,$2,current_identity_id FROM certops_management_periods WHERE id=$3 RETURNING id",
      [f.workspaceId, f.certificateId, f.managementPeriodId],
    )
  ).rows[0].id;
  await operations.transaction((client) =>
    material.createGroupForSource({
      client,
      workspaceId: f.workspaceId,
      certificateId: f.certificateId,
      issuerAgentId: f.issuer,
      materialStoreRef: "source_only",
      issuanceProfileRef: "shared",
      profileRevision: 1,
    }),
  );
  const before = (
    await pool.query(
      "SELECT * FROM certops_consumer_deployments WHERE rollout_id=$1",
      [rollout.id],
    )
  ).rows;
  assert.equal((await f.transfer()).status, 200);
  await assertMoved(f);
  assert.deepEqual(
    (
      await pool.query(
        "SELECT * FROM certops_consumer_deployments WHERE rollout_id=$1",
        [rollout.id],
      )
    ).rows,
    before,
  );
  assert.equal(
    (
      await pool.query(
        "SELECT state FROM certops_distribution_rollouts WHERE id=$1",
        [rollout.id],
      )
    ).rows[0].state,
    "verified",
  );
  assert.equal(
    (
      await pool.query(
        "SELECT COUNT(*)::int n FROM certops_job_approvals WHERE workspace_id=$1",
        [f.workspaceId],
      )
    ).rows[0].n,
    1,
  );
  assert.equal(
    (
      await pool.query(
        "SELECT workspace_id FROM certificate_job_log WHERE job_id=$1 AND message='Retained publication evidence'",
        [f.publishingJob.id],
      )
    ).rows[0].workspace_id,
    f.workspaceId,
  );
  assert.ok(
    (
      await pool.query(
        "SELECT ended_at FROM certops_management_periods WHERE id=$1",
        [period],
      )
    ).rows[0].ended_at,
  );
  assert.equal(
    (
      await pool.query(
        "SELECT COUNT(*)::int n FROM audit_events WHERE workspace_id=$1 AND action='TOKENS_TRANSFERRED_BETWEEN_WORKSPACES'",
        [f.destination],
      )
    ).rows[0].n,
    1,
  );
});

test("unclaimed pending deployment is cancelled, not moved or reauthorized", async () => {
  const f = await fixture(),
    rollout = await f.rollout();
  await operations.transaction((c) =>
    operations.advanceRollout(c, f.workspaceId, f.groupId, rollout.id),
  );
  const child = (
    await pool.query(
      "SELECT * FROM certificate_jobs WHERE workspace_id=$1 AND operation='deploy-from-store'",
      [f.workspaceId],
    )
  ).rows[0];
  assert.equal((await f.transfer()).status, 200);
  await assertMoved(f);
  const after = (
    await pool.query("SELECT * FROM certificate_jobs WHERE id=$1", [child.id])
  ).rows[0];
  assert.equal(after.status, "cancelled");
  assert.equal(after.workspace_id, f.workspaceId);
  assert.deepEqual(after.payload, child.payload);
  assert.equal(
    (
      await pool.query(
        "SELECT state FROM certops_distribution_rollouts WHERE id=$1",
        [rollout.id],
      )
    ).rows[0].state,
    "retired",
  );
});

test("claimed/running/uncertain distribution work requires reconciliation with an actionable API error", async (t) => {
  for (const status of ["claimed", "running", "orphaned_unknown_effect"])
    await t.test(status, async () => {
      const f = await fixture(),
        rollout = await f.rollout();
      await operations.transaction((c) =>
        operations.advanceRollout(c, f.workspaceId, f.groupId, rollout.id),
      );
      await pool.query(
        "UPDATE certificate_jobs SET status=$2,attempt_count=1,claim_id=gen_random_uuid(),claimed_by_agent_id=$3 WHERE workspace_id=$1 AND operation='deploy-from-store'",
        [f.workspaceId, status, f.issuer],
      );
      const result = await f.transfer();
      assert.equal(result.status, 409);
      assert.equal(
        result.body.code,
        "CERTOPS_DISTRIBUTION_TRANSFER_RECONCILIATION_REQUIRED",
      );
      assert.match(result.body.error, /reconcil/i);
      assert.equal(
        (
          await pool.query("SELECT workspace_id FROM tokens WHERE id=$1", [
            f.tokenId,
          ])
        ).rows[0].workspace_id,
        f.workspaceId,
      );
      assert.equal(
        (
          await pool.query(
            "SELECT ended_at FROM certops_management_periods WHERE id=$1",
            [f.managementPeriodId],
          )
        ).rows[0].ended_at,
        null,
      );
    });
});

test("an active result/job lock yields a bounded reconciliation response rather than a deadlock", async () => {
  const f = await fixture(),
    client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      "SELECT id FROM certificate_jobs WHERE id=$1 FOR UPDATE",
      [f.publishingJob.id],
    );
    const result = await f.transfer();
    assert.equal(result.status, 409);
    assert.equal(
      result.body.code,
      "CERTOPS_DISTRIBUTION_TRANSFER_RECONCILIATION_REQUIRED",
    );
  } finally {
    await client.query("ROLLBACK");
    client.release();
  }
});

test("never-started publication is cancelled and releases only its unused allocation", async () => {
  const f = await fixture({ published: false });
  await pool.query(
    "UPDATE certificate_jobs SET status='pending',attempt_count=0,claim_id=NULL,claimed_by_agent_id=NULL,lease_expires_at=NULL,lease_renewed_at=NULL,started_at=NULL WHERE id=$1",
    [f.publishingJob.id],
  );
  const before = (
    await pool.query("SELECT payload FROM certificate_jobs WHERE id=$1", [
      f.publishingJob.id,
    ])
  ).rows[0];
  assert.equal((await f.transfer()).status, 200);
  const after = (
    await pool.query("SELECT * FROM certificate_jobs WHERE id=$1", [
      f.publishingJob.id,
    ])
  ).rows[0];
  assert.equal(after.status, "cancelled");
  assert.equal(after.workspace_id, f.workspaceId);
  assert.deepEqual(after.payload, before.payload);
  const version = (
    await pool.query("SELECT * FROM certops_material_versions WHERE id=$1", [
      f.materialVersionId,
    ])
  ).rows[0];
  assert.equal(version.state, "failed");
  assert.equal(version.allocation_release_reason, "cancelled_before_execution");
  assert.ok(version.allocation_released_at);
});

test("attempted pending renewal and unresolved publication require reconciliation", async (t) => {
  for (const publication of [false, true])
    await t.test(
      publication ? "allocated publication" : "pending retry",
      async () => {
        const f = await fixture({ published: !publication });
        await pool.query(
          "UPDATE certificate_jobs SET status=$2,attempt_count=1 WHERE id=$1",
          [f.publishingJob.id, publication ? "failed" : "pending"],
        );
        const result = await f.transfer();
        assert.equal(result.status, 409);
        assert.equal(
          result.body.code,
          "CERTOPS_DISTRIBUTION_TRANSFER_RECONCILIATION_REQUIRED",
        );
        assert.equal(
          (
            await pool.query(
              "SELECT workspace_id FROM managed_certificates WHERE id=$1",
              [f.certificateId],
            )
          ).rows[0].workspace_id,
          f.workspaceId,
        );
      },
    );
});

test("transfer serializes a concurrent rollout and leaves no new executable source work", async () => {
  const f = await fixture(),
    client = await pool.connect();
  let competing;
  try {
    await client.query("BEGIN");
    await transferTokenAssociations(client, {
      tokenIds: [f.tokenId],
      fromWorkspaceId: f.workspaceId,
      toWorkspaceId: f.destination,
      targetOwnerId: f.actor,
    });
    competing = operations
      .requestRollout({
        workspaceId: f.workspaceId,
        groupId: f.groupId,
        materialVersionId: f.materialVersionId,
        actorUserId: f.actor,
        idempotencyKey: uuid(),
      })
      .then(
        () => ({ succeeded: true }),
        (error) => ({ error }),
      );
    // Observe the actual database lock wait; do not guess from a timer.
    let blocked = false;
    for (let i = 0; i < 100 && !blocked; i++) {
      blocked = (
        await pool.query(
          "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1::int=ANY(pg_blocking_pids(pid))) AS blocked",
          [(await client.query("SELECT pg_backend_pid() pid")).rows[0].pid],
        )
      ).rows[0].blocked;
      if (!blocked) await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(blocked, true);
    await client.query("COMMIT");
    const result = await competing;
    assert.ok(result.error);
    assert.match(
      result.error.code || result.error.message,
      /INACTIVE|NOT_FOUND|RETIRED/,
    );
    await assertMoved(f);
    assert.equal(
      (
        await pool.query(
          "SELECT COUNT(*)::int n FROM certificate_jobs WHERE workspace_id=$1 AND status IN ('pending','approved','pending_approval','claimed','running')",
          [f.workspaceId],
        )
      ).rows[0].n,
      0,
    );
  } finally {
    await client.query("ROLLBACK");
    client.release();
    if (competing) await competing;
  }
});

test("destination authorization denial and quota failure roll back inventory and source authority", async () => {
  const f = await fixture();
  await pool.query(
    "UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2",
    [f.destination, f.actor],
  );
  assert.equal((await f.transfer()).status, 403);
  await pool.query(
    "UPDATE workspace_memberships SET role='admin' WHERE workspace_id=$1 AND user_id=$2",
    [f.destination, f.actor],
  );
  await pool.query(
    "UPDATE workspaces SET certops_managed_identity_limit=0 WHERE id=$1",
    [f.destination],
  );
  await assert.rejects(
    operations.transaction((client) =>
      transferTokenAssociations(client, {
        tokenIds: [f.tokenId],
        fromWorkspaceId: f.workspaceId,
        toWorkspaceId: f.destination,
        targetOwnerId: f.actor,
      }),
    ),
    (error) => /quota|limit/i.test(error.message),
  );
  assert.equal(
    (
      await pool.query("SELECT workspace_id FROM tokens WHERE id=$1", [
        f.tokenId,
      ])
    ).rows[0].workspace_id,
    f.workspaceId,
  );
  assert.equal(
    (
      await pool.query(
        "SELECT state FROM certops_distribution_groups WHERE id=$1",
        [f.groupId],
      )
    ).rows[0].state,
    "active",
  );
  assert.equal(
    (
      await pool.query(
        "SELECT COUNT(*)::int n FROM certops_certificate_identities WHERE workspace_id=$1",
        [f.destination],
      )
    ).rows[0].n,
    0,
  );
});
