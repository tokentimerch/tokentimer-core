"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { createRequire } = require("node:module");
// Dedicated synthetic database only; never load the workstation's .env.
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.equal(process.env.DB_PORT, "59470");
assert.match(process.env.DB_NAME || "", /^pr329_review/);
process.env.NODE_ENV = "test";
process.env.CERTOPS_ENABLED = "true";
process.env.WORKER_API_KEY = "pr329-test-worker-only";
const apiRequire = createRequire(
  require.resolve("../../apps/api/package.json"),
);
const { pool } = apiRequire("./db/database");
const operations = apiRequire("./services/certops/distributionOperations");
const material = apiRequire("./services/certops/materialDistribution");
const { approveJob } = apiRequire("./services/certops/jobApprovals");
const { createCertificateIssuanceJob } = apiRequire(
  "./services/certops/issuance",
);
const health = apiRequire("./services/certops/renewalPathHealth");
const request = require("supertest");
const uuid = () => crypto.randomUUID();
let worker;
test.before(async () => {
  worker = await import("../../apps/worker/src/certops-worker.js");
});
test.after(() => pool.end());

async function fixture({ expired = false, validFor = "1 day" } = {}) {
  const workspaceId = uuid();
  async function user() {
    return (
      await pool.query(
        "INSERT INTO users(email,display_name,password_hash,auth_method) VALUES($1,'Review fixture','fixture-only','local') RETURNING id",
        [`${uuid()}@example.test`],
      )
    ).rows[0].id;
  }
  const actor = await user(),
    approver = await user(),
    manager = await user(),
    viewer = await user(),
    outsider = await user();
  await pool.query(
    "INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'PR329 isolated review',$2,'oss')",
    [workspaceId, actor],
  );
  for (const [id, role] of [
    [manager, "workspace_manager"],
    [viewer, "viewer"],
  ]) {
    await pool.query(
      "INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,$3)",
      [workspaceId, id, role],
    );
  }
  async function agent() {
    return (
      await pool.query(
        `INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash,
      supported_operations,declared_capabilities,declared_target_selectors,supported_dns_providers,declared_command_profile_names,capabilities_updated_at,last_seen_at)
      VALUES($1,$2,'0.17.3','1.0.0',$3,$4,'["renew"]','["material-store-vault-kv2-v1","certificate-publication-v1","evidence-claim-binding-v1","signed-payload-b64-v1"]',
        '["shared.example.test"]','["cloudflare"]','["certbot"]',NOW(),NOW()) RETURNING id`,
        [
          workspaceId,
          uuid(),
          `ttagent_${crypto.randomBytes(8).toString("hex")}`,
          crypto.randomBytes(32).toString("hex"),
        ],
      )
    ).rows[0].id;
  }
  const issuer = await agent(),
    consumer = await agent();
  const issued = await operations.transaction((client) =>
    createCertificateIssuanceJob({
      client,
      workspaceId,
      idempotencyKey: uuid(),
      requestedByUserId: actor,
      assignedAgentId: issuer,
      payload: {
        target: { type: "domain", reference: "shared.example.test" },
        sans: ["shared.example.test"],
        caEndpoint: "https://acme.example.test/directory",
        commandRef: "certbot",
        dnsProvider: "cloudflare",
        dnsZone: "example.test",
        keyAlgorithm: "rsa",
        keySize: 2048,
        publicationDestination: {
          materialStoreRef: "customer",
          issuanceProfileRef: "shared",
          profileRevision: 1,
        },
      },
    }),
  );
  const { groupId, materialVersionId, managementPeriodId } =
    issued.job.payload.publication;
  const certificateId = issued.job.subjectId;
  const fingerprint = crypto.randomBytes(32).toString("hex");
  const identityId = (
    await pool.query(
      "INSERT INTO certops_certificate_identities(workspace_id,fingerprint_sha256) VALUES($1,$2) RETURNING id",
      [workspaceId, fingerprint],
    )
  ).rows[0].id;
  // Synthetic PUBLIC metadata fixtures: no key material, disabled constraints,
  // shared database, or edits to an already immutable published version.
  await pool.query(
    `UPDATE certops_material_versions SET state='published',certificate_identity_id=$2,provider_version=1,
    fingerprint_sha256=$3,valid_to=clock_timestamp()+$4::interval,published_at=clock_timestamp(),publishing_claim_id=$5 WHERE id=$1`,
    [
      materialVersionId,
      identityId,
      fingerprint,
      expired ? "-1 second" : validFor,
      uuid(),
    ],
  );
  await pool.query(
    "UPDATE certificate_jobs SET status='succeeded',completed_at=NOW() WHERE id=$1",
    [issued.job.id],
  );
  const bindingId = uuid();
  const binding = {
    agentId: consumer,
    deploymentProfileRef: "web",
    profileRevision: 1,
    required: true,
    wave: 0,
    verificationPolicy: "served",
    freshnessSeconds: 3600,
    state: "active",
  };
  await operations.putBinding({
    workspaceId,
    groupId,
    bindingId,
    binding,
    actorUserId: actor,
  });
  const app = apiRequire("express")();
  app.use(apiRequire("express").json());
  // Session identity injection only replaces Passport deserialization. The
  // actual worker authentication, workspace lookup/membership and route guards run.
  app.use((req, _res, next) => {
    const id = Number(req.get("X-Test-Session"));
    if ([actor, approver, manager, viewer, outsider].includes(id)) {
      req.user = { id, auth_method: "local" };
      req.isAuthenticated = () => true;
    }
    next();
  });
  const rbac = apiRequire("./services/rbac");
  app.use(
    "/api/v1/workspaces/:id",
    apiRequire("./middleware/auth").requireAuth,
    rbac.loadWorkspace,
    rbac.requireWorkspaceMembership,
  );
  app.use(apiRequire("./routes/certops"));
  const base = `/api/v1/workspaces/${workspaceId}/certops`;
  const rolloutRequest = {
    workspaceId,
    groupId,
    materialVersionId,
    actorUserId: actor,
    idempotencyKey: uuid(),
  };
  async function approved() {
    const job = await operations.requestRollout({
      ...rolloutRequest,
      idempotencyKey: uuid(),
    });
    await approveJob({ workspaceId, jobId: job.id, approverUserId: approver });
    return job;
  }
  return {
    workspaceId,
    actor,
    approver,
    manager,
    viewer,
    outsider,
    issuer,
    consumer,
    agent,
    certificateId,
    identityId,
    groupId,
    materialVersionId,
    managementPeriodId,
    bindingId,
    binding,
    app,
    base,
    rolloutRequest,
    approved,
  };
}

test("distribution mutations require session managers through real upstream worker/workspace middleware", async () => {
  const f = await fixture();
  const { plaintextToken } = await apiRequire(
    "./services/certops/apiTokens",
  ).createApiToken({
    workspaceId: f.workspaceId,
    name: "Review token",
    scopes: ["certops:read", "certops:events:write"],
    createdBy: f.actor,
  });
  const endpoints = [
    [
      "put",
      `${f.base}/distribution-groups/${f.groupId}/consumers/${f.bindingId}`,
      f.binding,
    ],
    [
      "post",
      `${f.base}/distribution-groups/${f.groupId}/rollouts`,
      { materialVersionId: f.materialVersionId },
    ],
    [
      "post",
      `${f.base}/distribution-groups/${f.groupId}/rollouts/${uuid()}/state`,
      { state: "paused" },
    ],
    ["post", `${f.base}/distribution-jobs/${uuid()}/retry`, {}],
  ];
  for (const [method, url, body] of endpoints) {
    for (const [headers, status] of [
      [{ Authorization: "Bearer pr329-test-worker-only" }, 403],
      [{ Authorization: `Bearer ${plaintextToken}` }, 401],
      [{}, 401],
      [{ "X-Test-Session": String(f.viewer) }, 403],
      [{ "X-Test-Session": String(f.outsider) }, 403],
    ])
      assert.equal(
        (await request(f.app)[method](url).set(headers).send(body)).status,
        status,
        `${method} ${url} expected ${status}`,
      );
  }
  for (const actor of [f.actor, f.manager]) {
    assert.equal(
      (
        await request(f.app)
          .put(endpoints[0][1])
          .set("X-Test-Session", String(actor))
          .send(f.binding)
      ).status,
      200,
    );
    assert.equal(
      (
        await request(f.app)
          .post(endpoints[1][1])
          .set("X-Test-Session", String(actor))
          .set("Idempotency-Key", uuid())
          .send(endpoints[1][2])
      ).status,
      201,
    );
  }
  const approval = await f.approved();
  const snapshot = await operations.transaction((client) =>
    material.createRolloutSnapshot({
      client,
      ...f,
      approvalJobId: approval.id,
      approvedIntentHash: material.hashIntent(
        approval.payload.distributionRollout,
      ),
    }),
  );
  await operations.transaction((client) =>
    operations.advanceRollout(
      client,
      f.workspaceId,
      f.groupId,
      snapshot.rolloutId,
    ),
  );
  const child = (
    await pool.query(
      "SELECT job_id FROM certops_consumer_deployments WHERE rollout_id=$1",
      [snapshot.rolloutId],
    )
  ).rows[0].job_id;
  for (const actor of [f.actor, f.manager]) {
    assert.equal(
      (
        await request(f.app)
          .post(
            `${f.base}/distribution-groups/${f.groupId}/rollouts/${snapshot.rolloutId}/state`,
          )
          .set("X-Test-Session", String(actor))
          .send({ state: "paused" })
      ).status,
      200,
    );
    await pool.query(
      "UPDATE certificate_jobs SET status='failed' WHERE id=$1",
      [child],
    );
    assert.equal(
      (
        await request(f.app)
          .post(`${f.base}/distribution-jobs/${child}/retry`)
          .set("X-Test-Session", String(actor))
          .send({})
      ).status,
      200,
    );
  }
  assert.equal(
    (
      await request(f.app)
        .get(`${f.base}/distribution-groups`)
        .auth("pr329-test-worker-only", { type: "bearer" })
    ).status,
    200,
    "worker read paths remain usable",
  );
});

test("a valid active rollout expires while waiting for its offline consumer", async () => {
  const f = await fixture({ validFor: "2 seconds" }),
    job = await f.approved();
  await operations.transaction((client) =>
    operations.processDistributionIntent({
      client,
      row: {
        workspace_id: f.workspaceId,
        event_type: "distribution_approval_granted",
      },
      payload: { jobId: job.id },
    }),
  );
  const rollout = (
    await pool.query(
      "SELECT id FROM certops_distribution_rollouts WHERE approval_job_id=$1",
      [job.id],
    )
  ).rows[0];
  assert.equal(
    (
      await operations.transaction((c) =>
        operations.advanceRollout(c, f.workspaceId, f.groupId, rollout.id),
      )
    ).deferred,
    true,
  );
  const count = (
    await pool.query(
      "SELECT COUNT(*)::int n FROM certificate_jobs WHERE workspace_id=$1",
      [f.workspaceId],
    )
  ).rows[0].n;
  await new Promise((resolve) => setTimeout(resolve, 2100));
  await operations.transaction((c) =>
    operations.advanceRollout(c, f.workspaceId, f.groupId, rollout.id),
  );
  assert.equal(
    (
      await pool.query(
        "SELECT state FROM certops_distribution_rollouts WHERE id=$1",
        [rollout.id],
      )
    ).rows[0].state,
    "retired",
  );
  assert.equal(
    (
      await pool.query(
        "SELECT COUNT(*)::int n FROM certificate_jobs WHERE workspace_id=$1",
        [f.workspaceId],
      )
    ).rows[0].n,
    count,
  );
  await assert.rejects(
    operations.requestRollout({ ...f.rolloutRequest, idempotencyKey: uuid() }),
    { code: "CERTOPS_ROLLOUT_VERSION_INVALID" },
  );
  const child = (
    await pool.query(
      "SELECT * FROM certificate_jobs WHERE workspace_id=$1 AND operation='deploy-from-store'",
      [f.workspaceId],
    )
  ).rows[0];
  await assert.rejects(
    operations.transaction((client) =>
      material.resolveDistributionJobDefaults({
        client,
        workspaceId: f.workspaceId,
        operation: child.operation,
        subjectId: child.subject_id,
        payload: child.payload,
        assignedAgentId: child.assigned_agent_id,
        jobId: child.id,
      }),
    ),
    { code: "CERTOPS_ROLLOUT_VERSION_INVALID" },
  );
});

test("stale rollouts retire without queuing offline consumers or exhausting outbox retries", async (t) => {
  for (const condition of [
    "expired",
    "revoked",
    "decommissioned",
    "superseded",
    "period_closed",
    "group_disabled",
  ])
    await t.test(condition, async () => {
      const f = await fixture({ expired: condition === "expired" });
      const approvalId = uuid(),
        rolloutId = uuid();
      // Seed an already-expanded historical rollout, including one offline consumer.
      await pool.query(
        `INSERT INTO certificate_jobs(id,workspace_id,operation,source,subject_type,subject_id,status,payload)
      VALUES($1,$2,'noop','control-plane','managed_certificate',$3,'succeeded','{}')`,
        [approvalId, f.workspaceId, f.certificateId],
      );
      await pool.query(
        `INSERT INTO certops_distribution_rollouts(id,workspace_id,group_id,material_version_id,generation,approved_intent_hash,approval_job_id,state)
      VALUES($1,$2,$3,$4,1,repeat('a',64),$5,'deploying')`,
        [rolloutId, f.workspaceId, f.groupId, f.materialVersionId, approvalId],
      );
      await pool.query(
        "UPDATE certops_distribution_groups SET generation=$2 WHERE id=$1",
        [f.groupId, condition === "superseded" ? 2 : 1],
      );
      if (["revoked", "decommissioned"].includes(condition))
        await pool.query(
          "UPDATE certops_certificate_identities SET lifecycle_status=$2 WHERE id=$1",
          [f.identityId, condition],
        );
      if (condition === "period_closed")
        await pool.query(
          "UPDATE certops_management_periods SET ended_at=NOW(),ended_reason='retired' WHERE id=$1",
          [f.managementPeriodId],
        );
      if (condition === "group_disabled")
        await pool.query(
          "UPDATE certops_distribution_groups SET state='disabled' WHERE id=$1",
          [f.groupId],
        );
      await pool.query(
        `INSERT INTO certops_consumer_deployments(workspace_id,group_id,rollout_id,binding_id,assigned_agent_id,deployment_profile_ref,profile_revision,authorization_revision,required,wave,verification_policy,freshness_seconds)
      VALUES($1,$2,$3,$4,$5,'web',1,1,true,0,'served',3600)`,
        [f.workspaceId, f.groupId, rolloutId, f.bindingId, f.consumer],
      );
      await operations.transaction((client) =>
        material.enqueueDistributionEvent(
          client,
          f.workspaceId,
          "distribution_rollout_requested",
          rolloutId,
          { groupId: f.groupId, rolloutId },
        ),
      );
      await worker.drainCertOpsOutbox({ dbPool: pool, batchSize: 100 });
      assert.equal(
        (
          await pool.query(
            "SELECT state FROM certops_distribution_rollouts WHERE id=$1",
            [rolloutId],
          )
        ).rows[0].state,
        "retired",
      );
      const event = (
        await pool.query(
          "SELECT status,attempt_count,last_error FROM certops_outbox WHERE dedupe_key=$1",
          [rolloutId],
        )
      ).rows[0];
      assert.equal(event.status, "skipped");
      assert.equal(event.attempt_count, 1);
      assert.equal(event.last_error, null);
      assert.equal(
        (
          await pool.query(
            "SELECT job_id FROM certops_consumer_deployments WHERE rollout_id=$1",
            [rolloutId],
          )
        ).rows[0].job_id,
        null,
      );
      assert.equal(
        (
          await operations.transaction((c) =>
            operations.advanceRollout(c, f.workspaceId, f.groupId, rolloutId),
          )
        ).queued,
        false,
      );
    });
});

test("renewal health returns one current-period issuer across single, workspace and page projections", async () => {
  const f = await fixture();
  // Use a real profile contract; persistence below models stop/re-add management.
  const profile = apiRequire(
    "./services/certops/renewalProfileDerivation",
  ).deriveRenewalProfileFromIssuedCertificate({
    payload: (
      await pool.query(
        "SELECT payload FROM certificate_jobs WHERE workspace_id=$1 AND operation='issue'",
        [f.workspaceId],
      )
    ).rows[0].payload,
    certificate: {
      commonName: "shared.example.test",
      subjectAltNames: ["shared.example.test"],
    },
  });
  const profileId = (
    await pool.query(
      "INSERT INTO certificate_profiles(workspace_id,name,public_metadata) VALUES($1,'Shared renewal',$2) RETURNING id",
      [f.workspaceId, { renewalProfile: profile }],
    )
  ).rows[0].id;
  await pool.query(
    "UPDATE managed_certificates SET profile_id=$2,status='active' WHERE id=$1",
    [f.certificateId, profileId],
  );
  await pool.query(
    "UPDATE certops_management_periods SET ended_at=NOW(),ended_reason='stopped' WHERE id=$1",
    [f.managementPeriodId],
  );
  const period = (
    await pool.query(
      "INSERT INTO certops_management_periods(workspace_id,managed_certificate_id) VALUES($1,$2) RETURNING id",
      [f.workspaceId, f.certificateId],
    )
  ).rows[0].id;
  const newIssuer = await f.agent();
  const newGroup = (
    await pool.query(
      `INSERT INTO certops_distribution_groups(workspace_id,managed_certificate_id,management_period_id,issuer_agent_id,material_store_ref,issuance_profile_ref,profile_revision)
    VALUES($1,$2,$3,$4,'customer','shared',1) RETURNING id`,
      [f.workspaceId, f.certificateId, period, newIssuer],
    )
  ).rows[0].id;
  async function check(expected) {
    const options = {
      db: pool,
      workspaceId: f.workspaceId,
      certificateId: f.certificateId,
      certificateIds: [f.certificateId],
    };
    const batch = await health.resolveRenewalPathsForWorkspace(options);
    assert.equal(
      batch.length,
      1,
      "historical groups must not duplicate a certificate",
    );
    const single = await health.resolveRenewalPathForCertificate(options),
      page = (await health.resolveRenewalPathsForCertificateIds(options)).get(
        f.certificateId,
      );
    for (const value of [batch[0], single, page])
      assert.deepEqual(
        value.dependencies.map((d) => d.agentRowId),
        expected,
      );
  }
  await check([newIssuer]);
  await assert.rejects(
    pool.query(
      "UPDATE certops_distribution_groups SET issuer_agent_id=$2 WHERE id=$1",
      [newGroup, f.consumer],
    ),
    /immutable/,
  );
  await check([newIssuer]);
  await pool.query(
    "UPDATE certops_management_periods SET ended_at=NOW(),ended_reason='retired' WHERE id=$1",
    [period],
  );
  // Inspect actual query rows as well as projections: no historical issuer join.
  const queries = [];
  await health.resolveRenewalPathForCertificate({
    db: {
      query: async (...args) => {
        const result = await pool.query(...args);
        if (args[0].includes("FROM managed_certificates mc"))
          queries.push(result.rows);
        return result;
      },
    },
    workspaceId: f.workspaceId,
    certificateId: f.certificateId,
  });
  assert.equal(queries[0].length, 1);
  assert.equal(queries[0][0].distribution_issuer_agent_id, null);
  await pool.query(
    "UPDATE managed_certificates SET status='decommissioned' WHERE id=$1",
    [f.certificateId],
  );
  assert.equal(
    (
      await health.resolveRenewalPathsForWorkspace({
        db: pool,
        workspaceId: f.workspaceId,
      })
    ).length,
    0,
  );
});

test("binding changes terminally invalidate approval, preserve snapshots and permit a fresh API request", async () => {
  const f = await fixture(),
    job = await f.approved();
  const frozen = job.payload.distributionRollout;
  const edit = request(f.app)
    .put(`${f.base}/distribution-groups/${f.groupId}/consumers/${f.bindingId}`)
    .set("X-Test-Session", String(f.manager))
    .send({ ...f.binding, profileRevision: 2 });
  assert.equal((await edit).status, 200);
  await worker.drainCertOpsOutbox({ dbPool: pool, batchSize: 100 });
  const stale = (
    await pool.query("SELECT * FROM certificate_jobs WHERE id=$1", [job.id])
  ).rows[0];
  assert.equal(stale.status, "failed");
  assert.equal(stale.error_code, "CERTOPS_ROLLOUT_APPROVAL_STALE");
  assert.deepEqual(stale.payload.distributionRollout, frozen);
  assert.equal(stale.approved_payload_hash, null);
  assert.ok(stale.completed_at);
  const decisions = (
    await pool.query(
      "SELECT decision FROM certops_job_approvals WHERE job_id=$1 ORDER BY created_at,id",
      [job.id],
    )
  ).rows.map((r) => r.decision);
  assert.deepEqual(decisions, ["approved", "invalidated"]);
  const event = (
    await pool.query(
      "SELECT * FROM certops_outbox WHERE payload->>'jobId'=$1",
      [job.id],
    )
  ).rows[0];
  assert.equal(event.status, "skipped");
  assert.equal(event.attempt_count, 1);
  assert.equal(
    (
      await pool.query(
        "SELECT COUNT(*)::int n FROM certops_distribution_rollouts WHERE approval_job_id=$1",
        [job.id],
      )
    ).rows[0].n,
    0,
  );
  const replay = await operations.requestRollout({
    ...f.rolloutRequest,
    idempotencyKey: job.idempotencyKey,
  });
  assert.equal(replay.id, job.id);
  assert.equal(replay.status, "failed");
  await operations.transaction((client) =>
    operations.processDistributionIntent({
      client,
      row: {
        workspace_id: f.workspaceId,
        event_type: "distribution_approval_granted",
      },
      payload: { jobId: job.id },
    }),
  );
  assert.equal(
    (
      await pool.query(
        "SELECT COUNT(*)::int n FROM certops_job_approvals WHERE job_id=$1",
        [job.id],
      )
    ).rows[0].n,
    2,
  );
  // Idempotent recovery uses a new request key; replay returns the failed request.
  const response = await request(f.app)
    .post(`${f.base}/distribution-groups/${f.groupId}/rollouts`)
    .set("X-Test-Session", String(f.manager))
    .set("Idempotency-Key", uuid())
    .send({ materialVersionId: f.materialVersionId });
  assert.equal(response.status, 201);
  assert.equal(response.body.status, "pending_approval");
  const recovered = response.body;
  await approveJob({
    workspaceId: f.workspaceId,
    jobId: recovered.id,
    approverUserId: f.approver,
  });
  await worker.drainCertOpsOutbox({ dbPool: pool, batchSize: 100 });
  assert.equal(
    (
      await pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [
        recovered.id,
      ])
    ).rows[0].status,
    "succeeded",
  );
  // Completed approval expansion replays safely even after a later binding edit.
  await operations.putBinding({
    ...f,
    actorUserId: f.manager,
    binding: { ...f.binding, profileRevision: 3 },
  });
  const outcome = await operations.transaction((client) =>
    operations.processDistributionIntent({
      client,
      row: {
        workspace_id: f.workspaceId,
        event_type: "distribution_approval_granted",
      },
      payload: { jobId: recovered.id },
    }),
  );
  assert.equal(outcome.queued, true);
  assert.equal(
    (
      await pool.query(
        "SELECT COUNT(*)::int n FROM certops_distribution_rollouts WHERE approval_job_id=$1",
        [recovered.id],
      )
    ).rows[0].n,
    1,
  );
});

test("expansion serializes a concurrent binding edit and preserves the approved snapshot", async () => {
  const f = await fixture(),
    job = await f.approved(),
    client = await pool.connect();
  let edit;
  try {
    await client.query("BEGIN");
    await material.lockGroup(client, f.workspaceId, f.groupId);
    // The edit runs on a second connection and waits for expansion's group lock.
    edit = operations.putBinding({
      ...f,
      actorUserId: f.manager,
      binding: { ...f.binding, profileRevision: 2 },
    });
    await operations.processDistributionIntent({
      client,
      row: {
        workspace_id: f.workspaceId,
        event_type: "distribution_approval_granted",
      },
      payload: { jobId: job.id },
    });
    await client.query("COMMIT");
  } finally {
    await client.query("ROLLBACK");
    client.release();
  }
  await edit;
  const rollout = (
    await pool.query(
      "SELECT id FROM certops_distribution_rollouts WHERE approval_job_id=$1",
      [job.id],
    )
  ).rows[0];
  const snapshot = (
    await pool.query(
      "SELECT profile_revision,authorization_revision,job_id FROM certops_consumer_deployments WHERE rollout_id=$1",
      [rollout.id],
    )
  ).rows[0];
  assert.equal(snapshot.profile_revision, 1);
  assert.equal(snapshot.authorization_revision, 1);
  assert.equal(snapshot.job_id, null);
  assert.equal(
    (
      await pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [
        job.id,
      ])
    ).rows[0].status,
    "succeeded",
  );
  const outcome = await operations.transaction((c) =>
    operations.advanceRollout(c, f.workspaceId, f.groupId, rollout.id),
  );
  assert.equal(outcome.reason, "required_consumer_failed");
  assert.equal(
    (
      await pool.query(
        "SELECT job_id FROM certops_consumer_deployments WHERE rollout_id=$1",
        [rollout.id],
      )
    ).rows[0].job_id,
    null,
  );
});

test("workspace transfer retains source history and creates no destination issuer dependency", async () => {
  const f = await fixture(),
    destination = uuid();
  await pool.query(
    "INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'Transfer destination',$2,'oss')",
    [destination, f.actor],
  );
  const moved = await operations.transaction((client) =>
    client.query(
      "SELECT certops_transfer_management_sources($1,$2,$3::uuid[])",
      [f.workspaceId, destination, [f.certificateId]],
    ),
  );
  assert.equal(moved.rows[0].certops_transfer_management_sources, 1);
  assert.equal(
    (
      await pool.query(
        "SELECT workspace_id FROM managed_certificates WHERE id=$1",
        [f.certificateId],
      )
    ).rows[0].workspace_id,
    destination,
  );
  assert.ok(
    (
      await pool.query(
        "SELECT ended_at FROM certops_management_periods WHERE id=$1",
        [f.managementPeriodId],
      )
    ).rows[0].ended_at,
  );
  assert.equal(
    (
      await health.resolveRenewalPathsForWorkspace({
        db: pool,
        workspaceId: destination,
      })
    )[0].dependencies.length,
    0,
  );
});
