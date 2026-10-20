"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { createRequire } = require("node:module");
// Dedicated synthetic database only; never load the workstation's .env.
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.equal(process.env.DB_PORT, require("./qualification-database.cjs")("pr329_review", process.env.CI === "true" && process.env.DB_NAME === "pr329_review_distribution_ci_test" ? "5432" : process.env.DB_NAME === "pr329_review_consistency_test" ? "61532" : process.env.DB_NAME === "pr329_review_readiness_test" ? "61432" : "59470"));
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

test("manual renewal serializes same-key snapshot lookup with PostgreSQL transaction locks", async () => {
  const { manualRenewalJobCreator } = apiRequire("./services/certops/jobs");
  const first = await pool.connect(), second = await pool.connect();
  const workspaceId = uuid(), certificateId = uuid(), idempotencyKey = uuid();
  let stored = null, loads = 0;
  const certificate = { id: certificateId, workspace_id: workspaceId, common_name: "app.example.test",
    subject_alt_names: ["app.example.test"], not_after: new Date("2027-01-01T00:00:00Z"), key_mode: "agent-local",
    profile_id: uuid(), profile_name: "readiness", profile_key_mode: "agent-local",
    profile_public_metadata: { renewalProfile: { schemaVersion: 1, sanPolicy: {mode:"exact",sans:["app.example.test"],allowWildcards:false},
      keyAlgorithm:"rsa",keySize:2048,keyRotationPolicy:{rotateOnRenew:true},ca:{endpoint:"https://acme.example.test/directory"},
      acme:{kind:"certbot",commandRef:"certbot"},dns:{provider:"cloudflare",zone:"example.test"},
      target:{type:"endpoint",reference:"app.example.test",certPath:"/etc/ssl/app.pem"},
      deploymentTargets:[{type:"endpoint",reference:"app.example.test",certPath:"/etc/ssl/app.pem",reloadService:"nginx"}],
      verification:{host:"app.example.test",port:443,requireMatch:true} } } };
  // Only the advisory lock touches PostgreSQL. Public snapshots live in memory;
  // no product rows, receipts, ACME requests or database-injected fixtures.
  function transactionClient(client) {
    return { query(sql, params) {
      if (sql.includes("pg_advisory_xact_lock")) return client.query(sql, params);
      assert.ok(sql.includes("FROM certificate_jobs") && sql.includes("idempotency_key = $2"));
      return Promise.resolve({ rows: stored ? [stored] : [] });
    } };
  }
  const create = manualRenewalJobCreator({ certificateId,
    loadCertificate: async () => { loads++; return certificate; },
    createJob: async options => {
      if (!stored) stored = { id: uuid(), workspace_id: workspaceId, operation: "renew", source:"api", mode:"real",
        subject_type:"managed_certificate", subject_id:certificateId, payload:structuredClone(options.payload), status:"succeeded" };
      assert.deepEqual(options.payload, stored.payload);
      return stored.id;
    } });
  try {
    await first.query("BEGIN"); await second.query("BEGIN");
    const original = await create({ client: transactionClient(first), workspaceId, idempotencyKey });
    let finished = false;
    const replay = create({ client: transactionClient(second), workspaceId, idempotencyKey });
    replay.then(() => { finished = true; }, () => { finished = true; });
    const deadline = Date.now() + 5000;
    let waiting = false;
    while (Date.now() < deadline) {
      waiting = (await pool.query("SELECT wait_event='advisory' AS waiting FROM pg_stat_activity WHERE pid=$1", [second.processID])).rows[0]?.waiting;
      if (waiting) break;
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.equal(waiting, true, "The second transaction must wait before reading the snapshot");
    assert.equal(finished, false);
    certificate.not_after = new Date("2027-04-01T00:00:00Z");
    await first.query("COMMIT");
    assert.equal(await replay, original);
    assert.equal(loads, 1, "A concurrent replay must not re-materialize changed server state");
  } finally {
    await first.query("ROLLBACK"); await second.query("ROLLBACK");
    first.release(); second.release();
  }
});

async function fixture({ expired = false, validFor = "1 day", required = true } = {}) {
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
    required,
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

async function deploymentFixture(f) {
  const approval = await f.approved();
  const snapshot = await operations.transaction((client) => material.createRolloutSnapshot({
    client, ...f, approvalJobId: approval.id,
    approvedIntentHash: material.hashIntent(approval.payload.distributionRollout),
  }));
  await operations.transaction((client) => operations.advanceRollout(client, f.workspaceId, f.groupId, snapshot.rolloutId));
  const child = (await pool.query(`UPDATE certificate_jobs SET status='running',attempt_count=1,
    claim_id=gen_random_uuid(),claimed_by_agent_id=$2,lease_expires_at=clock_timestamp()+interval '5 minutes'
    WHERE id=(SELECT job_id FROM certops_consumer_deployments WHERE rollout_id=$1) RETURNING *`,
  [snapshot.rolloutId, f.consumer])).rows[0];
  const version = (await pool.query("SELECT * FROM certops_material_versions WHERE id=$1", [f.materialVersionId])).rows[0];
  const receipt = { schemaVersion: 1, workspaceId: f.workspaceId, groupId: f.groupId,
    bindingId: f.bindingId, materialVersionId: f.materialVersionId, generation: Number(snapshot.generation),
    fetched: true, installed: true, bound: true, servedVerified: true, trustValidated: false,
    fingerprintSha256: version.fingerprint_sha256, validTo: new Date(version.valid_to).toISOString(), observedAt: new Date().toISOString() };
  return { snapshot, child, receipt };
}

test("retired pending deployment cannot starve the next approved rollout with maxJobs one", async () => {
  const f=await fixture();
  await pool.query("UPDATE certops_agents SET declared_target_selectors=$2::jsonb,declared_capabilities=$3::jsonb,capabilities_updated_at=clock_timestamp() WHERE id=$1",[f.consumer,JSON.stringify([f.bindingId]),JSON.stringify(["material-store-vault-kv2-v1","deploy-from-store-v1","evidence-claim-binding-v1","signed-payload-b64-v1"])]);
  async function pending(){
    const approval=await f.approved();
    const snapshot=await operations.transaction(client=>material.createRolloutSnapshot({client,...f,approvalJobId:approval.id,approvedIntentHash:material.hashIntent(approval.payload.distributionRollout)}));
    await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,snapshot.rolloutId));
    const child=(await pool.query("SELECT * FROM certificate_jobs WHERE id=(SELECT job_id FROM certops_consumer_deployments WHERE rollout_id=$1)",[snapshot.rolloutId])).rows[0];
    return {snapshot,child};
  }
  const old=await pending();
  await operations.setRolloutState({...f,rolloutId:old.snapshot.rolloutId,state:"retired",actorUserId:f.actor});
  const fresh=await pending();
  const row=(await pool.query("SELECT agent_id FROM certops_agents WHERE id=$1",[f.consumer])).rows[0];
  const signing=apiRequire("./services/certops/jobSigning");const key=await signing.ensureActiveSigningKey();
  const claimed=await apiRequire("./services/certops/agentDispatch").claimJobs({agent:{id:f.consumer,workspaceId:f.workspaceId,agentId:row.agent_id,status:"active",agentVersion:"0.17.3",protocolVersion:"1.0.0"},body:{supportedActions:["deploy-from-store"],maxJobs:1}});
  assert.equal(claimed.jobs.length,1);
  const verified=require("../../packages/agent/src/signing").verifyJobEnvelope({claimed:claimed.jobs[0],...key,pinnedSigningKeyId:key.signingKeyId});
  assert.equal(verified.allowed,true);assert.equal(verified.job.jobId,fresh.child.id);
  assert.equal(verified.job.materialDeployment.rolloutId,fresh.snapshot.rolloutId);
  assert.equal((await pool.query("SELECT status FROM certificate_jobs WHERE id=$1",[old.child.id])).rows[0].status,"pending","Historical contained work is not rewritten by claim selection");
});

test("public material versions never expose publishing claims to administrators or managers", async () => {
  const f = await fixture();
  const endpoint = `${f.base}/distribution-groups/${f.groupId}/versions`;
  const fields = ["id","workspace_id","group_id","management_period_id","publishing_job_id","profile_revision","state",
    "certificate_identity_id","provider_version","fingerprint_sha256","valid_to","published_at","created_at",
    "allocation_released_at","allocation_release_reason"].sort();
  for (const actor of [f.actor,f.manager]) {
    const response = await request(f.app).get(endpoint).set("X-Test-Session",String(actor));
    assert.equal(response.status,200);
    assert.equal(response.body.versions.length,1);
    assert.equal(response.body.versions[0].id,f.materialVersionId);
    assert.deepEqual(Object.keys(response.body.versions[0]).sort(),fields);
    assert.equal(JSON.stringify(response.body).includes("publishing_claim_id"),false);
  }
  assert.equal((await request(f.app).get(endpoint).set("X-Test-Session",String(f.viewer))).status,403);
  assert.equal((await request(f.app).get(endpoint).set("X-Test-Session",String(f.outsider))).status,403);
});

test("paused workspaces allow authorized rollout containment without admitting execution", async () => {
  const f = await fixture();
  const approval = await f.approved();
  const snapshot = await operations.transaction(client => material.createRolloutSnapshot({
    client,...f,approvalJobId:approval.id,approvedIntentHash:material.hashIntent(approval.payload.distributionRollout),
  }));
  const endpoint = `${f.base}/distribution-groups/${f.groupId}/rollouts/${snapshot.rolloutId}/state`;
  const {setWorkspaceCertOpsPauseState} = apiRequire("./services/certops/workspaceKillSwitch");
  await setWorkspaceCertOpsPauseState({workspaceId:f.workspaceId,certOpsPaused:true,actorUserId:f.actor});
  const before = (await pool.query("SELECT id FROM certificate_jobs WHERE workspace_id=$1 ORDER BY id",[f.workspaceId])).rows;
  for (const state of ["paused","retired"]) {
    assert.equal((await request(f.app).post(endpoint).set("X-Test-Session",String(f.viewer)).send({state})).status,403);
    assert.equal((await request(f.app).post(endpoint).set("X-Test-Session",String(f.outsider)).send({state})).status,403);
    assert.equal((await request(f.app).post(endpoint).auth("pr329-test-worker-only",{type:"bearer"}).send({state})).status,403);
    const response = await request(f.app).post(endpoint).set("X-Test-Session",String(f.manager)).send({state});
    assert.equal(response.status,200,JSON.stringify(response.body));
    assert.equal(response.body.state,state);
    assert.equal((await request(f.app).post(endpoint).set("X-Test-Session",String(f.actor)).send({state:"deploying"})).status,409);
    await assert.rejects(operations.setRolloutState({...f,rolloutId:snapshot.rolloutId,state:"deploying",actorUserId:f.actor}),{code:"CERTOPS_WORKSPACE_PAUSED"});
  }
  assert.equal((await request(f.app).post(endpoint).set("X-Test-Session",String(f.actor)).send({state:"unknown"})).status,422);
  assert.deepEqual((await pool.query("SELECT id FROM certificate_jobs WHERE workspace_id=$1 ORDER BY id",[f.workspaceId])).rows,before);
  const events = (await pool.query("SELECT metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_ROLLOUT_STATE_CHANGED' ORDER BY id",[f.workspaceId])).rows;
  assert.deepEqual(events.map(row => row.metadata.state),["paused","retired"]);
});

test("optional authorization changes concurrent with successful receipts yield a degraded rollout and retain audit proof", async (t) => {
  for (const bindingFirst of [false, true]) await t.test(bindingFirst ? "binding commits first" : "receipt commits first", async () => {
    const f = await fixture({ required: false });
    const { snapshot, child, receipt } = await deploymentFixture(f);
    const client = await pool.connect();
    let competing;
    try {
      await client.query("BEGIN");
      await material.lockGroup(client, f.workspaceId, f.groupId);
      if (bindingFirst) {
        // Hold the real group lock while a receipt arrives on another connection.
        await client.query("UPDATE certops_consumer_bindings SET profile_revision=2,authorization_revision=authorization_revision+1 WHERE id=$1", [f.bindingId]);
        competing = operations.transaction((tx) => material.acceptDeploymentReceipt({
          client: tx, workspaceId: f.workspaceId, agentId: f.consumer, job: child, receipt, jobStatus: "succeeded",
        }));
      } else {
        const accepted = await material.acceptDeploymentReceipt({
          client, workspaceId: f.workspaceId, agentId: f.consumer, job: child, receipt, jobStatus: "succeeded",
        });
        assert.equal(accepted.historicalOnly, false);
        competing = operations.putBinding({ ...f, binding: { ...f.binding, profileRevision: 2 }, actorUserId: f.actor });
      }
      await client.query("COMMIT");
      const result = await competing;
      if (bindingFirst) assert.equal(result.historicalOnly, true);
    } finally {
      await client.query("ROLLBACK");
      client.release();
      if (competing) await competing.catch(() => {});
    }
    await pool.query("UPDATE certificate_jobs SET status='succeeded',completed_at=NOW() WHERE id=$1", [child.id]);
    await operations.transaction((tx) => operations.advanceRollout(tx, f.workspaceId, f.groupId, snapshot.rolloutId));
    assert.equal((await pool.query("SELECT state FROM certops_distribution_rollouts WHERE id=$1", [snapshot.rolloutId])).rows[0].state, "degraded");
    const proof = (await pool.query("SELECT stage,authorization_revision FROM certops_consumer_deployments WHERE rollout_id=$1", [snapshot.rolloutId])).rows[0];
    assert.equal(proof.stage, "served_verified");
    assert.equal(proof.authorization_revision, 1);
    assert.equal((await material.consumerMatrix({ client: pool, workspaceId: f.workspaceId, groupId: f.groupId }))[0].converged, false);
  });
});

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

test("malformed distribution identifiers return 422 without creating jobs", async () => {
  const f = await fixture();
  const count = async () => Number((await pool.query(
    "SELECT count(*) FROM certificate_jobs WHERE workspace_id=$1", [f.workspaceId],
  )).rows[0].count);
  const before = await count();
  const group = `${f.base}/distribution-groups/${f.groupId}`;
  const cases = [
    ["get", `${f.base}/distribution-groups/invalid/consumers`],
    ["get", `${f.base}/distribution-groups/invalid/versions`],
    ["put", `${group}/consumers/invalid`, f.binding],
    ["put", `${f.base}/distribution-groups/invalid/consumers/${f.bindingId}`, f.binding],
    ["post", `${f.base}/distribution-jobs/invalid/retry`, {}],
    ["post", `${group}/rollouts/invalid/state`, {state:"paused"}],
    ["post", `${f.base}/distribution-groups/invalid/rollouts/${uuid()}/state`, {state:"paused"}],
    ...[undefined, null, 17, {}, [], "invalid"].map(materialVersionId =>
      ["post", `${group}/rollouts`, {materialVersionId}]),
    ["post", `${f.base}/distribution-groups/invalid/rollouts`, {materialVersionId:f.materialVersionId}],
  ];
  for (const [method, url, body] of cases) {
    const response = await request(f.app)[method](url)
      .set("X-Test-Session", String(f.actor)).send(body);
    assert.equal(response.status, 422, `${method} ${url}`);
    assert.equal(response.body.code, "CERTOPS_MATERIAL_CONTRACT_INVALID");
  }
  assert.equal(await count(), before);
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

// ---------------------------------------------------------------------------
// Zero-custody guard on every distribution write route
// ---------------------------------------------------------------------------

// Throwaway EC keys generated in-process (never printed or reused), plus a
// structurally valid PKCS12-shaped DER. The detector parses real DER, so the
// containers must be genuine for the positive cases to mean anything.
function syntheticKeyVariants() {
  const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const passphrase = crypto.randomBytes(12).toString("hex");
  const pkcs8Der = privateKey.export({ type: "pkcs8", format: "der" });
  const encryptedDer = privateKey.export({ type: "pkcs8", format: "der", cipher: "aes-256-cbc", passphrase });
  const sec1Der = privateKey.export({ type: "sec1", format: "der" });
  const pem = (type, extra = {}) => privateKey.export({ type, format: "pem", ...extra });
  const pkcs12 = Buffer.alloc(94);
  Buffer.from([0x30, 0x5c, 0x02, 0x01, 0x03]).copy(pkcs12);
  crypto.randomBytes(16).copy(pkcs12, 60);
  const variants = {
    "PKCS8 PEM": pem("pkcs8"),
    "encrypted PKCS8 PEM": pem("pkcs8", { cipher: "aes-256-cbc", passphrase }),
    "EC (SEC1) PEM": pem("sec1"),
    "base64 PKCS8 DER": pkcs8Der.toString("base64"),
    "base64 encrypted PKCS8 DER": encryptedDer.toString("base64"),
    "base64 EC DER": sec1Der.toString("base64"),
    "base64 PKCS12 DER": pkcs12.toString("base64"),
    "base64 PEM": Buffer.from(pem("pkcs8")).toString("base64"),
    "base64url PEM": Buffer.from(pem("pkcs8") + "??>>??>>").toString("base64url"),
    "hex PEM": Buffer.from(pem("pkcs8")).toString("hex"),
    "gzip base64 PEM": require("node:zlib").gzipSync(pem("pkcs8")).toString("base64"),
  };
  // A slice from the middle of each sent value; it must never be echoed back.
  const needles = Object.fromEntries(Object.entries(variants).map(([name, value]) => {
    const text = String(value).replace(/-----[A-Z ]+-----|\s/g, "");
    return [name, text.slice(40, 72)];
  }));
  return { variants, needles };
}

async function distributionTableCounts(workspaceId) {
  const counts = {};
  for (const table of ["certificate_jobs", "certops_distribution_rollouts", "certops_consumer_deployments",
    "certops_consumer_bindings", "certops_outbox", "certops_material_versions"]) {
    counts[table] = (await pool.query(`SELECT count(*)::int n FROM ${table} WHERE workspace_id=$1`, [workspaceId])).rows[0].n;
  }
  counts.bindingRevision = (await pool.query("SELECT sum(authorization_revision)::int n FROM certops_consumer_bindings WHERE workspace_id=$1", [workspaceId])).rows[0].n;
  counts.nonKeyAudit = (await pool.query("SELECT count(*)::int n FROM audit_events WHERE workspace_id=$1 AND action<>'CERTOPS_KEY_MATERIAL_REJECTED'", [workspaceId])).rows[0].n;
  return counts;
}

test("every distribution write route rejects private-key material before any handler runs and persists or logs none of it", async () => {
  const f = await fixture();
  const { variants, needles } = syntheticKeyVariants();
  const handlerCalls = [];
  const originals = {};
  for (const [owner, names] of [[operations, ["putBinding", "requestRollout", "setRolloutState", "retryDistributionJob"]]]) {
    for (const name of names) {
      originals[name] = owner[name];
      owner[name] = (...args) => { handlerCalls.push(name); return originals[name](...args); };
    }
  }
  const routes = {
    "PUT consumer binding": (inject) => request(f.app)
      .put(`${f.base}/distribution-groups/${f.groupId}/consumers/${f.bindingId}`)
      .set("X-Test-Session", String(f.manager)).send(inject(f.binding)),
    "POST rollout": (inject) => request(f.app)
      .post(`${f.base}/distribution-groups/${f.groupId}/rollouts`)
      .set("X-Test-Session", String(f.manager)).set("Idempotency-Key", uuid())
      .send(inject({ materialVersionId: f.materialVersionId })),
    "POST rollout state": (inject) => request(f.app)
      .post(`${f.base}/distribution-groups/${f.groupId}/rollouts/${uuid()}/state`)
      .set("X-Test-Session", String(f.manager)).send(inject({ state: "paused" })),
    "POST job retry": (inject) => request(f.app)
      .post(`${f.base}/distribution-jobs/${uuid()}/retry`)
      .set("X-Test-Session", String(f.manager)).send(inject({})),
  };
  // Same value in different body positions, including ones that look benign.
  const placements = {
    "innocent top-level field": (body, value) => ({ ...body, note: value }),
    "nested object": (body, value) => ({ ...body, metadata: { deep: { deeper: { value } } } }),
    "array element": (body, value) => ({ ...body, labels: ["ok", { value }] }),
    "replacing a legitimate field": (body, value) => {
      const [first] = Object.keys(body);
      return { ...body, [first || "reason"]: value };
    },
  };
  const seen = [];
  const writes = [];
  const realStdout = process.stdout.write, realStderr = process.stderr.write;
  const capture = (chunk) => { seen.push(String(chunk)); return true; };
  try {
    // Controls: the same routes reach their handlers for clean bodies.
    const controls = { "PUT consumer binding": 200, "POST rollout": 201, "POST rollout state": 404, "POST job retry": 404 };
    for (const [route, status] of Object.entries(controls)) {
      handlerCalls.length = 0;
      const res = await routes[route]((body) => body);
      assert.equal(res.status, status, `${route} control must reach its handler`);
      assert.equal(handlerCalls.length, 1, `${route} control must call the service`);
    }
    handlerCalls.length = 0;
    const before = await distributionTableCounts(f.workspaceId);
    const rejectedBefore = (await pool.query("SELECT count(*)::int n FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_KEY_MATERIAL_REJECTED'", [f.workspaceId])).rows[0].n;
    process.stdout.write = capture; process.stderr.write = capture;
    let sent = 0;
    for (const [route, send] of Object.entries(routes)) {
      for (const [variant, value] of Object.entries(variants)) {
        for (const [placement, place] of Object.entries(placements)) {
          // The full placement matrix runs for PEM and PKCS12; other encodings use one position.
          if (!/^(PKCS8 PEM|base64 PKCS12 DER)$/.test(variant) && placement !== "nested object") continue;
          const res = await send((body) => place(body, value));
          sent++;
          writes.push(JSON.stringify(res.body), JSON.stringify(res.headers));
          assert.equal(res.status, 422, `${route} / ${variant} / ${placement}`);
          assert.equal(res.body.code, "PRIVATE_KEY_MATERIAL_REJECTED", `${route} / ${variant} / ${placement}`);
        }
      }
      // Near the scan-depth limit the value is still found, and bodies too deep to
      // scan are refused instead of being passed through unexamined.
      const nest = (depth, leaf) => Array.from({ length: depth }).reduce((inner) => ({ n: inner }), leaf);
      for (const [label, depth, leaf] of [["deep key", 10, variants["PKCS8 PEM"]], ["unscannable depth", 40, "benign"]]) {
        const res = await send((body) => ({ ...body, extra: nest(depth, leaf) }));
        sent++;
        assert.equal(res.status, 422, `${route} / ${label}`);
        assert.equal(res.body.code, "PRIVATE_KEY_MATERIAL_REJECTED");
      }
    }
    process.stdout.write = realStdout; process.stderr.write = realStderr;
    assert.deepEqual(handlerCalls, [], "no distribution service may run for a rejected request");
    assert.deepEqual(await distributionTableCounts(f.workspaceId), before, "rejected requests must persist nothing");
    const rejected = await pool.query("SELECT metadata,actor_user_id FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_KEY_MATERIAL_REJECTED'", [f.workspaceId]);
    assert.equal(rejected.rowCount - rejectedBefore, sent, "every rejection leaves exactly one audit event");
    for (const row of rejected.rows) {
      assert.deepEqual(Object.keys(row.metadata).sort(), ["body_type", "code", "method", "path"]);
      assert.equal(row.metadata.code, "PRIVATE_KEY_MATERIAL_REJECTED");
    }
    const everything = [...writes, ...seen].join("\n");
    for (const [variant, needle] of Object.entries(needles)) {
      assert.equal(everything.includes(needle), false, `${variant} must not appear in responses or logs`);
      for (const table of ["audit_events", "certificate_jobs", "certificate_job_log", "certops_outbox"]) {
        const hit = await pool.query(`SELECT 1 FROM ${table} t WHERE position($1 in t::text) > 0 LIMIT 1`, [needle]);
        assert.equal(hit.rowCount, 0, `${variant} must not be stored in ${table}`);
      }
    }
  } finally {
    process.stdout.write = realStdout; process.stderr.write = realStderr;
    for (const [name, original] of Object.entries(originals)) operations[name] = original;
  }
});

// ---------------------------------------------------------------------------
// Multi-wave rollouts: failure isolation and optional destinations
// ---------------------------------------------------------------------------

const DEPLOY_CAPABILITIES = ["material-store-vault-kv2-v1", "deploy-from-store-v1", "evidence-claim-binding-v1", "signed-payload-b64-v1"];
let labSigningKey;
async function labSigning() {
  if (!labSigningKey) {
    process.env.CERTOPS_SIGNING_ENCRYPTION_KEY ||= crypto.randomBytes(32).toString("hex");
    labSigningKey = await apiRequire("./services/certops/jobSigning").ensureActiveSigningKey();
  }
  return labSigningKey;
}

// Builds one rollout over several consumers (name, wave, required) and drives
// it through the real claim/ingest/advance path: signed envelope, nonce, receipt.
async function waveLab(f, specs, { maxParallel = 3 } = {}) {
  const dispatch = apiRequire("./services/certops/agentDispatch");
  const { verifyJobEnvelope } = require("../../packages/agent/src/signing");
  await labSigning();
  const nodes = {};
  for (const [index, spec] of specs.entries()) {
    const agentId = index === 0 ? f.consumer : await f.agent();
    const bindingId = index === 0 ? f.bindingId : uuid();
    await operations.putBinding({ workspaceId: f.workspaceId, groupId: f.groupId, bindingId, actorUserId: f.actor,
      binding: { ...f.binding, agentId, wave: spec.wave, required: spec.required !== false } });
    await pool.query(`UPDATE certops_agents SET declared_target_selectors=$2::jsonb,declared_capabilities=$3::jsonb,
      capabilities_updated_at=clock_timestamp() WHERE id=$1`, [agentId, JSON.stringify([bindingId]), JSON.stringify(DEPLOY_CAPABILITIES)]);
    nodes[spec.name] = { name: spec.name, agentId, bindingId };
  }
  const job = await operations.requestRollout({ ...f.rolloutRequest, idempotencyKey: uuid(), maxParallel });
  await approveJob({ workspaceId: f.workspaceId, jobId: job.id, approverUserId: f.approver });
  const snapshot = await operations.transaction((client) => material.createRolloutSnapshot({ client, ...f, maxParallel,
    approvalJobId: job.id, approvedIntentHash: material.hashIntent(job.payload.distributionRollout) }));
  const version = (await pool.query("SELECT * FROM certops_material_versions WHERE id=$1", [f.materialVersionId])).rows[0];
  const lab = { nodes, rolloutId: snapshot.rolloutId, generation: Number(snapshot.generation) };

  lab.advance = () => operations.transaction((client) => operations.advanceRollout(client, f.workspaceId, f.groupId, lab.rolloutId));
  lab.claim = async (name) => {
    const node = nodes[name];
    const row = (await pool.query("SELECT agent_id FROM certops_agents WHERE id=$1", [node.agentId])).rows[0];
    const agent = { id: node.agentId, workspaceId: f.workspaceId, agentId: row.agent_id, status: "active", protocolVersion: "1.0.0", agentVersion: "0.17.3" };
    const claimed = await dispatch.claimJobs({ agent, body: { supportedActions: ["deploy-from-store"], maxJobs: 1 } });
    if (!claimed.jobs.length) return null;
    const key = await labSigning();
    const verified = verifyJobEnvelope({ claimed: claimed.jobs[0], ...key, pinnedSigningKeyId: key.signingKeyId });
    assert.equal(verified.allowed, true);
    assert.equal(verified.job.materialDeployment.bindingId, node.bindingId, "an agent only ever receives its own destination");
    return { agent, intent: verified.job };
  };
  lab.report = async (claimed, outcome) => {
    const base = { jobId: claimed.intent.jobId, claimId: claimed.intent.claimId, nonce: claimed.intent.nonce };
    const body = outcome === "succeeded"
      ? { ...base, status: "succeeded", deploymentReceipt: { schemaVersion: 1, workspaceId: f.workspaceId, groupId: f.groupId,
        bindingId: claimed.intent.materialDeployment.bindingId, materialVersionId: f.materialVersionId, generation: lab.generation,
        fetched: true, installed: true, bound: true, servedVerified: true, trustValidated: false,
        fingerprintSha256: version.fingerprint_sha256, validTo: new Date(version.valid_to).toISOString(), observedAt: new Date().toISOString() } }
      : { ...base, status: "failed", errorMessage: "synthetic_deploy_failure" };
    const result = await dispatch.ingestResult({ agent: claimed.agent, body });
    assert.equal(result.ok, true);
  };
  // One destination attempt followed by the control-plane advance the outbox would trigger.
  lab.run = async (name, outcome) => {
    const claimed = await lab.claim(name);
    assert.ok(claimed, `${name} must have a deployment job to claim`);
    await lab.report(claimed, outcome);
    return lab.advance();
  };
  lab.deployments = async () => {
    const rows = (await pool.query(`SELECT d.binding_id,d.stage,d.failure_code,d.job_id,j.status AS job_status,j.completed_at
      FROM certops_consumer_deployments d LEFT JOIN certificate_jobs j ON j.id=d.job_id
      WHERE d.workspace_id=$1 AND d.rollout_id=$2`, [f.workspaceId, lab.rolloutId])).rows;
    return Object.fromEntries(Object.values(nodes).map((node) => [node.name, rows.find((row) => row.binding_id === node.bindingId)]));
  };
  lab.rolloutState = async () => (await pool.query("SELECT state FROM certops_distribution_rollouts WHERE id=$1", [lab.rolloutId])).rows[0].state;
  // "Current" = the destination's accepted proof is for this generation and version.
  lab.current = async () => {
    const rows = (await pool.query("SELECT binding_id,accepted_generation,desired_generation,observed_material_version_id FROM certops_consumer_current_state WHERE workspace_id=$1", [f.workspaceId])).rows;
    return Object.fromEntries(Object.values(nodes).map((node) => {
      const row = rows.find((candidate) => candidate.binding_id === node.bindingId);
      return [node.name, Number(row.accepted_generation) === Number(row.desired_generation) && row.observed_material_version_id === f.materialVersionId];
    }));
  };
  lab.deployJobCount = async () => (await pool.query(`SELECT count(*)::int n FROM certificate_jobs
    WHERE workspace_id=$1 AND operation='deploy-from-store'`, [f.workspaceId])).rows[0].n;
  lab.failedJobIds = async () => (await pool.query(`SELECT metadata->>'jobId' AS job_id FROM audit_events
    WHERE workspace_id=$1 AND action='CERTOPS_JOB_FAILED' ORDER BY id`, [f.workspaceId])).rows.map((row) => row.job_id);
  lab.snapshotOf = async (names) => {
    const deployments = await lab.deployments();
    return Object.fromEntries(await Promise.all(names.map(async (name) => {
      const state = (await pool.query("SELECT accepted_generation,observed_material_version_id,observed_fingerprint_sha256,observed_at FROM certops_consumer_current_state WHERE binding_id=$1", [nodes[name].bindingId])).rows[0];
      return [name, { stage: deployments[name].stage, job: deployments[name].job_id, jobStatus: deployments[name].job_status, completedAt: String(deployments[name].completed_at), state: JSON.stringify(state) }];
    })));
  };
  return lab;
}

test("a required failure in a later wave pauses the rollout, keeps earlier waves current and starts nothing further", async () => {
  const f = await fixture();
  const lab = await waveLab(f, [
    { name: "canary", wave: 0 },
    { name: "web-a", wave: 1 },
    { name: "web-b", wave: 1 },
    { name: "tail", wave: 2 },
  ]);
  assert.deepEqual(await lab.advance(), { deferred: true, retryInMs: 15000, reason: "waiting_for_consumers" });
  let deployments = await lab.deployments();
  assert.ok(deployments.canary.job_id);
  for (const later of ["web-a", "web-b", "tail"]) assert.equal(deployments[later].job_id, null, `${later} must wait for wave 0`);
  assert.equal(await lab.claim("web-a"), null, "wave 1 cannot be claimed before wave 0 is verified");

  await lab.run("canary", "succeeded");
  deployments = await lab.deployments();
  assert.ok(deployments["web-a"].job_id && deployments["web-b"].job_id);
  assert.equal(deployments.tail.job_id, null, "wave 2 must wait for wave 1");
  await lab.run("web-a", "succeeded");
  const earlier = await lab.snapshotOf(["canary", "web-a"]);
  const failedRun = await lab.run("web-b", "failed");

  assert.equal(failedRun.reason, "required_consumer_failed");
  assert.equal(await lab.rolloutState(), "paused");
  deployments = await lab.deployments();
  assert.equal(deployments["web-b"].stage, "failed");
  assert.equal(deployments["web-b"].failure_code, "agent_result_failed");
  assert.equal(deployments["web-b"].job_status, "failed");
  assert.deepEqual(await lab.snapshotOf(["canary", "web-a"]), earlier, "earlier destinations must not change");
  for (const name of ["canary", "web-a"]) {
    assert.equal(deployments[name].stage, "served_verified");
    assert.equal(deployments[name].job_status, "succeeded");
  }
  assert.equal(deployments.tail.job_id, null);
  assert.equal(deployments.tail.stage, "pending", "the later wave is never started");
  assert.equal(await lab.claim("tail"), null);
  assert.equal(await lab.deployJobCount(), 3, "no job exists for the unstarted wave and nothing was re-queued");
  assert.deepEqual(await lab.advance(), { queued: false, reason: "rollout_inactive" }, "a paused rollout does not resume by itself");
  assert.equal(await lab.deployJobCount(), 3);
  assert.deepEqual(await lab.current(), { canary: true, "web-a": true, "web-b": false, tail: false });
  assert.deepEqual(await lab.failedJobIds(), [deployments["web-b"].job_id], "audit names exactly the failed destination's job");

  // Recovery touches only the failed destination, then the later wave runs.
  await operations.retryDistributionJob({ workspaceId: f.workspaceId, jobId: deployments["web-b"].job_id, actorUserId: f.actor });
  await operations.setRolloutState({ workspaceId: f.workspaceId, groupId: f.groupId, rolloutId: lab.rolloutId, state: "deploying", actorUserId: f.actor });
  await lab.advance();
  await lab.run("web-b", "succeeded");
  await lab.run("tail", "succeeded");
  assert.equal(await lab.rolloutState(), "verified");
  deployments = await lab.deployments();
  const after = await lab.snapshotOf(["canary", "web-a"]);
  assert.equal(after.canary.job, earlier.canary.job, "the earlier destinations were never redeployed");
  assert.equal(after["web-a"].job, earlier["web-a"].job);
  assert.equal(await lab.deployJobCount(), 4);
});

test("a required failure inside a wave pauses the rollout without disturbing its verified sibling or later waves", async () => {
  const f = await fixture();
  const lab = await waveLab(f, [
    { name: "canary-a", wave: 0 },
    { name: "canary-b", wave: 0 },
    { name: "rest", wave: 1 },
  ], { maxParallel: 2 });
  await lab.advance();
  const claimedA = await lab.claim("canary-a");
  const claimedB = await lab.claim("canary-b");
  assert.ok(claimedA && claimedB, "both destinations of the same wave run together");
  await lab.report(claimedA, "succeeded");
  await lab.advance();
  const verified = await lab.snapshotOf(["canary-a"]);
  await lab.report(claimedB, "failed");
  const run = await lab.advance();

  assert.equal(run.reason, "required_consumer_failed");
  assert.equal(await lab.rolloutState(), "paused");
  const deployments = await lab.deployments();
  assert.equal(deployments["canary-b"].stage, "failed");
  assert.equal(deployments["canary-b"].failure_code, "agent_result_failed");
  assert.equal(deployments["canary-a"].stage, "served_verified");
  assert.deepEqual(await lab.snapshotOf(["canary-a"]), verified);
  assert.equal(deployments.rest.job_id, null);
  assert.equal(await lab.claim("rest"), null);
  assert.equal(await lab.deployJobCount(), 2);
  assert.deepEqual(await lab.current(), { "canary-a": true, "canary-b": false, rest: false });
  assert.deepEqual(await lab.failedJobIds(), [deployments["canary-b"].job_id]);
});

test("an optional destination failure never blocks the rollout, a required one does", async (t) => {
  await t.test("optional canary failure: later required waves still deploy and the rollout ends degraded", async () => {
    const f = await fixture();
    const lab = await waveLab(f, [
      { name: "required-w0", wave: 0 },
      { name: "optional-w0", wave: 0, required: false },
      { name: "required-w1", wave: 1 },
    ], { maxParallel: 2 });
    await lab.advance();
    await lab.run("required-w0", "succeeded");
    const run = await lab.run("optional-w0", "failed");
    assert.notEqual(run.reason, "required_consumer_failed");
    assert.notEqual(await lab.rolloutState(), "paused", "an optional failure must not pause the rollout");
    assert.ok((await lab.deployments())["required-w1"].job_id, "the next wave starts despite the optional failure");
    const before = await lab.snapshotOf(["required-w0"]);
    await lab.run("required-w1", "succeeded");

    assert.equal(await lab.rolloutState(), "degraded");
    const deployments = await lab.deployments();
    assert.equal(deployments["optional-w0"].stage, "failed");
    assert.equal(deployments["optional-w0"].failure_code, "agent_result_failed");
    assert.equal(deployments["required-w0"].stage, "served_verified");
    assert.equal(deployments["required-w1"].stage, "served_verified");
    assert.deepEqual(await lab.snapshotOf(["required-w0"]), before, "required destinations are not rolled back");
    assert.deepEqual(await lab.current(), { "required-w0": true, "optional-w0": false, "required-w1": true });
    assert.deepEqual(await lab.failedJobIds(), [deployments["optional-w0"].job_id]);
  });

  await t.test("optional failure in the final wave completes the required destinations and reports degraded", async () => {
    const f = await fixture();
    const lab = await waveLab(f, [{ name: "required", wave: 0 }, { name: "optional", wave: 1, required: false }]);
    await lab.advance();
    await lab.run("required", "succeeded");
    await lab.run("optional", "failed");
    assert.equal(await lab.rolloutState(), "degraded");
    assert.deepEqual(await lab.current(), { required: true, optional: false });
  });

  await t.test("a required failure still pauses when an optional destination succeeded", async () => {
    const f = await fixture();
    const lab = await waveLab(f, [
      { name: "optional", wave: 0, required: false },
      { name: "required", wave: 0 },
      { name: "later", wave: 1 },
    ], { maxParallel: 2 });
    await lab.advance();
    await lab.run("optional", "succeeded");
    const run = await lab.run("required", "failed");
    assert.equal(run.reason, "required_consumer_failed");
    assert.equal(await lab.rolloutState(), "paused");
    assert.equal((await lab.deployments()).later.job_id, null);
    assert.deepEqual(await lab.failedJobIds(), [(await lab.deployments()).required.job_id]);
  });

  await t.test("a required failure after an earlier optional failure pauses rather than degrades", async () => {
    const f = await fixture();
    const lab = await waveLab(f, [
      { name: "optional", wave: 0, required: false },
      { name: "required", wave: 1 },
    ]);
    await lab.advance();
    await lab.run("optional", "failed");
    await lab.run("required", "failed");
    assert.equal(await lab.rolloutState(), "paused");
  });
});
