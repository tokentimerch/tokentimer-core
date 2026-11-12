"use strict";
const { test, after } = require("node:test"),
  assert = require("node:assert/strict"),
  crypto = require("node:crypto");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.match(
  process.env.DB_NAME || "",
  /^distribution_lifecycle_[a-f0-9]+_test$/,
);
const { pool } = require("../../apps/api/db/database"),
  operations = require("../../apps/api/services/certops/distributionOperations");
const reconciliation = require("../../apps/api/services/certops/materialReconciliation"),
  { approveJob } = require("../../apps/api/services/certops/jobApprovals");
const { fixture } = require("../helpers/distribution-lifecycle-fixture.cjs");
after(() => pool.end());
async function setup(options = {}) {
  const f = await fixture(options);
  if (options.installedOnly)
    await operations.putBinding({
      ...f,
      binding: { ...f.binding, verificationPolicy: "installed" },
      actorUserId: f.actor,
    });
  await operations.requestRollout({ ...f, actorUserId: f.actor });
  const rollout = (
    await pool.query(
      "SELECT * FROM certops_distribution_rollouts WHERE workspace_id=$1",
      [f.workspaceId],
    )
  ).rows[0];
  await operations.transaction((client) =>
    operations.advanceRollout(client, f.workspaceId, f.groupId, rollout.id),
  );
  const original = (
    await pool.query(
      "SELECT j.* FROM certops_consumer_deployments d JOIN certificate_jobs j ON j.id=d.job_id WHERE d.rollout_id=$1",
      [rollout.id],
    )
  ).rows[0];
  await pool.query(
    "UPDATE certificate_jobs SET status='rejected',needs_operator_reconciliation=TRUE,attempt_count=3 WHERE id=$1",
    [original.id],
  );
  await pool.query(
    "UPDATE certops_consumer_deployments SET stage='failed' WHERE job_id=$1",
    [original.id],
  );
  return { ...f, original };
}
test("fresh independently reviewed claim-bound proof clears only the exact historical obligation", async () => {
  const f = await setup();
  const before = (
    await pool.query(
      "SELECT * FROM certops_consumer_current_state WHERE workspace_id=$1 AND binding_id=$2",
      [f.workspaceId, f.bindingId],
    )
  ).rows[0];
  const pending = await reconciliation.requestReconciliation({
    workspaceId: f.workspaceId,
    jobId: f.original.id,
    actorUserId: f.actor,
  });
  assert.equal(pending.status, "pending_approval");
  await assert.rejects(
    reconciliation.requestReconciliation({
      workspaceId: f.workspaceId,
      jobId: f.original.id,
      actorUserId: f.actor,
    }),
    { code: "CERTOPS_RECONCILIATION_ALREADY_REQUESTED" },
  );
  await assert.rejects(
    approveJob({
      workspaceId: f.workspaceId,
      jobId: pending.id,
      approverUserId: f.actor,
    }),
  );
  await approveJob({
    workspaceId: f.workspaceId,
    jobId: pending.id,
    approverUserId: f.approver,
  });
  const claim = crypto.randomUUID(),
    job = (
      await pool.query(
        "UPDATE certificate_jobs SET status='claimed',claim_id=$2,claimed_by_agent_id=assigned_agent_id,lease_expires_at=clock_timestamp()+interval '5 minutes' WHERE id=$1 RETURNING *",
        [pending.id, claim],
      )
    ).rows[0];
  const intent = job.payload.materialReconciliation.intent;
  const receipt = {
    schemaVersion: 1,
    workspaceId: f.workspaceId,
    originalJobId: f.original.id,
    groupId: f.groupId,
    bindingId: f.bindingId,
    materialVersionId: f.materialVersionId,
    generation: intent.generation,
    fingerprintSha256: intent.fingerprintSha256,
    proofKind: intent.preparationOnly === true ? "staged" : "deployed",
    observedAt: new Date().toISOString(),
  };
  await assert.rejects(
    operations.transaction((client) =>
      reconciliation.acceptReceipt({
        client,
        workspaceId: f.workspaceId,
        agentId: f.consumer,
        job,
        receipt: { ...receipt, originalJobId: crypto.randomUUID() },
      }),
    ),
    { code: "CERTOPS_RECONCILIATION_RECEIPT_MISMATCH" },
  );
  assert.equal(
    (
      await pool.query(
        "SELECT needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",
        [f.original.id],
      )
    ).rows[0].needs_operator_reconciliation,
    true,
  );
  await assert.rejects(
    operations.transaction((client) =>
      reconciliation.acceptReceipt({
        client,
        workspaceId: f.workspaceId,
        agentId: f.consumer,
        job,
        receipt: { ...receipt, proofKind: "staged" },
      }),
    ),
    { code: "CERTOPS_RECONCILIATION_RECEIPT_MISMATCH" },
  );
  await operations.transaction((client) =>
    reconciliation.acceptReceipt({
      client,
      workspaceId: f.workspaceId,
      agentId: f.consumer,
      job,
      receipt,
    }),
  );
  assert.equal(
    (
      await pool.query(
        "SELECT needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",
        [f.original.id],
      )
    ).rows[0].needs_operator_reconciliation,
    false,
  );
  assert.deepEqual(
    (
      await pool.query(
        "SELECT * FROM certops_consumer_current_state WHERE workspace_id=$1 AND binding_id=$2",
        [f.workspaceId, f.bindingId],
      )
    ).rows[0],
    before,
  );
  await assert.rejects(
    operations.transaction((client) =>
      reconciliation.acceptReceipt({
        client,
        workspaceId: f.workspaceId,
        agentId: f.consumer,
        job,
        receipt,
      }),
    ),
  );
});
test("expired reconciliation lease cannot settle the original obligation", async () => {
  const f = await setup();
  const pending = await reconciliation.requestReconciliation({
    workspaceId: f.workspaceId,
    jobId: f.original.id,
    actorUserId: f.actor,
  });
  await approveJob({
    workspaceId: f.workspaceId,
    jobId: pending.id,
    approverUserId: f.approver,
  });
  const job = (
    await pool.query(
      "UPDATE certificate_jobs SET status='claimed',claim_id=$2,claimed_by_agent_id=assigned_agent_id,lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1 RETURNING *",
      [pending.id, crypto.randomUUID()],
    )
  ).rows[0];
  const scope = job.payload.materialReconciliation,
    intent = scope.intent;
  const receipt = {
    schemaVersion: 1,
    workspaceId: f.workspaceId,
    originalJobId: f.original.id,
    groupId: f.groupId,
    bindingId: f.bindingId,
    materialVersionId: f.materialVersionId,
    generation: intent.generation,
    fingerprintSha256: intent.fingerprintSha256,
    proofKind: intent.preparationOnly === true ? "staged" : "deployed",
    observedAt: new Date().toISOString(),
  };
  await assert.rejects(
    operations.transaction((client) =>
      reconciliation.acceptReceipt({
        client,
        workspaceId: f.workspaceId,
        agentId: f.consumer,
        job,
        receipt,
      }),
    ),
    { code: "CERTOPS_RECONCILIATION_RECEIPT_MISMATCH" },
  );
  assert.equal(
    (
      await pool.query(
        "SELECT needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",
        [f.original.id],
      )
    ).rows[0].needs_operator_reconciliation,
    true,
  );
});
test("concurrent requests cannot create two live reconciliations for one obligation", async () => {
  const f = await setup();
  const attempts = await Promise.allSettled(
    Array.from({ length: 2 }, () =>
      reconciliation.requestReconciliation({
        workspaceId: f.workspaceId,
        jobId: f.original.id,
        actorUserId: f.actor,
      }),
    ),
  );
  const accepted = attempts.filter((x) => x.status === "fulfilled"),
    rejected = attempts.filter((x) => x.status === "rejected");
  assert.equal(accepted.length, 1);
  assert.equal(rejected.length, 1);
  assert.equal(
    rejected[0].reason.code,
    "CERTOPS_RECONCILIATION_ALREADY_REQUESTED",
  );
  assert.equal(
    (
      await pool.query(
        "SELECT needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",
        [f.original.id],
      )
    ).rows[0].needs_operator_reconciliation,
    true,
  );
});
test("an inspected receipt arriving after original retry cannot settle the pending job", async () => {
  const f = await setup();
  await pool.query(
    "UPDATE certificate_jobs SET status='blocked',attempt_count=1 WHERE id=$1",
    [f.original.id],
  );
  const pending = await reconciliation.requestReconciliation({
    workspaceId: f.workspaceId,
    jobId: f.original.id,
    actorUserId: f.actor,
  });
  await approveJob({
    workspaceId: f.workspaceId,
    jobId: pending.id,
    approverUserId: f.approver,
  });
  const claim = crypto.randomUUID();
  const job = (
    await pool.query(
      "UPDATE certificate_jobs SET status='claimed',claim_id=$2,claimed_by_agent_id=assigned_agent_id,lease_expires_at=clock_timestamp()+interval '5 minutes' WHERE id=$1 RETURNING *",
      [pending.id, claim],
    )
  ).rows[0];
  const scope = job.payload.materialReconciliation,
    intent = scope.intent;
  const receipt = {
    schemaVersion: 1,
    workspaceId: f.workspaceId,
    originalJobId: f.original.id,
    groupId: f.groupId,
    bindingId: f.bindingId,
    materialVersionId: f.materialVersionId,
    generation: intent.generation,
    fingerprintSha256: intent.fingerprintSha256,
    proofKind: intent.preparationOnly === true ? "staged" : "deployed",
    observedAt: new Date().toISOString(),
  };
  await operations.retryDistributionJob({
    workspaceId: f.workspaceId,
    jobId: f.original.id,
    actorUserId: f.actor,
  });
  await assert.rejects(
    operations.transaction((client) =>
      reconciliation.acceptReceipt({
        client,
        workspaceId: f.workspaceId,
        agentId: f.consumer,
        job,
        receipt,
      }),
    ),
    { code: "CERTOPS_RECONCILIATION_UNAVAILABLE" },
  );
  const after = (
    await pool.query(
      "SELECT status,needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",
      [f.original.id],
    )
  ).rows[0];
  assert.equal(after.status, "pending");
  assert.equal(after.needs_operator_reconciliation, true);
});
test("an older unresolved job remains fenced after a newer rollout supersedes it", async () => {
  const f = await setup();
  await operations.requestRollout({ ...f, actorUserId: f.actor });
  const latest = (
    await pool.query(
      "SELECT generation FROM certops_distribution_groups WHERE workspace_id=$1 AND id=$2",
      [f.workspaceId, f.groupId],
    )
  ).rows[0];
  assert.ok(
    Number(latest.generation) >
      f.original.payload.materialDeployment.generation,
  );
  await assert.rejects(
    reconciliation.requestReconciliation({
      workspaceId: f.workspaceId,
      jobId: f.original.id,
      actorUserId: f.actor,
    }),
    { code: "CERTOPS_RECONCILIATION_STALE" },
  );
  assert.equal(
    (
      await pool.query(
        "SELECT needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",
        [f.original.id],
      )
    ).rows[0].needs_operator_reconciliation,
    true,
  );
});
test("revoked and restored reviewer cannot revive an earlier reconciliation approval", async () => {
  const f = await setup();
  const pending = await reconciliation.requestReconciliation({
    workspaceId: f.workspaceId,
    jobId: f.original.id,
    actorUserId: f.actor,
  });
  await approveJob({
    workspaceId: f.workspaceId,
    jobId: pending.id,
    approverUserId: f.approver,
  });
  const job = (
    await pool.query("SELECT * FROM certificate_jobs WHERE id=$1", [pending.id])
  ).rows[0];
  await operations.transaction((client) =>
    reconciliation.assertClaimable({
      client,
      workspaceId: f.workspaceId,
      agentId: f.consumer,
      job,
    }),
  );
  await pool.query(
    "DELETE FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2",
    [f.workspaceId, f.approver],
  );
  await assert.rejects(
    operations.transaction((client) =>
      reconciliation.assertClaimable({
        client,
        workspaceId: f.workspaceId,
        agentId: f.consumer,
        job,
      }),
    ),
    { code: "CERTOPS_RECONCILIATION_AUTHORITY_STALE" },
  );
  await pool.query(
    "INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'workspace_manager')",
    [f.workspaceId, f.approver],
  );
  await assert.rejects(
    operations.transaction((client) =>
      reconciliation.assertClaimable({
        client,
        workspaceId: f.workspaceId,
        agentId: f.consumer,
        job,
      }),
    ),
    { code: "CERTOPS_RECONCILIATION_AUTHORITY_STALE" },
  );
  assert.equal(
    (
      await pool.query(
        "SELECT needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",
        [f.original.id],
      )
    ).rows[0].needs_operator_reconciliation,
    true,
  );
});
test("a real claim and nonce-bound result settle only the approved original obligation", async () => {
  const f = await setup();
  const pending = await reconciliation.requestReconciliation({
    workspaceId: f.workspaceId,
    jobId: f.original.id,
    actorUserId: f.actor,
  });
  await approveJob({
    workspaceId: f.workspaceId,
    jobId: pending.id,
    approverUserId: f.approver,
  });
  await pool.query(
    "UPDATE certops_agents SET declared_target_selectors=$2::jsonb,platform='linux' WHERE id=$1",
    [f.consumer, JSON.stringify([f.bindingId])],
  );
  const row = (
    await pool.query("SELECT * FROM certops_agents WHERE id=$1", [f.consumer])
  ).rows[0];
  const agent = {
    id: row.id,
    workspaceId: f.workspaceId,
    agentId: row.agent_id,
    agentVersion: row.agent_version,
    protocolVersion: row.protocol_version,
  };
  const dispatch = require("../../apps/api/services/certops/agentDispatch");
  const key =
    await require("../../apps/api/services/certops/jobSigning").ensureActiveSigningKey();
  const claimed = await dispatch.claimJobs({
    agent,
    body: { supportedActions: ["reconcile-from-store"], maxJobs: 1 },
  });
  assert.equal(claimed.jobs.length, 1);
  const envelope = claimed.jobs[0];
  const verified =
    require("../../packages/agent/src/signing").verifyJobEnvelope({
      claimed: envelope,
      publicKeyPem: key.publicKeyPem,
      pinnedSigningKeyId: key.signingKeyId,
    });
  assert.equal(verified.allowed, true);
  const wire = verified.job;
  assert.equal(wire.action, "reconcile-from-store");
  assert.equal(wire.materialReconciliation.originalJobId, f.original.id);
  const scope = wire.materialReconciliation,
    intent = scope.intent;
  const receipt = {
    schemaVersion: 1,
    workspaceId: f.workspaceId,
    originalJobId: f.original.id,
    groupId: f.groupId,
    bindingId: f.bindingId,
    materialVersionId: f.materialVersionId,
    generation: intent.generation,
    fingerprintSha256: intent.fingerprintSha256,
    proofKind: intent.preparationOnly === true ? "staged" : "deployed",
    observedAt: new Date().toISOString(),
  };
  await dispatch.ingestResult({
    agent,
    body: {
      jobId: wire.jobId,
      claimId: wire.claimId,
      nonce: wire.nonce,
      status: "succeeded",
      reconciliationReceipt: receipt,
    },
  });
  assert.equal(
    (
      await pool.query(
        "SELECT needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",
        [f.original.id],
      )
    ).rows[0].needs_operator_reconciliation,
    false,
  );
  const duplicate = await dispatch.ingestResult({
    agent,
    body: {
      jobId: wire.jobId,
      claimId: wire.claimId,
      nonce: wire.nonce,
      status: "succeeded",
      reconciliationReceipt: receipt,
    },
  });
  assert.equal(duplicate.duplicate, true);
  await assert.rejects(
    dispatch.ingestResult({
      agent,
      body: {
        jobId: wire.jobId,
        claimId: wire.claimId,
        nonce: wire.nonce,
        status: "succeeded",
        reconciliationReceipt: {
          ...receipt,
          fingerprintSha256: "b".repeat(64),
        },
      },
    }),
    { code: "CERTOPS_RECONCILIATION_RECEIPT_MISMATCH" },
  );
});
test("authenticated HTTP agent protocol carries an approved signed reconciliation and duplicate result", async () => {
  const f = await setup();
  const pending = await reconciliation.requestReconciliation({
    workspaceId: f.workspaceId,
    jobId: f.original.id,
    actorUserId: f.actor,
  });
  await approveJob({
    workspaceId: f.workspaceId,
    jobId: pending.id,
    approverUserId: f.approver,
  });
  const credential =
    require("../../apps/api/services/certops/agentCredentials").generateAgentCredential();
  await pool.query(
    `UPDATE certops_agents SET credential_prefix=$2,credential_hash=$3,platform='linux',
    declared_target_selectors=$4::jsonb WHERE id=$1`,
    [
      f.consumer,
      credential.credentialPrefix,
      credential.credentialHash,
      JSON.stringify([f.bindingId]),
    ],
  );
  const agent = (
    await pool.query("SELECT agent_id FROM certops_agents WHERE id=$1", [
      f.consumer,
    ])
  ).rows[0];
  const express = require(
    require.resolve("express", {
      paths: [require.resolve("../../apps/api/package.json")],
    }),
  );
  const app = express();
  app.use(express.json());
  // Test enables the feature explicitly; credential auth and route handlers are real.
  app.use(
    require("../../apps/api/routes/certops-agent").createCertOpsAgentRouter({
      certOpsEnabledMiddleware: (_req, _res, next) => next(),
    }),
  );
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  try {
    const serverUrl = `http://127.0.0.1:${server.address().port}`;
    const denied = await fetch(`${serverUrl}/api/v1/certops/agent/jobs/claim`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer invalid",
      },
      body: "{}",
    });
    assert.equal(denied.status, 401);
    let loseResultAck = false,
      duplicateAcknowledged = false;
    const fetchWithLostAck = async (url, options) => {
      const response = await fetch(url, options);
      if (String(url).endsWith("/agent/jobs/results")) {
        if (loseResultAck) {
          loseResultAck = false;
          await response.arrayBuffer();
          throw new Error("synthetic post-commit connection loss");
        }
        const body = await response.clone().json();
        duplicateAcknowledged = body.duplicate === true;
      }
      return response;
    };
    const client =
      require("../../packages/agent/src/protocol").createProtocolClient({
        serverUrl,
        agentId: agent.agent_id,
        protocolVersion: "1.0.0",
        allowInsecureLocalHttp: true,
        getCredential: () => credential.plaintextCredential,
        fetchImpl: fetchWithLostAck,
      });
    const key =
      await require("../../apps/api/services/certops/jobSigning").ensureActiveSigningKey();
    const result = await client.claim({
      maxJobs: 1,
      supportedActions: ["reconcile-from-store"],
    });
    assert.equal(result.length, 1);
    const checked =
      require("../../packages/agent/src/signing").verifyJobEnvelope({
        claimed: result[0],
        publicKeyPem: key.publicKeyPem,
        pinnedSigningKeyId: key.signingKeyId,
      });
    assert.equal(checked.allowed, true);
    const wire = checked.job,
      scope = wire.materialReconciliation,
      intent = scope.intent;
    // Receipt is synthetic: this verifies authenticated transport, not agent inspection.
    const receipt = {
      schemaVersion: 1,
      workspaceId: f.workspaceId,
      originalJobId: f.original.id,
      groupId: f.groupId,
      bindingId: f.bindingId,
      materialVersionId: f.materialVersionId,
      generation: intent.generation,
      fingerprintSha256: intent.fingerprintSha256,
      proofKind: intent.preparationOnly === true ? "staged" : "deployed",
      observedAt: new Date().toISOString(),
    };
    const payload = {
      jobId: wire.jobId,
      attemptId: wire.claimId,
      claimId: wire.claimId,
      nonce: wire.nonce,
      status: "succeeded",
      reconciliationReceipt: receipt,
    };
    const fs = require("node:fs"),
      os = require("node:os"),
      path = require("node:path");
    const outbox = require("../../packages/agent/src/outbox");
    const dir = fs.mkdtempSync(
      path.join(os.tmpdir(), "tt-reconciliation-outbox-"),
    );
    try {
      outbox.enqueueOutboxEntry(dir, { result: payload });
      const initialTime = Date.now();
      loseResultAck = true;
      const first = await outbox.drainOutbox(dir, client, {
        now: () => initialTime,
      });
      assert.equal(first.transmitted, 0);
      assert.equal(outbox.listOutboxEntries(dir).length, 1);
      assert.equal(
        (
          await pool.query(
            "SELECT needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",
            [f.original.id],
          )
        ).rows[0].needs_operator_reconciliation,
        false,
      );
      const second = await outbox.drainOutbox(dir, client, {
        now: () => initialTime + 60000,
      });
      assert.equal(second.transmitted, 1);
      assert.equal(outbox.listOutboxEntries(dir).length, 0);
      assert.equal(duplicateAcknowledged, true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    assert.equal(
      (
        await pool.query(
          "SELECT needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",
          [f.original.id],
        )
      ).rows[0].needs_operator_reconciliation,
      false,
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
const fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");

test(
  "real login approval and Linux agent inspect installed legacy evidence through lost-ack recovery",
  // skip-reason: platform -- the CI PostgreSQL job runs this Linux execution case.
  { skip: process.platform !== "linux", timeout: 60000 },
  async (t) => {
    const cert = fs.readFileSync(
      path.join(
        __dirname,
        "../../packages/agent/src/verify/fixtures/leaf.crt.pem",
      ),
      "utf8",
    );
    const privateKeyPem = fs.readFileSync(
      path.join(
        __dirname,
        "../../packages/agent/src/verify/fixtures/leaf.key.pem",
      ),
      "utf8",
    );
    const x509 = new crypto.X509Certificate(cert),
      fingerprint = crypto.createHash("sha256").update(x509.raw).digest("hex");
    const f = await setup({ fingerprint, installedOnly: true });
    const directory = fs.mkdtempSync(
      path.join(os.tmpdir(), "tt-original-reconciliation-"),
    );
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    const row = (
      await pool.query("SELECT agent_id FROM certops_agents WHERE id=$1", [
        f.consumer,
      ])
    ).rows[0];
    const tokenFile = path.join(directory, "token");
    fs.writeFileSync(tokenFile, "synthetic-local-store-only", { mode: 0o600 });
    const credential =
      require("../../apps/api/services/certops/agentCredentials").generateAgentCredential();
    await pool.query(
      "UPDATE certops_agents SET credential_prefix=$2,credential_hash=$3,platform='linux',declared_target_selectors=$4::jsonb WHERE id=$1",
      [
        f.consumer,
        credential.credentialPrefix,
        credential.credentialHash,
        JSON.stringify([f.bindingId]),
      ],
    );
    const bundle = {
      schemaVersion: 1,
      workspaceId: f.workspaceId,
      groupId: f.groupId,
      materialVersionId: f.materialVersionId,
      certificatePem: cert,
      privateKeyPem,
      fingerprintSha256: fingerprint,
      sans: require("../../packages/agent/src/verify").parseDnsSans(
        x509.subjectAltName,
      ),
    };
    const storeServer = require("node:http").createServer((_req, res) =>
      res.end(
        JSON.stringify({
          data: {
            data: bundle,
            metadata: { version: 1, deletion_time: "", destroyed: false },
          },
        }),
      ),
    );
    await new Promise((resolve) => storeServer.listen(0, "127.0.0.1", resolve));
    t.after(() => new Promise((resolve) => storeServer.close(resolve)));
    const intent = f.original.payload.materialDeployment;
    const stateDir = path.join(directory, "state"),
      target = {
        type: "endpoint",
        reference: "fixture",
        certPath: path.join(directory, "cert.pem"),
        keyPath: path.join(directory, "key.pem"),
      };
    const bindings = {
      [f.bindingId]: {
        workspaceId: f.workspaceId,
        groupId: f.groupId,
        agentId: row.agent_id,
        materialStoreRef: "customer",
        deploymentProfileRef: intent.deploymentProfileRef,
        profileRevision: intent.profileRevision,
        authorizationRevision: intent.authorizationRevision,
        verificationPolicy: "installed",
        target,
        probes: [],
      },
    };
    const stores = {
      customer: {
        address: `http://127.0.0.1:${storeServer.address().port}`,
        mount: "secret",
        tokenFile,
        groups: {
          [f.groupId]: {
            workspaceId: f.workspaceId,
            prefix: `${f.workspaceId}/${f.groupId}`,
            sans: bundle.sans,
            keyAlgorithm: x509.publicKey.asymmetricKeyType,
          },
        },
      },
    };
    const policyEngine = {
      checkPath: () => ({ allowed: true }),
      checkTargetScope: () => ({ allowed: true }),
    };
    const lifecycle = require("../../packages/agent/src/material-store/lifecycle");
    const interrupted = await lifecycle.executePinnedDeployment({
      job: {
        jobId: f.original.id,
        workspaceId: f.workspaceId,
        agentId: row.agent_id,
        materialDeployment: intent,
      },
      bindings,
      stores,
      stateDir,
      policyEngine,
      fixtureLoopbackHttp: true,
      checkLease: async () => {
        if (fs.existsSync(target.certPath))
          throw new Error("lost acknowledgement after install");
      },
    });
    assert.equal(interrupted.status, "orphaned_unknown_effect");
    const journalPath = path.join(
        stateDir,
        "material-bindings",
        `${f.bindingId}.json`,
      ),
      journal = JSON.parse(fs.readFileSync(journalPath, "utf8"));
    assert.equal(journal.uncertain, true);
    // Exercise the original deployed journal format; no invented historical claim.
    delete journal.originalJobId;
    require("../../packages/agent/src/material-store").writeProtectedJson(
      journalPath,
      journal,
    );
    const before = {
      cert: fs.readFileSync(target.certPath),
      key: fs.readFileSync(target.keyPath),
      state: (
        await pool.query(
          "SELECT * FROM certops_consumer_current_state WHERE workspace_id=$1 AND binding_id=$2",
          [f.workspaceId, f.bindingId],
        )
      ).rows[0],
    };
    const password = `Synthetic-${crypto.randomBytes(24).toString("hex")}`;
    const bcrypt = require(
      require.resolve("bcryptjs", {
        paths: [require.resolve("../../apps/api/package.json")],
      }),
    );
    await pool.query(
      "UPDATE users SET password_hash=$2,email_verified=TRUE WHERE id=ANY($1::int[])",
      [[f.actor, f.approver], await bcrypt.hash(password, 10)],
    );
    const users = (
      await pool.query("SELECT id,email FROM users WHERE id=ANY($1::int[])", [
        [f.actor, f.approver],
      ])
    ).rows;
    const port = await new Promise((resolve) => {
      const server = require("node:net").createServer();
      server.listen(0, "127.0.0.1", () => {
        const p = server.address().port;
        server.close(() => resolve(p));
      });
    });
    const base = `http://127.0.0.1:${port}`;
    const api = require("node:child_process").spawn(
      process.execPath,
      ["apps/api/index.js"],
      {
        cwd: process.cwd(),
        env: {
          ...process.env,
          PORT: String(port),
          HOST: "127.0.0.1",
          SESSION_SECRET: crypto.randomBytes(32).toString("hex"),
          CREDENTIAL_PEPPER: crypto.randomBytes(32).toString("hex"),
          PUBLIC_APP_URL: base,
        },
        stdio: ["ignore", "ignore", "ignore"],
      },
    );
    t.after(async () => {
      if (api.exitCode === null) {
        api.kill("SIGTERM");
        await new Promise((resolve) => {
          api.once("exit", resolve);
          setTimeout(() => {
            api.kill("SIGKILL");
            resolve();
          }, 5000).unref();
        });
      }
    });
    const session = () => {
      const cookies = new Map();
      let csrf;
      const call = async (route, method = "GET", body) => {
        const response = await fetch(`${base}${route}`, {
          method,
          signal: AbortSignal.timeout(15000),
          headers: {
            "content-type": "application/json",
            cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join("; "),
            ...(csrf ? { "x-csrf-token": csrf } : {}),
          },
          ...(body ? { body: JSON.stringify(body) } : {}),
        });
        for (const value of response.headers.getSetCookie()) {
          const first = value.split(";", 1)[0],
            i = first.indexOf("=");
          cookies.set(first.slice(0, i), first.slice(i + 1));
        }
        return { status: response.status, body: await response.json() };
      };
      return {
        call,
        async login(email) {
          csrf = (await call("/api/csrf-token")).body.csrfToken;
          assert.equal(
            (await call("/auth/login", "POST", { email, password })).status,
            200,
          );
          csrf = (await call("/api/csrf-token")).body.csrfToken;
        },
      };
    };
    let ready = false;
    for (let i = 0; i < 100; i++) {
      if (api.exitCode !== null) throw new Error("Owned API exited");
      try {
        if (
          (await fetch(`${base}/health`, { signal: AbortSignal.timeout(1000) }))
            .ok
        ) {
          ready = true;
          break;
        }
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    assert.equal(ready, true);
    const owner = session(),
      reviewer = session();
    await owner.login(users.find((u) => u.id === f.actor).email);
    await reviewer.login(users.find((u) => u.id === f.approver).email);
    const prefix = `/api/v1/workspaces/${f.workspaceId}/certops`;
    const created = await owner.call(
      `${prefix}/distribution-jobs/${f.original.id}/reconciliation`,
      "POST",
      {},
    );
    assert.equal(created.status, 200, JSON.stringify(created.body));
    const id = created.body.job.id;
    assert.equal(created.body.job.status, "pending_approval");
    assert.equal(
      (await owner.call(`${prefix}/jobs/${id}/approve`, "POST", {})).status,
      403,
    );
    const approved = await reviewer.call(
      `${prefix}/jobs/${id}/approve`,
      "POST",
      {},
    );
    assert.equal(approved.status, 200, JSON.stringify(approved.body));
    let loseAck = true,
      duplicate = false;
    const client =
      require("../../packages/agent/src/protocol").createProtocolClient({
        serverUrl: base,
        agentId: row.agent_id,
        protocolVersion: "1.0.0",
        allowInsecureLocalHttp: true,
        getCredential: () => credential.plaintextCredential,
        fetchImpl: async (url, options) => {
          const response = await fetch(url, options);
          if (String(url).endsWith("/agent/jobs/results")) {
            if (loseAck) {
              loseAck = false;
              await response.arrayBuffer();
              throw new Error("lost result acknowledgement");
            }
            duplicate = (await response.clone().json()).duplicate === true;
          }
          return response;
        },
      });
    const claims = await client.claim({
      maxJobs: 1,
      supportedActions: ["reconcile-from-store"],
    });
    assert.equal(claims.length, 1);
    const signing =
      await require("../../apps/api/services/certops/jobSigning").ensureActiveSigningKey();
    const checked =
      require("../../packages/agent/src/signing").verifyJobEnvelope({
        claimed: claims[0],
        publicKeyPem: signing.publicKeyPem,
        pinnedSigningKeyId: signing.signingKeyId,
      });
    assert.equal(checked.allowed, true);
    const wire = checked.job;
    const result = await require("../../packages/agent/src").executeJob({
      job: wire,
      jobId: wire.jobId,
      claimId: wire.claimId,
      attemptId: wire.claimId,
      policyEngine,
      client,
      leaseClient: client,
      executionContext: {
        execution: { dryRun: false, keysDir: path.join(stateDir, "keys") },
        materialBindings: bindings,
        materialStores: stores,
      },
      log: () => {},
    });
    assert.equal(result.status, "succeeded", JSON.stringify(result));
    assert.equal(result.reconciliationReceipt.originalJobId, f.original.id);
    assert.equal(
      JSON.parse(fs.readFileSync(journalPath, "utf8")).uncertain,
      false,
    );
    const outbox = require("../../packages/agent/src/outbox"),
      outboxDir = path.join(directory, "outbox");
    outbox.enqueueOutboxEntry(outboxDir, {
      result: {
        jobId: wire.jobId,
        attemptId: wire.claimId,
        claimId: wire.claimId,
        nonce: wire.nonce,
        ...result,
      },
    });
    const now = Date.now();
    assert.equal(
      (await outbox.drainOutbox(outboxDir, client, { now: () => now }))
        .transmitted,
      0,
    );
    assert.equal(
      (await outbox.drainOutbox(outboxDir, client, { now: () => now + 60000 }))
        .transmitted,
      1,
    );
    assert.equal(duplicate, true);
    const original = (
      await pool.query(
        "SELECT status,needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",
        [f.original.id],
      )
    ).rows[0];
    assert.deepEqual(original, {
      status: "rejected",
      needs_operator_reconciliation: false,
    });
    assert.deepEqual(
      (
        await pool.query(
          "SELECT * FROM certops_consumer_current_state WHERE workspace_id=$1 AND binding_id=$2",
          [f.workspaceId, f.bindingId],
        )
      ).rows[0],
      before.state,
    );
    assert.deepEqual(fs.readFileSync(target.certPath), before.cert);
    assert.deepEqual(fs.readFileSync(target.keyPath), before.key);
  },
);

test(
  "reconciliation yields to group or retry locks and duplicate requests never wait on a claimed inspection",
  { timeout: 10000 },
  async () => {
    const f = await setup(),
      pending = await reconciliation.requestReconciliation({
        workspaceId: f.workspaceId,
        jobId: f.original.id,
        actorUserId: f.actor,
      });
    await approveJob({
      workspaceId: f.workspaceId,
      jobId: pending.id,
      approverUserId: f.approver,
    });
    const job = (
      await pool.query("SELECT * FROM certificate_jobs WHERE id=$1", [
        pending.id,
      ])
    ).rows[0];
    const blocker = await pool.connect();
    try {
      await blocker.query("BEGIN");
      await blocker.query(
        "SELECT 1 FROM certificate_jobs WHERE id=$1 FOR UPDATE",
        [pending.id],
      );
      await assert.rejects(
        reconciliation.requestReconciliation({
          workspaceId: f.workspaceId,
          jobId: f.original.id,
          actorUserId: f.actor,
        }),
        { code: "CERTOPS_RECONCILIATION_ALREADY_REQUESTED" },
      );
      await blocker.query("ROLLBACK");
      await blocker.query("BEGIN");
      await blocker.query(
        "SELECT 1 FROM certops_distribution_groups WHERE id=$1 FOR UPDATE",
        [f.groupId],
      );
      await assert.rejects(
        operations.transaction((client) =>
          reconciliation.assertClaimable({
            client,
            workspaceId: f.workspaceId,
            agentId: f.consumer,
            job,
          }),
        ),
        { code: "CERTOPS_DISTRIBUTION_BUSY" },
      );
      await blocker.query("ROLLBACK");
      await blocker.query("BEGIN");
      await blocker.query(
        "SELECT 1 FROM certificate_jobs WHERE id=$1 FOR UPDATE",
        [f.original.id],
      );
      await assert.rejects(
        reconciliation.requestReconciliation({
          workspaceId: f.workspaceId,
          jobId: f.original.id,
          actorUserId: f.actor,
        }),
        { code: "CERTOPS_RECONCILIATION_CONCURRENT_WORK" },
      );
    } finally {
      await blocker.query("ROLLBACK");
      blocker.release();
    }
  },
);
