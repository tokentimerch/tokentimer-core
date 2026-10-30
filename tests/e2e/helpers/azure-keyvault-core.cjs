"use strict";
// Real PostgreSQL + actual Core services + verified packaged agent. Public
// setup rows replace HTTP/operator/CA orchestration; never call this full E2E.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { Client } = require("pg");
const {
  check,
  rejects,
  verifyMaterial,
} = require("./azure-keyvault-live-io.cjs");
const material = require("../../../apps/api/services/certops/materialDistribution");
const signing = require("../../../apps/api/services/certops/jobSigning");
const approvals = require("../../../apps/api/services/certops/jobApprovals");
const {
  migrations,
  applyMigrationSql,
  applyPostCommitSql,
} = require("../../../apps/api/migrations/migrate");

async function open({ root, packageRoot, config, materials }) {
  check(
    process.env.NODE_ENV === "test" &&
      !!process.env.DB_HOST &&
      (process.env.TT_AZURE_QUALIFICATION_REQUIRED !== "1" ||
        process.env.DB_HOST === "127.0.0.1"),
    "AZURE_KV_DISPOSABLE_POSTGRES_REQUIRED",
  );
  const connection = {
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
  };
  check(
    Number.isInteger(connection.port) &&
      connection.port > 0 &&
      !!process.env.DB_NAME,
    "AZURE_KV_POSTGRES_CONFIGURATION_REQUIRED",
  );
  const database = `kvqual_${process.pid}_${crypto.randomBytes(6).toString("hex")}`;
  const admin = new Client({ ...connection, database: process.env.DB_NAME });
  let db,
    created = false;
  const previousKey = process.env.CERTOPS_SIGNING_ENCRYPTION_KEY;
  async function close() {
    try {
      await db?.end();
      if (created) await admin.query(`DROP DATABASE ${database} WITH (FORCE)`);
    } finally {
      await admin.end();
      if (previousKey === undefined)
        delete process.env.CERTOPS_SIGNING_ENCRYPTION_KEY;
      else process.env.CERTOPS_SIGNING_ENCRYPTION_KEY = previousKey;
    }
  }
  try {
    await admin.connect();
    await admin.query(`CREATE DATABASE ${database}`);
    created = true;
    db = new Client({ ...connection, database });
    await db.connect();
    for (const migration of migrations) {
      await applyMigrationSql(db, migration);
      await applyPostCommitSql(db, migration);
    }
    process.env.CERTOPS_SIGNING_ENCRYPTION_KEY = crypto
      .randomBytes(32)
      .toString("hex");
    const publicSigning = await signing.ensureActiveSigningKey({ client: db });
    const agentSigning = require(path.join(packageRoot, "src/signing"));
    const lifecycle = require(
      path.join(packageRoot, "src/material-store/lifecycle"),
    );
    const storeApi = require(path.join(packageRoot, "src/material-store"));
    const users = [];
    for (const name of ["requester", "approver"])
      users.push(
        (
          await db.query(
            "INSERT INTO users(email,display_name,password_hash,auth_method) VALUES($1,$2,'unused','local') RETURNING id",
            [`${name}@kvqual.example.test`, name],
          )
        ).rows[0].id,
      );
    const workspaceId = (
      await db.query(
        "INSERT INTO workspaces(id,name,plan,created_by) VALUES(gen_random_uuid(),'Disposable Azure qualification','oss',$1) RETURNING id",
        [users[0]],
      )
    ).rows[0].id;
    const agent = (
      await db.query(
        `INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash,platform)
      VALUES($1,$2,$5,'1.0.0',$3,$4,$6) RETURNING *`,
        [
          workspaceId,
          crypto.randomUUID(),
          `ttagent_${crypto.randomBytes(8).toString("hex")}`,
          crypto.randomBytes(32).toString("hex"),
          require(path.join(packageRoot, "package.json")).version,
          process.platform,
        ],
      )
    ).rows[0];
    const sans = ["valid.example.com", "www.valid.example.com"];
    const source = (
      await db.query(
        `INSERT INTO managed_certificates(workspace_id,source,source_ref,fingerprint_sha256,status,common_name,subject_alt_names,not_after,key_mode)
      VALUES($1,'agent_filesystem',$2,$3,'active','valid.example.com',$4,$5,'vault-managed') RETURNING *`,
        [
          workspaceId,
          crypto.randomUUID(),
          verifyMaterial(materials[0]),
          sans,
          new crypto.X509Certificate(materials[0].certificatePem).validTo,
        ],
      )
    ).rows[0];
    const group = await material.createGroupForSource({
      client: db,
      workspaceId,
      certificateId: source.id,
      issuerAgentId: agent.id,
      materialStoreRef: "qualification",
      issuanceProfileRef: "shared",
      profileRevision: 1,
      type: "azure-key-vault",
    });
    const scope = {
      workspaceId,
      prefix: `qualification/${workspaceId}/${group.id}`,
      sans,
      keyAlgorithm: "rsa",
      issuerAgentId: agent.agent_id,
      issuanceProfileRef: "shared",
      profileRevision: 1,
      caEndpoint: "https://qualification.invalid/directory",
      dnsProvider: "cloudflare",
      dnsZone: "example.com",
    };
    const stores = (auth) => ({
      qualification: {
        ...config,
        ...(auth ? { auth } : {}),
        groups: { [group.id]: scope },
      },
    });
    async function sign(job) {
      const claimed = await signing.signJobForDispatch({
        client: db,
        workspaceId,
        agentId: agent.id,
        envelopeVersion: 2,
        job,
      });
      const verdict = agentSigning.verifyJobEnvelope({
        claimed,
        publicKeyPem: publicSigning.publicKeyPem,
        pinnedSigningKeyId: publicSigning.signingKeyId,
      });
      check(
        verdict.allowed &&
          agentSigning.checkJobTimeWindow({
            job: verdict.job,
            nowMs: Date.now(),
          }).allowed &&
          agentSigning.checkAgentIdBinding({
            job: verdict.job,
            boundAgentId: agent.agent_id,
            requireSignedAgentId: true,
          }).allowed,
        "AZURE_KV_SIGNED_AGENT_JOB_REJECTED",
      );
      const tampered = {
        ...claimed,
        signatureB64: Buffer.alloc(64).toString("base64"),
      };
      check(
        !agentSigning.verifyJobEnvelope({
          claimed: tampered,
          publicKeyPem: publicSigning.publicKeyPem,
          pinnedSigningKeyId: publicSigning.signingKeyId,
        }).allowed,
        "AZURE_KV_SIGNED_JOB_TAMPERING_ACCEPTED",
      );
      return verdict.job;
    }
    async function claimedJob(operation, payload) {
      return (
        await db.query(
          `INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status,payload,assigned_agent_id,claimed_by_agent_id,claim_id,lease_expires_at)
        VALUES($1,'managed_certificate',$2,$3,'running',$4::jsonb,$5,$5,$6,NOW()+INTERVAL '30 minutes') RETURNING *`,
          [
            workspaceId,
            source.id,
            operation,
            JSON.stringify(payload),
            agent.id,
            crypto.randomUUID(),
          ],
        )
      ).rows[0];
    }
    const lease = (job) => async () => {
      const result = await db.query(
        "SELECT 1 FROM certificate_jobs WHERE id=$1 AND workspace_id=$2 AND status='running' AND claimed_by_agent_id=$3 AND claim_id=$4 AND lease_expires_at>clock_timestamp()",
        [job.id, workspaceId, agent.id, job.claim_id],
      );
      check(result.rowCount === 1, "AZURE_KV_REAL_CLAIM_LEASE_LOST");
    };
    async function publication(index) {
      const publication = {
        type: "azure-key-vault",
        groupId: group.id,
        managementPeriodId: group.management_period_id,
        materialVersionId: crypto.randomUUID(),
        materialStoreRef: "qualification",
        issuanceProfileRef: "shared",
        profileRevision: 1,
      };
      const payload = {
        publication,
        keyMode: "vault-managed",
        sans,
        target: { type: "domain", reference: "valid.example.com" },
        keyAlgorithm: "rsa",
        keySize: 2048,
        caEndpoint: scope.caEndpoint,
        dnsProvider: scope.dnsProvider,
        dnsZone: scope.dnsZone,
        commandRef: "renew-shared",
      };
      const job = await claimedJob("renew", payload);
      await material.allocateMaterialVersion({
        client: db,
        workspaceId,
        groupId: group.id,
        job,
      });
      const signed = await sign({
        ...payload,
        jobId: job.id,
        action: "renew",
        workspaceId,
        agentId: agent.agent_id,
        certificateId: source.id,
      });
      const options = {
        job: signed,
        stores: stores(),
        stateDir: path.join(root, "issuer-state"),
        keysDir: path.join(root, "keys"),
      };
      const session = lifecycle.publicationSession(options);
      const bundle = session.makeBundle(
        materials[index].certificatePem,
        materials[index].privateKeyPem,
        verifyMaterial(materials[index]),
      );
      session.stage(
        bundle.certificatePem,
        bundle.privateKeyPem,
        bundle.fingerprintSha256,
      );
      return {
        job,
        signed,
        options,
        session,
        bundle,
        lease: lease(job),
        recreate: () => lifecycle.publicationSession(options),
      };
    }
    async function accept(published, result) {
      check(
        result.status === "succeeded",
        "AZURE_KV_PUBLICATION_NOT_SUCCEEDED",
      );
      await material.acceptPublicationReceipt({
        client: db,
        workspaceId,
        agentId: agent.id,
        job: published.job,
        receipt: result.publicationReceipt,
        certificatePem: result.publicationCertificatePem,
      });
      const stored = (
        await db.query("SELECT * FROM certops_material_versions WHERE id=$1", [
          published.bundle.materialVersionId,
        ])
      ).rows[0];
      check(
        stored.provider_version === null &&
          stored.provider_version_ref ===
            result.publicationReceipt.providerVersion &&
          stored.fingerprint_sha256 === published.bundle.fingerprintSha256,
        "AZURE_KV_POSTGRES_EXACT_PIN_NOT_PERSISTED",
      );
      check(
        !JSON.stringify(stored).includes(published.bundle.privateKeyPem),
        "AZURE_KV_PRIVATE_KEY_ENTERED_CONTROL_PLANE",
      );
      check(
        (
          await signing.consumeNonce({
            client: db,
            nonce: published.signed.nonce,
            jobId: published.job.id,
            workspaceId,
            agentRowId: agent.id,
          })
        ).consumed,
        "AZURE_KV_SIGNED_NONCE_REJECTED",
      );
      await db.query(
        "UPDATE certificate_jobs SET status='succeeded' WHERE id=$1",
        [published.job.id],
      );
      return stored;
    }
    let binding;
    async function rollout(published, receipt, consumerAuth) {
      if (!binding)
        binding = (
          await db.query(
            `INSERT INTO certops_consumer_bindings(workspace_id,group_id,assigned_agent_id,deployment_profile_ref,profile_revision,verification_policy)
        VALUES($1,$2,$3,'consumer',1,'installed') RETURNING *`,
            [workspaceId, group.id, agent.id],
          )
        ).rows[0];
      await db.query("BEGIN");
      let snapshot;
      try {
        const { intent } = await material.buildRolloutIntent({
          client: db,
          workspaceId,
          groupId: group.id,
          materialVersionId: published.bundle.materialVersionId,
        });
        const request = (
          await db.query(
            `INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status,payload,requested_by_user_id)
          VALUES($1,'managed_certificate',$2,'noop','pending_approval',$3::jsonb,$4) RETURNING *`,
            [
              workspaceId,
              source.id,
              JSON.stringify({ distributionRollout: intent }),
              users[0],
            ],
          )
        ).rows[0];
        await rejects(
          () =>
            material.createRolloutSnapshot({
              client: db,
              workspaceId,
              groupId: group.id,
              materialVersionId: published.bundle.materialVersionId,
              approvalJobId: request.id,
              approvedIntentHash: material.hashIntent(intent),
            }),
          ["CERTOPS_ROLLOUT_APPROVAL_REQUIRED"],
        );
        // Actual approval service with a distinct fixture approver. This is not
        // a browser login/RBAC qualification, and no human approval is invented.
        await approvals.approveJob({
          client: db,
          workspaceId,
          jobId: request.id,
          approverUserId: users[1],
          reason: "Disposable qualification service integration",
        });
        snapshot = await material.createRolloutSnapshot({
          client: db,
          workspaceId,
          groupId: group.id,
          materialVersionId: published.bundle.materialVersionId,
          approvalJobId: request.id,
          approvedIntentHash: material.hashIntent(intent),
        });
        await db.query("COMMIT");
      } catch (error) {
        await db.query("ROLLBACK");
        throw error;
      }
      const deployment = {
        provider: "azure-key-vault",
        groupId: group.id,
        bindingId: binding.id,
        rolloutId: snapshot.rolloutId,
        materialVersionId: published.bundle.materialVersionId,
        materialStoreRef: "qualification",
        providerVersion: receipt.providerVersion,
        fingerprintSha256: published.bundle.fingerprintSha256,
        generation: snapshot.generation,
        deploymentProfileRef: "consumer",
        profileRevision: 1,
        authorizationRevision: 1,
        verificationPolicy: "installed",
      };
      const job = await claimedJob("deploy-from-store", {
        materialDeployment: deployment,
      });
      await db.query(
        "UPDATE certops_consumer_deployments SET job_id=$2 WHERE rollout_id=$1 AND binding_id=$3",
        [snapshot.rolloutId, job.id, binding.id],
      );
      await material.resolveDistributionJobDefaults({
        client: db,
        workspaceId,
        operation: "deploy-from-store",
        subjectId: source.id,
        payload: job.payload,
        assignedAgentId: agent.id,
        jobId: job.id,
      });
      const signed = await sign({
        jobId: job.id,
        action: "deploy-from-store",
        workspaceId,
        agentId: agent.agent_id,
        materialDeployment: deployment,
      });
      const directory = path.join(root, "consumer-files");
      fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
      const target = {
        type: "endpoint",
        reference: "qualification-files",
        certPath: path.join(directory, "fullchain.pem"),
        keyPath: path.join(directory, "key.pem"),
      };
      const options = {
        job: signed,
        stores: stores(consumerAuth),
        stateDir: path.join(root, "consumer-state"),
        platform: process.platform,
        bindings: {
          [binding.id]: {
            workspaceId,
            groupId: group.id,
            agentId: agent.agent_id,
            materialStoreRef: "qualification",
            deploymentProfileRef: "consumer",
            profileRevision: 1,
            authorizationRevision: 1,
            verificationPolicy: "installed",
            target,
          },
        },
        policyEngine: {
          checkPath: (file) => ({
            allowed: [target.certPath, target.keyPath].includes(file),
          }),
          checkTargetScope: () => ({ allowed: true }),
        },
        checkLease: lease(job),
        reload: () => {
          throw new Error("AZURE_KV_INSTALLED_RELOAD_FORBIDDEN");
        },
      };
      return { options, job, target, snapshot, lease: lease(job) };
    }
    async function acceptDeployment(deployment, result) {
      check(
        result.status === "succeeded" &&
          result.deploymentReceipt.installed &&
          !result.deploymentReceipt.servedVerified,
        "AZURE_KV_LINUX_DEPLOYMENT_FAILED",
      );
      const args = {
        client: db,
        workspaceId,
        agentId: agent.id,
        job: deployment.job,
        jobStatus: "succeeded",
      };
      await rejects(
        () =>
          material.acceptDeploymentReceipt({
            ...args,
            receipt: { ...result.deploymentReceipt, installed: false },
          }),
        ["CERTOPS_DEPLOYMENT_ASSURANCE_MISSING"],
      );
      for (const patch of [
        { generation: result.deploymentReceipt.generation + 1 },
        { fingerprintSha256: "0".repeat(64) },
      ])
        await rejects(
          () =>
            material.acceptDeploymentReceipt({
              ...args,
              receipt: { ...result.deploymentReceipt, ...patch },
            }),
          ["CERTOPS_DEPLOYMENT_RECEIPT_MISMATCH"],
        );
      await rejects(
        () =>
          material.acceptDeploymentReceipt({
            ...args,
            agentId: crypto.randomUUID(),
            receipt: result.deploymentReceipt,
          }),
        ["CERTOPS_DEPLOYMENT_RECEIPT_MISMATCH"],
      );
      await rejects(
        () =>
          material.acceptDeploymentReceipt({
            ...args,
            receipt: {
              ...result.deploymentReceipt,
              observedAt: new Date(Date.now() - 86400000).toISOString(),
            },
          }),
        ["CERTOPS_DEPLOYMENT_EVIDENCE_STALE"],
      );
      check(
        !(
          await material.consumerMatrix({
            client: db,
            workspaceId,
            groupId: group.id,
          })
        ).find((row) => row.binding_id === binding.id)?.converged,
        "AZURE_KV_INVALID_EVIDENCE_PROMOTED",
      );
      await material.acceptDeploymentReceipt({
        ...args,
        receipt: result.deploymentReceipt,
      });
      const row = (
        await material.consumerMatrix({
          client: db,
          workspaceId,
          groupId: group.id,
        })
      ).find(
        (row) => row.binding_id === binding.id || row.bindingId === binding.id,
      );
      check(row?.converged === true, "AZURE_KV_CONVERGENCE_NOT_CONFIRMED");
      check(
        (
          await signing.consumeNonce({
            client: db,
            workspaceId,
            agentRowId: agent.id,
            jobId: deployment.job.id,
            nonce: deployment.options.job.nonce,
          })
        ).consumed,
        "AZURE_KV_DEPLOYMENT_NONCE_REJECTED",
      );
      await db.query(
        "UPDATE certificate_jobs SET status='succeeded' WHERE id=$1",
        [deployment.job.id],
      );
    }
    return {
      close,
      publication,
      accept,
      rollout,
      acceptDeployment,
      lifecycle,
      storeApi,
      stores,
      workspaceId,
      groupId: group.id,
    };
  } catch (error) {
    await close();
    throw error;
  }
}
module.exports = { open };
