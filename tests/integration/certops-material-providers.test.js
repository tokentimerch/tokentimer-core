"use strict";
// Real PostgreSQL, public material only. This suite owns a disposable database;
// provider/network boundaries are tested independently by the gated real suite.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { Client, Pool } = require("pg");
const {
  migrations,
  applyMigrationSql,
  applyPostCommitSql,
} = require("../../apps/api/migrations/migrate");
const material = require("../../apps/api/services/certops/materialDistribution");
const {
  listDistributionGroups,
} = require("../../apps/api/services/certops/distributionRead");
const { resolveDistributionJobDefaults } = material;
const config = {
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || "tokentimer",
  password: process.env.DB_PASSWORD || "password",
};
const dbName = `certops_providers_${process.pid}_${Date.now()}`;
describe("CertOps material provider references on PostgreSQL", function () {
  this.timeout(180000);
  let db, userId;
  before(async () => {
    const admin = new Client({
      ...config,
      database: process.env.DB_NAME || "tokentimer",
    });
    await admin.connect();
    await admin.query(`CREATE DATABASE ${dbName}`);
    await admin.end();
    db = new Pool({ ...config, database: dbName });
    const client = await db.connect();
    try {
      for (const migration of migrations) {
        await applyMigrationSql(client, migration);
        await applyPostCommitSql(client, migration);
      }
    } finally {
      client.release();
    }
    userId = (
      await db.query(
        "INSERT INTO users(email,display_name,password_hash,auth_method) VALUES('providers@example.test','Providers','unused','local') RETURNING id",
      )
    ).rows[0].id;
  });
  after(async () => {
    await db?.end();
    const admin = new Client({
      ...config,
      database: process.env.DB_NAME || "tokentimer",
    });
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    await admin.end();
  });
  for (const provider of ["vault-kv2", "openbao-kv2", "azure-key-vault"])
    it(`${provider}: accepts claim-bound publication, preserves exact pins, and fences immutable provider authority`, async () => {
      const client = await db.connect();
      await client.query("BEGIN");
      try {
        const workspaceId = (
          await client.query(
            "INSERT INTO workspaces(id,name,plan,created_by) VALUES(gen_random_uuid(),'Provider test','oss',$1) RETURNING id",
            [userId],
          )
        ).rows[0].id;
        const agent = (
          await client.query(
            `INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash)
        VALUES($1,$2,'0.18.1','1.0.0',$3,$4) RETURNING *`,
            [
              workspaceId,
              crypto.randomUUID(),
              `ttagent_${crypto.randomBytes(8).toString("hex")}`,
              crypto.randomBytes(32).toString("hex"),
            ],
          )
        ).rows[0];
        const certificatePem = fs.readFileSync(
          path.join(
            __dirname,
            "../../packages/agent/src/verify/fixtures/leaf.crt.pem",
          ),
          "utf8",
        );
        const cert = new crypto.X509Certificate(certificatePem),
          fingerprintSha256 = crypto
            .createHash("sha256")
            .update(cert.raw)
            .digest("hex");
        const source = (
          await client.query(
            `INSERT INTO managed_certificates(workspace_id,source,source_ref,fingerprint_sha256,status,common_name,subject_alt_names,not_after,key_mode)
        VALUES($1,'agent_filesystem',$2,$3,'active','valid.example.com',$4,$5,'vault-managed') RETURNING *`,
            [
              workspaceId,
              crypto.randomUUID(),
              fingerprintSha256,
              ["valid.example.com", "www.valid.example.com"],
              cert.validTo,
            ],
          )
        ).rows[0];
        const group = await material.createGroupForSource({
          client,
          workspaceId,
          certificateId: source.id,
          issuerAgentId: agent.id,
          materialStoreRef: "customer",
          issuanceProfileRef: "shared",
          profileRevision: 1,
          type: provider,
        });
        const materialVersionId = crypto.randomUUID();
        const publication = {
          type: provider,
          groupId: group.id,
          managementPeriodId: group.management_period_id,
          materialVersionId,
          materialStoreRef: "customer",
          issuanceProfileRef: "shared",
          profileRevision: 1,
        };
        const payload = {
          publication,
          keyMode: "vault-managed",
          sans: ["valid.example.com", "www.valid.example.com"],
          target: { type: "domain", reference: "valid.example.com" },
          keyAlgorithm: "rsa",
          keySize: 2048,
          caEndpoint: "https://ca.example.test/directory",
          dnsProvider: "cloudflare",
          dnsZone: "example.com",
          commandRef: "renew-shared",
        };
        const job = (
          await client.query(
            `INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status,payload,assigned_agent_id,claimed_by_agent_id,claim_id,lease_expires_at)
        VALUES($1,'managed_certificate',$2,'renew','running',$3::jsonb,$4,$4,$5,NOW()+INTERVAL '5 minutes') RETURNING *`,
            [
              workspaceId,
              source.id,
              JSON.stringify(payload),
              agent.id,
              crypto.randomUUID(),
            ],
          )
        ).rows[0];
        await material.allocateMaterialVersion({
          client,
          workspaceId,
          groupId: group.id,
          job,
        });
        const providerVersion =
          provider === "azure-key-vault"
            ? crypto.randomBytes(16).toString("hex")
            : 1;
        const receipt = {
          schemaVersion: 1,
          workspaceId,
          groupId: group.id,
          materialVersionId,
          materialStoreRef: "customer",
          provider,
          providerVersion,
          fingerprintSha256,
          validTo: new Date(cert.validTo).toISOString(),
        };
        await material.acceptPublicationReceipt({
          client,
          workspaceId,
          agentId: agent.id,
          job,
          receipt,
          certificatePem,
        });
        const stored = (
          await client.query(
            "SELECT * FROM certops_material_versions WHERE id=$1",
            [materialVersionId],
          )
        ).rows[0];
        assert.equal(
          stored.provider_version_ref,
          provider === "azure-key-vault" ? providerVersion : null,
        );
        assert.equal(
          stored.provider_version,
          provider === "azure-key-vault" ? null : 1,
        );
        assert.equal(JSON.stringify(stored).includes("PRIVATE KEY"), false);
        const groups = (await listDistributionGroups({ client, workspaceId }))
          .groups;
        assert.equal(groups[0].material_store_provider, provider);
        assert.equal(groups[0].provider_version, providerVersion);
        await resolveDistributionJobDefaults({
          client,
          workspaceId,
          operation: "renew",
          subjectId: source.id,
          payload,
          assignedAgentId: agent.id,
          jobId: job.id,
        });
        await assert.rejects(
          resolveDistributionJobDefaults({
            client,
            workspaceId,
            operation: "renew",
            subjectId: source.id,
            payload: {
              ...payload,
              publication: {
                ...publication,
                type:
                  provider === "azure-key-vault"
                    ? "vault-kv2"
                    : "azure-key-vault",
              },
            },
            assignedAgentId: agent.id,
            jobId: job.id,
          }),
          { code: "CERTOPS_MATERIAL_PROVIDER_MISMATCH" },
        );
        await client.query("SAVEPOINT immutable_provider");
        await assert.rejects(
          client.query(
            "UPDATE certops_distribution_groups SET material_store_provider=$2 WHERE id=$1",
            [
              group.id,
              provider === "azure-key-vault" ? "vault-kv2" : "azure-key-vault",
            ],
          ),
          /immutable/,
        );
        await client.query("ROLLBACK TO SAVEPOINT immutable_provider");
        await client.query("SAVEPOINT immutable_version");
        await assert.rejects(
          client.query(
            "UPDATE certops_material_versions SET provider_version_ref=$2 WHERE id=$1",
            [materialVersionId, "f".repeat(32)],
          ),
          /immutable|mismatch/,
        );
        await client.query("ROLLBACK TO SAVEPOINT immutable_version");
        // Publish a different leaf, then explicitly authorize rollback to the
        // still-permitted retained version. Source-current and consumer-desired
        // are separate identities; a rollback must not require a new CA order.
        const nextPem = fs.readFileSync(
          path.join(
            __dirname,
            "../../packages/agent/src/verify/fixtures/selfsigned.crt.pem",
          ),
          "utf8",
        );
        const nextCert = new crypto.X509Certificate(nextPem),
          nextId = crypto.randomUUID();
        assert.notEqual(
          crypto.createHash("sha256").update(nextCert.raw).digest("hex"),
          fingerprintSha256,
        );
        const nextPayload = {
          ...payload,
          publication: { ...publication, materialVersionId: nextId },
        };
        const nextJob = (
          await client.query(
            `INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status,payload,assigned_agent_id,claimed_by_agent_id,claim_id,lease_expires_at)
        VALUES($1,'managed_certificate',$2,'renew','running',$3::jsonb,$4,$4,$5,NOW()+INTERVAL '5 minutes') RETURNING *`,
            [
              workspaceId,
              source.id,
              JSON.stringify(nextPayload),
              agent.id,
              crypto.randomUUID(),
            ],
          )
        ).rows[0];
        await material.allocateMaterialVersion({
          client,
          workspaceId,
          groupId: group.id,
          job: nextJob,
        });
        await material.acceptPublicationReceipt({
          client,
          workspaceId,
          agentId: agent.id,
          job: nextJob,
          receipt: {
            ...receipt,
            materialVersionId: nextId,
            providerVersion:
              provider === "azure-key-vault"
                ? crypto.randomBytes(16).toString("hex")
                : 1,
            fingerprintSha256: crypto
              .createHash("sha256")
              .update(nextCert.raw)
              .digest("hex"),
            validTo: new Date(nextCert.validTo).toISOString(),
          },
          certificatePem: nextPem,
        });
        const binding = (
          await client.query(
            `INSERT INTO certops_consumer_bindings(workspace_id,group_id,assigned_agent_id,deployment_profile_ref,profile_revision,verification_policy)
        VALUES($1,$2,$3,'consumer',1,'served') RETURNING *`,
            [workspaceId, group.id, agent.id],
          )
        ).rows[0];
        const { intent } = await material.buildRolloutIntent({
          client,
          workspaceId,
          groupId: group.id,
          materialVersionId,
        });
        assert.equal(intent.providerVersion, providerVersion);
        assert.equal(intent.provider || "vault-kv2", provider);
        const approval = (
          await client.query(
            `INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status,payload)
        VALUES($1,'managed_certificate',$2,'noop','pending',$3::jsonb) RETURNING *`,
            [
              workspaceId,
              source.id,
              JSON.stringify({ distributionRollout: intent }),
            ],
          )
        ).rows[0];
        const snapshotOptions = {
          client,
          workspaceId,
          groupId: group.id,
          materialVersionId,
          approvalJobId: approval.id,
          approvedIntentHash: material.hashIntent(intent),
        };
        await assert.rejects(material.createRolloutSnapshot(snapshotOptions), {
          code: "CERTOPS_ROLLOUT_APPROVAL_REQUIRED",
        });
        await client.query(
          "UPDATE workspaces SET certops_require_approval_always=false WHERE id=$1",
          [workspaceId],
        );
        const snapshot = await material.createRolloutSnapshot({
          ...snapshotOptions,
          approvalRequired: false,
        });
        const deployment = {
          provider,
          groupId: group.id,
          bindingId: binding.id,
          rolloutId: snapshot.rolloutId,
          materialVersionId,
          materialStoreRef: "customer",
          providerVersion,
          fingerprintSha256,
          generation: snapshot.generation,
          deploymentProfileRef: "consumer",
          profileRevision: 1,
          authorizationRevision: 1,
          verificationPolicy: "served",
        };
        const child = (
          await client.query(
            `INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status,payload,assigned_agent_id,claimed_by_agent_id,claim_id,lease_expires_at)
        VALUES($1,'managed_certificate',$2,'deploy-from-store','running',$3::jsonb,$4,$4,$5,NOW()+INTERVAL '5 minutes') RETURNING *`,
            [
              workspaceId,
              source.id,
              JSON.stringify({ materialDeployment: deployment }),
              agent.id,
              crypto.randomUUID(),
            ],
          )
        ).rows[0];
        await client.query(
          "UPDATE certops_consumer_deployments SET job_id=$3 WHERE workspace_id=$1 AND binding_id=$2",
          [workspaceId, binding.id, child.id],
        );
        const resolution = {
          client,
          workspaceId,
          operation: "deploy-from-store",
          subjectId: source.id,
          payload: child.payload,
          assignedAgentId: agent.id,
          jobId: child.id,
        };
        await resolveDistributionJobDefaults(resolution);
        await assert.rejects(
          resolveDistributionJobDefaults({
            ...resolution,
            payload: {
              materialDeployment: {
                ...deployment,
                providerVersion:
                  provider === "azure-key-vault" ? "0".repeat(32) : 2,
              },
            },
          }),
          { code: "CERTOPS_DEPLOYMENT_INTENT_MISMATCH" },
        );
        const proof = {
          schemaVersion: 1,
          workspaceId,
          groupId: group.id,
          bindingId: binding.id,
          materialVersionId,
          generation: snapshot.generation,
          fetched: true,
          installed: true,
          bound: true,
          servedVerified: true,
          trustValidated: false,
          fingerprintSha256,
          validTo: receipt.validTo,
          observedAt: new Date().toISOString(),
        };
        await material.acceptDeploymentReceipt({
          client,
          workspaceId,
          agentId: agent.id,
          job: child,
          receipt: { ...proof, bound: false, servedVerified: false },
          jobStatus: "failed",
          errorMessage: "material_windows_activation_failed",
        });
        assert.equal(
          (
            await client.query(
              "SELECT failure_code FROM certops_consumer_deployments WHERE job_id=$1",
              [child.id],
            )
          ).rows[0].failure_code,
          "material_windows_activation_failed",
        );
        assert.equal(
          (
            await material.consumerMatrix({
              client,
              workspaceId,
              groupId: group.id,
            })
          )[0].converged,
          false,
        );
        await material.acceptDeploymentReceipt({
          client,
          workspaceId,
          agentId: agent.id,
          job: child,
          receipt: proof,
          jobStatus: "succeeded",
        });
        const consumer = (
          await material.consumerMatrix({
            client,
            workspaceId,
            groupId: group.id,
          })
        )[0];
        assert.equal(consumer.desired_version, providerVersion);
        assert.equal(consumer.observed_version, providerVersion);
        assert.equal(
          consumer.converged,
          true,
          "an authorized retained-version rollback can converge while the source holds a newer leaf",
        );
      } finally {
        await client.query("ROLLBACK");
        client.release();
      }
    });
});
