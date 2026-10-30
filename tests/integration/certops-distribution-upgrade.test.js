"use strict";

const assert = require("node:assert/strict");
const { randomBytes } = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { Client } = require("pg");

describe("Core distribution and lifecycle migration histories", function () {
  this.timeout(120000);
  const extensionHistories = {
    "mainline-installed-78": ["certops_installed_file_distribution"],
    "mainline-stats-79": ["certops_installed_file_distribution", "auto_sync_provider_stats"],
    "mainline-metrics-80": ["certops_installed_file_distribution", "auto_sync_provider_stats", "auto_sync_run_metrics"],
    "mainline-labels-81": ["certops_installed_file_distribution", "auto_sync_provider_stats", "auto_sync_run_metrics", "auto_sync_metric_labels"],
    "mainline-system-82": ["certops_installed_file_distribution", "auto_sync_provider_stats", "auto_sync_run_metrics", "auto_sync_metric_labels", "auto_sync_system_metrics"],
    "provider-preview-81": ["certops_installed_file_distribution", "auto_sync_provider_stats", "auto_sync_run_metrics", "certops_material_providers"],
    "provider-preview-82": ["certops_installed_file_distribution", "auto_sync_provider_stats", "auto_sync_run_metrics", "auto_sync_metric_labels", "certops_material_providers"],
    "provider-preview-78": ["certops_material_providers"],
    "provider-preview-79": ["certops_installed_file_distribution", "certops_material_providers"],
    "provider-preview-78-installed-79": ["certops_material_providers", "certops_installed_file_distribution"],
  };

  for (const history of [
    "fresh",
    "distribution-first",
    "enrollment-first",
    "canonical-core",
    "mainline-alert-context",
    "previous-distribution",
    "mainline-installed-78",
    "provider-preview-78",
    "mainline-stats-79",
    "mainline-metrics-80",
    "mainline-labels-81",
    "mainline-system-82",
    "provider-preview-81",
    "provider-preview-82",
    "provider-preview-79",
    "provider-preview-78-installed-79",
  ]) {
    it(`upgrades ${history} through the actual composed executor`, async () => {
      const root = path.resolve(__dirname, "../..");
      const api = path.join(root,"apps/api");
      const name = `tt_enterprise_enrollment_${randomBytes(8).toString("hex")}`;
      const connection = {
        host: process.env.DB_HOST || "localhost",
        port: Number(
          process.env.DB_PORT || process.env.TT_TEST_DB_PORT || 5432,
        ),
        user: process.env.DB_USER || "tokentimer",
        password: process.env.DB_PASSWORD || "password",
        database: process.env.DB_NAME || "tokentimer",
      };
      const admin = new Client(connection);
      let db;
      let created = false;
      await admin.connect();
      try {
        await admin.query(`CREATE DATABASE ${name}`);
        created = true;
        db = new Client({ ...connection, database: name });
        await db.connect();
        const env = {
          ...process.env,
          NODE_ENV: "test",
          DB_HOST: connection.host,
          DB_PORT: String(connection.port),
          DB_USER: connection.user,
          DB_PASSWORD: connection.password,
          DB_NAME: name,
        };
        function execute(args, timeout = 90000) {
          const result = spawnSync(process.execPath, args, {
            cwd: api,
            env,
            encoding: "utf8",
            timeout,
          });
          assert.equal(
            result.status,
            0,
            `${result.error || ""}\n${result.stderr}\n${result.stdout?.slice(-1800)}`,
          );
        }
        function executeConcurrent() {
          return Promise.allSettled(Array.from({ length: 3 }, () => new Promise((resolve, reject) => {
            const child = spawn(process.execPath, ["migrations/migrate.js"], { cwd: api, env, windowsHide: true, timeout: 90000 });
            let output = "";
            for (const stream of [child.stdout, child.stderr]) stream.on("data", chunk => { output = (output + chunk.toString()).slice(-10000); });
            child.on("error", reject);
            child.on("close", code => code === 0 ? resolve() : reject(new Error(`Concurrent migration failed (${code}): ${output}`)));
          }))).then(results => {
            const failures = results.filter(result => result.status === "rejected");
            if (failures.length) throw failures[0].reason;
          });
        }
        let before = [];
        let oldJob;
        let workspace;
        let retained;
        if (history !== "fresh") {
          const canonical = [
            "certops_certificate_enrollments",
            "certops_adcs_evidence_types",
            "certops_profile_issuer",
            "certops_job_alert_context",
            "certops_material_distribution",
            "certops_distribution_review",
            "certops_distribution_transfer",
          ];
          const names = history === "distribution-first" ? [canonical[4],canonical[5],canonical[6],canonical[0],canonical[1],canonical[2],canonical[3]] : history === "enrollment-first" ? [canonical[0],canonical[4],canonical[5],canonical[6],canonical[1],canonical[2],canonical[3]] : history === "previous-distribution" ? [canonical[0],canonical[1],canonical[2],canonical[4],canonical[5],canonical[6],canonical[3]] : canonical;
          const count = history === "distribution-first" ? 3 : history === "enrollment-first" || history === "mainline-alert-context" ? 4 : history === "previous-distribution" ? 6 : 3;
          // Run real historical SQL through the original executor. The ledger
          // is created by migration execution, never fabricated with inserts.
          const legacyExtension = extensionHistories[history];
          const script = legacyExtension
            ? "const c=require('./migrations/migrate');const names=" + JSON.stringify(legacyExtension) +
              ";const list=[...c.migrations.filter(m=>m.version<=77),...names.map((name,i)=>({...c.migrations.find(m=>m.name===name),version:78+i}))];c.migrations.splice(0,c.migrations.length,...list);c.runMigrations().then(()=>process.exit(0)).catch(e=>{console.error(e);process.exit(1)});"
            :
            "const c=require('./migrations/migrate');const {composeMigrations}=require('./migrations/compose-migrations');const names=" +
            JSON.stringify(names.slice(0, count)) +
            ";const recorded=names.map((name,i)=>({version:70+i,name}));const list=composeMigrations(c.migrations,recorded).filter(m=>m.version<=69+names.length);c.migrations.splice(0,c.migrations.length,...list.map(m=>m.name==='certops_job_alert_context'?{...m,postCommitSql:undefined}:m));c.runMigrations().then(()=>process.exit(0)).catch(e=>{console.error(e);process.exit(1)});";
          execute(["-e", script]);
          before = (
            await db.query(
              "SELECT version,name,executed_at FROM migrations ORDER BY version",
            )
          ).rows;
          const user = (
            await db.query(
              "INSERT INTO users(email,display_name,password_hash,auth_method) VALUES('upgrade@example.test','Upgrade','fake-hash','local') RETURNING id",
            )
          ).rows[0];
          workspace = (
            await db.query(
              "INSERT INTO workspaces(id,name,created_by,plan) VALUES(gen_random_uuid(),'Upgrade',$1,'oss') RETURNING id",
              [user.id],
            )
          ).rows[0];
          oldJob = (
            await db.query(
              "INSERT INTO certificate_jobs(workspace_id,operation,status,source) VALUES($1,$2,'pending','api') RETURNING *",
              [
                workspace.id,
                history === "distribution-first"
                  ? "deploy-from-store"
                  : "renew",
              ],
            )
          ).rows[0];
          if (legacyExtension) {
            const { randomUUID } = require("node:crypto");
            const fingerprint = randomBytes(32).toString("hex");
            const agent = (await db.query(`INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash,platform)
              VALUES($1,$2,'0.18.1','1.0.0',$3,$4,'linux') RETURNING id`,
            [workspace.id, randomUUID(), `ttagent_${randomBytes(8).toString("hex")}`, randomBytes(32).toString("hex")])).rows[0].id;
            const source = (await db.query(`INSERT INTO managed_certificates(workspace_id,source,source_ref,fingerprint_sha256,status,not_after)
              VALUES($1,'agent_filesystem',$2,$3,'active',NOW()+INTERVAL '1 day') RETURNING id`,
            [workspace.id, randomUUID(), fingerprint])).rows[0].id;
            const period = (await db.query("SELECT id,current_identity_id FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL", [workspace.id, source])).rows[0];
            const group = (await db.query(`INSERT INTO certops_distribution_groups(workspace_id,managed_certificate_id,management_period_id,issuer_agent_id,material_store_ref,issuance_profile_ref,profile_revision,generation)
              VALUES($1,$2,$3,$4,'retained','retained',1,1) RETURNING id`, [workspace.id, source, period.id, agent])).rows[0].id;
            const version = (await db.query(`INSERT INTO certops_material_versions(workspace_id,group_id,management_period_id,publishing_job_id,publishing_claim_id,profile_revision,state,provider_version,certificate_identity_id,fingerprint_sha256,valid_to,published_at)
              VALUES($1,$2,$3,$4,$5,1,'published',1,$6,$7,NOW()+INTERVAL '1 day',NOW()) RETURNING id`,
            [workspace.id, group, period.id, oldJob.id, randomUUID(), period.current_identity_id, fingerprint])).rows[0].id;
            const policy = legacyExtension.includes("certops_installed_file_distribution") ? "installed" : "served";
            const binding = (await db.query(`INSERT INTO certops_consumer_bindings(workspace_id,group_id,assigned_agent_id,deployment_profile_ref,profile_revision,verification_policy)
              VALUES($1,$2,$3,'retained',1,$4) RETURNING id`, [workspace.id, group, agent, policy])).rows[0].id;
            await db.query(`INSERT INTO certops_consumer_current_state(workspace_id,group_id,binding_id,desired_material_version_id,desired_generation,accepted_generation,observed_material_version_id,observed_fingerprint_sha256,observed_valid_to,verification_method,observed_at)
              VALUES($1,$2,$3,$4,1,1,$4,$5,NOW()+INTERVAL '1 day',$6,NOW())`, [workspace.id, group, binding, version, fingerprint, policy]);
            const snapshots = [
              ["certops_distribution_groups", group, "material_store_provider"],
              ["certops_material_versions", version, "provider_version_ref"],
              ["certops_consumer_bindings", binding, "unused_additive_column"],
            ];
            const read = async () => ({
              rows: await Promise.all(snapshots.map(async ([table, id, additive]) =>
                (await db.query(`SELECT to_jsonb(row)-$2::text AS value FROM ${table} row WHERE id=$1`, [id, additive])).rows[0].value)),
              state: (await db.query("SELECT * FROM certops_consumer_current_state WHERE binding_id=$1", [binding])).rows[0],
            });
            retained = { read, before: await read() };
            if (legacyExtension.includes("auto_sync_provider_stats")) {
              await db.query("UPDATE auto_sync_provider_stats SET items_created_total=17 WHERE provider='github'");
              retained.telemetry = (await db.query("SELECT * FROM auto_sync_provider_stats ORDER BY provider")).rows;
            }
            if (legacyExtension.includes("auto_sync_run_metrics")) {
              await db.query("INSERT INTO auto_sync_run_outcome_stats(provider,status,runs_total) VALUES('github','success',9)");
              retained.metrics = (await db.query("SELECT * FROM auto_sync_run_outcome_stats ORDER BY provider,status")).rows;
            }
          }
        }
        // The CLI must finish after the committed work, without waiting for
        // the imported Core executor's 30-second idle pool timeout.
        if (history === "fresh" || extensionHistories[history]) await executeConcurrent();
        else execute(["migrations/migrate.js"], 10000);
        const after = (
          await db.query(
            "SELECT version,name,executed_at FROM migrations ORDER BY version",
          )
        ).rows;
        if (retained) assert.deepEqual(await retained.read(), retained.before, "upgrade preserves published pins, installed/served assurance and accepted evidence");
        if (retained?.telemetry) assert.deepEqual((await db.query("SELECT * FROM auto_sync_provider_stats ORDER BY provider")).rows, retained.telemetry);
        if (retained?.metrics) assert.deepEqual((await db.query("SELECT * FROM auto_sync_run_outcome_stats ORDER BY provider,status")).rows, retained.metrics);
        const combined = (await db.query(`SELECT
          EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='certops_distribution_groups' AND column_name='material_store_provider') AS provider,
          EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='certops_material_versions' AND column_name='provider_version_ref') AS opaque,
          EXISTS(SELECT 1 FROM pg_constraint WHERE conname='certops_consumer_bindings_verification_policy_check' AND pg_get_constraintdef(oid) LIKE '%installed%') AS installed`)).rows[0];
        assert.deepEqual(combined, { provider: true, opaque: true, installed: true });
        assert.deepEqual(
          after.filter((row) => row.version <= (before.at(-1)?.version || 0)),
          before,
        );
        const canonical = [
          "certops_certificate_enrollments",
          "certops_adcs_evidence_types",
          "certops_profile_issuer",
            "certops_job_alert_context",
          "certops_material_distribution",
          "certops_distribution_review",
          "certops_distribution_transfer",
        ];
        const mainlineOrder = history === "distribution-first" ? [canonical[4],canonical[5],canonical[6],canonical[0],canonical[1],canonical[2],canonical[3]] : history === "enrollment-first" ? [canonical[0],canonical[4],canonical[5],canonical[6],canonical[1],canonical[2],canonical[3]] : history === "previous-distribution" ? [canonical[0],canonical[1],canonical[2],canonical[4],canonical[5],canonical[6],canonical[3]] : canonical;
        // Both assurance and provider changes follow every supported history.
        const expected = [
          ...mainlineOrder,
          "onboarding_sessions",
          ...(history.startsWith("provider-preview-78")
            ? ["certops_material_providers", "certops_installed_file_distribution", "auto_sync_provider_stats", "auto_sync_run_metrics", "auto_sync_metric_labels", "auto_sync_system_metrics"]
            : history === "provider-preview-79"
              ? ["certops_installed_file_distribution", "certops_material_providers", "auto_sync_provider_stats", "auto_sync_run_metrics", "auto_sync_metric_labels", "auto_sync_system_metrics"]
              : history === "provider-preview-81"
                ? ["certops_installed_file_distribution", "auto_sync_provider_stats", "auto_sync_run_metrics", "certops_material_providers", "auto_sync_metric_labels", "auto_sync_system_metrics"]
                : history === "provider-preview-82"
                  ? ["certops_installed_file_distribution", "auto_sync_provider_stats", "auto_sync_run_metrics", "auto_sync_metric_labels", "certops_material_providers", "auto_sync_system_metrics"]
                  : ["certops_installed_file_distribution", "auto_sync_provider_stats", "auto_sync_run_metrics", "auto_sync_metric_labels", "auto_sync_system_metrics", "certops_material_providers"]),
        ];
        assert.deepEqual(
          after.filter((row) => row.version >= 70).map((row) => row.name),
          expected,
        );
        if (oldJob) {
          const expectedJob =
            history === "distribution-first"
              ? { ...oldJob, enrollment_id: null, preflight_seq: null, certificate_token_id: null }
              : ["canonical-core", "mainline-alert-context"].includes(history)
                ? { ...oldJob, distribution_request_hash: null, certificate_token_id: null }
                : { ...oldJob, certificate_token_id: null };
          assert.deepEqual(
            (
              await db.query("SELECT * FROM certificate_jobs WHERE id=$1", [
                oldJob.id,
              ])
            ).rows[0],
            expectedJob,
          );
          for (const operation of [
            "issue",
            "renew",
            "deploy-from-store",
            "adcs-preflight",
            "continue-enrollment",
          ]) {
            await db.query(
              "INSERT INTO certificate_jobs(workspace_id,operation,status,source) VALUES($1,$2,'pending','api')",
              [workspace.id, operation],
            );
          }
          await assert.rejects(
            db.query(
              "INSERT INTO certificate_jobs(workspace_id,operation,status,source) VALUES($1,'unknown-operation','pending','api')",
              [workspace.id],
            ),
            { code: "23514" },
          );
        }
        for (const table of [
          "certificate_issuers",
          "certificate_enrollments",
          "certops_distribution_groups",
          "certops_agent_job_log",
          "auto_sync_provider_stats",
          "auto_sync_run_outcome_stats",
          "auto_sync_run_freshness",
        ]) {
          assert.equal(
            (await db.query("SELECT to_regclass($1)::text AS name", [table]))
              .rows[0].name,
            table,
          );
        }
        const schema = await db.query(
          "SELECT convalidated FROM pg_constraint WHERE conrelid='certificate_profiles'::regclass AND conname='fk_certificate_profiles_issuer'",
        );
        assert.equal(schema.rowCount, 1);
        assert.equal(schema.rows[0].convalidated, true);
        assert.equal(
          (
            await db.query(
              "SELECT 1 FROM information_schema.columns WHERE table_name='certificate_profiles' AND column_name='issuer_id'",
            )
          ).rowCount,
          1,
        );
        const evidence = (
          await db.query(
            "SELECT pg_get_constraintdef(oid) AS value FROM pg_constraint WHERE conrelid='certificate_evidence'::regclass AND contype='c'",
          )
        ).rows
          .map((r) => r.value)
          .join(" ");
        assert.match(evidence, /adcs-submitted/);
        execute(["migrations/migrate.js"], 10000);
        assert.deepEqual(
          (
            await db.query(
              "SELECT version,name,executed_at FROM migrations ORDER BY version",
            )
          ).rows,
          after,
        );
      } finally {
        if (db) await db.end();
        if (created) await admin.query(`DROP DATABASE ${name}`);
        await admin.end();
      }
    });
  }
});
