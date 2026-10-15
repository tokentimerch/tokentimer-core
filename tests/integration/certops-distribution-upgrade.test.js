"use strict";

const assert = require("node:assert/strict");
const { randomBytes } = require("node:crypto");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { Client } = require("pg");

describe("Core distribution and lifecycle migration histories", function () {
  this.timeout(120000);

  for (const history of [
    "fresh",
    "distribution-first",
    "enrollment-first",
    "canonical-core",
    "mainline-alert-context",
    "previous-distribution",
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
        let before = [];
        let oldJob;
        let workspace;
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
          const script =
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
        }
        // The CLI must finish after the committed work, without waiting for
        // the imported Core executor's 30-second idle pool timeout.
        execute(["migrations/migrate.js"], 10000);
        const after = (
          await db.query(
            "SELECT version,name,executed_at FROM migrations ORDER BY version",
          )
        ).rows;
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
        const expected = history === "distribution-first" ? [canonical[4],canonical[5],canonical[6],canonical[0],canonical[1],canonical[2],canonical[3]] : history === "enrollment-first" ? [canonical[0],canonical[4],canonical[5],canonical[6],canonical[1],canonical[2],canonical[3]] : history === "previous-distribution" ? [canonical[0],canonical[1],canonical[2],canonical[4],canonical[5],canonical[6],canonical[3]] : canonical;
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
