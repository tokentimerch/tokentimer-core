"use strict";
/** Actual PostgreSQL conflict-lock regression using production invitation SQL.
 * Only an independently named disposable schema is created; no real workspace,
 * user, invitation, network API or email is touched. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const { setTimeout: delay } = require("node:timers/promises");

describe("Workspace invitation atomic admin protection", function () {
  this.timeout(15000);
  it("both invitation UPSERTs preserve a concurrently promoted admin and implicit owner", async function () {
    const schema = `membership_guard_${crypto.randomBytes(8).toString("hex")}`;
    assert.match(schema, /^membership_guard_[a-f0-9]{16}$/);
    const pool = new Pool({
      host: process.env.DB_HOST || "localhost",
      port: Number(process.env.DB_PORT || process.env.TT_TEST_DB_PORT || 5432),
      database: process.env.DB_NAME || "tokentimer",
      user: process.env.DB_USER || "tokentimer",
      password: process.env.DB_PASSWORD || "password",
      max: 3,
      connectionTimeoutMillis: 5000,
      statement_timeout: 10000,
    });
    let a, b, observer;
    let created = false,
      pending;
    try {
      a = await pool.connect();
      b = await pool.connect();
      observer = await pool.connect();
      await a.query(`CREATE SCHEMA ${schema}`);
      created = true;
      await a.query(
        `CREATE TABLE ${schema}.workspaces(id uuid PRIMARY KEY,created_by uuid); CREATE TABLE ${schema}.workspace_memberships(user_id uuid,workspace_id uuid,role text,invited_by uuid,PRIMARY KEY(user_id,workspace_id))`,
      );
      const user = crypto.randomUUID(),
        workspace = crypto.randomUUID(),
        owner = crypto.randomUUID();
      await a.query(`INSERT INTO ${schema}.workspaces VALUES($1,$2)`, [
        workspace,
        owner,
      ]);
      const queries = [
        {
          file: "apps/api/routes/workspaces.js",
          expression:
            /`(INSERT INTO workspace_memberships \(user_id, workspace_id, role, invited_by\) VALUES \(\$1,\$2,\$3,\$4\)[\s\S]*?RETURNING user_id)`/,
          args: [user, workspace, "viewer", owner],
        },
        {
          file: "apps/api/services/workspace.js",
          expression:
            /`(INSERT INTO workspace_memberships \(user_id, workspace_id, role, invited_by\)[\s\S]*?RETURNING role)`/,
          args: [user, workspace, "viewer"],
        },
      ];
      const aid = (await a.query("SELECT pg_backend_pid() AS pid")).rows[0].pid,
        bid = (await b.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
      for (const descriptor of queries) {
        const source = fs.readFileSync(
            path.resolve(__dirname, "../..", descriptor.file),
            "utf8",
          ),
          match = source.match(descriptor.expression);
        assert.ok(match, "production invitation query must be located");
        const sql = match[1]
          .replace(
            "INSERT INTO workspace_memberships",
            `INSERT INTO ${schema}.workspace_memberships`,
          )
          .replace("FROM workspaces w", `FROM ${schema}.workspaces w`);
        await a.query(`DELETE FROM ${schema}.workspace_memberships`);
        await a.query(
          `INSERT INTO ${schema}.workspace_memberships VALUES($1,$2,'workspace_manager',NULL)`,
          [user, workspace],
        );
        await a.query("BEGIN");
        await a.query(
          `UPDATE ${schema}.workspace_memberships SET role='admin' WHERE user_id=$1`,
          [user],
        );
        pending = b.query(sql, descriptor.args);
        let blocked = false;
        const deadline = Date.now() + 5000;
        while (Date.now() < deadline) {
          const rows = await observer.query(
            "SELECT $1::int = ANY(pg_blocking_pids($2::int)) AS blocked",
            [aid, bid],
          );
          if (rows.rows[0].blocked) {
            blocked = true;
            break;
          }
          await delay(10);
        }
        assert.equal(
          blocked,
          true,
          "invitation must actually wait for the held promotion lock",
        );
        await a.query("COMMIT");
        assert.equal((await pending).rowCount, 0);
        pending = undefined;
        assert.equal(
          (await a.query(`SELECT role FROM ${schema}.workspace_memberships`))
            .rows[0].role,
          "admin",
        );
        await a.query(
          `UPDATE ${schema}.workspace_memberships SET role='workspace_manager'`,
        );
        assert.equal((await b.query(sql, descriptor.args)).rowCount, 1);
        assert.equal(
          (await a.query(`SELECT role FROM ${schema}.workspace_memberships`))
            .rows[0].role,
          "viewer",
        );
        if (descriptor.file.includes("services/")) {
          await a.query(`DELETE FROM ${schema}.workspace_memberships`);
          assert.equal(
            (await b.query(sql, [owner, workspace, "viewer"])).rowCount,
            0,
          );
          assert.equal(
            (
              await a.query(
                `SELECT count(*)::int AS count FROM ${schema}.workspace_memberships`,
              )
            ).rows[0].count,
            0,
          );
        }
      }
    } finally {
      try {
        if (a) await a.query("ROLLBACK");
        if (pending) await pending.catch(() => {});
        if (created) await a.query(`DROP SCHEMA ${schema} CASCADE`);
      } finally {
        a?.release();
        b?.release();
        observer?.release();
        await pool.end();
      }
    }
  });
});
