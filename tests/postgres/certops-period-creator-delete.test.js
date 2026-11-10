"use strict";
const { test, after } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.match(process.env.DB_NAME || "", /^pr329_.*_test$/);
assert.equal(process.env.NODE_ENV, "test");
const { pool } = require("../../apps/api/db/database");
after(() => pool.end());

test("deleting a creator nullifies only its retained closed period attribution", async () => {
  const db = await pool.connect();
  try {
    await db.query("BEGIN");
    const nonce = crypto.randomUUID(), ws = crypto.randomUUID(), source = crypto.randomUUID();
    const users = (await db.query("INSERT INTO users(email,display_name,password_hash,auth_method) VALUES($1,'owner','x','local'),($2,'creator','x','local') RETURNING id", [`${nonce}-owner@example.test`,`${nonce}-creator@example.test`])).rows;
    await db.query("INSERT INTO workspaces(id,name,created_by) VALUES($1,'period fixture',$2)", [ws, users[0].id]);
    await db.query("INSERT INTO managed_certificates(id,workspace_id,source,created_by) VALUES($1,$2,'api',$3)", [source,ws,users[1].id]);
    const period = (await db.query("SELECT id FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2", [ws,source])).rows[0].id;
    await db.query("UPDATE certops_management_periods SET ended_at=NOW(),ended_reason='probe' WHERE id=$1", [period]);
    await db.query("DELETE FROM managed_certificates WHERE workspace_id=$1 AND id=$2", [ws,source]);
    const before = (await db.query("SELECT to_jsonb(p)-'created_by' AS state FROM certops_management_periods p WHERE id=$1", [period])).rows[0].state;
    async function rejectUpdate(sql, args) {
      await db.query("SAVEPOINT reject_edit");
      await assert.rejects(db.query(sql,args), error => error.code === "23514");
      await db.query("ROLLBACK TO SAVEPOINT reject_edit");
    }
    await rejectUpdate("UPDATE certops_management_periods SET created_by=NULL WHERE id=$1", [period]);
    await rejectUpdate("UPDATE certops_management_periods SET ended_reason='rewritten' WHERE id=$1", [period]);
    await rejectUpdate("UPDATE certops_management_periods SET automation_enabled=NOT automation_enabled WHERE id=$1", [period]);
    // A nested user-defined trigger is not an FK delete: the referenced user
    // still exists, so its attempt to clear attribution must also fail.
    await db.query("CREATE TEMP TABLE fake_period_update (id uuid)");
    await db.query(`CREATE FUNCTION pg_temp.try_clear_period_creator() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE certops_management_periods SET created_by=NULL WHERE id=NEW.id; RETURN NEW; END $$`);
    await db.query("CREATE TRIGGER fake_period_update BEFORE INSERT ON fake_period_update FOR EACH ROW EXECUTE FUNCTION pg_temp.try_clear_period_creator()");
    // Create the shadow before the guard first evaluates its user lookup.
    await db.query("CREATE TEMP TABLE users(id integer)");
    await rejectUpdate("INSERT INTO fake_period_update(id) VALUES($1)", [period]);
    await db.query("DROP TABLE pg_temp.users");
    await rejectUpdate("INSERT INTO fake_period_update(id) VALUES($1)", [period]);
    // A restricted role that cannot see the creator through RLS must fail
    // closed instead of interpreting an invisible row as a deleted user.
    const restrictedRole = `period_probe_${nonce.replaceAll("-", "")}`;
    await db.query(`CREATE ROLE "${restrictedRole}" NOLOGIN`);
    await db.query("ALTER TABLE public.users ENABLE ROW LEVEL SECURITY");
    await db.query(`GRANT USAGE ON SCHEMA public TO "${restrictedRole}"`);
    await db.query(`GRANT SELECT ON public.users TO "${restrictedRole}"`);
    await db.query(`GRANT SELECT, UPDATE ON public.certops_management_periods TO "${restrictedRole}"`);
    await db.query(`GRANT INSERT ON fake_period_update TO "${restrictedRole}"`);
    await db.query(`SET LOCAL ROLE "${restrictedRole}"`);
    assert.equal((await db.query("SELECT row_security_active('public.users') AS active")).rows[0].active, true);
    await rejectUpdate("INSERT INTO fake_period_update(id) VALUES($1)", [period]);
    await db.query("RESET ROLE");
    await db.query("ALTER TABLE public.users DISABLE ROW LEVEL SECURITY");
    // Even an actual FK action cannot change another historical field.
    await db.query(`CREATE FUNCTION pg_temp.alter_period_during_fk() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.created_by IS NULL THEN NEW.ended_reason := 'tampered'; END IF; RETURN NEW; END $$`);
    await db.query("CREATE TRIGGER aaa_period_tamper BEFORE UPDATE ON certops_management_periods FOR EACH ROW EXECUTE FUNCTION pg_temp.alter_period_during_fk()");
    await rejectUpdate("DELETE FROM users WHERE id=$1", [users[1].id]);
    await db.query("DROP TRIGGER aaa_period_tamper ON certops_management_periods");
    await db.query(`GRANT DELETE ON public.users TO "${restrictedRole}"`);
    await db.query(`SET LOCAL ROLE "${restrictedRole}"`);
    await db.query("DELETE FROM users WHERE id=$1", [users[1].id]);
    await db.query("RESET ROLE");
    const row=(await db.query("SELECT created_by,to_jsonb(p)-'created_by' AS state FROM certops_management_periods p WHERE id=$1", [period])).rows[0];
    assert.equal(row.created_by,null); assert.deepEqual(row.state,before);
    await rejectUpdate("UPDATE certops_management_periods SET ended_reason='rewritten' WHERE id=$1", [period]);
  } finally { await db.query("ROLLBACK"); db.release(); }
});
