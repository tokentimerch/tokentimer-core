/**
 * Contact-group migrations 52-54 - upgrade path on a populated, messy
 * 0.15.0 database.
 *
 * Unlike a fresh-install test (empty schema) or an upgrade test seeded with
 * already-clean join rows, this stops at migration 51 (the last 0.15.0
 * schema), plants the shapes 0.15.0 actually stored, then applies 52, 53,
 * and 54 in order:
 *   - tokens.contact_group_id / certops_agents.contact_group_id as the only
 *     assignment (no join tables yet)
 *   - matching workspace_settings.contact_groups JSON (free-text ids, not
 *     an FK)
 *   - empty / whitespace / NULL singular values that must not become join
 *     rows
 *   - after 52+53, a 0.15.0 writer that updates the singular column and
 *     never touches the join (stale join A, singular C)
 *
 * Migration 54 exists to repair that last case before join membership is
 * authoritative. 0.15.0 never writes token_contact_groups /
 * certops_agent_contact_groups; a leftover 0.15.0 writer after 54 leaves
 * the same drift, which is why mixed fleets are unsupported.
 */

const { expect } = require("chai");
const { Client, Pool } = require("pg");
const path = require("path");

const DB_HOST = process.env.DB_HOST || "localhost";
const DB_PORT = Number(process.env.DB_PORT || process.env.TT_TEST_DB_PORT || 5432);
const DB_USER = process.env.DB_USER || "tokentimer";
const DB_PASSWORD = process.env.DB_PASSWORD || "password";
const ADMIN_DB_NAME = process.env.DB_NAME || "tokentimer";
const UPGRADE_DB_NAME = "tokentimer_contact_groups_52_54_upgrade_test";

const GROUP_A = "A";
const GROUP_C = "C";

const { migrations } = require(
  path.join(__dirname, "..", "..", "apps", "api", "migrations", "migrate.js"),
);

const MIGRATION_52 = migrations.find((m) => m.version === 52);
const MIGRATION_53 = migrations.find((m) => m.version === 53);
const MIGRATION_54 = migrations.find((m) => m.version === 54);

async function adminClient() {
  const client = new Client({
    user: DB_USER,
    host: DB_HOST,
    database: ADMIN_DB_NAME,
    password: DB_PASSWORD,
    port: DB_PORT,
  });
  await client.connect();
  return client;
}

async function dropDatabase(name) {
  const admin = await adminClient();
  try {
    await admin.query(
      `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
      [name],
    );
    await admin.query(`DROP DATABASE IF EXISTS ${name}`);
  } finally {
    await admin.end();
  }
}

async function applyMigrations(client, list) {
  for (const migration of list) {
    await client.query("BEGIN");
    try {
      await client.query(migration.sql);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw new Error(
        `Migration ${migration.version} (${migration.name}) failed: ${err.message}`,
      );
    }
  }
}

describe("Contact-group migrations 52-54 - upgrade path on a populated, messy 0.15.0 database", function () {
  this.timeout(180000);

  let pool;
  let workspaceId;
  let stableTokenId;
  let driftTokenId;
  let emptyTokenId;
  let whitespaceTokenId;
  let nullTokenId;
  let stableAgentId;
  let driftAgentId;
  let emptyAgentId;
  let assignedBootstrapId;
  let nullBootstrapId;

  async function tokenJoinIds(tokenId) {
    const { rows } = await pool.query(
      `SELECT contact_group_id
         FROM token_contact_groups
        WHERE token_id = $1
        ORDER BY contact_group_id`,
      [tokenId],
    );
    return rows.map((row) => row.contact_group_id);
  }

  async function agentJoinIds(agentId) {
    const { rows } = await pool.query(
      `SELECT contact_group_id
         FROM certops_agent_contact_groups
        WHERE agent_id = $1
        ORDER BY contact_group_id`,
      [agentId],
    );
    return rows.map((row) => row.contact_group_id);
  }

  async function bootstrapIds(bootstrapId) {
    const { rows } = await pool.query(
      `SELECT contact_group_id, contact_group_ids
         FROM certops_agent_bootstrap_tokens
        WHERE id = $1`,
      [bootstrapId],
    );
    return rows[0];
  }

  before(async function () {
    expect(MIGRATION_52, "migration 52 must exist").to.not.equal(undefined);
    expect(MIGRATION_53, "migration 53 must exist").to.not.equal(undefined);
    expect(MIGRATION_54, "migration 54 must exist").to.not.equal(undefined);
    expect(MIGRATION_52.name).to.equal("multi_contact_groups_per_asset");
    expect(MIGRATION_53.name).to.equal("bootstrap_contact_group_ids");
    expect(MIGRATION_54.name).to.equal("rebuild_contact_group_join_from_singular");

    await dropDatabase(UPGRADE_DB_NAME);
    const admin = await adminClient();
    try {
      await admin.query(`CREATE DATABASE ${UPGRADE_DB_NAME}`);
    } finally {
      await admin.end();
    }

    pool = new Pool({
      user: DB_USER,
      host: DB_HOST,
      database: UPGRADE_DB_NAME,
      password: DB_PASSWORD,
      port: DB_PORT,
      max: 4,
    });

    const client = await pool.connect();
    try {
      const pre52 = migrations.filter((m) => m.version <= 51);
      expect(pre52.length).to.be.greaterThan(0);
      expect(pre52.some((m) => m.version === 51)).to.equal(true);
      expect(pre52.some((m) => m.version === 52)).to.equal(false);

      await applyMigrations(client, pre52);

      const userResult = await client.query(
        `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
         VALUES ('upgrade-52-54-test@example.com', 'upgrade-52-54-test@example.com', 'Upgrade 52-54 Test User', 'x', 'local', TRUE)
         RETURNING id`,
      );
      const userId = userResult.rows[0].id;

      const ws = await client.query(
        `INSERT INTO workspaces (id, name, created_by, plan)
         VALUES (gen_random_uuid(), 'Upgrade 52-54 Test WS', $1, 'oss')
         RETURNING id`,
        [userId],
      );
      workspaceId = ws.rows[0].id;

      // 0.15.0 stored contact groups only as workspace JSON plus a singular
      // id on the asset. Migrations 52-54 do not read this JSON; it is here
      // so the seed matches a real 0.15.0 workspace.
      await client.query(
        `INSERT INTO workspace_settings (workspace_id, contact_groups, default_contact_group_id)
         VALUES ($1, $2::jsonb, $3)`,
        [
          workspaceId,
          JSON.stringify([
            { id: GROUP_A, name: "Group A", emails: ["a@example.com"] },
            { id: GROUP_C, name: "Group C", emails: ["c@example.com"] },
          ]),
          GROUP_A,
        ],
      );

      const tokenRows = await client.query(
        `INSERT INTO tokens
           (user_id, workspace_id, created_by, name, expiration, type, category, contact_group_id)
         VALUES
           ($1, $2, $1, 'stable assigned token', CURRENT_DATE + 90, 'ssl_cert', 'cert', $3),
           ($1, $2, $1, 'drift assigned token',  CURRENT_DATE + 90, 'ssl_cert', 'cert', $3),
           ($1, $2, $1, 'empty group token',     CURRENT_DATE + 90, 'ssl_cert', 'cert', ''),
           ($1, $2, $1, 'whitespace group token',CURRENT_DATE + 90, 'ssl_cert', 'cert', '   '),
           ($1, $2, $1, 'null group token',      CURRENT_DATE + 90, 'ssl_cert', 'cert', NULL)
         RETURNING id, name`,
        [userId, workspaceId, GROUP_A],
      );
      const tokenByName = new Map(tokenRows.rows.map((row) => [row.name, row.id]));
      stableTokenId = tokenByName.get("stable assigned token");
      driftTokenId = tokenByName.get("drift assigned token");
      emptyTokenId = tokenByName.get("empty group token");
      whitespaceTokenId = tokenByName.get("whitespace group token");
      nullTokenId = tokenByName.get("null group token");

      const assignedBootstrap = await client.query(
        `INSERT INTO certops_agent_bootstrap_tokens
           (workspace_id, name, token_prefix, token_hash, expires_at, contact_group_id)
         VALUES
           ($1, 'assigned bootstrap', 'ttboot_0000000000000052', repeat('a', 64), NOW() + INTERVAL '7 days', $2)
         RETURNING id`,
        [workspaceId, GROUP_A],
      );
      assignedBootstrapId = assignedBootstrap.rows[0].id;

      const nullBootstrap = await client.query(
        `INSERT INTO certops_agent_bootstrap_tokens
           (workspace_id, name, token_prefix, token_hash, expires_at, contact_group_id)
         VALUES
           ($1, 'null bootstrap', 'ttboot_0000000000000053', repeat('c', 64), NOW() + INTERVAL '7 days', NULL)
         RETURNING id`,
        [workspaceId],
      );
      nullBootstrapId = nullBootstrap.rows[0].id;

      const stableAgent = await client.query(
        `INSERT INTO certops_agents
           (workspace_id, agent_id, agent_version, protocol_version, credential_prefix, credential_hash, bootstrap_token_id, contact_group_id)
         VALUES
           ($1, 'upgrade-52-54-agent-stable', '1.0.0', '1.0.0', 'ttagent_0000000000000052', repeat('b', 64), $2, $3)
         RETURNING id`,
        [workspaceId, assignedBootstrapId, GROUP_A],
      );
      stableAgentId = stableAgent.rows[0].id;

      const driftAgent = await client.query(
        `INSERT INTO certops_agents
           (workspace_id, agent_id, agent_version, protocol_version, credential_prefix, credential_hash, bootstrap_token_id, contact_group_id)
         VALUES
           ($1, 'upgrade-52-54-agent-drift', '1.0.0', '1.0.0', 'ttagent_0000000000000053', repeat('d', 64), $2, $3)
         RETURNING id`,
        [workspaceId, assignedBootstrapId, GROUP_A],
      );
      driftAgentId = driftAgent.rows[0].id;

      const emptyAgent = await client.query(
        `INSERT INTO certops_agents
           (workspace_id, agent_id, agent_version, protocol_version, credential_prefix, credential_hash, bootstrap_token_id, contact_group_id)
         VALUES
           ($1, 'upgrade-52-54-agent-empty', '1.0.0', '1.0.0', 'ttagent_0000000000000054', repeat('e', 64), $2, '')
         RETURNING id`,
        [workspaceId, nullBootstrapId],
      );
      emptyAgentId = emptyAgent.rows[0].id;
    } finally {
      client.release();
    }
  });

  after(async function () {
    if (pool) await pool.end();
    await dropDatabase(UPGRADE_DB_NAME);
  });

  it("backfills join rows from non-empty singular assignments (migration 52)", async () => {
    const client = await pool.connect();
    try {
      await applyMigrations(client, [MIGRATION_52]);
    } finally {
      client.release();
    }

    expect(await tokenJoinIds(stableTokenId)).to.deep.equal([GROUP_A]);
    expect(await tokenJoinIds(driftTokenId)).to.deep.equal([GROUP_A]);
    expect(await tokenJoinIds(emptyTokenId)).to.deep.equal([]);
    expect(await tokenJoinIds(whitespaceTokenId)).to.deep.equal([]);
    expect(await tokenJoinIds(nullTokenId)).to.deep.equal([]);

    expect(await agentJoinIds(stableAgentId)).to.deep.equal([GROUP_A]);
    expect(await agentJoinIds(driftAgentId)).to.deep.equal([GROUP_A]);
    expect(await agentJoinIds(emptyAgentId)).to.deep.equal([]);
  });

  it("backfills bootstrap contact_group_ids from the singular id (migration 53)", async () => {
    const client = await pool.connect();
    try {
      await applyMigrations(client, [MIGRATION_53]);
    } finally {
      client.release();
    }

    const assigned = await bootstrapIds(assignedBootstrapId);
    expect(assigned.contact_group_id).to.equal(GROUP_A);
    expect(assigned.contact_group_ids).to.deep.equal([GROUP_A]);

    const empty = await bootstrapIds(nullBootstrapId);
    expect(empty.contact_group_id).to.equal(null);
    expect(empty.contact_group_ids).to.deep.equal([]);
  });

  it("rebuilds join membership from the singular column and overwrites bootstrap JSONB (migration 54)", async () => {
    // 0.15.0 writer: update singular only. Join still has A.
    await pool.query(
      `UPDATE tokens SET contact_group_id = $1, updated_at = NOW() WHERE id = $2`,
      [GROUP_C, driftTokenId],
    );
    await pool.query(
      `UPDATE certops_agents SET contact_group_id = $1, updated_at = NOW() WHERE id = $2`,
      [GROUP_C, driftAgentId],
    );
    expect(await tokenJoinIds(driftTokenId)).to.deep.equal([GROUP_A]);
    expect(await agentJoinIds(driftAgentId)).to.deep.equal([GROUP_A]);

    // Prove 54 overwrites JSONB from singular even when the array already
    // drifted (53 only fills empty arrays).
    await pool.query(
      `UPDATE certops_agent_bootstrap_tokens
          SET contact_group_ids = '["stale"]'::jsonb
        WHERE id = $1`,
      [assignedBootstrapId],
    );

    const client = await pool.connect();
    try {
      await applyMigrations(client, [MIGRATION_54]);
    } finally {
      client.release();
    }

    expect(await tokenJoinIds(stableTokenId)).to.deep.equal([GROUP_A]);
    expect(await tokenJoinIds(driftTokenId)).to.deep.equal([GROUP_C]);
    expect(await tokenJoinIds(emptyTokenId)).to.deep.equal([]);
    expect(await tokenJoinIds(whitespaceTokenId)).to.deep.equal([]);
    expect(await tokenJoinIds(nullTokenId)).to.deep.equal([]);

    expect(await agentJoinIds(stableAgentId)).to.deep.equal([GROUP_A]);
    expect(await agentJoinIds(driftAgentId)).to.deep.equal([GROUP_C]);
    expect(await agentJoinIds(emptyAgentId)).to.deep.equal([]);

    const assigned = await bootstrapIds(assignedBootstrapId);
    expect(assigned.contact_group_id).to.equal(GROUP_A);
    expect(assigned.contact_group_ids).to.deep.equal([GROUP_A]);

    const empty = await bootstrapIds(nullBootstrapId);
    expect(empty.contact_group_ids).to.deep.equal([]);

    const tokenDupes = await pool.query(
      `SELECT token_id, COUNT(*)::int AS n
         FROM token_contact_groups
        WHERE workspace_id = $1
        GROUP BY token_id
       HAVING COUNT(*) > 1`,
      [workspaceId],
    );
    expect(tokenDupes.rows).to.have.length(0);

    const agentDupes = await pool.query(
      `SELECT agent_id, COUNT(*)::int AS n
         FROM certops_agent_contact_groups
        WHERE workspace_id = $1
        GROUP BY agent_id
       HAVING COUNT(*) > 1`,
      [workspaceId],
    );
    expect(agentDupes.rows).to.have.length(0);

    const leftoverA = await pool.query(
      `SELECT 1
         FROM token_contact_groups
        WHERE token_id = $1 AND contact_group_id = $2`,
      [driftTokenId, GROUP_A],
    );
    expect(leftoverA.rows).to.have.length(0);
  });
});
