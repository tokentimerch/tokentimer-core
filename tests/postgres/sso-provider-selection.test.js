"use strict";

const { after, before, it } = require("node:test");
const assert = require("node:assert/strict");
const { mkdtemp, rm, writeFile } = require("node:fs/promises");
const { tmpdir } = require("node:os");
const { join } = require("node:path");
const { randomUUID } = require("node:crypto");
const { Pool } = require("pg");
const { MIGRATION_V1_SQL, MIGRATION_V2_SQL } = require("../../apps/api/migrations/sso-schema.js");
const registry = require("../../apps/api/sso/provider-registry.js");
const { reconcileSsoProvidersFromEnv } = require("../../apps/api/sso/bootstrap-from-env.js");

const schema = "sso_provider_test_" + randomUUID().replaceAll("-", "");
const connection = {
  host: process.env.DB_HOST || "localhost",
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || "tokentimer",
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || "tokentimer",
};
const setup = new Pool(connection);
const pool = new Pool({ ...connection, options: `-c search_path=${schema},public` });
const oidc = { issuer: "https://idp.example.test", client_id: "tokentimer" };
const saml = { issuer: "tokentimer", entry_point: "https://idp.example.test/saml", cert: "fixture" };
const numericPeer = "2147483648";
let schemaCreated;

before(async () => {
  await setup.query(`CREATE SCHEMA ${schema}`);
  schemaCreated = true;
  await pool.query(`
    CREATE TABLE users (id INTEGER PRIMARY KEY, is_admin BOOLEAN, auth_method TEXT, password_hash TEXT, email_verified BOOLEAN, email TEXT, display_name TEXT, updated_at TIMESTAMPTZ);
    CREATE TABLE workspaces (id UUID PRIMARY KEY, created_by INTEGER REFERENCES users);
    CREATE TABLE workspace_memberships (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id INTEGER REFERENCES users,
      workspace_id UUID REFERENCES workspaces, role TEXT NOT NULL, invited_by INTEGER REFERENCES users,
      UNIQUE(user_id, workspace_id)
    );
    CREATE TABLE workspace_invitations (
      id UUID PRIMARY KEY, workspace_id UUID REFERENCES workspaces, role TEXT NOT NULL,
      email TEXT NOT NULL, accepted_at TIMESTAMPTZ
    );
    CREATE TABLE audit_events (
      id BIGSERIAL PRIMARY KEY, actor_user_id INTEGER REFERENCES users, subject_user_id INTEGER,
      action TEXT NOT NULL, target_type TEXT, target_id INTEGER, channel TEXT, metadata JSONB, workspace_id UUID
    );
    CREATE TABLE system_settings (id INTEGER PRIMARY KEY, sso_config_version BIGINT, updated_at TIMESTAMPTZ, sso_global_settings JSONB DEFAULT '{}');
    INSERT INTO system_settings VALUES (1, 1, NOW());
    INSERT INTO users (id, is_admin, auth_method, password_hash, email_verified, email, display_name)
    VALUES (1, TRUE, 'local', '$2b$12$' || repeat('A', 53), TRUE, 'admin@example.test', 'Local Admin');
    ${MIGRATION_V1_SQL}
    ${MIGRATION_V2_SQL}
  `);
});

after(async () => {
  await pool.end();
  try {
    if (schemaCreated) await setup.query(`DROP SCHEMA ${schema} CASCADE`);
  } finally {
    await setup.end();
  }
});

it("admits one provider total across concurrent OIDC and SAML activations", async () => {
  await registry.createProvider(pool, { type: "oidc", slug: "openid", config: oidc });
  await registry.createProvider(pool, { type: "oidc", slug: numericPeer, config: oidc });
  await registry.createProvider(pool, { type: "saml", slug: "assertion", config: saml });
  assert.deepEqual(await registry.enabledProviderRows(pool), []);
  const results = await Promise.allSettled([
    registry.updateProvider(pool, "openid", { enabled: true }),
    registry.updateProvider(pool, numericPeer, { enabled: true }),
    registry.updateProvider(pool, "assertion", { enabled: true }),
  ]);
  const conflicts = results.filter(result => result.status === "rejected");
  assert.equal(conflicts.length, 2);
  for (const { reason } of conflicts) {
    assert.equal(reason.code, "active_provider_exists");
    assert.match(reason.message, /one active SSO provider, either OIDC or SAML/);
  }
  assert.equal((await registry.enabledProviderRows(pool)).length, 1);
  await assert.rejects(
    registry.createProvider(pool, { type: "saml", slug: "second", enabled: true, config: saml }),
    { code: "active_provider_exists" },
  );
  assert.equal(await registry.getProvider(pool, "second"), null);
});

it("requires explicit selection and local recovery, retaining peer links and auditing the disable", async () => {
  await pool.query("UPDATE sso_providers SET enabled = TRUE");
  await pool.query(`
    INSERT INTO external_identities (user_id, provider_slug, protocol, subject_id)
    VALUES (1, 'openid', 'oidc', 'previous-oidc'), (1, $1, 'oidc', 'peer'),
           (1, 'assertion', 'saml', 'previous-saml')
  `, [numericPeer]);
  await assert.rejects(
    registry.updateProvider(pool, numericPeer, { enabled: false }),
    { code: "provider_selection_required" },
  );
  await registry.updateProvider(pool, "openid", { enabled: true, displayName: "Renamed" });
  assert.equal((await registry.enabledProviderRows(pool)).length, 3);
  assert.equal((await registry.getProvider(pool, "openid")).runtime.lastReason, "provider_selection_required");
  assert.equal((await registry.getProvider(pool, "assertion")).runtime.lastReason, "provider_selection_required");
  assert.equal((await registry.listProviders(pool)).every(row => row.runtime.lastReason === "provider_selection_required"), true);
  await pool.query("UPDATE users SET email_verified = FALSE WHERE id = 1");
  await assert.rejects(
    registry.updateProvider(pool, "openid", { enabled: true, selectForSignIn: true }),
    { code: "last_login_method" },
  );
  assert.equal((await registry.enabledProviderRows(pool)).length, 3);
  await pool.query("UPDATE users SET email_verified = TRUE WHERE id = 1");
  await registry.updateProvider(pool, "openid", { enabled: true, selectForSignIn: true }, { userId: 1 });
  assert.deepEqual(await registry.enabledProviderRows(pool), [{ slug: "openid", type: "oidc" }]);
  assert.equal((await registry.listProviders(pool)).length, 3);
  assert.equal((await pool.query("SELECT * FROM external_identities")).rowCount, 3);
  assert.deepEqual((await pool.query(
    `SELECT target_id, metadata->>'selected_provider_slug' AS selected,
             metadata->>'slug' AS slug, metadata->>'type' AS type
       FROM audit_events WHERE action = 'SSO_PROVIDER_DISABLED' AND metadata->>'slug' IN ($1, 'assertion')
       ORDER BY slug`,
    [numericPeer],
  )).rows, [
    { target_id: null, selected: "openid", slug: numericPeer, type: "oidc" },
    { target_id: null, selected: "openid", slug: "assertion", type: "saml" },
  ]);
});

it("reconciles the one-provider bootstrap policy and shares the API transaction lock", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "sso-provider-test-"));
  const manifestPath = join(dir, "providers.json");
  const previous = process.env.SSO_PROVIDERS_BOOTSTRAP_FILE;
  process.env.SSO_PROVIDERS_BOOTSTRAP_FILE = manifestPath;
  t.after(async () => {
    if (previous === undefined) delete process.env.SSO_PROVIDERS_BOOTSTRAP_FILE;
    else process.env.SSO_PROVIDERS_BOOTSTRAP_FILE = previous;
    await rm(dir, { recursive: true, force: true });
  });
  const entries = [
    { slug: "openid", type: "oidc", config: oidc },
    { slug: "assertion", type: "saml", config: saml },
  ];
  await writeFile(manifestPath, JSON.stringify({ providers: entries }));
  await reconcileSsoProvidersFromEnv(pool, { logger: {} });
  assert.deepEqual(await registry.enabledProviderRows(pool), []);
  const mixed = entries.map(entry => ({ ...entry, enabled: true }));
  await writeFile(manifestPath, JSON.stringify({ providers: mixed }));
  await assert.rejects(reconcileSsoProvidersFromEnv(pool, { logger: {} }), { code: "active_provider_exists" });
  assert.deepEqual(await registry.enabledProviderRows(pool), []);

  await pool.query("UPDATE sso_providers SET enabled = TRUE WHERE slug IN ('openid', 'assertion')");
  await writeFile(manifestPath, JSON.stringify({ providers: entries }));
  assert.deepEqual(await reconcileSsoProvidersFromEnv(pool, { logger: {} }), {
    skipped: true, reason: "provider_selection_required",
  });
  assert.equal((await registry.enabledProviderRows(pool)).length, 2);

  await writeFile(manifestPath, JSON.stringify({ providers: [entries[0], mixed[1]] }));
  await pool.query("UPDATE users SET email_verified = FALSE WHERE id = 1");
  assert.deepEqual(await reconcileSsoProvidersFromEnv(pool, { logger: {} }), {
    skipped: true, reason: "provider_selection_required",
  });
  assert.equal((await registry.enabledProviderRows(pool)).length, 2);
  await pool.query("UPDATE users SET email_verified = TRUE WHERE id = 1");
  await reconcileSsoProvidersFromEnv(pool, { logger: {} });
  assert.deepEqual(await registry.enabledProviderRows(pool), [{ slug: "assertion", type: "saml" }]);

  await registry.updateProvider(pool, "assertion", { enabled: false });
  await registry.createProvider(pool, { type: "oidc", slug: "api-oidc", config: oidc });
  const results = await Promise.allSettled([
    reconcileSsoProvidersFromEnv(pool, { logger: {} }),
    registry.updateProvider(pool, "api-oidc", { enabled: true }),
  ]);
  assert.equal(results.filter(result => result.status === "fulfilled").length, 1);
  assert.equal(results.find(result => result.status === "rejected").reason.code, "active_provider_exists");
  assert.equal((await registry.enabledProviderRows(pool)).length, 1);
  const [active] = await registry.enabledProviderRows(pool);
  await registry.updateProvider(pool, active.slug, { enabled: false });
});

it("keeps linked OIDC subjects bound to the original issuer", async () => {
  await assert.rejects(
    registry.updateProvider(pool, "openid", { config: { issuer: oidc.issuer + "/" } }),
    { code: "issuer_has_linked_accounts" },
  );
  assert.equal((await registry.getProvider(pool, "openid")).config.issuer, oidc.issuer);
});

it("returns committed provider changes with a single database connection", async () => {
  const single = new Pool({ ...connection, options: "-c search_path=" + schema + ",public", max: 1, connectionTimeoutMillis: 2000 });
  try {
    const created = await registry.createProvider(single, { type: "oidc", slug: "single", config: oidc });
    assert.equal(created.slug, "single");
    const updated = await registry.updateProvider(single, "single", { displayName: "Single connection" });
    assert.equal(updated.displayName, "Single connection");
  } finally {
    await single.end();
  }
});

it("recognizes an existing verified local administrator when bootstrap is disabled", async () => {
  const saved = process.env.DISABLE_ADMIN_BOOTSTRAP;
  process.env.DISABLE_ADMIN_BOOTSTRAP = "true";
  try {
    const { evaluateLoginReachability } = require("../../apps/api/sso/login-reachability.js");
    const options = { changingSlug: "openid", getRuntimeStatus: () => ({}) };
    assert.equal((await evaluateLoginReachability(pool, options)).hasUsableLocalAdmin, true);
    await pool.query("UPDATE users SET email_verified = FALSE WHERE id = 1");
    assert.equal((await evaluateLoginReachability(pool, options)).hasUsableLocalAdmin, false);
    await pool.query("UPDATE users SET auth_method = 'sso' WHERE id = 1");
    assert.equal((await evaluateLoginReachability(pool, options)).hasUsableLocalAdmin, true);
    await pool.query("UPDATE users SET auth_method = 'local', email_verified = TRUE WHERE id = 1");
    assert.equal((await evaluateLoginReachability(pool, { ...options, localAuthEnabled: false })).hasUsableLocalAdmin, false);
  } finally {
    if (saved === undefined) delete process.env.DISABLE_ADMIN_BOOTSTRAP;
    else process.env.DISABLE_ADMIN_BOOTSTRAP = saved;
  }
});

it("commits concurrent SSO policy edits and versions from locked settings snapshots", async () => {
  const settings = require("../../apps/api/services/systemSettings.js");
  const { saveVersionedSsoSettings, getSsoConfigVersion } = require("../../apps/api/sso/sso-config-version.js");
  const { SSO_GLOBAL_ENV_MAP } = require("../../apps/api/sso/sso-global-settings-schema.js");
  settings.registerJsonColumn("sso_global_settings", { envMap: SSO_GLOBAL_ENV_MAP });
  const save = (values) => saveVersionedSsoSettings(settings.saveJsonColumn, pool, "sso_global_settings", values, null, { strictKeys: true });
  const before = await getSsoConfigVersion(pool);
  await Promise.all([save({ strict_membership_sync: true }), save({ idp_http_timeout_ms: 19000 })]);
  assert.deepEqual((await pool.query("SELECT sso_global_settings FROM system_settings")).rows[0].sso_global_settings,
    { strict_membership_sync: true, idp_http_timeout_ms: 19000 });
  assert.equal(await getSsoConfigVersion(pool), before + 2);
  await assert.rejects(save({ unknown: true }), { code: "JSON_COLUMN_UNKNOWN_KEYS" });
  assert.equal(await getSsoConfigVersion(pool), before + 2);
});

it("consumes each pending SSO invitation once and honors changes before acceptance", async () => {
  const { acceptPendingInvitations } = require("../../apps/api/services/workspace.js");
  const workspace = randomUUID();
  await pool.query("INSERT INTO workspaces VALUES($1, 1)", [workspace]);
  await pool.query("INSERT INTO users(id) VALUES(2), (3)");
  const email = "invited@example.test";
  const options = { sso: true, verifiedEmail: email };
  async function invite() {
    const id = randomUUID();
    await pool.query("INSERT INTO workspace_invitations VALUES($1,$2,'viewer',$3,NULL)", [id, workspace, email]);
    return id;
  }

  // Synchronize the two lookups before either login can claim the invitation.
  const bothRead = Promise.withResolvers();
  let readers = 0;
  const concurrent = {
    async query(sql, params) {
      const result = await pool.query(sql, params);
      if (sql.startsWith("SELECT id, email")) {
        if (++readers === 2) bothRead.resolve();
        await bothRead.promise;
      }
      return result;
    },
  };
  await invite();
  const claims = await Promise.all([2, 3].map(userId => acceptPendingInvitations(concurrent, userId, email, options)));
  assert.equal(claims.flat().length, 1);
  assert.equal((await pool.query("SELECT user_id FROM workspace_memberships WHERE workspace_id=$1", [workspace])).rowCount, 1);

  for (const replacementRole of ["workspace_manager", null]) {
    const id = await invite();
    const changed = {
      async query(sql, params) {
        const result = await pool.query(sql, params);
        if (sql.startsWith("SELECT id, email")) {
          if (replacementRole) await pool.query("UPDATE workspace_invitations SET role=$2 WHERE id=$1", [id, replacementRole]);
          else await pool.query("DELETE FROM workspace_invitations WHERE id=$1", [id]);
        }
        return result;
      },
    };
    const accepted = await acceptPendingInvitations(changed, 2, email, options);
    assert.deepEqual(accepted, replacementRole ? [{ workspace_id: workspace, role: replacementRole }] : []);
  }
});

function adminProviderRoutes(t, query = pool.query.bind(pool)) {
  const express = require("node:module").createRequire(require.resolve("../../apps/api/package.json"))("express");
  const apiPool = require("../../apps/api/db/database").pool;
  t.mock.method(apiPool, "connect", () => pool.connect());
  t.mock.method(apiPool, "query", query);
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.isAuthenticated = () => true;
    req.user = { id: 1, auth_method: "local", email_verified: true };
    next();
  });
  app.use(require("../../apps/api/routes/sso-providers"));
  return require("supertest")(app);
}

function useTestKeyring(t) {
  const previous = process.env.SSO_SECRETS_KEYRING;
  const previousFile = process.env.SSO_SECRETS_KEYRING_FILE;
  delete process.env.SSO_SECRETS_KEYRING_FILE;
  process.env.SSO_SECRETS_KEYRING = JSON.stringify({ primary: "test", keys: { test: Buffer.alloc(32, 1).toString("base64") } });
  const { _resetKeyringForTests } = require("../../apps/api/sso/secrets-keyring");
  _resetKeyringForTests(null);
  t.after(() => {
    if (previous === undefined) delete process.env.SSO_SECRETS_KEYRING;
    else process.env.SSO_SECRETS_KEYRING = previous;
    if (previousFile !== undefined) process.env.SSO_SECRETS_KEYRING_FILE = previousFile;
    _resetKeyringForTests(null);
  });
}

const providersPath = "/api/admin/sso/providers";

it("audits provider administration with a numeric slug as metadata", async (t) => {
  useTestKeyring(t);
  const api = adminProviderRoutes(t);
  const slug = "2147483649";
  const path = providersPath + "/" + slug;
  await api.post(providersPath).send({ slug, type: "saml", config: saml }).expect(201);
  await api.put(path).send({ displayName: "Numeric provider" }).expect(200);
  const tested = await api.post(path + "/test").expect(200);
  assert.ok(tested.body.checks.length > 0);
  await api.delete(path).expect(200);

  const { rows } = await pool.query(
    `SELECT action, target_id FROM audit_events
       WHERE target_type = 'sso_provider' AND metadata->>'slug' = $1 ORDER BY id`,
    [slug],
  );
  assert.deepEqual(rows, ["CREATED", "UPDATED", "TESTED", "DELETED"].map(
    (action) => ({ action: "SSO_PROVIDER_" + action, target_id: null }),
  ));
});

async function mutationSnapshot(slug) {
  const { rows } = await pool.query(`
    SELECT (SELECT to_jsonb(p) FROM sso_providers p WHERE p.slug = $1) AS provider,
           (SELECT jsonb_agg(to_jsonb(s) ORDER BY s.secret_name) FROM sso_provider_secrets s
              JOIN sso_providers p ON p.id = s.provider_id WHERE p.slug = $1) AS secrets,
           (SELECT jsonb_agg(to_jsonb(c) ORDER BY c.cache_key) FROM saml_request_cache c WHERE c.provider_slug = $1) AS cache,
           (SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM audit_events a WHERE a.metadata->>'slug' = $1) AS audits,
           sso_config_version FROM system_settings WHERE id = 1`, [slug]);
  return rows[0];
}

it("rolls back provider, secrets, cache, config version and audit events together", async (t) => {
  useTestKeyring(t);
  const api = adminProviderRoutes(t);
  const slug = "audit-rollback";
  const path = providersPath + "/" + slug;
  const create = { slug, type: "oidc", config: oidc };
  const secret = { client_secret: "test-secret" };
  await pool.query("UPDATE sso_providers SET enabled = FALSE");

  async function rejectedAudit(action, send) {
    const beforeMutation = await mutationSnapshot(slug);
    await pool.query(`ALTER TABLE audit_events ADD CONSTRAINT test_reject_audit CHECK (action <> '${action}') NOT VALID`);
    try {
      const response = await send().expect(500);
      assert.deepEqual(response.body, { error: "SSO request failed." });
      assert.deepEqual(await mutationSnapshot(slug), beforeMutation);
    } finally {
      await pool.query("ALTER TABLE audit_events DROP CONSTRAINT test_reject_audit");
    }
  }

  await rejectedAudit("SSO_PROVIDER_CREATED", () => api.post(providersPath).send(create));
  await rejectedAudit("SSO_PROVIDER_SECRET_SET", () => api.post(providersPath).send({ ...create, secrets: secret }));
  await api.post(providersPath).send({ ...create, enabled: true, secrets: secret }).expect(201);
  await pool.query("INSERT INTO saml_request_cache (provider_slug,cache_key,cache_value) VALUES ($1,'cache-key','test-value')", [slug]);
  await rejectedAudit("SSO_PROVIDER_UPDATED", () => api.put(path).send({ displayName: "Updated" }));
  await rejectedAudit("SSO_PROVIDER_DISABLED", () => api.put(path).send({ enabled: false }));
  await rejectedAudit("SSO_PROVIDER_SECRET_SET", () => api.put(path).send({ secrets: { client_secret: "replacement" } }));
  await rejectedAudit("SSO_PROVIDER_SECRET_CLEARED", () => api.put(path).send({ clearSecrets: ["client_secret"] }));
  await rejectedAudit("SSO_PROVIDER_DELETED", () => api.delete(path));
  await api.delete(path).expect(200);
});

it("previews and retires an in-use provider with explicit cleanup and an independent local admin", async (t) => {
  const api = adminProviderRoutes(t);
  const slug = "retire";
  const path = providersPath + "/" + slug;
  const workspace = randomUUID();
  await registry.createProvider(pool, { type: "oidc", slug, config: oidc });
  await pool.query("INSERT INTO workspaces VALUES ($1, 1)", [workspace]);
  await pool.query(`
    INSERT INTO users (id, is_admin, auth_method, password_hash, email_verified, email)
    VALUES (4, TRUE, 'sso', '$2b$12$' || repeat('A', 53), TRUE, 'sso-admin@example.test')
  `);
  await pool.query("INSERT INTO sso_system_admin_grants (user_id, provider_slug) VALUES (4, $1)", [slug]);
  await pool.query("INSERT INTO external_identities (user_id, provider_slug, protocol, subject_id) VALUES (4, $1, 'oidc', 'subject')", [slug]);
  await pool.query(`
    INSERT INTO workspace_memberships (user_id, workspace_id, role, source, source_provider_slug)
    VALUES (4, $1, 'viewer', 'sso', $2)
  `, [workspace, slug]);
  const preview = await api.post(path + "/impact").send({ delete: true }).expect(200);
  assert.deepEqual(preview.body.dependency_counts, {
    identities_count: 1, memberships_count: 1, group_mappings_count: 0, admin_grants_count: 1,
  });
  assert.equal(preview.body.has_usable_local_admin, true);
  await api.delete(path).expect(409);
  await api.delete(path).query({ confirmRetirement: "true", membershipPolicy: "convert-to-manual" }).expect(409);
  const confirm = { confirmRetirement: "true", membershipPolicy: "convert-to-manual", identityPolicy: "archive" };
  await pool.query("UPDATE users SET email_verified = FALSE WHERE id = 1");
  const blocked = await api.delete(path).query(confirm).expect(409);
  assert.equal(blocked.body.code, "last_login_method");
  assert.equal((await registry.countDependencies(pool, slug)).identities_count, 1);
  await pool.query("UPDATE users SET email_verified = TRUE WHERE id = 1");
  await api.delete(path).query(confirm).expect(200);
  assert.equal(await registry.getProvider(pool, slug), null);
  assert.equal((await pool.query("SELECT is_admin FROM users WHERE id = 4")).rows[0].is_admin, false);
  assert.deepEqual((await pool.query("SELECT source, source_provider_slug FROM workspace_memberships WHERE user_id = 4")).rows,
    [{ source: "manual", source_provider_slug: null }]);
  assert.equal((await pool.query("SELECT 1 FROM sso_deleted_external_identities_archive WHERE provider_slug = $1 AND deleted_by = 1", [slug])).rowCount, 1);
});

it("returns the committed provider and bounded warnings when post-commit status is unavailable", async (t) => {
  useTestKeyring(t);
  let failQuery = "SELECT enabled FROM sso_providers";
  const api = adminProviderRoutes(t, (sql, params) => {
    if (failQuery && sql.includes(failQuery)) throw new Error("private diagnostic text");
    return pool.query(sql, params);
  });
  const slug = "audit-result";
  const path = providersPath + "/" + slug;
  const secret = "fixture-password";
  const status = require("../../apps/api/sso/sso-runtime-status");
  status.setProviderRuntimeStatus(slug, { registered: true, appliedConfigVersion: 1 });
  t.after(() => status.removeProviderRuntimeStatus(slug));
  function checkWarning(response) {
    assert.deepEqual(response.body.sso_reload_warnings.map((warning) => warning.code), ["reload_failed"]);
    assert.doesNotMatch(JSON.stringify(response.body), /private diagnostic text|fixture-password/);
    if (response.body.runtime) {
      assert.equal(response.body.runtime.signInReady, false);
      assert.equal(response.body.runtime.appliedConfigVersion, null);
    }
  }
  const created = await api.post(providersPath).send({ slug, type: "oidc", enabled: true, config: oidc, secrets: { client_secret: secret } }).expect(201);
  checkWarning(created);
  assert.deepEqual(created.body.secrets_set, ["client_secret"]);
  const duplicate = await api.post(providersPath).send({ slug, type: "oidc", config: oidc }).expect(409);
  assert.equal(duplicate.body.code, "23505");

  failQuery = "FROM sso_providers WHERE slug = $1";
  const updated = await api.put(path).send({ displayName: "Renamed provider" }).expect(200);
  checkWarning(updated);
  assert.equal(updated.body.displayName, "Renamed provider");

  failQuery = null;
  const disabled = await api.put(path).send({ enabled: false, clearSecrets: ["client_secret", "absent"] }).expect(200);
  assert.deepEqual(disabled.body.secrets_set, []);
  assert.equal(disabled.body.sso_reload_warnings, undefined);

  const reload = require("../../apps/api/sso/reload-strategies");
  reload.configureSsoStrategyReload({ pool: { query: async () => { throw new Error("private diagnostic text"); } } });
  t.after(() => reload._resetReloadContextForTests());
  const removed = await api.delete(path).expect(200);
  checkWarning(removed);
  assert.equal(removed.body.ok, true);
  const final = await mutationSnapshot(slug);
  assert.equal(final.provider, null);
  assert.deepEqual(final.audits.map((event) => event.action), [
    "SSO_PROVIDER_CREATED", "SSO_PROVIDER_SECRET_SET", "SSO_PROVIDER_UPDATED", "SSO_PROVIDER_DISABLED",
    "SSO_PROVIDER_SECRET_CLEARED", "SSO_PROVIDER_DELETED",
  ]);
  assert.deepEqual(final.audits.filter((event) => event.action.startsWith("SSO_PROVIDER_SECRET_"))
    .map((event) => event.metadata.secret_name), ["client_secret", "client_secret"]);
  assert.doesNotMatch(JSON.stringify(final.audits), /fixture-password|private diagnostic text/);
});
