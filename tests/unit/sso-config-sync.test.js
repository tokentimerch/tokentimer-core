"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { setImmediate } = require("node:timers/promises");
const sync = require("../../apps/api/sso/sso-config-sync.js");
const reload = require("../../apps/api/sso/reload-strategies.js");
const statuses = require("../../apps/api/sso/sso-runtime-status.js");
const { resolveProviderSecurityConfig } = require("../../apps/api/sso/sso-global-settings.js");

function fixture(t, setupOidcStrategy, providers) {
  const db = { version: 3, versionReads: 0, allowAutoLink: true };
  const pool = {
    async query(sql) {
      if (sql.includes("sso_config_version")) {
        db.versionReads++;
        return { rows: [{ v: db.version }] };
      }
      assert.ok(sql.includes("FROM sso_providers"));
      return { rows: providers.map((slug) => ({ slug, enabled: true, type: "oidc" })) };
    },
  };
  sync.markLocalSsoConfigVersion(2);
  reload.configureSsoStrategyReload({
    pool,
    systemSettings: {
      getJsonSettingValue: assert.fail,
      getFreshJsonSettingValues: async () => ({ allow_auto_link_local_accounts: db.allowAutoLink }),
    },
    setupOidcStrategy,
    setupSamlStrategy: async () => ({ registered: false, reason: "not_configured" }),
  });
  t.after(() => {
    reload._resetReloadContextForTests();
    statuses._resetForTests();
  });
  return db;
}

function setReady(slug, registered) {
  statuses.setProviderRuntimeStatus(slug, { type: "oidc", registered, signInReady: registered });
}

async function auth(slug) {
  const res = {
    status(code) { this.code = code; return this; },
    json() { return this.code; },
  };
  return sync.ssoConfigSyncMiddleware()({ params: { 0: slug } }, res, () => 200);
}

test("requests observing a newer policy during discovery share one follow-up reload", async (t) => {
  const entered = Promise.withResolvers();
  const release = Promise.withResolvers();
  const policies = [];
  const db = fixture(t, async () => {
    policies.push(resolveProviderSecurityConfig({}).allowAutoLinkLocalAccounts);
    if (policies.length === 1) {
      entered.resolve();
      await release.promise;
    }
    setReady("main", true);
    return { registered: true };
  }, ["main"]);

  const previous = sync.reloadAllSsoStrategiesIfStale();
  await entered.promise;
  db.version = 4;
  db.allowAutoLink = false;
  const first = auth("main");
  const second = auth("main");
  await setImmediate();
  assert.equal(sync.getObservedSsoConfigVersion(), 4);
  assert.deepEqual(policies, [true]);
  release.resolve();
  assert.deepEqual(await Promise.all([previous, first, second]), [true, 200, 200]);
  assert.deepEqual(policies, [true, false]);
  assert.equal(statuses.getProviderRuntimeStatus("main").appliedConfigVersion, 4);
  assert.equal(db.versionReads, 3);
});

test("a failed provider closes its route while a current sibling can authenticate", async (t) => {
  let attempts = 0;
  const db = fixture(t, async () => {
    attempts++;
    setReady("healthy", true);
    setReady("invalid", false);
    return { registered: true };
  }, ["healthy", "invalid"]);

  assert.equal(await auth("healthy"), 200);
  assert.equal(await auth("invalid"), 503);
  assert.equal(db.versionReads, 2);
  assert.equal(attempts, 2);
});

test("failure to read the current policy blocks authentication for a previously ready provider", async (t) => {
  fixture(t, async () => {
    setReady("main", true);
    return { registered: true };
  }, ["main"]);
  const ctx = reload.__getReloadContextForSync();
  await auth("main");
  ctx.pool.query = async () => { throw new Error("database unavailable"); };
  assert.equal(await auth("main"), 503);
});
