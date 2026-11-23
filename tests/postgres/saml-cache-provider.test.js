"use strict";

const { after, before, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { pool } = require("../../apps/api/db/database.js");
const {
  createPostgresSamlCacheProvider,
  bindSamlCacheToBrowser,
  startSamlCacheCleanupTimer,
  _stopSamlCacheCleanupTimerForTests,
} = require("../../apps/api/sso/saml-cache-provider.js");

describe("SAML request cache on PostgreSQL", () => {
  const schema = "saml_cache_test_" + randomUUID().replaceAll("-", "");
  const lockKey = 867530901;
  let schemaCreated = false;
  let cacheConnection;

  before(async () => {
    await pool.query(`CREATE SCHEMA ${schema}`);
    schemaCreated = true;
    cacheConnection = await pool.connect();
    await cacheConnection.query(`SET search_path TO ${schema}`);
    await cacheConnection.query(`CREATE TABLE saml_request_cache (
      provider_slug TEXT NOT NULL,
      cache_key TEXT NOT NULL,
      cache_value TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (provider_slug, cache_key)
    )`);
  });

  after(async () => {
    _stopSamlCacheCleanupTimerForTests();
    cacheConnection?.release(true);
    try {
      if (schemaCreated) await pool.query(`DROP SCHEMA ${schema} CASCADE`);
    } finally {
      await pool.end();
    }
  });

  it("keeps identical request IDs isolated and ignores expired requests", async () => {
    const first = createPostgresSamlCacheProvider(cacheConnection, { providerSlug: "first", ttlSec: 60 });
    const second = createPostgresSamlCacheProvider(cacheConnection, { providerSlug: "second", ttlSec: 60 });

    await first.saveAsync("same-request", "first response");
    await second.saveAsync("same-request", "second response");
    assert.equal(await first.removeAsync("same-request"), "first response");
    assert.equal(await first.getAsync("same-request"), null);
    assert.equal(await second.getAsync("same-request"), "second response");

    await cacheConnection.query(`UPDATE saml_request_cache
      SET created_at = NOW() - INTERVAL '61 seconds'
      WHERE provider_slug = 'second' AND cache_key = 'same-request'`);
    assert.equal(await second.getAsync("same-request"), null);
    assert.equal(await second.consumeAsync("same-request"), null);
    await first.saveAsync("new-request", "new response");
    const remaining = await cacheConnection.query("SELECT cache_key FROM saml_request_cache WHERE provider_slug = 'second'");
    assert.deepEqual(remaining.rows, [{ cache_key: "same-request" }]);
  });

  it("consumes a browser's pending request once across independent connections", async () => {
    const secondConnection = await pool.connect();
    try {
      await secondConnection.query(`SET search_path TO ${schema}`);
      function browserCache(connection, browserId) {
        const cache = createPostgresSamlCacheProvider(connection, { providerSlug: "saml" });
        return bindSamlCacheToBrowser(cache, browserId);
      }
      const initiator = browserCache(cacheConnection, "browser-one");
      const sameBrowser = browserCache(secondConnection, "browser-one");
      const otherBrowser = browserCache(secondConnection, "browser-two");
      await initiator.saveAsync("request", "pending");
      assert.equal(await otherBrowser.getAsync("request"), null);
      assert.equal(await otherBrowser.consumeAsync("request"), null);
      const results = await Promise.all([
        initiator.consumeAsync("request"), sameBrowser.consumeAsync("request"),
      ]);
      assert.deepEqual(results.sort(), [null, "pending"]);
      assert.equal(await sameBrowser.getAsync("request"), null);
    } finally {
      secondConnection.release(true);
    }
  });

  function runOneSweep() {
    return new Promise((resolve, reject) => {
      const timer = startSamlCacheCleanupTimer({
        query(sql, params) {
          _stopSamlCacheCleanupTimerForTests();
          return cacheConnection.query(sql, params).then(resolve, reject);
        },
      }, { intervalMs: 10 });
      timer.ref();
    });
  }

  it("skips a locked sweep and releases its own lock on statement completion", { timeout: 10_000 }, async (t) => {
    const savedTtl = process.env.SAML_CACHE_TTL_SEC;
    const savedInterval = process.env.SAML_CACHE_CLEANUP_INTERVAL_MS;
    process.env.SAML_CACHE_TTL_SEC = "60";
    delete process.env.SAML_CACHE_CLEANUP_INTERVAL_MS;
    t.after(() => {
      if (savedTtl === undefined) delete process.env.SAML_CACHE_TTL_SEC;
      else process.env.SAML_CACHE_TTL_SEC = savedTtl;
      if (savedInterval === undefined) delete process.env.SAML_CACHE_CLEANUP_INTERVAL_MS;
      else process.env.SAML_CACHE_CLEANUP_INTERVAL_MS = savedInterval;
    });

    await cacheConnection.query(`INSERT INTO saml_request_cache (provider_slug, cache_key, cache_value, created_at)
      VALUES ('sweep', 'expired', 'expired', NOW() - INTERVAL '5 minutes'),
             ('sweep', 'live', 'live', NOW())`);
    const holder = await pool.connect();
    try {
      assert.notEqual(holder.processID, cacheConnection.processID);
      await holder.query("BEGIN");
      await holder.query("SELECT pg_advisory_xact_lock($1)", [lockKey]);
      assert.equal((await runOneSweep()).rowCount, 0);
      await holder.query("COMMIT");

      assert.ok((await runOneSweep()).rowCount >= 1);
      const remaining = await cacheConnection.query("SELECT cache_key FROM saml_request_cache WHERE provider_slug = 'sweep'");
      assert.deepEqual(remaining.rows, [{ cache_key: "live" }]);

      const heldAfterSweep = await holder.query("SELECT pg_try_advisory_xact_lock($1) AS acquired", [lockKey]);
      assert.equal(heldAfterSweep.rows[0].acquired, true);
    } finally {
      holder.release(true);
    }
  });
});
