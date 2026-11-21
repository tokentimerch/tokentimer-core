"use strict";

const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert");

const {
  createPostgresSamlCacheProvider,
  startSamlCacheCleanupTimer,
  _stopSamlCacheCleanupTimerForTests,
} = require("../../apps/api/sso/saml-cache-provider.js");

describe("saml cache cleanup", () => {
  afterEach(() => {
    _stopSamlCacheCleanupTimerForTests();
  });

  it("saveAsync triggers opportunistic prune for the provider scope", async () => {
    const queries = [];
    const pool = {
      query: async (sql, params) => {
        queries.push({ sql, params });
        return { rowCount: 0, rows: [] };
      },
    };
    const cache = createPostgresSamlCacheProvider(pool, {
      providerSlug: "azure-ad",
      ttlSec: 60,
    });
    await cache.saveAsync("k1", "v1");
    assert.ok(
      queries.some(
        (q) =>
          /DELETE FROM saml_request_cache/i.test(q.sql) &&
          q.params[0] === "azure-ad",
      ),
    );
    assert.ok(
      queries.some(
        (q) =>
          /INSERT INTO saml_request_cache/i.test(q.sql) &&
          q.params[0] === "azure-ad",
      ),
    );
  });

  it("scopes InResponseTo lookups and removals by provider", async () => {
    const values = new Map();
    const pool = {
      query: async (sql, [providerSlug, key, value]) => {
        const storageKey = JSON.stringify([providerSlug, key]);
        if (/INSERT INTO saml_request_cache/i.test(sql)) {
          values.set(storageKey, value);
        }
        const hit = values.get(storageKey);
        if (/RETURNING cache_value/i.test(sql)) {
          values.delete(storageKey);
        }
        return { rows: hit === undefined ? [] : [{ cache_value: hit }] };
      },
    };
    const first = createPostgresSamlCacheProvider(pool, { providerSlug: "keycloak" });
    const second = createPostgresSamlCacheProvider(pool, { providerSlug: "azure-ad" });

    await first.saveAsync("request-id", "first");
    assert.strictEqual(await second.getAsync("request-id"), null);
    assert.strictEqual(await second.removeAsync("request-id"), null);
    assert.strictEqual(await first.getAsync("request-id"), "first");
    assert.strictEqual(await first.removeAsync("request-id"), "first");
    assert.strictEqual(await first.getAsync("request-id"), null);
  });

  it("sweeps expiry under a transaction-scoped lock on the same connection", async () => {
    let captureQuery;
    const queryCalled = new Promise((resolve) => { captureQuery = resolve; });
    const pool = {
      query: async (sql, params) => {
        captureQuery({ sql, params });
        return { rowCount: 0, rows: [] };
      },
    };

    const timer = startSamlCacheCleanupTimer(pool, { intervalMs: 20 });
    timer.ref();
    const { sql, params } = await queryCalled;

    assert.match(sql, /WITH cleanup_lock AS MATERIALIZED/i);
    assert.match(sql, /pg_try_advisory_xact_lock\(\$1\)/i);
    assert.match(sql, /DELETE FROM saml_request_cache\s+WHERE \(SELECT acquired FROM cleanup_lock\)/i);
    assert.match(sql, /created_at < NOW\(\) - \(\$2::text/);
    assert.strictEqual(typeof params[0], "number");
    assert.ok(Number(params[1]) > 0);
  });
});
