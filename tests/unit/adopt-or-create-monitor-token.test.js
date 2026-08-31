"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { pathToFileURL } = require("url");

async function importFresh(relativePath) {
  const abs = path.join(__dirname, "..", "..", relativePath);
  const href = `${pathToFileURL(abs).href}?t=${Date.now()}-${Math.random()}`;
  return import(href);
}

describe("adoptOrCreateMonitorToken", () => {
  it("reuses an existing name+location token instead of inserting a duplicate", async () => {
    const mod = await importFresh(
      "apps/worker/src/shared/adoptOrCreateMonitorToken.js",
    );
    const calls = [];
    const client = {
      async query(sql, params) {
        calls.push({ sql, params });
        if (sql.includes("SELECT id FROM tokens")) {
          return { rows: [{ id: 35 }] };
        }
        throw new Error(`unexpected query: ${sql}`);
      },
    };

    const tokenId = await mod.adoptOrCreateMonitorToken(client, {
      workspaceId: "ws-1",
      hostname: "app.example.com",
      url: "https://app.example.com",
      sslData: {
        ssl_valid_to: "2027-01-01T00:00:00.000Z",
        ssl_issuer: "CN=Test CA",
        ssl_serial: "abc",
        ssl_subject: "CN=app.example.com",
        ssl_fingerprint: "deadbeef",
      },
      defaultContactGroupId: null,
    });

    assert.strictEqual(tokenId, 35);
    assert.equal(
      calls.some((c) => c.sql.includes("INSERT INTO tokens")),
      false,
    );
    assert.deepStrictEqual(calls[0].params, [
      "ws-1",
      "app.example.com",
      "https://app.example.com",
    ]);
  });

  it("inserts a new token when name+location does not match", async () => {
    const mod = await importFresh(
      "apps/worker/src/shared/adoptOrCreateMonitorToken.js",
    );
    const client = {
      async query(sql, params) {
        if (sql.includes("SELECT id FROM tokens")) {
          return { rows: [] };
        }
        if (sql.includes("INSERT INTO tokens")) {
          assert.strictEqual(params[1], "app.example.com");
          assert.strictEqual(params[7], "https://app.example.com");
          assert.strictEqual(params[9], "cg-1");
          return { rows: [{ id: 99 }] };
        }
        throw new Error(`unexpected query: ${sql}`);
      },
    };

    const tokenId = await mod.adoptOrCreateMonitorToken(client, {
      workspaceId: "ws-1",
      hostname: "app.example.com",
      url: "https://app.example.com",
      sslData: {
        ssl_valid_to: "2027-01-01T00:00:00.000Z",
        ssl_issuer: "CN=Test CA",
        ssl_serial: "abc",
        ssl_subject: "CN=app.example.com",
        ssl_fingerprint: "deadbeef",
      },
      defaultContactGroupId: "cg-1",
    });

    assert.strictEqual(tokenId, 99);
  });
});
