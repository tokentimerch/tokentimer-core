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

describe("autoSyncFailure helpers", () => {
  it("formatAutoSyncError prefers API error body over Axios message", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    const err = {
      message: "Request failed with status code 401",
      response: {
        status: 401,
        data: {
          error:
            "Authentication failed. Token may be expired (Azure CLI tokens expire quickly).",
        },
      },
    };
    assert.strictEqual(
      mod.formatAutoSyncError(err),
      "Authentication failed. Token may be expired (Azure CLI tokens expire quickly).",
    );
  });

  it("formatAutoSyncError falls back to err.message", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    assert.strictEqual(
      mod.formatAutoSyncError(new Error("Network timeout")),
      "Network timeout",
    );
  });
});
