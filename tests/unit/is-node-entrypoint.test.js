"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { pathToFileURL } = require("url");

describe("isNodeEntrypoint", () => {
  it("matches the executed entry file across path formats", async () => {
    const { isNodeEntrypoint } = await import(
      pathToFileURL(
        path.join(
          __dirname,
          "..",
          "..",
          "apps",
          "worker",
          "src",
          "is-node-entrypoint.js",
        ),
      ).href
    );

    const entry = path.join(
      __dirname,
      "..",
      "..",
      "apps",
      "worker",
      "src",
      "runner.js",
    );
    const moduleUrl = pathToFileURL(path.resolve(entry)).href;

    assert.strictEqual(isNodeEntrypoint(moduleUrl, ["node", entry]), true);
    if (process.platform === "win32") {
      assert.strictEqual(
        isNodeEntrypoint(moduleUrl, ["node", entry.replace(/\//g, "\\")]),
        true,
      );
    }
    assert.strictEqual(isNodeEntrypoint(moduleUrl, ["node", __filename]), false);
  });
});
