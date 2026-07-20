"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  createControllerLogger,
} = require(path.resolve(__dirname, "../../apps/k8s-controller/src/logger.js"));

describe("CertOps Kubernetes controller logging", () => {
  it("scrubs tokens, authorization values, private keys, nested errors, and stacks", () => {
    const lines = [];
    const logger = createControllerLogger({
      now: () => "2026-07-20T00:00:00.000Z",
      write: (line) => lines.push(line),
    });
    const error = new Error("cookie: session=raw-cookie-value");
    error.stack = "Error: Authorization: Bearer raw-bearer-value";

    logger.error("Authorization: Bearer controller-token-value", {
      authorization: "Bearer raw-header-value",
      error,
      nested: {
        apiToken: "raw-api-token-value",
        material: "-----BEGIN PRIVATE KEY-----\nraw-private-key",
      },
    });

    const output = lines.join("");
    for (const secret of [
      "controller-token-value",
      "raw-header-value",
      "raw-cookie-value",
      "raw-bearer-value",
      "raw-api-token-value",
      "raw-private-key",
    ]) {
      assert.doesNotMatch(output, new RegExp(secret));
    }
    assert.match(output, /\[REDACTED\]|\[PRIVATE_KEY_REDACTED\]/);
  });
});
