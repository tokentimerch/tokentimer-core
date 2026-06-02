"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { loadEnvFile } = require("../../scripts/load-root-env");

function withCleanEnv(keys, callback) {
  const previous = new Map(
    keys.map((key) => [
      key,
      {
        exists: Object.prototype.hasOwnProperty.call(process.env, key),
        value: process.env[key],
      },
    ]),
  );

  for (const key of keys) {
    delete process.env[key];
  }

  try {
    callback();
  } finally {
    for (const [key, entry] of previous.entries()) {
      if (entry.exists) {
        process.env[key] = entry.value;
      } else {
        delete process.env[key];
      }
    }
  }
}

describe("load root env", () => {
  it("parses quoted and unquoted values with inline comments", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-env-"));
    const envFile = path.join(tempDir, ".env");

    fs.writeFileSync(
      envFile,
      [
        'A="value" # comment',
        "B='value' # comment",
        "C=value # comment",
        'D="value # not comment"',
      ].join(os.EOL),
    );

    try {
      withCleanEnv(["A", "B", "C", "D"], () => {
        assert.strictEqual(loadEnvFile(envFile), true);
        assert.strictEqual(process.env.A, "value");
        assert.strictEqual(process.env.B, "value");
        assert.strictEqual(process.env.C, "value");
        assert.strictEqual(process.env.D, "value # not comment");
      });
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
