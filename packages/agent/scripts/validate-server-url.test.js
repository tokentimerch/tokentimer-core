"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");

const script = path.join(__dirname, "validate-server-url.js");

function run(args) {
  return spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
}

describe("validate-server-url (H9)", () => {
  it("accepts https origins", () => {
    const result = run(["https://cp.example.com"]);
    assert.equal(result.status, 0);
    assert.equal(result.stdout.trim(), "https://cp.example.com");
  });

  it("rejects non-local http without the insecure flag", () => {
    const result = run(["http://cp.example.com"]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /HTTPS|http:\/\//i);
    assert.match(result.stderr, /allow-insecure-local-http/);
  });

  it("rejects local http without the insecure flag", () => {
    const result = run(["http://127.0.0.1:4010"]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /HTTPS|local development/i);
  });

  it("accepts loopback http only with --allow-insecure-local-http", () => {
    const ok = run(["http://127.0.0.1:4010", "--allow-insecure-local-http"]);
    assert.equal(ok.status, 0);
    assert.equal(ok.stdout.trim(), "http://127.0.0.1:4010");

    const localhost = run(["http://localhost:4010", "--allow-insecure-local-http"]);
    assert.equal(localhost.status, 0);

    const stillRemote = run([
      "http://cp.example.com",
      "--allow-insecure-local-http",
    ]);
    assert.equal(stillRemote.status, 1);
  });

  it("rejects credentials, query, fragment, and path like the runtime", () => {
    for (const url of [
      "https://user:pass@cp.example.com",
      "https://cp.example.com?x=1",
      "https://cp.example.com#frag",
      "https://cp.example.com/api",
    ]) {
      const result = run([url]);
      assert.equal(result.status, 1, url);
    }
  });
});
