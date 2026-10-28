"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { inspectOutbound } = require("./outbound");

const fixtures = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, "../../contracts/mcp/fixtures/read-tools.json"), "utf8"),
);
const ID = "0123456789abcdef";

describe("outbound secret check", () => {
  it("passes every valid output the contract describes (no false positives)", () => {
    let checked = 0;
    for (const [tool, cases] of Object.entries(fixtures)) {
      if (tool.startsWith("$")) continue;
      for (const output of cases.output.valid) {
        const verdict = inspectOutbound(output);
        assert.equal(verdict.clean, true, `${tool}: ${verdict.reason}`);
        checked += 1;
      }
    }
    assert.ok(checked >= 8);
  });

  it("withholds private keys in any common form", () => {
    for (const pem of [
      "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----",
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
      "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIA\n-----END EC PRIVATE KEY-----",
      "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHDBO\n-----END ENCRYPTED PRIVATE KEY-----",
    ]) {
      const verdict = inspectOutbound({ note: { value: pem, untrusted: true, truncated: false } });
      assert.equal(verdict.clean, false);
      assert.equal(verdict.reason, "private_key_material");
    }
  });

  it("withholds every TokenTimer credential family, which the shared detector does not know", () => {
    for (const prefix of ["ttopc_", "ttopg_", "ttagent_", "ttboot_", "ttx_"]) {
      const verdict = inspectOutbound({ commonName: { value: `CN=${prefix}${ID}_${"a".repeat(64)}`, untrusted: true, truncated: false } });
      assert.equal(verdict.clean, false, prefix);
      assert.equal(verdict.reason, "credential_shape", prefix);
    }
  });

  it("withholds bearer headers and generic secrets", () => {
    assert.equal(inspectOutbound("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789").clean, false);
    assert.equal(inspectOutbound({ reason: "api_key=AKIAIOSFODNN7EXAMPLE secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" }).clean, false);
  });

  it("withholds a secret hidden in a deeply nested string", () => {
    const deep = { a: [{ b: { c: [{ d: `x ttopc_${ID}_${"f".repeat(64)} y` }] } }] };
    assert.equal(inspectOutbound(deep).clean, false);
  });

  it("does not trip on ordinary text that merely mentions the words", () => {
    for (const text of ["rotate the private key before expiry", "bearer token auth is disabled", "CN=api.example.com", "ttopc is the prefix"]) {
      assert.equal(inspectOutbound({ message: text }).clean, true, text);
    }
  });
});
