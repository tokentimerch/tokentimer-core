"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  resolveAdcsChainHelperPath,
  validateCertificateChain,
  EXIT_OK,
  EXIT_DEFERRED,
  EXIT_FAIL,
} = require("./chain-helper");

describe("resolveAdcsChainHelperPath", () => {
  it("reports a clear error when the binary is missing", () => {
    const resolved = resolveAdcsChainHelperPath({
      packageRoot: path.join(__dirname, "..", "..", "does-not-exist"),
    });
    assert.ok(resolved.error);
    assert.match(resolved.error, /tokentimer-adcs-chain/);
  });
});

describe("validateCertificateChain", () => {
  it("maps exit 0 + verdict valid", async () => {
    const result = await validateCertificateChain({
      helperPath: "helper",
      certPath: "leaf.pem",
      caKeySha256: "a".repeat(64),
      execFileImpl: async () => ({
        stdout: JSON.stringify({ verdict: "valid" }),
        stderr: "",
      }),
    });
    assert.equal(result.ok, true);
    assert.equal(result.exitCode, EXIT_OK);
    assert.equal(result.verdict, "valid");
  });

  it("maps deferred exit to revocation_unknown only with matching verdict", async () => {
    const result = await validateCertificateChain({
      helperPath: "helper",
      certPath: "leaf.pem",
      caKeySha256: "a".repeat(64),
      execFileImpl: async () => {
        const err = new Error("deferred");
        err.code = EXIT_DEFERRED;
        err.stdout = JSON.stringify({
          verdict: "revocation_unknown",
          error: "offline",
        });
        err.stderr = "";
        throw err;
      },
    });
    assert.equal(result.ok, true);
    assert.equal(result.verdict, "revocation_unknown");
  });

  it("maps ca_key_changed", async () => {
    const result = await validateCertificateChain({
      helperPath: "helper",
      certPath: "leaf.pem",
      caKeySha256: "a".repeat(64),
      execFileImpl: async () => {
        const err = new Error("fail");
        err.code = EXIT_FAIL;
        err.stdout = JSON.stringify({
          verdict: "ca_key_changed",
          error: "pin miss",
        });
        err.stderr = "";
        throw err;
      },
    });
    assert.equal(result.ok, false);
    assert.equal(result.verdict, "ca_key_changed");
  });

  it("rejects a successful exit with a missing verdict", async () => {
    const result = await validateCertificateChain({
      helperPath: "helper",
      certPath: "leaf.pem",
      caKeySha256: "a".repeat(64),
      execFileImpl: async () => ({
        stdout: JSON.stringify({ trustStatus: 0 }),
        stderr: "",
      }),
    });
    assert.equal(result.ok, false);
    assert.equal(result.verdict, "invalid");
    assert.match(result.detail, /recognized verdict/);
  });

  it("rejects exit/verdict disagreement", async () => {
    const result = await validateCertificateChain({
      helperPath: "helper",
      certPath: "leaf.pem",
      caKeySha256: "a".repeat(64),
      execFileImpl: async () => {
        const err = new Error("fail");
        err.code = EXIT_FAIL;
        err.stdout = JSON.stringify({ verdict: "valid" });
        err.stderr = "";
        throw err;
      },
    });
    assert.equal(result.ok, false);
    assert.equal(result.verdict, "invalid");
    assert.match(result.detail, /disagrees/);
  });

  it("rejects deferred exit paired with invalid verdict", async () => {
    const result = await validateCertificateChain({
      helperPath: "helper",
      certPath: "leaf.pem",
      caKeySha256: "a".repeat(64),
      execFileImpl: async () => {
        const err = new Error("deferred");
        err.code = EXIT_DEFERRED;
        err.stdout = JSON.stringify({ verdict: "invalid", error: "broken" });
        err.stderr = "";
        throw err;
      },
    });
    assert.equal(result.ok, false);
    assert.equal(result.verdict, "invalid");
    assert.match(result.detail, /disagrees/);
  });
});
