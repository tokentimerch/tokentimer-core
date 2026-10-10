"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { X509Certificate } = require("node:crypto");

const {
  readHighestRequestId,
  recordHighestRequestId,
  tryReconcileUncertainSubmission,
} = require("./adcs-enrollment-reconcile");

describe("adcs-enrollment-reconcile", () => {
  let stateDir;

  beforeEach(() => {
    stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "adcs-reconcile-"));
  });

  afterEach(() => {
    fs.rmSync(stateDir, { recursive: true, force: true });
  });

  it("records and reads the per-CA RequestId watermark", async () => {
    const caConfig = "CAHOST.example.com\\TestCA";
    assert.equal(readHighestRequestId(stateDir, caConfig), 0);
    await recordHighestRequestId(stateDir, caConfig, 10);
    assert.equal(readHighestRequestId(stateDir, caConfig), 10);
    await recordHighestRequestId(stateDir, caConfig, 7);
    assert.equal(readHighestRequestId(stateDir, caConfig), 10);
    await recordHighestRequestId(stateDir, caConfig, 12);
    assert.equal(readHighestRequestId(stateDir, caConfig), 12);
  });

  it("reconciles when a retrieved leaf SPKI matches the journaled CSR SPKI", async () => {
    const keyPath = path.join(stateDir, "k.pem");
    const certPath = path.join(stateDir, "c.pem");
    const openssl = spawnSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        keyPath,
        "-out",
        certPath,
        "-days",
        "1",
        "-nodes",
        "-subj",
        "/CN=reconcile.test",
      ],
      { encoding: "utf8" },
    );
    if (openssl.status !== 0) {
      // Watermark + unresolved paths still cover environments without openssl.
      return;
    }
    const certificatePem = fs.readFileSync(certPath, "utf8");
    const cert = new X509Certificate(certificatePem);
    const spki = cert.publicKey.export({ type: "spki", format: "der" });
    const csrSpkiSha256 = crypto.createHash("sha256").update(spki).digest("hex");

    await recordHighestRequestId(stateDir, "CA\\Lab", 4);
    const issuer = {
      async retrieve(requestId) {
        if (requestId === 5) {
          return { outcome: "issued", certificatePem, requestId: 5 };
        }
        return { outcome: "uncertain", detail: "not found" };
      },
    };
    const result = await tryReconcileUncertainSubmission({
      issuer,
      stateDir,
      caConfig: "CA\\Lab",
      csrSpkiSha256,
      windowSize: 4,
      assertIssuanceOutcome: (v) => v,
    });
    assert.equal(result.status, "reconciled");
    assert.equal(result.requestId, 5);
    assert.equal(readHighestRequestId(stateDir, "CA\\Lab"), 5);
  });

  it("leaves submission unresolved when no SPKI match is found", async () => {
    await recordHighestRequestId(stateDir, "CA\\Lab", 1);
    const issuer = {
      async retrieve() {
        return { outcome: "uncertain", detail: "denied access" };
      },
    };
    const result = await tryReconcileUncertainSubmission({
      issuer,
      stateDir,
      caConfig: "CA\\Lab",
      csrSpkiSha256: "a".repeat(64),
      windowSize: 3,
      assertIssuanceOutcome: (v) => v,
    });
    assert.equal(result.status, "unresolved");
    assert.equal(result.probed, 3);
  });
});
