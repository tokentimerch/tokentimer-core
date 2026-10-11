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
  readWatermark,
  tryReconcileUncertainSubmission,
  watermarkPath,
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

  it("fails closed on a corrupt watermark instead of treating it as zero", () => {
    const caConfig = "CA\\Lab";
    fs.mkdirSync(path.dirname(watermarkPath(stateDir, caConfig)), { recursive: true });
    fs.writeFileSync(watermarkPath(stateDir, caConfig), "{not-json", "utf8");
    const read = readWatermark(stateDir, caConfig);
    assert.equal(read.ok, false);
    assert.match(read.error, /corrupt/i);
    assert.throws(() => readHighestRequestId(stateDir, caConfig), (err) => {
      assert.equal(err.code, "ADCS_REQUESTID_WATERMARK_CORRUPT");
      return true;
    });
  });

  it("returns unique_candidate without advancing the CA watermark on uncertain probes", async () => {
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
    assert.equal(result.status, "unique_candidate");
    assert.equal(result.requestId, 5);
    // Uncertain probes and the candidate itself must not advance the watermark;
    // only a confirmed attach (caller) may call recordHighestRequestId.
    assert.equal(readHighestRequestId(stateDir, "CA\\Lab"), 4);
    // Enrollment cursor stays on the first unresolved/open id (the match).
    assert.equal(result.nextSearchFrom, 5);
  });

  it("does not skip unresolved RequestIds when the watermark advances elsewhere", async () => {
    await recordHighestRequestId(stateDir, "CA\\Lab", 100);
    const probed = [];
    const issuer = {
      async retrieve(requestId) {
        probed.push(requestId);
        return { outcome: "uncertain", detail: "pending or inaccessible" };
      },
    };
    const first = await tryReconcileUncertainSubmission({
      issuer,
      stateDir,
      caConfig: "CA\\Lab",
      csrSpkiSha256: "a".repeat(64),
      reconcileSearchFrom: 105,
      windowSize: 3,
      assertIssuanceOutcome: (v) => v,
    });
    assert.equal(first.status, "unresolved");
    assert.deepEqual(probed, [105, 106, 107]);
    assert.equal(first.nextSearchFrom, 105);
    // Another enrollment confirms a higher RequestId on the same CA.
    await recordHighestRequestId(stateDir, "CA\\Lab", 200);
    assert.equal(readHighestRequestId(stateDir, "CA\\Lab"), 200);

    probed.length = 0;
    const second = await tryReconcileUncertainSubmission({
      issuer,
      stateDir,
      caConfig: "CA\\Lab",
      csrSpkiSha256: "a".repeat(64),
      reconcileSearchFrom: first.nextSearchFrom,
      windowSize: 3,
      assertIssuanceOutcome: (v) => v,
    });
    assert.equal(second.status, "unresolved");
    assert.deepEqual(probed, [105, 106, 107]);
    assert.equal(second.nextSearchFrom, 105);
  });

  it("reports ambiguous when more than one SPKI match appears in the window", async () => {
    const keyPath = path.join(stateDir, "k2.pem");
    const certPath = path.join(stateDir, "c2.pem");
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
        "/CN=ambiguous.test",
      ],
      { encoding: "utf8" },
    );
    if (openssl.status !== 0) {
      return;
    }
    const certificatePem = fs.readFileSync(certPath, "utf8");
    const cert = new X509Certificate(certificatePem);
    const spki = cert.publicKey.export({ type: "spki", format: "der" });
    const csrSpkiSha256 = crypto.createHash("sha256").update(spki).digest("hex");

    const issuer = {
      async retrieve(requestId) {
        if (requestId === 2 || requestId === 4) {
          return { outcome: "issued", certificatePem, requestId };
        }
        return { outcome: "uncertain", detail: "not found" };
      },
    };
    const result = await tryReconcileUncertainSubmission({
      issuer,
      stateDir,
      caConfig: "CA\\Lab",
      csrSpkiSha256,
      reconcileSearchFrom: 1,
      windowSize: 4,
      assertIssuanceOutcome: (v) => v,
    });
    assert.equal(result.status, "ambiguous");
    assert.equal(result.matchCount, 2);
    assert.equal(result.nextSearchFrom, 1);
    assert.equal(readHighestRequestId(stateDir, "CA\\Lab"), 0);
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
    assert.equal(result.nextSearchFrom, 2);
    assert.equal(readHighestRequestId(stateDir, "CA\\Lab"), 1);
  });
});
