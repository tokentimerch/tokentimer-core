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
  captureEnrollmentReconcileSearchFrom,
  tryReconcileUncertainSubmission,
  watermarkPath,
  watermarkLockPath,
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

  it("captures an enrollment cursor from the watermark before CA contact", async () => {
    assert.equal(captureEnrollmentReconcileSearchFrom(stateDir, "CA\\Lab"), 1);
    await recordHighestRequestId(stateDir, "CA\\Lab", 104);
    assert.equal(captureEnrollmentReconcileSearchFrom(stateDir, "CA\\Lab"), 105);
  });

  it("keeps enrollment A's captured cursor when enrollment B advances the watermark", async () => {
    await recordHighestRequestId(stateDir, "CA\\Lab", 104);
    const enrollmentACursor = captureEnrollmentReconcileSearchFrom(stateDir, "CA\\Lab");
    assert.equal(enrollmentACursor, 105);
    // Enrollment B confirms a higher RequestId on the same CA.
    await recordHighestRequestId(stateDir, "CA\\Lab", 110);
    assert.equal(readHighestRequestId(stateDir, "CA\\Lab"), 110);

    const probed = [];
    const issuer = {
      async retrieve(requestId) {
        probed.push(requestId);
        return { outcome: "uncertain", detail: "pending" };
      },
    };
    const result = await tryReconcileUncertainSubmission({
      issuer,
      stateDir,
      caConfig: "CA\\Lab",
      csrSpkiSha256: "a".repeat(64),
      reconcileSearchFrom: enrollmentACursor,
      windowSize: 3,
      assertIssuanceOutcome: (v) => v,
    });
    assert.equal(result.status, "unresolved");
    assert.deepEqual(probed, [105, 106, 107]);
    assert.equal(result.nextSearchFrom, 105);
  });

  it("requires reconcileSearchFrom and does not fall back to the live watermark", async () => {
    await recordHighestRequestId(stateDir, "CA\\Lab", 50);
    const result = await tryReconcileUncertainSubmission({
      issuer: { async retrieve() { return { outcome: "uncertain" }; } },
      stateDir,
      caConfig: "CA\\Lab",
      csrSpkiSha256: "a".repeat(64),
      windowSize: 3,
      assertIssuanceOutcome: (v) => v,
    });
    assert.equal(result.status, "error");
    assert.match(result.error, /reconcileSearchFrom is required/);
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
      reconcileSearchFrom: 5,
      windowSize: 4,
      assertIssuanceOutcome: (v) => v,
    });
    assert.equal(result.status, "unique_candidate");
    assert.equal(result.requestId, 5);
    assert.equal(result.attachmentEligible, true);
    assert.equal(readHighestRequestId(stateDir, "CA\\Lab"), 4);
    assert.equal(result.nextSearchFrom, 5);
  });

  it("marks unique_candidate attachment-ineligible when earlier RequestIds remain open", async () => {
    const keyPath = path.join(stateDir, "k3.pem");
    const certPath = path.join(stateDir, "c3.pem");
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
        "/CN=open-pred.test",
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
        if (requestId === 1) return { outcome: "uncertain", detail: "pending" };
        if (requestId === 2) return { outcome: "issued", certificatePem, requestId: 2 };
        return { outcome: "uncertain", detail: "not found" };
      },
    };
    const result = await tryReconcileUncertainSubmission({
      issuer,
      stateDir,
      caConfig: "CA\\Lab",
      csrSpkiSha256,
      reconcileSearchFrom: 1,
      windowSize: 3,
      assertIssuanceOutcome: (v) => v,
    });
    assert.equal(result.status, "unique_candidate");
    assert.equal(result.requestId, 2);
    assert.equal(result.attachmentEligible, false);
    assert.equal(result.nextSearchFrom, 1);
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
      reconcileSearchFrom: 2,
      windowSize: 3,
      assertIssuanceOutcome: (v) => v,
    });
    assert.equal(result.status, "unresolved");
    assert.equal(result.probed, 3);
    assert.equal(result.nextSearchFrom, 2);
  });

  it("recovers a stale watermark lock left by a dead process after crash", async () => {
    const caConfig = "CA\\Lab";
    const lockPath = watermarkLockPath(stateDir, caConfig);
    fs.mkdirSync(path.dirname(lockPath), { recursive: true });
    // Dead PID with a fresh timestamp: reclaim via process-not-alive, not age.
    fs.writeFileSync(lockPath, `999999991\n${new Date().toISOString()}\n`, "utf8");
    await recordHighestRequestId(stateDir, caConfig, 7);
    assert.equal(readHighestRequestId(stateDir, caConfig), 7);
    assert.equal(fs.existsSync(lockPath), false);
  });

  it("recovers an aged watermark lock even if the recorded pid looks live", async () => {
    const caConfig = "CA\\Lab";
    const lockPath = watermarkLockPath(stateDir, caConfig);
    fs.mkdirSync(path.dirname(lockPath), { recursive: true });
    fs.writeFileSync(lockPath, `${process.pid}\n2020-01-01T00:00:00.000Z\n`, "utf8");
    await recordHighestRequestId(stateDir, caConfig, 8);
    assert.equal(readHighestRequestId(stateDir, caConfig), 8);
  });

  it("does not steal a live watermark lock from a concurrent holder", async () => {
    const caConfig = "CA\\Lab";
    const lockPath = watermarkLockPath(stateDir, caConfig);
    fs.mkdirSync(path.dirname(lockPath), { recursive: true });
    fs.writeFileSync(lockPath, `${process.pid}\n${new Date().toISOString()}\n`, "utf8");
    await assert.rejects(
      () => recordHighestRequestId(stateDir, caConfig, 3),
      (err) => {
        assert.equal(err.code, "ADCS_WATERMARK_LOCKED");
        return true;
      },
    );
    fs.unlinkSync(lockPath);
  });

  it("allows only one owner when two contenders reclaim the same stale watermark lock", async () => {
    const { reclaimStaleLockFile, acquireExclusiveLockFile, parseStoreLockContents } = require("../windows-cert-store");
    const caConfig = "CA\\Lab";
    const lockPath = watermarkLockPath(stateDir, caConfig);
    fs.mkdirSync(path.dirname(lockPath), { recursive: true });
    fs.writeFileSync(lockPath, "999999991\n2020-01-01T00:00:00.000Z\nstale-token\n", "utf8");

    // B observes stale; A wins reclaim+acquire inside B's pre-rename pause;
    // B must restore A's lock rather than dual-own.
    let winner;
    const reclaimedByB = reclaimStaleLockFile(lockPath, {
      beforeReclaimRename() {
        assert.equal(reclaimStaleLockFile(lockPath), true);
        winner = acquireExclusiveLockFile(lockPath, "ADCS_WATERMARK_LOCKED", "busy");
      },
    });
    assert.equal(reclaimedByB, false);
    assert.equal(
      parseStoreLockContents(fs.readFileSync(lockPath, "utf8")).ownerToken,
      winner.ownerToken,
    );
    winner.release();

    await recordHighestRequestId(stateDir, caConfig, 42);
    assert.equal(readHighestRequestId(stateDir, caConfig), 42);
  });
});
