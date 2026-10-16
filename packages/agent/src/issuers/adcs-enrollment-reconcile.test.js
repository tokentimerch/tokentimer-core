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
  retrieveProposedEnrollmentCandidate,
  leafSpkiSha256Hex,
  watermarkPath,
  watermarkLockPath,
} = require("./adcs-enrollment-reconcile");

describe("signed operator enrollment reconciliation", () => {
  const certificatePem = fs.readFileSync(path.join(__dirname, "..", "verify", "fixtures", "selfsigned.crt.pem"), "utf8");
  const csrSpkiSha256 = leafSpkiSha256Hex(certificatePem);
  const { assertIssuanceOutcome } = require("./index");
  it("retrieves exactly the proposed RequestId and requires a real matching leaf SPKI", async () => {
    const calls = [];
    const result = await retrieveProposedEnrollmentCandidate({ requestId: 77, csrSpkiSha256,
      reconcileSearchFrom: 12, assertIssuanceOutcome, issuer: {
        retrieve: async (id) => { calls.push(id); return { outcome: "issued", certificatePem }; },
      } });
    assert.deepEqual(calls, [77]);
    assert.equal(result.status, "unique_candidate");
    assert.equal(result.requestId, 77);
    assert.equal(result.nextSearchFrom, 12);
    assert.equal(result.attachmentEligible, true);
  });
  it("refuses a foreign SPKI or malformed certificate without attaching or resubmitting", async () => {
    for (const candidate of [certificatePem, "not a certificate"]) {
      const result = await retrieveProposedEnrollmentCandidate({ requestId: 77, csrSpkiSha256: "0".repeat(64),
        assertIssuanceOutcome, issuer: { retrieve: async () => ({ outcome: "issued", certificatePem: candidate }) } });
      assert.equal(result.status, "error");
      assert.equal(result.requestId, undefined);
    }
  });
  it("keeps unissued and inaccessible operator candidates uncertain", async () => {
    for (const outcome of [{ outcome: "pending", requestId: 77 }, { outcome: "denied", caHresult: "0x80094012", detail: "denied" },
      { outcome: "uncertain", caHresult: "0x80070005", detail: "inaccessible" }]) {
      const result = await retrieveProposedEnrollmentCandidate({ requestId: 77, csrSpkiSha256,
        assertIssuanceOutcome, issuer: { retrieve: async () => outcome } });
      assert.equal(result.status, "unresolved");
      assert.equal(result.requestId, undefined);
    }
  });
  it("rejects invalid unsigned-size ids before any CA call", async () => {
    for (const requestId of [0, -1, 1.5, 4294967296, "77"]) {
      const result = await retrieveProposedEnrollmentCandidate({ requestId, csrSpkiSha256,
        assertIssuanceOutcome, issuer: { retrieve: async () => { assert.fail("no invalid CA call"); } } });
      assert.equal(result.status, "error");
    }
  });
});

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

  it("keeps enrollment A's captured start while extending the scan past a later watermark", async () => {
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
    // Start stays enrollment-scoped; end reaches live watermark + window.
    assert.equal(probed[0], 105);
    assert.deepEqual(probed, [105, 106, 107, 108, 109, 110, 111, 112, 113]);
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

  it("does not keep E_ACCESSDENIED or denied probes as open for attachmentEligible", async () => {
    const issuer = {
      async retrieve(requestId) {
        if (requestId === 1) {
          return { outcome: "uncertain", detail: "foreign", caHresult: "0x80070005" };
        }
        if (requestId === 2) {
          return { outcome: "denied", detail: "admin deny", caHresult: "0x80094014" };
        }
        return { outcome: "uncertain", detail: "empty", caHresult: "0x80094004" };
      },
    };
    const result = await tryReconcileUncertainSubmission({
      issuer,
      stateDir,
      caConfig: "CA\\Lab",
      csrSpkiSha256: "a".repeat(64),
      reconcileSearchFrom: 1,
      windowSize: 3,
      assertIssuanceOutcome: (v) => v,
    });
    assert.equal(result.status, "unresolved");
    assert.equal(result.nextSearchFrom, 3);
    assert.equal(result.probed, 3);
  });

  it("skips E_ACCESSDENIED and denied probes so a later unique match can attach", async (t) => {
    const keyPath = path.join(stateDir, "k-access.pem");
    const certPath = path.join(stateDir, "c-access.pem");
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
        "/CN=access.denied.test",
      ],
      { encoding: "utf8" },
    );
    if (openssl.status !== 0) {
      // skip-reason: no-host - needs a real openssl binary on PATH
      t.skip("openssl unavailable");
      return;
    }
    const certificatePem = fs.readFileSync(certPath, "utf8");
    const cert = new X509Certificate(certificatePem);
    const spki = cert.publicKey.export({ type: "spki", format: "der" });
    const csrSpkiSha256 = crypto.createHash("sha256").update(spki).digest("hex");

    const issuer = {
      async retrieve(requestId) {
        if (requestId === 1) {
          return {
            outcome: "uncertain",
            detail: "foreign",
            caHresult: "0x80070005",
          };
        }
        if (requestId === 2) {
          return { outcome: "denied", detail: "admin deny", caHresult: "0x80094014" };
        }
        if (requestId === 3) {
          return { outcome: "issued", certificatePem, requestId: 3 };
        }
        return { outcome: "uncertain", detail: "empty", caHresult: "0x80094004" };
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
    assert.equal(result.requestId, 3);
    assert.equal(result.attachmentEligible, true);
    assert.equal(result.nextSearchFrom, 3);
  });

  it("recovers a watermark lock after the holder worker crashes", async () => {
    const { acquireExclusiveLockFile } = require("../windows-cert-store");
    const caConfig = "CA\\Lab";
    const lockPath = watermarkLockPath(stateDir, caConfig);
    const held = acquireExclusiveLockFile(
      lockPath,
      "ADCS_WATERMARK_LOCKED",
      "busy",
    );
    await held._workerForTests.terminate();
    await recordHighestRequestId(stateDir, caConfig, 7);
    assert.equal(readHighestRequestId(stateDir, caConfig), 7);
  });

  it("ignores an abandoned watermark marker file that is not backed by a live listen", async () => {
    const caConfig = "CA\\Lab";
    const lockPath = watermarkLockPath(stateDir, caConfig);
    fs.mkdirSync(path.dirname(lockPath), { recursive: true });
    fs.writeFileSync(lockPath, `${process.pid}\n2020-01-01T00:00:00.000Z\nabandoned\n`, "utf8");
    await recordHighestRequestId(stateDir, caConfig, 8);
    assert.equal(readHighestRequestId(stateDir, caConfig), 8);
  });

  it("does not steal a live watermark lock from a concurrent holder", async () => {
    const { acquireExclusiveLockFile } = require("../windows-cert-store");
    const caConfig = "CA\\Lab";
    const lockPath = watermarkLockPath(stateDir, caConfig);
    const held = acquireExclusiveLockFile(
      lockPath,
      "ADCS_WATERMARK_LOCKED",
      "busy",
    );
    await assert.rejects(
      () => recordHighestRequestId(stateDir, caConfig, 3),
      (err) => {
        assert.equal(err.code, "ADCS_WATERMARK_LOCKED");
        return true;
      },
    );
    held.release();
  });

  it("allows only one watermark writer when three processes contend", async () => {
    const { spawn } = require("node:child_process");
    const caConfig = "CA\\Lab";
    const lockPath = watermarkLockPath(stateDir, caConfig);
    const barrierDir = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "wm-barrier-"));
    const storeModule = path.join(__dirname, "..", "windows-cert-store", "index.js");
    const script = `
      const fs = require("fs");
      const path = require("path");
      const { acquireExclusiveLockFile } = require(${JSON.stringify(storeModule)});
      const lockPath = process.env.TT_LOCK_PATH;
      const barrierDir = process.env.TT_BARRIER_DIR;
      const id = process.env.TT_CONTENDER_ID;
      fs.writeFileSync(path.join(barrierDir, id + ".ready"), "1");
      const deadline = Date.now() + 10000;
      while (Date.now() < deadline) {
        if (fs.readdirSync(barrierDir).filter((n) => n.endsWith(".ready")).length >= 3) break;
      }
      try {
        const lock = acquireExclusiveLockFile(lockPath, "ADCS_WATERMARK_LOCKED", "busy");
        fs.writeFileSync(path.join(barrierDir, id + ".won"), lock.ownerToken);
        const holdUntil = Date.now() + 1500;
        while (Date.now() < holdUntil) {}
        lock.release();
        process.exit(0);
      } catch (err) {
        fs.writeFileSync(path.join(barrierDir, id + ".lost"), err && err.code ? err.code : "ERR");
        process.exit(2);
      }
    `;
    await Promise.all(
      ["a", "b", "c"].map(
        (id) =>
          new Promise((resolve, reject) => {
            const child = spawn(process.execPath, ["-e", script], {
              env: {
                ...process.env,
                TT_LOCK_PATH: lockPath,
                TT_BARRIER_DIR: barrierDir,
                TT_CONTENDER_ID: id,
              },
              stdio: "ignore",
            });
            const timer = setTimeout(() => {
              child.kill();
              reject(new Error(`contender ${id} timed out`));
            }, 20000);
            child.on("exit", () => {
              clearTimeout(timer);
              resolve();
            });
          }),
      ),
    );
    const won = fs.readdirSync(barrierDir).filter((n) => n.endsWith(".won"));
    const lost = fs.readdirSync(barrierDir).filter((n) => n.endsWith(".lost"));
    assert.equal(won.length, 1, `won=${won} lost=${lost}`);
    assert.equal(lost.length, 2);
    await recordHighestRequestId(stateDir, caConfig, 42);
    assert.equal(readHighestRequestId(stateDir, caConfig), 42);
  });
});
