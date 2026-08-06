"use strict";

/**
 * Tests for packages/agent/src/windows-cert-store/index.js.
 *
 * These tests never require a real Windows host: certreq invocations are
 * exercised through an injected execFile stub (same pattern as
 * acme/acme.test.js), and the thumbprint/PEM-parsing logic is verified
 * against the real fixture certificate already committed for
 * verify/verify.test.js, cross-checked against node:crypto's own
 * X509Certificate.fingerprint so this module's independent sha1(DER)
 * computation cannot silently drift from what a real certificate parser
 * reports.
 *
 * Real-host verification (real certreq.exe, a real CNG-backed
 * non-exportable key, a real CA response) is tracked separately as the
 * next milestone and is NOT claimed here.
 */

const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { X509Certificate } = require("node:crypto");

const {
  SUPPORTED_KEY_ALGORITHM_NAMES,
  buildContainerName,
  isAgentOwnedContainerName,
  buildCertreqInf,
  computeSha1ThumbprintFromPem,
  normalizeCsrPemLabel,
  generateCsrViaCng,
  acceptCertificateViaCng,
  acquireStoreLock,
  isProcessAlive,
  isStoreLockStale,
  parseStoreLockContents,
  MAX_STORE_LOCK_AGE_MS,
  removeAbandonedKeyContainer,
  WINDOWS_STORE_NAME_PATTERN,
} = require("./index.js");

const FIXTURE_CERT_PEM = fs.readFileSync(
  path.join(__dirname, "..", "verify", "fixtures", "selfsigned.crt.pem"),
  "utf8",
);
const FIXTURE_THUMBPRINT = new X509Certificate(FIXTURE_CERT_PEM).fingerprint.replace(/:/g, "");

const tempDirs = [];
function makeTempDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-windows-cert-store-test-"));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  while (tempDirs.length > 0) {
    fs.rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

/** execFile stub factory, mirroring acme.test.js's makeExecStub. */
function makeExecStub({ error = null, stdout = "", stderr = "", onCall } = {}) {
  const calls = [];
  function execFileStub(file, args, options, callback) {
    calls.push({ file, args, options });
    if (typeof onCall === "function") onCall({ file, args, options });
    process.nextTick(() => callback(error, stdout, stderr));
  }
  execFileStub.calls = calls;
  return execFileStub;
}

// ---------------------------------------------------------------------------
// buildContainerName / buildCertreqInf: injection-safety and shape
// ---------------------------------------------------------------------------

describe("buildContainerName", () => {
  it("produces a name matching the safe container-name alphabet regardless of jobId content", () => {
    const hostile = 'job"];[NewSection]\nEvil=1\r\n';
    const name = buildContainerName(hostile);
    assert.match(name, /^tokentimer-[A-Za-z0-9_-]+-[a-f0-9]{8}$/);
  });

  it("produces unique names across calls", () => {
    const a = buildContainerName("job-1");
    const b = buildContainerName("job-1");
    assert.notEqual(a, b);
  });
});

describe("isAgentOwnedContainerName", () => {
  it("accepts a name buildContainerName actually produces", () => {
    assert.equal(isAgentOwnedContainerName(buildContainerName("job-1")), true);
  });

  it("rejects a container name that merely happens to be present, not agent-created", () => {
    // Exactly the shape a human operator or a different tool's own CNG
    // enrollment would leave in certutil's "Key Container =" line: a real,
    // non-exportable container, just not one this agent's buildContainerName
    // produced. Ownership must never be inferred from presence alone.
    assert.equal(isAgentOwnedContainerName("IIS-CertReq-2024-01-01"), false);
    assert.equal(isAgentOwnedContainerName("some-other-tools-container"), false);
  });

  it("rejects null/undefined/empty without throwing", () => {
    assert.equal(isAgentOwnedContainerName(null), false);
    assert.equal(isAgentOwnedContainerName(undefined), false);
    assert.equal(isAgentOwnedContainerName(""), false);
  });

  it("rejects a name that starts with the prefix but breaks the safe alphabet", () => {
    assert.equal(isAgentOwnedContainerName("tokentimer-evil\r\nInjected=1"), false);
  });
});

describe("buildCertreqInf", () => {
  const validInput = {
    commonName: "www.example.com",
    altNames: ["example.com"],
    containerName: "tokentimer-job-1-abcd1234",
    algorithm: "rsa-2048",
  };

  it("embeds the requested subject, container, and key settings", () => {
    const inf = buildCertreqInf(validInput);
    assert.match(inf, /Subject = "CN=www\.example\.com"/);
    assert.match(inf, /KeyContainer = "tokentimer-job-1-abcd1234"/);
    assert.match(inf, /KeyLength = 2048/);
    assert.match(inf, /KeyAlgorithm = RSA/);
    assert.match(inf, /Exportable = FALSE/);
    assert.match(inf, /MachineKeySet = TRUE/);
    assert.match(inf, /ProviderName = "Microsoft Software Key Storage Provider"/);
  });

  it("de-duplicates the common name against altNames in the SAN extension", () => {
    const inf = buildCertreqInf({ ...validInput, altNames: ["www.example.com", "example.com"] });
    const sanLine = inf.split("\r\n").find((line) => line.startsWith("2.5.29.17"));
    assert.equal(sanLine.match(/dns=www\.example\.com/g).length, 1);
    assert.match(sanLine, /dns=example\.com/);
  });

  it("rejects a commonName outside the hostname alphabet (rules out INF injection)", () => {
    assert.throws(
      () => buildCertreqInf({ ...validInput, commonName: 'evil"\r\n[NewSection]\r\nX=1' }),
      /commonName must be a valid hostname/,
    );
  });

  it("rejects an altName outside the hostname alphabet", () => {
    assert.throws(
      () => buildCertreqInf({ ...validInput, altNames: ["ok.example.com", "bad\ninjected"] }),
      /altNames\[1\] must be a valid hostname/,
    );
  });

  it("rejects a containerName outside its safe alphabet", () => {
    assert.throws(
      () => buildCertreqInf({ ...validInput, containerName: "not a safe name!" }),
      /containerName must match/,
    );
  });

  it("rejects an unsupported algorithm", () => {
    assert.throws(
      () => buildCertreqInf({ ...validInput, algorithm: "dsa-1024" }),
      /unsupported algorithm/,
    );
  });

  it("supports every documented algorithm name", () => {
    for (const algorithm of SUPPORTED_KEY_ALGORITHM_NAMES) {
      assert.doesNotThrow(() => buildCertreqInf({ ...validInput, algorithm }));
    }
  });
});

// ---------------------------------------------------------------------------
// computeSha1ThumbprintFromPem
// ---------------------------------------------------------------------------

describe("computeSha1ThumbprintFromPem", () => {
  it("matches node:crypto's own X509Certificate.fingerprint for a real certificate", () => {
    assert.equal(computeSha1ThumbprintFromPem(FIXTURE_CERT_PEM), FIXTURE_THUMBPRINT);
  });

  it("is uppercase hex with no separators (the Windows store convention)", () => {
    const thumbprint = computeSha1ThumbprintFromPem(FIXTURE_CERT_PEM);
    assert.match(thumbprint, /^[0-9A-F]{40}$/);
  });

  it("rejects a non-PEM string", () => {
    assert.throws(() => computeSha1ThumbprintFromPem("not a pem"), /not a recognizable PEM block/);
  });

  it("rejects an empty string", () => {
    assert.throws(() => computeSha1ThumbprintFromPem(""), /non-empty PEM string/);
  });
});

// ---------------------------------------------------------------------------
// normalizeCsrPemLabel
// ---------------------------------------------------------------------------

describe("normalizeCsrPemLabel", () => {
  it("rewrites the legacy 'NEW CERTIFICATE REQUEST' label certreq emits to the RFC 2986 label", () => {
    // A minimal, syntactically-valid-enough DER blob for label rewriting
    // purposes: the test only asserts the label and byte-preservation, not
    // ASN.1 well-formedness (that is exercised for real by generateCsrViaCng
    // against a real certreq output on the next milestone's VM pass).
    const der = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]);
    const base64 = der.toString("base64");
    const legacy = `-----BEGIN NEW CERTIFICATE REQUEST-----\n${base64}\n-----END NEW CERTIFICATE REQUEST-----\n`;

    const normalized = normalizeCsrPemLabel(legacy);

    assert.match(normalized, /^-----BEGIN CERTIFICATE REQUEST-----/);
    assert.match(normalized, /-----END CERTIFICATE REQUEST-----\n$/);
    const roundTripBase64 = normalized
      .split("\n")
      .slice(1, -2)
      .join("");
    assert.equal(Buffer.from(roundTripBase64, "base64").toString("hex"), der.toString("hex"));
  });

  it("passes through the RFC 2986 label unchanged in content", () => {
    const der = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]);
    const base64 = der.toString("base64");
    const standard = `-----BEGIN CERTIFICATE REQUEST-----\n${base64}\n-----END CERTIFICATE REQUEST-----\n`;
    const normalized = normalizeCsrPemLabel(standard);
    assert.match(normalized, /^-----BEGIN CERTIFICATE REQUEST-----/);
  });

  it("rejects a certificate PEM (wrong label family)", () => {
    assert.throws(() => normalizeCsrPemLabel(FIXTURE_CERT_PEM), /not a recognizable PEM block/);
  });
});

// ---------------------------------------------------------------------------
// generateCsrViaCng: argv construction, no shell, cleanup, error surfacing
// ---------------------------------------------------------------------------

describe("generateCsrViaCng", () => {
  it("invokes certreq -q -new <inf> <req> without a shell and with the expected argv shape", async () => {
    const workDir = makeTempDir();
    const csrDer = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]);
    const csrPem = `-----BEGIN NEW CERTIFICATE REQUEST-----\n${csrDer.toString("base64")}\n-----END NEW CERTIFICATE REQUEST-----\n`;

    const execFileImpl = makeExecStub({
      onCall: ({ args }) => {
        // Simulate certreq writing the .req file it was told to produce.
        const reqPath = args[args.length - 1];
        fs.writeFileSync(reqPath, csrPem, "utf8");
      },
    });

    const result = await generateCsrViaCng({
      commonName: "www.example.com",
      altNames: ["example.com"],
      jobId: "job-42",
      workDir,
      execFileImpl,
      certreqPath: "certreq.exe",
    });

    assert.equal(result.ok, true);
    assert.match(result.csrPem, /^-----BEGIN CERTIFICATE REQUEST-----/);
    assert.match(result.containerName, /^tokentimer-job-42-/);

    assert.equal(execFileImpl.calls.length, 1);
    const call = execFileImpl.calls[0];
    assert.equal(call.file, "certreq.exe");
    assert.deepEqual(call.args.slice(0, 2), ["-q", "-new"]);
    assert.equal(call.options.shell, undefined);
  });

  it("cleans up the INF and .req scratch files after a successful run", async () => {
    const workDir = makeTempDir();
    const execFileImpl = makeExecStub({
      onCall: ({ args }) => {
        const reqPath = args[args.length - 1];
        fs.writeFileSync(
          reqPath,
          "-----BEGIN NEW CERTIFICATE REQUEST-----\nMAMCAQA=\n-----END NEW CERTIFICATE REQUEST-----\n",
          "utf8",
        );
      },
    });

    await generateCsrViaCng({
      commonName: "www.example.com",
      jobId: "job-cleanup",
      workDir,
      execFileImpl,
    });

    assert.deepEqual(fs.readdirSync(workDir), []);
  });

  it("returns ok: false with bounded output excerpts on a nonzero exit, and still cleans up", async () => {
    const workDir = makeTempDir();
    const error = Object.assign(new Error("certreq failed"), { code: 1 });
    const execFileImpl = makeExecStub({ error, stdout: "", stderr: "CertReq: Request denied" });

    const result = await generateCsrViaCng({
      commonName: "www.example.com",
      jobId: "job-fail",
      workDir,
      execFileImpl,
    });

    assert.equal(result.ok, false);
    assert.equal(result.exitCode, 1);
    assert.match(result.stderrExcerpt, /Request denied/);
    assert.deepEqual(fs.readdirSync(workDir), []);
  });

  it("rejects a hostile commonName before ever invoking execFile", async () => {
    const workDir = makeTempDir();
    const execFileImpl = makeExecStub();
    await assert.rejects(
      generateCsrViaCng({
        commonName: 'evil"\r\n[NewSection]',
        jobId: "job-injection",
        workDir,
        execFileImpl,
      }),
      /commonName must be a valid hostname/,
    );
    assert.equal(execFileImpl.calls.length, 0);
  });
});

// ---------------------------------------------------------------------------
// acceptCertificateViaCng
// ---------------------------------------------------------------------------

describe("acceptCertificateViaCng", () => {
  it("invokes certreq -q -accept <cer> without a shell and returns the precomputed thumbprint", async () => {
    const workDir = makeTempDir();
    const execFileImpl = makeExecStub();

    const result = await acceptCertificateViaCng({
      certificatePem: FIXTURE_CERT_PEM,
      workDir,
      execFileImpl,
    });

    assert.equal(result.ok, true);
    assert.equal(result.thumbprint, FIXTURE_THUMBPRINT);

    assert.equal(execFileImpl.calls.length, 1);
    const call = execFileImpl.calls[0];
    assert.deepEqual(call.args.slice(0, 2), ["-q", "-accept"]);
  });

  it("cleans up the staged .cer file after completion, success or failure", async () => {
    const workDirOk = makeTempDir();
    await acceptCertificateViaCng({
      certificatePem: FIXTURE_CERT_PEM,
      workDir: workDirOk,
      execFileImpl: makeExecStub(),
    });
    assert.deepEqual(fs.readdirSync(workDirOk), []);

    const workDirFail = makeTempDir();
    const error = Object.assign(new Error("accept failed"), { code: 2 });
    await acceptCertificateViaCng({
      certificatePem: FIXTURE_CERT_PEM,
      workDir: workDirFail,
      execFileImpl: makeExecStub({ error }),
    });
    assert.deepEqual(fs.readdirSync(workDirFail), []);
  });

  it("returns ok: false with the exit code on a nonzero exit", async () => {
    const workDir = makeTempDir();
    const error = Object.assign(new Error("no matching request"), { code: 2 });
    const result = await acceptCertificateViaCng({
      certificatePem: FIXTURE_CERT_PEM,
      workDir,
      execFileImpl: makeExecStub({ error, stderr: "CertReq: No match" }),
    });
    assert.equal(result.ok, false);
    assert.equal(result.exitCode, 2);
    assert.match(result.stderrExcerpt, /No match/);
  });

  it("rejects a non-certificate PEM before invoking execFile", async () => {
    const workDir = makeTempDir();
    const execFileImpl = makeExecStub();
    await assert.rejects(
      acceptCertificateViaCng({ certificatePem: "not a pem", workDir, execFileImpl }),
      /not a recognizable PEM block/,
    );
    assert.equal(execFileImpl.calls.length, 0);
  });

  it("mirrors into a non-default store via addstore + repairstore, then deletes the My-store copy", async () => {
    const workDir = makeTempDir();
    const calls = [];
    const execFileImpl = (file, args, options, callback) => {
      calls.push({ file, args });
      process.nextTick(() => callback(null, "", ""));
    };

    const result = await acceptCertificateViaCng({
      certificatePem: FIXTURE_CERT_PEM,
      workDir,
      store: "WebHosting",
      execFileImpl,
    });

    assert.equal(result.ok, true);
    assert.equal(result.store, "WebHosting");
    assert.equal(result.thumbprint, FIXTURE_THUMBPRINT);

    // certreq -accept, then certutil -addstore, -repairstore, -delstore, in that order.
    assert.equal(calls.length, 4);
    assert.equal(calls[0].file, "certreq.exe");
    assert.deepEqual(calls[0].args.slice(0, 2), ["-q", "-accept"]);
    assert.equal(calls[1].file, "certutil.exe");
    assert.deepEqual(calls[1].args.slice(0, 2), ["-addstore", "WebHosting"]);
    assert.equal(calls[2].file, "certutil.exe");
    assert.deepEqual(calls[2].args, ["-repairstore", "WebHosting", FIXTURE_THUMBPRINT]);
    assert.equal(calls[3].file, "certutil.exe");
    assert.deepEqual(calls[3].args, ["-delstore", "My", FIXTURE_THUMBPRINT]);
  });

  it("touches certreq only, never certutil, for the default My store", async () => {
    const workDir = makeTempDir();
    const calls = [];
    const execFileImpl = (file, args, options, callback) => {
      calls.push({ file, args });
      process.nextTick(() => callback(null, "", ""));
    };
    const result = await acceptCertificateViaCng({
      certificatePem: FIXTURE_CERT_PEM,
      workDir,
      store: "My",
      execFileImpl,
    });
    assert.equal(result.ok, true);
    assert.equal(result.store, "My");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].file, "certreq.exe");
  });

  it("stops at addstore and never calls repairstore/delstore when addstore fails", async () => {
    const workDir = makeTempDir();
    const calls = [];
    const execFileImpl = (file, args, options, callback) => {
      calls.push({ file, args });
      if (file === "certutil.exe" && args[0] === "-addstore") {
        process.nextTick(() =>
          callback(Object.assign(new Error("access denied"), { code: 5 }), "", "Access is denied."),
        );
        return;
      }
      process.nextTick(() => callback(null, "", ""));
    };

    const result = await acceptCertificateViaCng({
      certificatePem: FIXTURE_CERT_PEM,
      workDir,
      store: "WebHosting",
      execFileImpl,
    });

    assert.equal(result.ok, false);
    assert.equal(result.stage, "addstore");
    assert.match(result.stderrExcerpt, /Access is denied/);
    // Only certreq -accept and the failed addstore call; repairstore/delstore never ran.
    assert.equal(calls.length, 2);
  });

  it("stops at repairstore and never calls delstore when repairstore fails", async () => {
    const workDir = makeTempDir();
    const calls = [];
    const execFileImpl = (file, args, options, callback) => {
      calls.push({ file, args });
      if (file === "certutil.exe" && args[0] === "-repairstore") {
        process.nextTick(() =>
          callback(Object.assign(new Error("no key match"), { code: 1 }), "", "no matching key found"),
        );
        return;
      }
      process.nextTick(() => callback(null, "", ""));
    };

    const result = await acceptCertificateViaCng({
      certificatePem: FIXTURE_CERT_PEM,
      workDir,
      store: "WebHosting",
      execFileImpl,
    });

    assert.equal(result.ok, false);
    assert.equal(result.stage, "repairstore");
    assert.match(result.stderrExcerpt, /no matching key found/);
    assert.equal(calls.length, 3);
  });

  it("rejects a store name outside the safe alphabet before invoking execFile", async () => {
    const workDir = makeTempDir();
    const execFileImpl = makeExecStub();
    await assert.rejects(
      acceptCertificateViaCng({
        certificatePem: FIXTURE_CERT_PEM,
        workDir,
        store: 'evil"; rm -rf /',
        execFileImpl,
      }),
      /store must match/,
    );
    assert.equal(execFileImpl.calls.length, 0);
  });
});

// ---------------------------------------------------------------------------
// acquireStoreLock: mutex semantics (decision 13)
// ---------------------------------------------------------------------------

describe("acquireStoreLock", () => {
  it("acquires and releases cleanly", () => {
    const stateDir = makeTempDir();
    const lock = acquireStoreLock(stateDir, "My");
    assert.equal(fs.existsSync(lock.lockPath), true);
    lock.release();
    assert.equal(fs.existsSync(lock.lockPath), false);
  });

  it("refuses a second concurrent acquisition on the same store", () => {
    const stateDir = makeTempDir();
    const lock = acquireStoreLock(stateDir, "My");
    assert.throws(() => acquireStoreLock(stateDir, "My"), /is locked by a concurrent/);
    lock.release();
  });

  it("allows independent locks on different stores", () => {
    const stateDir = makeTempDir();
    const lockMy = acquireStoreLock(stateDir, "My");
    const lockWebHosting = acquireStoreLock(stateDir, "WebHosting");
    lockMy.release();
    lockWebHosting.release();
  });

  it("release is idempotent", () => {
    const stateDir = makeTempDir();
    const lock = acquireStoreLock(stateDir, "My");
    lock.release();
    assert.doesNotThrow(() => lock.release());
  });

  it("rejects a store name outside the safe alphabet", () => {
    const stateDir = makeTempDir();
    assert.throws(
      () => acquireStoreLock(stateDir, "My/../../evil"),
      /invalid store name/,
    );
  });

  it("WINDOWS_STORE_NAME_PATTERN accepts common store names", () => {
    for (const name of ["My", "WebHosting", "Root", "custom-store_1"]) {
      assert.equal(WINDOWS_STORE_NAME_PATTERN.test(name), true);
    }
  });

  it("steals a lock left behind by a process that is no longer alive (crash/OOM/taskkill)", () => {
    const stateDir = makeTempDir();
    const lockDir = path.join(stateDir, "windows-cert-store");
    fs.mkdirSync(lockDir, { recursive: true });
    const lockPath = path.join(lockDir, "My.lock");
    // PID 0 is never a real process on Windows or POSIX, and isProcessAlive
    // treats a non-positive PID as dead outright -- this stands in for "the
    // recorded PID has since exited" without depending on OS PID reuse
    // timing in the test itself.
    fs.writeFileSync(lockPath, `0\n${new Date().toISOString()}\n`);

    const lock = acquireStoreLock(stateDir, "My");
    assert.equal(fs.existsSync(lock.lockPath), true);
    const contents = fs.readFileSync(lock.lockPath, "utf8");
    assert.equal(contents.startsWith(`${process.pid}\n`), true);
    lock.release();
  });

  it("steals a lock that has simply existed longer than MAX_STORE_LOCK_AGE_MS, even if its PID is still alive", () => {
    const stateDir = makeTempDir();
    const lockDir = path.join(stateDir, "windows-cert-store");
    fs.mkdirSync(lockDir, { recursive: true });
    const lockPath = path.join(lockDir, "My.lock");
    const ancientTimestamp = new Date(Date.now() - MAX_STORE_LOCK_AGE_MS - 1000).toISOString();
    // Uses this test's own PID, which is genuinely alive -- proving the
    // steal is driven by age, not liveness, in this case.
    fs.writeFileSync(lockPath, `${process.pid}\n${ancientTimestamp}\n`);

    const lock = acquireStoreLock(stateDir, "My");
    assert.equal(fs.existsSync(lock.lockPath), true);
    lock.release();
  });

  it("does NOT steal a fresh lock held by a live process: still fails with STORE_LOCKED", () => {
    const stateDir = makeTempDir();
    const lock = acquireStoreLock(stateDir, "My");
    assert.throws(() => acquireStoreLock(stateDir, "My"), /is locked by a concurrent/);
    lock.release();
  });

  it("isStoreLockStale returns false for an unparseable lock file (fails closed)", () => {
    const stateDir = makeTempDir();
    const lockDir = path.join(stateDir, "windows-cert-store");
    fs.mkdirSync(lockDir, { recursive: true });
    const lockPath = path.join(lockDir, "My.lock");
    fs.writeFileSync(lockPath, "not a lock file at all");

    assert.equal(isStoreLockStale(lockPath), false);
    assert.throws(() => acquireStoreLock(stateDir, "My"), /is locked by a concurrent/);
  });

  it("isStoreLockStale returns true for a lock file that no longer exists", () => {
    const stateDir = makeTempDir();
    const lockPath = path.join(stateDir, "windows-cert-store", "My.lock");
    assert.equal(isStoreLockStale(lockPath), true);
  });

  it("isProcessAlive(0) and isProcessAlive(-1) are false; isProcessAlive(process.pid) is true", () => {
    assert.equal(isProcessAlive(0), false);
    assert.equal(isProcessAlive(-1), false);
    assert.equal(isProcessAlive(process.pid), true);
  });

  it("parseStoreLockContents round-trips a real lock file's own format", () => {
    const now = new Date();
    const parsed = parseStoreLockContents(`${process.pid}\n${now.toISOString()}\n`);
    assert.equal(parsed.pid, process.pid);
    assert.equal(parsed.createdAt.getTime(), now.getTime());
  });

  it("parseStoreLockContents returns null for garbage input", () => {
    assert.equal(parseStoreLockContents("garbage"), null);
    assert.equal(parseStoreLockContents(""), null);
  });
});

// ---------------------------------------------------------------------------
// removeAbandonedKeyContainer: cleanup for a CSR container that never
// reached acceptCertificateViaCng (ACME failure/rejection between the two).
// ---------------------------------------------------------------------------

describe("removeAbandonedKeyContainer", () => {
  it("invokes certutil -csp <KSP> -delkey <containerName> without a shell", async () => {
    const execFileImpl = makeExecStub({});
    const containerName = buildContainerName("job-99");

    const result = await removeAbandonedKeyContainer({ containerName, execFileImpl });

    assert.equal(result.ok, true);
    assert.equal(execFileImpl.calls.length, 1);
    const call = execFileImpl.calls[0];
    assert.equal(call.file, "certutil.exe");
    assert.deepEqual(call.args, [
      "-csp",
      "Microsoft Software Key Storage Provider",
      "-delkey",
      containerName,
    ]);
    assert.equal(call.options.shell, undefined);
  });

  it("does NOT call -delstore first (unlike removeCertificateAndKeyContainer): only one certutil call", async () => {
    const execFileImpl = makeExecStub({});
    await removeAbandonedKeyContainer({
      containerName: buildContainerName("job-1"),
      execFileImpl,
    });
    assert.equal(execFileImpl.calls.length, 1);
    assert.equal(execFileImpl.calls[0].args[0], "-csp");
  });

  it("returns ok:false with exit code and excerpts when certutil -delkey fails", async () => {
    const execFileImpl = makeExecStub({
      error: Object.assign(new Error("boom"), { code: 1 }),
      stderr: "certutil: key container not found",
    });

    const result = await removeAbandonedKeyContainer({
      containerName: buildContainerName("job-2"),
      execFileImpl,
    });

    assert.equal(result.ok, false);
    assert.equal(result.exitCode, 1);
    assert.match(result.stderrExcerpt, /key container not found/);
  });

  it("rejects a containerName outside the safe alphabet before invoking execFile", async () => {
    const execFileImpl = makeExecStub({});
    await assert.rejects(
      removeAbandonedKeyContainer({ containerName: "evil;rm -rf", execFileImpl }),
      /containerName must match/,
    );
    assert.equal(execFileImpl.calls.length, 0);
  });
});
