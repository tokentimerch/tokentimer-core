"use strict";

/**
 * Tests for packages/agent/src/windows-cert-store/index.js.
 *
 * These tests never require a real Windows host: certreq invocations are
 * exercised through an injected execFile stub (same pattern as
 * acme/acme.test.js), and the thumbprint/PEM-parsing logic is verified
 * against the real fixture certificate already committed for
 * verify/verify.test.js, cross-checked against node:crypto's own
 * X509Certificate.fingerprint so the Windows thumbprint cannot silently
 * drift from what a real certificate parser reports.
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
  buildEnrollmentContainerName,
  isAgentOwnedContainerName,
  recordIssuedContainer,
  hasIssuedContainerRecord,
  removeIssuedContainerRecord,
  buildCertreqInf,
  computeSha1ThumbprintFromPem,
  normalizeCsrPemLabel,
  generateCsrViaCng,
  acceptCertificateViaCng,
  acquireStoreLock,
  acquireEnrollmentLock,
  acquireExclusiveLockFile,
  exclusiveLockIpcPath,
  exclusiveLockIpcTarget,
  parseStoreLockContents,
  removeAbandonedKeyContainer,
  removeCertificateAndKeyContainer,
  WINDOWS_STORE_NAME_PATTERN,
} = require("./index.js");
const { spawn } = require("node:child_process");

const FIXTURE_CERT_PEM = fs.readFileSync(
  path.join(__dirname, "..", "verify", "fixtures", "selfsigned.crt.pem"),
  "utf8",
);
const FIXTURE_THUMBPRINT = new X509Certificate(FIXTURE_CERT_PEM)
  .fingerprint.replace(/:/g, "")
  .toUpperCase();

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

describe("buildEnrollmentContainerName", () => {
  const ENROLLMENT_ID = "3f2c8a1e-4b5d-4e6f-8a7b-9c0d1e2f3a4b";

  it("is deterministic per enrollment and agent-owned", () => {
    const name = buildEnrollmentContainerName(ENROLLMENT_ID);
    assert.equal(name, `tokentimer-enr-${ENROLLMENT_ID}`);
    assert.equal(buildEnrollmentContainerName(ENROLLMENT_ID), name);
    assert.equal(isAgentOwnedContainerName(name), true);
  });

  it("rejects anything but a lowercase UUID instead of sanitizing it", () => {
    for (const bad of [
      ENROLLMENT_ID.toUpperCase(),
      `${ENROLLMENT_ID}x`,
      "3f2c8a1e4b5d4e6f8a7b9c0d1e2f3a4b",
      "../3f2c8a1e-4b5d-4e6f-8a7b-9c0d1e2f3a4b",
      "",
      null,
      undefined,
      42,
    ]) {
      assert.throws(() => buildEnrollmentContainerName(bad), /enrollmentId must be a lowercase UUID/);
    }
  });

  it("never produces a name buildContainerName could produce", () => {
    // Even for a job id shaped like an enrollment container, the ACME name
    // keeps its random 8-hex suffix and so cannot equal the enrollment one.
    const acme = buildContainerName(`enr-${ENROLLMENT_ID}`);
    assert.notEqual(acme, buildEnrollmentContainerName(ENROLLMENT_ID));
    assert.match(acme, /-[a-f0-9]{8}$/);
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

describe("recordIssuedContainer / hasIssuedContainerRecord / removeIssuedContainerRecord", () => {
  it("records an issuance, reports it present, then removes it", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-windows-cert-store-"));
    try {
      const containerName = buildContainerName("job-1");
      assert.equal(hasIssuedContainerRecord({ stateDir: dir, containerName }), false);

      recordIssuedContainer({ stateDir: dir, containerName, jobId: "job-1", certificateId: "cert-1" });
      assert.equal(hasIssuedContainerRecord({ stateDir: dir, containerName }), true);

      removeIssuedContainerRecord({ stateDir: dir, containerName });
      assert.equal(hasIssuedContainerRecord({ stateDir: dir, containerName }), false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("hasIssuedContainerRecord returns false for an unrelated container name, never throws", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-windows-cert-store-"));
    try {
      recordIssuedContainer({ stateDir: dir, containerName: buildContainerName("job-1") });
      assert.equal(
        hasIssuedContainerRecord({ stateDir: dir, containerName: buildContainerName("job-2") }),
        false,
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("removeIssuedContainerRecord is a silent no-op when no record exists", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-windows-cert-store-"));
    try {
      assert.doesNotThrow(() =>
        removeIssuedContainerRecord({ stateDir: dir, containerName: buildContainerName("job-1") }),
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("recordIssuedContainer rejects a containerName outside the closed alphabet", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-windows-cert-store-"));
    try {
      assert.throws(() =>
        recordIssuedContainer({ stateDir: dir, containerName: "not; safe" }),
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
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
    assert.match(inf, /^Silent = TRUE$/m);
  });

  it("asks for keyEncipherment only on RSA keys", () => {
    const expected = {
      "rsa-2048": "0xa0",
      "rsa-3072": "0xa0",
      "rsa-4096": "0xa0",
      "ec-p256": "0x80",
      "ec-p384": "0x80",
    };
    assert.deepEqual(Object.keys(expected).sort(), [...SUPPORTED_KEY_ALGORITHM_NAMES].sort());
    for (const [algorithm, keyUsage] of Object.entries(expected)) {
      const inf = buildCertreqInf({ ...validInput, algorithm });
      assert.deepEqual(inf.match(/^KeyUsage = .*$/gm), [`KeyUsage = ${keyUsage}`], algorithm);
    }
  });

  it("never names a certificate template", () => {
    for (const algorithm of SUPPORTED_KEY_ALGORITHM_NAMES) {
      const inf = buildCertreqInf({ ...validInput, algorithm });
      assert.doesNotMatch(inf, /RequestAttributes|CertificateTemplate/i);
    }
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

  it("rejects a well-formed CERTIFICATE PEM whose body is not X.509", () => {
    const garbageCertPem =
      "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";
    assert.throws(
      () => computeSha1ThumbprintFromPem(garbageCertPem),
      /did not parse as X\.509/,
    );
  });

  it("rejects a CERTIFICATE REQUEST PEM (label matches, body is not a cert)", () => {
    const csrPem =
      "-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE REQUEST-----\n";
    assert.throws(
      () => computeSha1ThumbprintFromPem(csrPem),
      /did not parse as X\.509/,
    );
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
  it("invokes certreq -q -machine -new <inf> <req> without a shell and with the expected argv shape", async () => {
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
    assert.equal(call.args.length, 5);
    assert.deepEqual(call.args.slice(0, 3), ["-q", "-machine", "-new"]);
    assert.match(call.args[3], /\.inf$/);
    assert.match(call.args[4], /\.req$/);
    assert.equal(call.options.shell, undefined);
  });

  it("names the container after the enrollment when given an enrollmentId", async () => {
    const workDir = makeTempDir();
    const enrollmentId = "3f2c8a1e-4b5d-4e6f-8a7b-9c0d1e2f3a4b";
    let infText = null;
    const execFileImpl = makeExecStub({
      onCall: ({ file, args }) => {
        if (file !== "certreq.exe" || !args.includes("-new")) return;
        infText = fs.readFileSync(args[3], "utf8");
        fs.writeFileSync(
          args[4],
          "-----BEGIN NEW CERTIFICATE REQUEST-----\nMAMCAQA=\n-----END NEW CERTIFICATE REQUEST-----\n",
          "utf8",
        );
      },
    });

    const result = await generateCsrViaCng({
      commonName: "www.example.com",
      jobId: "job-42",
      enrollmentId,
      algorithm: "ec-p256",
      workDir,
      execFileImpl,
    });

    assert.equal(result.ok, true);
    assert.equal(result.containerName, `tokentimer-enr-${enrollmentId}`);
    assert.match(infText, new RegExp(`KeyContainer = "tokentimer-enr-${enrollmentId}"`));
    assert.match(infText, /^KeyUsage = 0x80$/m);
    assert.equal(execFileImpl.calls.length, 2);
    assert.equal(execFileImpl.calls[0].file, "certutil.exe");
    assert.deepEqual(execFileImpl.calls[0].args, [
      "-csp",
      "Microsoft Software Key Storage Provider",
      "-key",
    ]);
    assert.equal(execFileImpl.calls[1].file, "certreq.exe");
  });

  it("refuses a second enrollment generate when the container already exists", async () => {
    const workDir = makeTempDir();
    const enrollmentId = "3f2c8a1e-4b5d-4e6f-8a7b-9c0d1e2f3a4b";
    const containerName = `tokentimer-enr-${enrollmentId}`;
    const execFileImpl = makeExecStub({
      stdout: `Microsoft Software Key Storage Provider:\n  ${containerName}\n`,
    });

    const result = await generateCsrViaCng({
      commonName: "www.example.com",
      jobId: "job-42",
      enrollmentId,
      workDir,
      execFileImpl,
    });

    assert.equal(result.ok, false);
    assert.equal(result.reason, "enrollment_container_exists");
    assert.equal(result.containerName, containerName);
    assert.equal(execFileImpl.calls.length, 1);
    assert.equal(execFileImpl.calls[0].file, "certutil.exe");
    assert.deepEqual(fs.readdirSync(workDir), []);
  });

  it("never calls certreq -new when the Software KSP listing probe fails", async () => {
    const workDir = makeTempDir();
    const enrollmentId = "3f2c8a1e-4b5d-4e6f-8a7b-9c0d1e2f3a4b";
    const error = Object.assign(new Error("certutil failed"), { code: 1 });
    const execFileImpl = makeExecStub({
      error,
      stderr: "CertUtil: The system cannot find the path specified.",
    });

    const result = await generateCsrViaCng({
      commonName: "www.example.com",
      jobId: "job-42",
      enrollmentId,
      workDir,
      execFileImpl,
    });

    assert.equal(result.ok, false);
    assert.equal(result.reason, "enrollment_container_probe_failed");
    assert.equal(execFileImpl.calls.length, 1);
    assert.equal(execFileImpl.calls[0].file, "certutil.exe");
    assert.equal(
      execFileImpl.calls.some((call) => call.file === "certreq.exe"),
      false,
    );
    assert.deepEqual(fs.readdirSync(workDir), []);
  });

  it("does not treat a similarly named KSP line as the enrollment container", async () => {
    const workDir = makeTempDir();
    const enrollmentId = "3f2c8a1e-4b5d-4e6f-8a7b-9c0d1e2f3a4b";
    const containerName = `tokentimer-enr-${enrollmentId}`;
    let infText = null;
    const execFileImpl = makeExecStub({
      onCall: ({ file, args }) => {
        if (file === "certutil.exe") {
          // Prefix / suffix neighbors must not match the exact listing line.
          return;
        }
        if (file === "certreq.exe" && args.includes("-new")) {
          infText = fs.readFileSync(args[3], "utf8");
          fs.writeFileSync(
            args[4],
            "-----BEGIN NEW CERTIFICATE REQUEST-----\nMAMCAQA=\n-----END NEW CERTIFICATE REQUEST-----\n",
            "utf8",
          );
        }
      },
      stdout: [
        "Microsoft Software Key Storage Provider:",
        `  ${containerName}-extra`,
        `  prefix-${containerName}`,
        "",
      ].join("\n"),
    });

    const result = await generateCsrViaCng({
      commonName: "www.example.com",
      jobId: "job-42",
      enrollmentId,
      workDir,
      execFileImpl,
    });

    assert.equal(result.ok, true);
    assert.equal(result.containerName, containerName);
    assert.match(infText, new RegExp(`KeyContainer = "${containerName}"`));
    assert.equal(execFileImpl.calls[0].file, "certutil.exe");
    assert.equal(execFileImpl.calls[1].file, "certreq.exe");
  });

  it("rejects a malformed enrollmentId before ever invoking execFile", async () => {
    const workDir = makeTempDir();
    const execFileImpl = makeExecStub();
    await assert.rejects(
      generateCsrViaCng({
        commonName: "www.example.com",
        jobId: "job-42",
        enrollmentId: "not-a-uuid",
        workDir,
        execFileImpl,
      }),
      /enrollmentId must be a lowercase UUID/,
    );
    assert.equal(execFileImpl.calls.length, 0);
    assert.deepEqual(fs.readdirSync(workDir), []);
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
  it("invokes certreq -q -machine -accept <cer> without a shell and returns the precomputed thumbprint", async () => {
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
    assert.equal(call.args.length, 4);
    assert.deepEqual(call.args.slice(0, 3), ["-q", "-machine", "-accept"]);
    assert.match(call.args[3], /\.cer$/);
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

  it("rejects a garbage CERTIFICATE PEM before invoking execFile", async () => {
    const workDir = makeTempDir();
    const execFileImpl = makeExecStub();
    const garbageCertPem =
      "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";
    await assert.rejects(
      acceptCertificateViaCng({
        certificatePem: garbageCertPem,
        workDir,
        execFileImpl,
      }),
      /did not parse as X\.509/,
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

    // certreq -accept, then certutil -addstore, -repairstore, -delstore, -store (verify), in that order.
    assert.equal(calls.length, 5);
    assert.equal(calls[0].file, "certreq.exe");
    assert.deepEqual(calls[0].args.slice(0, 3), ["-q", "-machine", "-accept"]);
    assert.equal(calls[1].file, "certutil.exe");
    assert.deepEqual(calls[1].args.slice(0, 2), ["-addstore", "WebHosting"]);
    assert.equal(calls[2].file, "certutil.exe");
    assert.deepEqual(calls[2].args, ["-repairstore", "WebHosting", FIXTURE_THUMBPRINT]);
    assert.equal(calls[3].file, "certutil.exe");
    assert.deepEqual(calls[3].args, ["-delstore", "My", FIXTURE_THUMBPRINT]);
    assert.equal(calls[4].file, "certutil.exe");
    assert.deepEqual(calls[4].args, ["-store", "WebHosting", FIXTURE_THUMBPRINT]);
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

  it("stops at the post-mirror verify query (and reports it as its own stage) when the certificate is not actually retrievable from targetStore afterward", async () => {
    const workDir = makeTempDir();
    const calls = [];
    const execFileImpl = (file, args, options, callback) => {
      calls.push({ file, args });
      if (file === "certutil.exe" && args[0] === "-store") {
        process.nextTick(() =>
          callback(Object.assign(new Error("not found"), { code: 1 }), "", "Object was not found."),
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
    assert.equal(result.stage, "verify");
    assert.match(result.stderrExcerpt, /Object was not found/);
    // addstore, repairstore, delstore all ran (each reported success); only
    // the final independent confirmation query failed.
    assert.equal(calls.length, 5);
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

  it("recovers after the holder worker crashes without an explicit release", async () => {
    const stateDir = makeTempDir();
    const lock = acquireStoreLock(stateDir, "My");
    await lock._workerForTests.terminate();
    // Kernel drops the pipe/socket listen on worker death; a marker file
    // left behind must not block the next acquisition.
    const next = acquireStoreLock(stateDir, "My");
    assert.equal(typeof next.ownerToken, "string");
    next.release();
  });

  it("does not treat an abandoned or corrupt marker file as the mutex", () => {
    const stateDir = makeTempDir();
    const lockDir = path.join(stateDir, "windows-cert-store");
    fs.mkdirSync(lockDir, { recursive: true });
    const lockPath = path.join(lockDir, "My.lock");
    fs.writeFileSync(lockPath, ""); // crash between listen and marker write
    const lock = acquireStoreLock(stateDir, "My");
    assert.equal(fs.existsSync(lock.lockPath), true);
    lock.release();
    fs.writeFileSync(lockPath, "not a lock file at all");
    const again = acquireStoreLock(stateDir, "My");
    again.release();
  });

  it("does NOT steal a lock held by a live process: still fails with STORE_LOCKED", () => {
    const stateDir = makeTempDir();
    const lock = acquireStoreLock(stateDir, "My");
    assert.throws(() => acquireStoreLock(stateDir, "My"), /is locked by a concurrent/);
    lock.release();
  });

  it("parseStoreLockContents round-trips a real lock marker's own format", () => {
    const now = new Date();
    const token = "a".repeat(32);
    const parsed = parseStoreLockContents(`${process.pid}\n${now.toISOString()}\n${token}\n`);
    assert.equal(parsed.pid, process.pid);
    assert.equal(parsed.createdAt.getTime(), now.getTime());
    assert.equal(parsed.ownerToken, token);
  });

  it("parseStoreLockContents accepts legacy two-line markers without an owner token", () => {
    const now = new Date();
    const parsed = parseStoreLockContents(`${process.pid}\n${now.toISOString()}\n`);
    assert.equal(parsed.pid, process.pid);
    assert.equal(parsed.ownerToken, null);
  });

  it("parseStoreLockContents returns null for garbage input", () => {
    assert.equal(parseStoreLockContents("garbage"), null);
    assert.equal(parseStoreLockContents(""), null);
  });

  it("release of a prior same-process holder cannot drop a later holder's IPC lock", () => {
    const stateDir = makeTempDir();
    const first = acquireStoreLock(stateDir, "My");
    const firstToken = first.ownerToken;
    // Simulate the old holder surviving past a crash-recovery acquire by
    // killing its worker (IPC released) then letting a replacement acquire.
    // first.release() must not tear down the replacement's listen.
    return first._workerForTests.terminate().then(() => {
      const second = acquireStoreLock(stateDir, "My");
      assert.notEqual(second.ownerToken, firstToken);
      first.release();
      assert.throws(() => acquireStoreLock(stateDir, "My"), /is locked by a concurrent/);
      second.release();
    });
  });

  it("allows only one cross-process owner among three simultaneous contenders", async () => {
    const stateDir = makeTempDir();
    const lockPath = path.join(stateDir, "windows-cert-store", "race.lock");
    fs.mkdirSync(path.dirname(lockPath), { recursive: true });
    const barrierDir = makeTempDir();
    const script = `
      const fs = require("fs");
      const path = require("path");
      const { acquireExclusiveLockFile } = require(${JSON.stringify(path.join(__dirname, "index.js"))});
      const lockPath = process.env.TT_LOCK_PATH;
      const barrierDir = process.env.TT_BARRIER_DIR;
      const id = process.env.TT_CONTENDER_ID;
      fs.writeFileSync(path.join(barrierDir, id + ".ready"), "1");
      const deadline = Date.now() + 10000;
      while (Date.now() < deadline) {
        const ready = fs.readdirSync(barrierDir).filter((n) => n.endsWith(".ready"));
        if (ready.length >= 3) break;
      }
      try {
        const lock = acquireExclusiveLockFile(lockPath, "STORE_LOCKED", "busy");
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
    for (const name of lost) {
      assert.equal(fs.readFileSync(path.join(barrierDir, name), "utf8"), "STORE_LOCKED");
    }
  });

  it("exclusiveLockIpcPath is short, hashed, and stable (no long-path collision)", () => {
    const base = path.join(makeTempDir(), "a".repeat(120));
    const p1 = path.join(base, "one.lock");
    const p2 = path.join(base, "two.lock");
    assert.equal(exclusiveLockIpcPath(p1), exclusiveLockIpcPath(p1));
    assert.notEqual(exclusiveLockIpcPath(p1), exclusiveLockIpcPath(p2));
    const t1 = exclusiveLockIpcTarget(p1);
    const t2 = exclusiveLockIpcTarget(p2);
    if (process.platform === "win32") {
      assert.equal(t1.ipcKind, "pipe");
      assert.match(t1.ipcPath, /^\\\\\.\\pipe\\tokentimer-agent-[0-9a-f]{40}$/);
    } else if (process.platform === "linux") {
      assert.equal(t1.ipcKind, "abstract");
      assert.equal(t1.ipcPath.charCodeAt(0), 0);
      assert.ok(t1.ipcPath.length < 80);
    } else {
      assert.equal(t1.ipcKind, "file");
      assert.ok(t1.ipcPath.length < 120);
      assert.ok(t1.ipcPath.startsWith(path.join(os.tmpdir(), "tokentimer-agent-ipc")));
    }
    // Distinct long lock paths must be independently acquirable.
    const a = acquireExclusiveLockFile(p1, "STORE_LOCKED", "busy");
    const b = acquireExclusiveLockFile(p2, "STORE_LOCKED", "busy");
    assert.notEqual(a.ownerToken, b.ownerToken);
    a.release();
    b.release();
    void t2;
  });

  it("assertHeld fails after the lock worker dies while the parent still thinks it owns the lock", async () => {
    const stateDir = makeTempDir();
    const lock = acquireStoreLock(stateDir, "My");
    assert.doesNotThrow(() => lock.assertHeld());
    await lock._workerForTests.terminate();
    // Heartbeat goes stale without waiting for the exit event delivery.
    await new Promise((r) => setTimeout(r, 600));
    assert.equal(lock.lost, true);
    assert.throws(() => lock.assertHeld(), (err) => {
      assert.equal(err.code, "STORE_LOCK_LOST");
      return true;
    });
    // Successor may acquire; prior holder must not continue protected work.
    const next = acquireStoreLock(stateDir, "My");
    assert.throws(() => lock.assertHeld(), /lock lost/);
    next.release();
    lock.release();
  });

  it("lock.run aborts an in-flight critical section when the worker dies", async () => {
    const stateDir = makeTempDir();
    const lock = acquireStoreLock(stateDir, "My");
    let afterLoss = false;
    const work = lock.run(async (signal) => {
      await new Promise((r) => setTimeout(r, 50));
      await lock._workerForTests.terminate();
      await new Promise((resolve, reject) => {
        if (signal.aborted) {
          reject(signal.reason);
          return;
        }
        const timer = setTimeout(resolve, 2000);
        signal.addEventListener(
          "abort",
          () => {
            clearTimeout(timer);
            reject(signal.reason);
          },
          { once: true },
        );
      });
      afterLoss = true;
      return "should-not-resolve";
    });
    await assert.rejects(work, (err) => {
      assert.equal(err.code, "STORE_LOCK_LOST");
      return true;
    });
    assert.equal(afterLoss, false);
    lock.release();
    const next = acquireStoreLock(stateDir, "My");
    next.release();
  });

  it("release after worker death still frees the IPC name for a successor", async () => {
    const stateDir = makeTempDir();
    const lock = acquireStoreLock(stateDir, "My");
    await lock._workerForTests.terminate();
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(lock.lost, true);
    // release() must not skip terminate when lost is already set.
    lock.release();
    const next = acquireStoreLock(stateDir, "My");
    assert.equal(typeof next.ownerToken, "string");
    next.release();
  });

  it("release then immediate reacquire admits only one of two competing processes", async () => {
    const stateDir = makeTempDir();
    const lockPath = path.join(stateDir, "windows-cert-store", "handoff.lock");
    fs.mkdirSync(path.dirname(lockPath), { recursive: true });
    const held = acquireExclusiveLockFile(lockPath, "STORE_LOCKED", "busy");
    const barrierDir = makeTempDir();
    const script = `
      const fs = require("fs");
      const path = require("path");
      const { acquireExclusiveLockFile } = require(${JSON.stringify(path.join(__dirname, "index.js"))});
      const lockPath = process.env.TT_LOCK_PATH;
      const barrierDir = process.env.TT_BARRIER_DIR;
      const id = process.env.TT_CONTENDER_ID;
      const go = path.join(barrierDir, "go");
      const deadline = Date.now() + 10000;
      while (Date.now() < deadline && !fs.existsSync(go)) {}
      try {
        const lock = acquireExclusiveLockFile(lockPath, "STORE_LOCKED", "busy");
        fs.writeFileSync(path.join(barrierDir, id + ".won"), lock.ownerToken);
        const holdUntil = Date.now() + 800;
        while (Date.now() < holdUntil) {}
        lock.release();
        process.exit(0);
      } catch (err) {
        fs.writeFileSync(path.join(barrierDir, id + ".lost"), err && err.code ? err.code : "ERR");
        process.exit(2);
      }
    `;
    const kids = Promise.all(
      ["b", "c"].map(
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
    // Let children park on the go-file, then release and open the gate.
    await new Promise((r) => setTimeout(r, 200));
    held.release();
    fs.writeFileSync(path.join(barrierDir, "go"), "1");
    await kids;
    const won = fs.readdirSync(barrierDir).filter((n) => n.endsWith(".won"));
    const lost = fs.readdirSync(barrierDir).filter((n) => n.endsWith(".lost"));
    assert.equal(won.length, 1, `won=${won} lost=${lost}`);
    assert.equal(lost.length, 1);
  });
});

describe("exclusiveLockIpcTarget file-socket reclaim (pathname platforms)", () => {
  it("recovers an abandoned reclaim-gate directory left by a crashed worker", async () => {
    if (process.platform === "win32" || process.platform === "linux") {
      return;
    }
    const lockPath = path.join(makeTempDir(), "gate-stale.lock");
    const target = exclusiveLockIpcTarget(lockPath);
    assert.equal(target.ipcKind, "file");
    fs.mkdirSync(path.dirname(target.ipcPath), { recursive: true });
    const gatePath = `${target.ipcPath}.reclaim-gate`;
    fs.mkdirSync(gatePath, { recursive: true });
    const ancient = new Date(Date.now() - 60_000);
    fs.utimesSync(gatePath, ancient, ancient);
    // Abandoned socket + aged gate: acquire must still succeed.
    const holderScript = `
      const net = require("net");
      const fs = require("fs");
      const s = net.createServer(() => {});
      s.listen({ path: process.env.TT_IPC, exclusive: true }, () => {
        fs.writeFileSync(process.env.TT_READY, "1");
        setInterval(() => {}, 1000);
      });
    `;
    const ready = path.join(makeTempDir(), "ready");
    const holder = spawn(process.execPath, ["-e", holderScript], {
      env: { ...process.env, TT_IPC: target.ipcPath, TT_READY: ready },
      stdio: "ignore",
    });
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && !fs.existsSync(ready)) {
      await new Promise((r) => setTimeout(r, 20));
    }
    holder.kill("SIGKILL");
    await new Promise((r) => holder.once("exit", r));
    const lock = acquireExclusiveLockFile(lockPath, "STORE_LOCKED", "busy");
    assert.equal(typeof lock.ownerToken, "string");
    lock.release();
  });

  it("allows only one owner when two processes reclaim the same abandoned pathname socket", async () => {
    if (process.platform === "win32" || process.platform === "linux") {
      // Named pipes / abstract sockets have no reclaimable filesystem pathname.
      return;
    }
    const lockPath = path.join(makeTempDir(), "stale-reclaim.lock");
    const target = exclusiveLockIpcTarget(lockPath);
    assert.equal(target.ipcKind, "file");
    fs.mkdirSync(path.dirname(target.ipcPath), { recursive: true });
    try {
      fs.unlinkSync(target.ipcPath);
    } catch {
      // ok
    }

    const holderScript = `
      const net = require("net");
      const fs = require("fs");
      const s = net.createServer(() => {});
      s.listen({ path: process.env.TT_IPC, exclusive: true }, () => {
        fs.writeFileSync(process.env.TT_READY, "1");
        setInterval(() => {}, 1000);
      });
    `;
    const ready = path.join(makeTempDir(), "ready");
    const holder = spawn(process.execPath, ["-e", holderScript], {
      env: { ...process.env, TT_IPC: target.ipcPath, TT_READY: ready },
      stdio: "ignore",
    });
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && !fs.existsSync(ready)) {
      await new Promise((r) => setTimeout(r, 20));
    }
    holder.kill("SIGKILL");
    await new Promise((r) => holder.once("exit", r));

    const barrierDir = makeTempDir();
    const script = `
      const fs = require("fs");
      const path = require("path");
      const { acquireExclusiveLockFile } = require(${JSON.stringify(path.join(__dirname, "index.js"))});
      const lockPath = process.env.TT_LOCK_PATH;
      const barrierDir = process.env.TT_BARRIER_DIR;
      const id = process.env.TT_CONTENDER_ID;
      fs.writeFileSync(path.join(barrierDir, id + ".ready"), "1");
      const deadline = Date.now() + 10000;
      while (Date.now() < deadline) {
        if (fs.readdirSync(barrierDir).filter((n) => n.endsWith(".ready")).length >= 2) break;
      }
      try {
        const lock = acquireExclusiveLockFile(lockPath, "STORE_LOCKED", "busy");
        fs.writeFileSync(path.join(barrierDir, id + ".won"), lock.ownerToken);
        const holdUntil = Date.now() + 1200;
        while (Date.now() < holdUntil) {}
        lock.release();
        process.exit(0);
      } catch (err) {
        fs.writeFileSync(path.join(barrierDir, id + ".lost"), err && err.code ? err.code : "ERR");
        process.exit(2);
      }
    `;
    await Promise.all(
      ["a", "b"].map(
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
    assert.equal(lost.length, 1);
  });
});

describe("acquireEnrollmentLock", () => {
  const enrollmentId = "3f2c8a1e-4b5d-4e6f-8a7b-9c0d1e2f3a4b";

  it("acquires and releases independently of the store lock", () => {
    const stateDir = makeTempDir();
    const store = acquireStoreLock(stateDir, "My");
    const enrollment = acquireEnrollmentLock(stateDir, enrollmentId);
    assert.notEqual(store.lockPath, enrollment.lockPath);
    enrollment.release();
    store.release();
  });

  it("refuses a second concurrent acquisition on the same enrollment", () => {
    const stateDir = makeTempDir();
    const lock = acquireEnrollmentLock(stateDir, enrollmentId);
    assert.throws(
      () => acquireEnrollmentLock(stateDir, enrollmentId),
      /enrollment .* is locked by a concurrent AD CS operation/,
    );
    lock.release();
  });

  it("rejects a malformed enrollmentId", () => {
    const stateDir = makeTempDir();
    assert.throws(
      () => acquireEnrollmentLock(stateDir, "not-a-uuid"),
      /enrollmentId must be a lowercase UUID/,
    );
  });
});

// ---------------------------------------------------------------------------
// removeCertificateAndKeyContainer: deletes the store entry, then the CNG
// key container (interrupted-cleanup idempotency).
// ---------------------------------------------------------------------------

describe("removeCertificateAndKeyContainer", () => {
  it("calls -delstore then -delkey, in that order, without a shell", async () => {
    const calls = [];
    const execFileImpl = (file, args, options, callback) => {
      calls.push({ file, args, options });
      process.nextTick(() => callback(null, "", ""));
    };
    const containerName = buildContainerName("job-1");

    const result = await removeCertificateAndKeyContainer({
      thumbprint: FIXTURE_THUMBPRINT,
      store: "My",
      containerName,
      execFileImpl,
    });

    assert.equal(result.ok, true);
    assert.equal(calls.length, 2);
    assert.deepEqual(calls[0].args, ["-delstore", "My", FIXTURE_THUMBPRINT]);
    assert.deepEqual(calls[1].args, [
      "-csp",
      "Microsoft Software Key Storage Provider",
      "-delkey",
      containerName,
    ]);
    assert.equal(calls[0].options.shell, undefined);
    assert.equal(calls[1].options.shell, undefined);
  });

  it("returns ok:false at stage delstore when certutil -delstore fails for a reason other than a missing thumbprint", async () => {
    const execFileImpl = makeExecStub({
      error: Object.assign(new Error("boom"), { code: 5 }),
      stderr: "Access is denied.",
    });
    const result = await removeCertificateAndKeyContainer({
      thumbprint: FIXTURE_THUMBPRINT,
      store: "My",
      containerName: buildContainerName("job-2"),
      execFileImpl,
    });
    assert.equal(result.ok, false);
    assert.equal(result.stage, "delstore");
    assert.equal(result.exitCode, 5);
    assert.match(result.stderrExcerpt, /Access is denied/);
  });

  it(
    "regression: treats certutil -delkey's NTE_BAD_KEYSET (\"Keyset does not exist\") as ok:true, " +
      "not a failure -- real-host finding (2026-08-09): a crash between a first, fully successful " +
      "-delstore+-delkey pair and the caller persisting that success (e.g. windows-retention's " +
      "sweepLedger marking the ledger row \"removed\") left a retried cleanup call failing this second " +
      "half forever, even though the on-disk state was already exactly the desired end state; a missing " +
      "key container must be treated the same way -delstore already treats a missing thumbprint " +
      "(absence IS success for a delete), or the ledger row can never reach \"removed\" and sweepLedger " +
      "retries an operation that can never succeed again on every future sweep",
    async () => {
      const execFileImpl = (file, args, options, callback) => {
        if (args[0] === "-delstore") {
          process.nextTick(() => callback(null, "CertUtil: -delstore command completed successfully.", ""));
          return;
        }
        process.nextTick(() =>
          callback(
            Object.assign(new Error("delkey failed"), { code: -2146893802 }),
            "CertUtil: -delkey command FAILED: 0x80090016 (-2146893802 NTE_BAD_KEYSET)\r\nCertUtil: Keyset does not exist\r\n",
            "",
          ),
        );
      };

      const result = await removeCertificateAndKeyContainer({
        thumbprint: FIXTURE_THUMBPRINT,
        store: "My",
        containerName: buildContainerName("job-3"),
        execFileImpl,
      });

      assert.equal(result.ok, true);
      assert.equal(result.keyContainerAlreadyAbsent, true);
    },
  );

  it("still returns ok:false at stage delkey for a genuine -delkey failure unrelated to NTE_BAD_KEYSET", async () => {
    const execFileImpl = (file, args, options, callback) => {
      if (args[0] === "-delstore") {
        process.nextTick(() => callback(null, "", ""));
        return;
      }
      process.nextTick(() =>
        callback(Object.assign(new Error("access denied"), { code: 5 }), "", "Access is denied."),
      );
    };

    const result = await removeCertificateAndKeyContainer({
      thumbprint: FIXTURE_THUMBPRINT,
      store: "My",
      containerName: buildContainerName("job-4"),
      execFileImpl,
    });

    assert.equal(result.ok, false);
    assert.equal(result.stage, "delkey");
    assert.equal(result.exitCode, 5);
    assert.match(result.stderrExcerpt, /Access is denied/);
  });

  it("never calls -delkey when -delstore fails", async () => {
    const calls = [];
    const execFileImpl = (file, args, options, callback) => {
      calls.push({ args });
      process.nextTick(() => callback(Object.assign(new Error("boom"), { code: 1 }), "", "some error"));
    };
    await removeCertificateAndKeyContainer({
      thumbprint: FIXTURE_THUMBPRINT,
      store: "My",
      containerName: buildContainerName("job-5"),
      execFileImpl,
    });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].args[0], "-delstore");
  });

  it("does not start -delkey when -delstore is aborted by STORE_LOCK_LOST", async () => {
    const calls = [];
    const ac = new AbortController();
    ac.abort(Object.assign(new Error("store lock lost"), { code: "STORE_LOCK_LOST" }));
    const execFileImpl = (file, args, options, callback) => {
      calls.push({ file, args });
      process.nextTick(() => callback(null, "", ""));
    };
    const result = await removeCertificateAndKeyContainer({
      thumbprint: FIXTURE_THUMBPRINT,
      store: "My",
      containerName: buildContainerName("job-abort-delstore"),
      execFileImpl,
      signal: ac.signal,
    });
    assert.equal(result.ok, false);
    assert.equal(result.stage, "delstore");
    assert.equal(result.reason, "aborted");
    assert.equal(calls.length, 0);
  });

  it("does not start -delkey when lock is lost mid -delstore", async () => {
    const calls = [];
    const ac = new AbortController();
    const execFileImpl = (file, args, options, callback) => {
      calls.push({ file, args: [...args] });
      const fakeChild = {
        kill() {
          process.nextTick(() =>
            callback(Object.assign(new Error("killed"), { code: "ABORT_ERR" }), "", ""),
          );
        },
      };
      if (args[0] === "-delstore") {
        setTimeout(
          () => ac.abort(Object.assign(new Error("store lock lost"), { code: "STORE_LOCK_LOST" })),
          10,
        );
        setTimeout(() => callback(null, "late", ""), 500);
        return fakeChild;
      }
      process.nextTick(() => callback(null, "", ""));
      return fakeChild;
    };
    const result = await removeCertificateAndKeyContainer({
      thumbprint: FIXTURE_THUMBPRINT,
      store: "My",
      containerName: buildContainerName("job-abort-mid-delstore"),
      execFileImpl,
      signal: ac.signal,
    });
    assert.equal(result.ok, false);
    assert.equal(result.stage, "delstore");
    assert.equal(result.reason, "aborted");
    assert.equal(
      calls.some((c) => c.args.includes("-delkey")),
      false,
    );
  });

  it("rejects an invalid thumbprint/store/containerName before invoking execFile", async () => {
    const execFileImpl = makeExecStub({});
    await assert.rejects(
      removeCertificateAndKeyContainer({
        thumbprint: "not-hex",
        store: "My",
        containerName: buildContainerName("job-6"),
        execFileImpl,
      }),
      /thumbprint must be a 40-hex-char SHA-1 string/,
    );
    await assert.rejects(
      removeCertificateAndKeyContainer({
        thumbprint: FIXTURE_THUMBPRINT,
        store: "not a store; rm -rf",
        containerName: buildContainerName("job-7"),
        execFileImpl,
      }),
      /store must match/,
    );
    await assert.rejects(
      removeCertificateAndKeyContainer({
        thumbprint: FIXTURE_THUMBPRINT,
        store: "My",
        containerName: "evil;rm -rf",
        execFileImpl,
      }),
      /containerName must match/,
    );
    assert.equal(execFileImpl.calls.length, 0);
  });
});

// ---------------------------------------------------------------------------
// removeAbandonedKeyContainer: cleanup for a CSR container that never
// reached acceptCertificateViaCng (ACME failure/rejection between the two).
// ---------------------------------------------------------------------------

describe("execWithoutShell AbortSignal", () => {
  const { execWithoutShell, mirrorAcceptedCertificateToStore } = require("./index");

  it("normalizes lock-loss abort reasons to ABORT_ERR with cause", async () => {
    const ac = new AbortController();
    const lost = Object.assign(new Error("enrollment lock lost"), {
      code: "ENROLLMENT_LOCK_LOST",
    });
    ac.abort(lost);
    const calls = [];
    const result = await execWithoutShell(
      (file, args, opts, cb) => {
        calls.push({ file, args });
        cb(null, "", "");
      },
      ["certutil.exe", "-delkey", "x"],
      1000,
      ac.signal,
    );
    assert.equal(calls.length, 0);
    assert.equal(result.execError && result.execError.code, "ABORT_ERR");
    assert.equal(result.execError.cause && result.execError.cause.code, "ENROLLMENT_LOCK_LOST");
  });

  it("kills an in-flight child when the signal aborts", async () => {
    const ac = new AbortController();
    let killed = false;
    const resultPromise = execWithoutShell(
      (file, args, opts, cb) => {
        const fakeChild = {
          kill() {
            killed = true;
            process.nextTick(() =>
              cb(Object.assign(new Error("killed"), { code: "ABORT_ERR" }), "", ""),
            );
          },
        };
        setTimeout(
          () => ac.abort(Object.assign(new Error("lost"), { code: "STORE_LOCK_LOST" })),
          20,
        );
        setTimeout(() => cb(null, "late", ""), 500);
        return fakeChild;
      },
      ["certutil.exe", "-delkey", "x"],
      5000,
      ac.signal,
    );
    const result = await resultPromise;
    assert.equal(killed, true);
    assert.equal(result.execError && result.execError.code, "ABORT_ERR");
    assert.equal(result.execError.cause && result.execError.cause.code, "STORE_LOCK_LOST");
  });

  it("terminates a real OS child before abort resolves, not only eventually", async () => {
    const { execFile } = require("node:child_process");
    const ac = new AbortController();
    /** @type {number|null} */
    let childPid = null;
    const resultPromise = execWithoutShell(
      (file, args, opts, cb) => {
        const child = execFile(file, args, opts, cb);
        childPid = child.pid ?? null;
        return child;
      },
      [process.execPath, "-e", "setTimeout(() => {}, 60000)"],
      15000,
      ac.signal,
    );
    for (let i = 0; i < 50 && childPid == null; i += 1) {
      await new Promise((r) => setTimeout(r, 10));
    }
    assert.ok(childPid, "child pid should be assigned before abort");
    assert.doesNotThrow(() => process.kill(childPid, 0), "child should be alive before abort");

    ac.abort(Object.assign(new Error("lost"), { code: "STORE_LOCK_LOST" }));
    const result = await resultPromise;
    assert.equal(result.execError && result.execError.code, "ABORT_ERR");
    assert.equal(result.execError.cause && result.execError.cause.code, "STORE_LOCK_LOST");
    // Promise must not resolve while the child is still shutting down.
    let stillAlive = false;
    try {
      process.kill(childPid, 0);
      stillAlive = true;
    } catch {
      stillAlive = false;
    }
    assert.equal(stillAlive, false, `pid ${childPid} must be gone before ABORT_ERR resolves`);
  });

  it("does not admit a successor while an aborted real child is still alive", async () => {
    const { execFile } = require("node:child_process");
    const stateDir = makeTempDir();
    const lock = acquireStoreLock(stateDir, "My");
    const ac = new AbortController();
    /** @type {number|null} */
    let childPid = null;
    /** @type {boolean} */
    let successorSawLivePredecessor = false;

    const workPromise = (async () => {
      const result = await execWithoutShell(
        (file, args, opts, cb) => {
          const child = execFile(file, args, opts, cb);
          childPid = child.pid ?? null;
          return child;
        },
        [process.execPath, "-e", "setTimeout(() => {}, 60000)"],
        15000,
        ac.signal,
      );
      // Release only after execWithoutShell confirms child exit.
      lock.release();
      return result;
    })();

    for (let i = 0; i < 50 && childPid == null; i += 1) {
      await new Promise((r) => setTimeout(r, 10));
    }
    assert.ok(childPid, "child pid should be assigned before abort");

    ac.abort(Object.assign(new Error("lost"), { code: "STORE_LOCK_LOST" }));

    const successorProbe = (async () => {
      for (let i = 0; i < 200; i += 1) {
        try {
          const next = acquireStoreLock(stateDir, "My");
          try {
            process.kill(childPid, 0);
            successorSawLivePredecessor = true;
          } catch {
            // predecessor already gone — expected ordering
          }
          next.release();
          return;
        } catch {
          await new Promise((r) => setTimeout(r, 10));
        }
      }
    })();

    const result = await workPromise;
    await successorProbe;
    assert.equal(result.execError && result.execError.code, "ABORT_ERR");
    assert.equal(
      successorSawLivePredecessor,
      false,
      "successor must not hold the store lock while the predecessor child is still alive",
    );
  });

  it("maps ENROLLMENT_LOCK_LOST abort during certreq -new to reason aborted", async () => {
    const workDir = makeTempDir();
    const ac = new AbortController();
    ac.abort(
      Object.assign(new Error("enrollment lock lost"), { code: "ENROLLMENT_LOCK_LOST" }),
    );
    const result = await generateCsrViaCng({
      commonName: "host.example.com",
      jobId: "job-abort-new",
      workDir,
      signal: ac.signal,
      execFileImpl: makeExecStub({
        stdout: "-----BEGIN NEW CERTIFICATE REQUEST-----\nMIIB\n-----END NEW CERTIFICATE REQUEST-----\n",
      }),
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, "aborted");
  });

  it("maps ENROLLMENT_LOCK_LOST abort during certreq -accept to reason aborted", async () => {
    const workDir = makeTempDir();
    const ac = new AbortController();
    ac.abort(
      Object.assign(new Error("enrollment lock lost"), { code: "ENROLLMENT_LOCK_LOST" }),
    );
    const result = await acceptCertificateViaCng({
      certificatePem: FIXTURE_CERT_PEM,
      workDir,
      signal: ac.signal,
      execFileImpl: makeExecStub({}),
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, "aborted");
  });

  it("maps STORE_LOCK_LOST abort during mirror addstore to reason aborted", async () => {
    const workDir = makeTempDir();
    const certPath = path.join(workDir, "mirror.cer");
    fs.writeFileSync(certPath, FIXTURE_CERT_PEM, "utf8");
    const ac = new AbortController();
    ac.abort(Object.assign(new Error("store lock lost"), { code: "STORE_LOCK_LOST" }));
    const result = await mirrorAcceptedCertificateToStore({
      certPath,
      thumbprint: FIXTURE_THUMBPRINT,
      targetStore: "WebHosting",
      signal: ac.signal,
      execFileImpl: makeExecStub({}),
    });
    assert.equal(result.ok, false);
    assert.equal(result.stage, "addstore");
    assert.equal(result.reason, "aborted");
  });

  it("kills an in-flight certreq -new when ENROLLMENT_LOCK_LOST aborts mid-call", async () => {
    const workDir = makeTempDir();
    const ac = new AbortController();
    let killed = false;
    const result = await generateCsrViaCng({
      commonName: "host.example.com",
      jobId: "job-inflight-new",
      workDir,
      signal: ac.signal,
      execFileImpl: (file, args, opts, cb) => {
        const fakeChild = {
          kill() {
            killed = true;
            process.nextTick(() =>
              cb(Object.assign(new Error("killed"), { code: "ABORT_ERR" }), "", ""),
            );
          },
        };
        setTimeout(
          () =>
            ac.abort(
              Object.assign(new Error("enrollment lock lost"), { code: "ENROLLMENT_LOCK_LOST" }),
            ),
          15,
        );
        setTimeout(() => cb(null, "late", ""), 500);
        return fakeChild;
      },
    });
    assert.equal(killed, true);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "aborted");
  });

  it("kills an in-flight certreq -accept when ENROLLMENT_LOCK_LOST aborts mid-call", async () => {
    const workDir = makeTempDir();
    const ac = new AbortController();
    let killed = false;
    const result = await acceptCertificateViaCng({
      certificatePem: FIXTURE_CERT_PEM,
      workDir,
      signal: ac.signal,
      execFileImpl: (file, args, opts, cb) => {
        const fakeChild = {
          kill() {
            killed = true;
            process.nextTick(() =>
              cb(Object.assign(new Error("killed"), { code: "ABORT_ERR" }), "", ""),
            );
          },
        };
        setTimeout(
          () =>
            ac.abort(
              Object.assign(new Error("enrollment lock lost"), { code: "ENROLLMENT_LOCK_LOST" }),
            ),
          15,
        );
        setTimeout(() => cb(null, "late", ""), 500);
        return fakeChild;
      },
    });
    assert.equal(killed, true);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "aborted");
  });

  it("kills an in-flight mirror addstore when STORE_LOCK_LOST aborts mid-call", async () => {
    const workDir = makeTempDir();
    const certPath = path.join(workDir, "mirror-inflight.cer");
    fs.writeFileSync(certPath, FIXTURE_CERT_PEM, "utf8");
    const ac = new AbortController();
    let killed = false;
    const result = await mirrorAcceptedCertificateToStore({
      certPath,
      thumbprint: FIXTURE_THUMBPRINT,
      targetStore: "WebHosting",
      signal: ac.signal,
      execFileImpl: (file, args, opts, cb) => {
        const fakeChild = {
          kill() {
            killed = true;
            process.nextTick(() =>
              cb(Object.assign(new Error("killed"), { code: "ABORT_ERR" }), "", ""),
            );
          },
        };
        setTimeout(
          () => ac.abort(Object.assign(new Error("store lock lost"), { code: "STORE_LOCK_LOST" })),
          15,
        );
        setTimeout(() => cb(null, "late", ""), 500);
        return fakeChild;
      },
    });
    assert.equal(killed, true);
    assert.equal(result.ok, false);
    assert.equal(result.stage, "addstore");
    assert.equal(result.reason, "aborted");
  });
});

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
