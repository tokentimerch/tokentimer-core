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
  filesystemSafeJobId,
  decodeEnrollmentSnapshot,
  mapSnapshotKeyAlgorithm,
  resolvePinnedCaCertPath,
  cachePinnedCaCert,
  writeEnrollmentRequestJournal,
  readEnrollmentRequestJournal,
} = require("./adcs-enrollment");

function makeOpenSslCa(dir) {
  const keyPath = path.join(dir, "ca.key");
  const pemPath = path.join(dir, "ca.pem");
  const result = spawnSync(
    "openssl",
    [
      "req",
      "-x509",
      "-new",
      "-nodes",
      "-newkey",
      "rsa:2048",
      "-keyout",
      keyPath,
      "-out",
      pemPath,
      "-days",
      "1",
      "-subj",
      "/CN=TestCA",
    ],
    { encoding: "utf8" },
  );
  if (result.status !== 0) return null;
  const pem = fs.readFileSync(pemPath);
  const cert = new X509Certificate(pem);
  const spki = cert.publicKey.export({ type: "spki", format: "der" });
  return {
    pem,
    caKeySha256: crypto.createHash("sha256").update(spki).digest("hex"),
  };
}

describe("filesystemSafeJobId", () => {
  it("replaces characters Windows rejects in directory names", () => {
    assert.equal(filesystemSafeJobId("job:with:colons"), "job_with_colons");
    assert.match(filesystemSafeJobId("a".repeat(200)), /^a{128}$/);
  });
});

describe("decodeEnrollmentSnapshot", () => {
  const enrollmentId = "11111111-2222-3333-4444-555555555555";
  const snapshot = {
    kind: "adcs",
    caConfig: "ca.example.com\\Example CA",
    template: "WebServer",
    caKeySha256: "a".repeat(64),
    authorizedDnsNames: ["app.example.com"],
    keyAlgorithm: "ecdsa",
    keySize: 256,
  };
  const snapshotBytes = Buffer.from(JSON.stringify(snapshot), "utf8");
  const snapshotSha256 = crypto
    .createHash("sha256")
    .update(snapshotBytes)
    .digest("hex");
  const snapshotB64 = snapshotBytes.toString("base64");

  it("accepts a well-formed enrollment binding", () => {
    const decoded = decodeEnrollmentSnapshot({
      enrollment: {
        enrollmentId,
        attempt: 2,
        snapshotB64,
        snapshotSha256,
      },
    });
    assert.equal(decoded.ok, true);
    assert.equal(decoded.enrollmentId, enrollmentId);
    assert.equal(decoded.attempt, 2);
    assert.equal(decoded.snapshot.kind, "adcs");
  });

  it("rejects a digest mismatch", () => {
    const decoded = decodeEnrollmentSnapshot({
      enrollment: {
        enrollmentId,
        attempt: 1,
        snapshotB64,
        snapshotSha256: "b".repeat(64),
      },
    });
    assert.equal(decoded.ok, false);
    assert.match(decoded.error, /does not match/);
  });
});

describe("mapSnapshotKeyAlgorithm", () => {
  it("maps snapshot keyAlgorithm/keySize to CNG algorithm ids", () => {
    assert.deepEqual(
      mapSnapshotKeyAlgorithm({ keyAlgorithm: "ecdsa", keySize: 256 }),
      { algorithm: "ec-p256" },
    );
    assert.deepEqual(
      mapSnapshotKeyAlgorithm({ keyAlgorithm: "rsa", keySize: 2048 }),
      { algorithm: "rsa-2048" },
    );
  });
});

describe("pinned CA cert cache and RequestId journal", () => {
  let stateDir;

  beforeEach(() => {
    stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "adcs-enroll-"));
  });

  afterEach(() => {
    fs.rmSync(stateDir, { recursive: true, force: true });
  });

  it("pins a CA cert under stateDir/adcs-ca and refuses a pin mismatch", async (t) => {
    const ca = makeOpenSslCa(stateDir);
    if (!ca) {
      // skip-reason: no-host - needs a real openssl binary on PATH
      t.skip("openssl not available");
      return;
    }
    const dest = await cachePinnedCaCert({
      stateDir,
      caKeySha256: ca.caKeySha256,
      certBytes: ca.pem,
    });
    const resolved = resolvePinnedCaCertPath({
      stateDir,
      caKeySha256: ca.caKeySha256,
    });
    assert.equal(resolved.ok, true);
    assert.equal(resolved.caCertPath, dest);

    const wrong = resolvePinnedCaCertPath({
      stateDir,
      caKeySha256: "c".repeat(64),
      caCertPath: dest,
    });
    assert.equal(wrong.ok, false);
    assert.equal(wrong.errorCode, "ADCS_CA_KEY_UNPINNED");
  });

  it("round-trips the RequestId journal", async () => {
    const enrollmentId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const containerName = `tokentimer-enr-${enrollmentId}`;
    const csrPem =
      "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n";
    await writeEnrollmentRequestJournal({
      stateDir,
      enrollmentId,
      attempt: 1,
      requestId: 99,
      snapshotSha256: "d".repeat(64),
      jobId: "job:1",
      csrSpkiSha256: "e".repeat(64),
      templateOid: "1.3.6.1.4.1.311.21.8.1.2.3",
      containerName,
      csrPem,
    });
    const read = readEnrollmentRequestJournal(stateDir, enrollmentId);
    assert.equal(read.requestId, 99);
    assert.equal(read.attempt, 1);
    assert.equal(read.csrSpkiSha256, "e".repeat(64));
    assert.equal(read.templateOid, "1.3.6.1.4.1.311.21.8.1.2.3");
    assert.equal(read.containerName, containerName);
  });
});
