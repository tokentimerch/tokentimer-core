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
  computeSpkiSha256Hex,
  decodeEnrollmentSnapshot,
  mapSnapshotKeyAlgorithm,
  resolvePinnedCaCertPath,
  cachePinnedCaCert,
  cacheTemplateOid,
  resolveTemplateOid,
  templateOidCachePath,
  PREFLIGHT_CACHE_TTL_MS,
  writeEnrollmentRequestJournal,
  readEnrollmentRequestJournal,
} = require("./adcs-enrollment");
const {
  ADCS_PREFLIGHT_MAX_AGE_MS,
} = require("../../vendor/contracts/adcs-preflight-freshness.cjs");

const CA_CONFIG = "ca01.corp.example.com\\Corp Issuing CA 01";
const TEMPLATE = "TokenTimerWebServer";
const TEMPLATE_OID = "1.3.6.1.4.1.311.21.8.1.2";

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

  it("bounds signed cleanup directives to known terminal states", () => {
    for (const terminalState of ["expired", "cancelled", "abandoned", "installed", "", null]) {
      const decoded = decodeEnrollmentSnapshot({ enrollment: {
        enrollmentId, attempt: 2, snapshotB64, snapshotSha256, terminalState,
      } });
      assert.equal(decoded.ok, ["expired", "cancelled", "abandoned"].includes(terminalState));
      if (decoded.ok) assert.equal(decoded.terminalState, terminalState);
    }
  });

  it("bounds proposed RequestIds and rejects mixed cleanup/reconcile directives", () => {
    for (const reconcileRequestId of [1, 4294967295, 0, -1, 4294967296, 1.5, "77", null]) {
      const decoded = decodeEnrollmentSnapshot({ enrollment: {
        enrollmentId, attempt: 2, snapshotB64, snapshotSha256, reconcileRequestId,
      } });
      assert.equal(decoded.ok, [1, 4294967295].includes(reconcileRequestId));
    }
    assert.equal(decodeEnrollmentSnapshot({ enrollment: { enrollmentId, attempt: 2,
      snapshotB64, snapshotSha256, reconcileRequestId: 77, terminalState: "abandoned" } }).ok, false);
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

  it("reuses a cached template OID only within the preflight TTL", async () => {
    await cacheTemplateOid({ stateDir, caConfig: CA_CONFIG, template: TEMPLATE, templateOid: TEMPLATE_OID });
    const args = { stateDir, caConfig: CA_CONFIG, template: TEMPLATE };
    const file = templateOidCachePath(stateDir, CA_CONFIG, TEMPLATE);
    const writeUpdatedAt = (updatedAt) => {
      const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
      fs.writeFileSync(file, JSON.stringify({ ...parsed, updatedAt }));
    };

    writeUpdatedAt(new Date(Date.now() - PREFLIGHT_CACHE_TTL_MS + 60_000).toISOString());
    assert.deepEqual(resolveTemplateOid(args), { ok: true, templateOid: TEMPLATE_OID });

    writeUpdatedAt(new Date(Date.now() - PREFLIGHT_CACHE_TTL_MS - 60_000).toISOString());
    assert.equal(resolveTemplateOid(args).ok, false);

    writeUpdatedAt("not-a-date");
    assert.equal(resolveTemplateOid(args).ok, false);
  });

  it("uses the shared 24-hour preflight lifetime for the agent cache", () => {
    assert.equal(PREFLIGHT_CACHE_TTL_MS, ADCS_PREFLIGHT_MAX_AGE_MS);
    assert.equal(ADCS_PREFLIGHT_MAX_AGE_MS, 24 * 60 * 60 * 1000);
  });

  it("reuses a pinned CA cert only within the preflight TTL", async () => {
    const certBytes = fs.readFileSync(path.join(__dirname, "..", "verify", "fixtures", "ca.crt.pem"));
    const caKeySha256 = computeSpkiSha256Hex(certBytes);
    const dest = await cachePinnedCaCert({ stateDir, caKeySha256, certBytes });
    const agedAt = (ageMs) => {
      const when = new Date(Date.now() - ageMs);
      fs.utimesSync(dest, when, when);
    };
    const resolve = () => resolvePinnedCaCertPath({ stateDir, caKeySha256 });

    agedAt(PREFLIGHT_CACHE_TTL_MS - 60_000);
    assert.equal(resolve().ok, true);

    agedAt(PREFLIGHT_CACHE_TTL_MS + 60_000);
    const stale = resolve();
    assert.equal(stale.ok, false);
    assert.equal(stale.errorCode, "ADCS_CA_KEY_UNPINNED");
  });

  it("reuses a just-written CA cert whose mtime reads a few ms ahead, but not a far-future one", async () => {
    const certBytes = fs.readFileSync(path.join(__dirname, "..", "verify", "fixtures", "ca.crt.pem"));
    const caKeySha256 = computeSpkiSha256Hex(certBytes);
    const dest = await cachePinnedCaCert({ stateDir, caKeySha256, certBytes });
    const datedAheadBy = (ms) => {
      const when = new Date(Date.now() + ms);
      fs.utimesSync(dest, when, when);
    };
    const resolve = () => resolvePinnedCaCertPath({ stateDir, caKeySha256 });

    datedAheadBy(3);
    assert.equal(resolve().ok, true);

    datedAheadBy(60 * 60 * 1000);
    assert.equal(resolve().ok, false);
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
