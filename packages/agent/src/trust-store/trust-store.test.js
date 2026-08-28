"use strict";

/**
 * Tests for packages/agent/src/trust-store/index.js.
 *
 * All exec/fs/spawn access goes through injected seams; no real
 * certutil.exe, update-ca-certificates, or update-ca-trust is ever
 * invoked. Fixture certificates are the same self-signed test CA/
 * intermediate/leaf already used by ../verify/verify.test.js
 * (../verify/fixtures), reused here rather than generated fresh so this
 * file needs no openssl/child-process cert generation of its own.
 */

const { describe, it, afterEach, mock } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const trustStore = require("./index.js");
const receipt = require("./receipt.js");
const { validateTrustResult } = require("../../../contracts/certops/validate-trust-result.cjs");

const FIXTURES_DIR = path.join(__dirname, "..", "verify", "fixtures");
const CA_PEM = fs.readFileSync(path.join(FIXTURES_DIR, "ca.crt.pem"), "utf8");
const INTERMEDIATE_PEM = fs.readFileSync(path.join(FIXTURES_DIR, "intermediate.crt.pem"), "utf8");
const LEAF_PEM = fs.readFileSync(path.join(FIXTURES_DIR, "leaf.crt.pem"), "utf8");

const CA_FINGERPRINT = "21aa0209d087f03bf76703e25befdcdf3ede8f606acab4c43280a32bf517971e";
const INTERMEDIATE_FINGERPRINT = "3c2cc4c0b53535d35f4a208118fd9cc071c6d66bc89116b157d7c4993c7974d6";
const LEAF_FINGERPRINT = "91bc74ba7fb9602a6aa195116d058d657e036c848ee120553592e35585ef1a9c";

const WORKSPACE_ID = "11111111-1111-4111-8111-111111111111";
const AGENT_ID = "22222222-2222-4222-8222-222222222222";

const tempDirs = [];
function makeTempDir(label) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `tt-trust-store-test-${label}-`));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  while (tempDirs.length > 0) {
    fs.rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

function distributeJob(overrides = {}) {
  return {
    schemaVersion: 1,
    jobId: "job-dist-1",
    workspaceId: WORKSPACE_ID,
    agentId: AGENT_ID,
    trustAnchorId: "anchor-1",
    action: "distribute-trust",
    anchorType: "root",
    fingerprintSha256: CA_FINGERPRINT,
    pem: CA_PEM,
    mode: "real",
    requestedAt: new Date().toISOString(),
    transitionGeneration: 1,
    ...overrides,
  };
}

function revokeJob(overrides = {}) {
  return {
    schemaVersion: 1,
    jobId: "job-revoke-1",
    workspaceId: WORKSPACE_ID,
    agentId: AGENT_ID,
    trustAnchorId: "anchor-1",
    action: "revoke-trust",
    anchorType: "root",
    fingerprintSha256: CA_FINGERPRINT,
    mode: "real",
    requestedAt: new Date().toISOString(),
    transitionGeneration: 1,
    ...overrides,
  };
}

/** In-memory fs stand-in for the Linux install/remove/probe/scan seams, so
 * these tests never touch the real filesystem outside a temp receipt
 * directory. Shape matches only what trust-store/index.js actually calls
 * (mkdirSync/writeFileSync/readFileSync/readdirSync/unlinkSync). */
function makeFakeFs(initialFiles = {}) {
  const files = new Map(Object.entries(initialFiles));
  return {
    mkdirSync() {},
    writeFileSync(filePath, contents) {
      files.set(filePath, contents);
    },
    readFileSync(filePath) {
      if (!files.has(filePath)) {
        const err = new Error(`ENOENT: ${filePath}`);
        err.code = "ENOENT";
        throw err;
      }
      return files.get(filePath);
    },
    readdirSync(dirPath) {
      const prefix = path.join(dirPath, path.sep);
      const names = [];
      for (const filePath of files.keys()) {
        if (filePath.startsWith(prefix) && !filePath.slice(prefix.length).includes(path.sep)) {
          names.push(filePath.slice(prefix.length));
        }
      }
      return names;
    },
    unlinkSync(filePath) {
      if (!files.has(filePath)) {
        const err = new Error(`ENOENT: ${filePath}`);
        err.code = "ENOENT";
        throw err;
      }
      files.delete(filePath);
    },
    _files: files,
  };
}

/** execFileImpl stand-in matching child_process.execFile's callback
 * shape (file, args, options, callback), never actually spawning
 * anything. */
function makeFakeExecFile({ succeed = true, stdout = "", stderr = "" } = {}) {
  const calls = [];
  const impl = (file, args, options, callback) => {
    calls.push([file, ...args]);
    if (succeed) {
      callback(null, stdout, stderr);
    } else {
      const err = new Error("fake command failed");
      err.code = 1;
      callback(err, stdout, stderr);
    }
  };
  impl.calls = calls;
  return impl;
}

describe("trust-store: verifyAnchorPem (fingerprint + Basic Constraints re-validation)", () => {
  it("accepts a well-formed root CA PEM matching its own claimed fingerprint", () => {
    const result = trustStore.verifyAnchorPem(CA_PEM, CA_FINGERPRINT);
    assert.equal(result.ok, true);
    assert.equal(result.actualFingerprintSha256, CA_FINGERPRINT);
  });

  it("accepts a well-formed intermediate CA PEM matching its own claimed fingerprint", () => {
    const result = trustStore.verifyAnchorPem(INTERMEDIATE_PEM, INTERMEDIATE_FINGERPRINT);
    assert.equal(result.ok, true);
  });

  it("refuses on fingerprint mismatch, never returning der for the caller to install", () => {
    const result = trustStore.verifyAnchorPem(CA_PEM, INTERMEDIATE_FINGERPRINT);
    assert.equal(result.ok, false);
    assert.equal(result.failureCategory, "fingerprint_mismatch");
  });

  it("refuses a leaf (non-CA) certificate even when its fingerprint matches, via Basic Constraints re-validation", () => {
    const result = trustStore.verifyAnchorPem(LEAF_PEM, LEAF_FINGERPRINT);
    assert.equal(result.ok, false);
    assert.equal(result.failureCategory, "not_a_ca_certificate");
  });

  it("refuses a concatenated multi-certificate bundle (single-CA re-validation)", () => {
    const bundle = `${CA_PEM}\n${INTERMEDIATE_PEM}`;
    const result = trustStore.verifyAnchorPem(bundle, CA_FINGERPRINT);
    assert.equal(result.ok, false);
    assert.equal(result.failureCategory, "multiple_certificates_in_pem");
  });

  it("refuses unparseable garbage without throwing", () => {
    const result = trustStore.verifyAnchorPem("-----BEGIN CERTIFICATE-----\nnotbase64\n-----END CERTIFICATE-----", CA_FINGERPRINT);
    assert.equal(result.ok, false);
    assert.equal(result.failureCategory, "unparseable_certificate");
  });

  it("refuses an empty or non-string pem", () => {
    assert.equal(trustStore.verifyAnchorPem("", CA_FINGERPRINT).ok, false);
    assert.equal(trustStore.verifyAnchorPem(null, CA_FINGERPRINT).ok, false);
  });

  it("refuses a malformed expected fingerprint", () => {
    const result = trustStore.verifyAnchorPem(CA_PEM, "not-a-fingerprint");
    assert.equal(result.ok, false);
    assert.equal(result.failureCategory, "invalid_payload");
  });
});

describe("trust-store: deterministicAnchorFilename", () => {
  it("is deterministic for the same fingerprint+extension", () => {
    const a = trustStore.deterministicAnchorFilename(CA_FINGERPRINT, "crt");
    const b = trustStore.deterministicAnchorFilename(CA_FINGERPRINT, "crt");
    assert.equal(a, b);
    assert.match(a, /^tokentimer-[a-f0-9]{64}\.crt$/);
  });

  it("differs for different fingerprints", () => {
    assert.notEqual(
      trustStore.deterministicAnchorFilename(CA_FINGERPRINT, "crt"),
      trustStore.deterministicAnchorFilename(INTERMEDIATE_FINGERPRINT, "crt"),
    );
  });

  it("differs for different extensions on the same fingerprint", () => {
    assert.notEqual(
      trustStore.deterministicAnchorFilename(CA_FINGERPRINT, "crt"),
      trustStore.deterministicAnchorFilename(CA_FINGERPRINT, "pem"),
    );
  });

  it("rejects an invalid fingerprint or extension", () => {
    assert.throws(() => trustStore.deterministicAnchorFilename("not-a-fingerprint", "crt"));
    assert.throws(() => trustStore.deterministicAnchorFilename(CA_FINGERPRINT, "EXE!"));
  });
});

describe("trust-store: commandExistsOnPath / detectDebianFamily / detectRhelFamily", () => {
  it("commandExistsOnPath finds a command present in one PATH directory", () => {
    const existsSyncImpl = (p) => p === path.join("/usr/bin", "update-ca-certificates");
    assert.equal(
      trustStore.commandExistsOnPath("update-ca-certificates", {
        existsSyncImpl,
        pathEnv: ["/usr/bin", "/bin"].join(path.delimiter),
      }),
      true,
    );
  });

  it("commandExistsOnPath returns false when the command is nowhere on PATH", () => {
    const existsSyncImpl = () => false;
    assert.equal(
      trustStore.commandExistsOnPath("update-ca-certificates", {
        existsSyncImpl,
        pathEnv: ["/usr/bin", "/bin"].join(path.delimiter),
      }),
      false,
    );
  });

  it("detectDebianFamily requires BOTH the anchors directory and the update command", () => {
    const dirOnly = trustStore.detectDebianFamily({
      existsSyncImpl: (p) => p === trustStore.DEBIAN_ANCHORS_DIR,
      pathEnv: "/usr/bin",
    });
    assert.equal(dirOnly, false);

    const both = trustStore.detectDebianFamily({
      existsSyncImpl: (p) => p === trustStore.DEBIAN_ANCHORS_DIR || p === path.join("/usr/bin", "update-ca-certificates"),
      pathEnv: "/usr/bin",
    });
    assert.equal(both, true);
  });

  it("detectRhelFamily requires BOTH the anchors directory and the update command", () => {
    const commandOnly = trustStore.detectRhelFamily({
      existsSyncImpl: (p) => p === path.join("/usr/bin", "update-ca-trust"),
      pathEnv: "/usr/bin",
    });
    assert.equal(commandOnly, false);

    const both = trustStore.detectRhelFamily({
      existsSyncImpl: (p) => p === trustStore.RHEL_ANCHORS_DIR || p === path.join("/usr/bin", "update-ca-trust"),
      pathEnv: "/usr/bin",
    });
    assert.equal(both, true);
  });
});

describe("trust-store: resolveTrustStorePrerequisites (capability-advertisement gate)", () => {
  it("is always a candidate on Windows, regardless of Linux directory/command detection", () => {
    const result = trustStore.resolveTrustStorePrerequisites({
      platform: "win32",
      existsSyncImpl: () => false,
      pathEnv: "",
    });
    assert.equal(result.candidate, true);
    assert.equal(result.family, "windows");
  });

  it("is a candidate on a Linux host where the Debian-family paths/commands resolve", () => {
    const result = trustStore.resolveTrustStorePrerequisites({
      platform: "linux",
      existsSyncImpl: (p) => p === trustStore.DEBIAN_ANCHORS_DIR || p === path.join("/usr/bin", "update-ca-certificates"),
      pathEnv: "/usr/bin",
    });
    assert.equal(result.candidate, true);
    assert.equal(result.family, "debian");
  });

  it("is a candidate on a Linux host where the RHEL-family paths/commands resolve", () => {
    const result = trustStore.resolveTrustStorePrerequisites({
      platform: "linux",
      existsSyncImpl: (p) => p === trustStore.RHEL_ANCHORS_DIR || p === path.join("/usr/bin", "update-ca-trust"),
      pathEnv: "/usr/bin",
    });
    assert.equal(result.candidate, true);
    assert.equal(result.family, "rhel");
  });

  it("is NOT a candidate on a Linux host where neither family resolves", () => {
    const result = trustStore.resolveTrustStorePrerequisites({
      platform: "linux",
      existsSyncImpl: () => false,
      pathEnv: "/usr/bin",
    });
    assert.equal(result.candidate, false);
    assert.equal(result.family, null);
  });
});

describe("trust-store: resolveConcreteStore", () => {
  it("maps windows root/intermediate to Root/CA", () => {
    assert.equal(trustStore.resolveConcreteStore("windows", "root"), "Root");
    assert.equal(trustStore.resolveConcreteStore("windows", "intermediate"), "CA");
  });

  it("maps debian/rhel families to their fixed store names regardless of anchorType", () => {
    assert.equal(trustStore.resolveConcreteStore("debian", "root"), trustStore.DEBIAN_STORE_NAME);
    assert.equal(trustStore.resolveConcreteStore("rhel", "intermediate"), trustStore.RHEL_STORE_NAME);
  });

  it("throws for an unsupported family or anchorType", () => {
    assert.throws(() => trustStore.resolveConcreteStore("bogus", "root"));
    assert.throws(() => trustStore.resolveConcreteStore("windows", "bogus"));
  });
});

describe("trust-store: linuxAnchorFilePath / probeLinuxAnchorFile", () => {
  it("Debian-family path lives under DEBIAN_ANCHORS_DIR with a .crt extension", () => {
    const p = trustStore.linuxAnchorFilePath("debian", CA_FINGERPRINT);
    assert.equal(p, path.join(trustStore.DEBIAN_ANCHORS_DIR, `tokentimer-${CA_FINGERPRINT}.crt`));
  });

  it("RHEL-family path lives under RHEL_ANCHORS_DIR with a .pem extension", () => {
    const p = trustStore.linuxAnchorFilePath("rhel", CA_FINGERPRINT);
    assert.equal(p, path.join(trustStore.RHEL_ANCHORS_DIR, `tokentimer-${CA_FINGERPRINT}.pem`));
  });

  it("probeLinuxAnchorFile reports absent when the file does not exist", () => {
    const fsImpl = makeFakeFs({});
    const result = trustStore.probeLinuxAnchorFile({ family: "debian", fingerprintSha256: CA_FINGERPRINT, fsImpl });
    assert.equal(result.present, false);
  });

  it("probeLinuxAnchorFile reports present when the file's content hashes to the expected fingerprint", () => {
    const filePath = trustStore.linuxAnchorFilePath("debian", CA_FINGERPRINT);
    const fsImpl = makeFakeFs({ [filePath]: CA_PEM });
    const result = trustStore.probeLinuxAnchorFile({ family: "debian", fingerprintSha256: CA_FINGERPRINT, fsImpl });
    assert.equal(result.present, true);
  });

  it("probeLinuxAnchorFile reports a conflict when the file's content does not match its own deterministic-name fingerprint", () => {
    const filePath = trustStore.linuxAnchorFilePath("debian", CA_FINGERPRINT);
    const fsImpl = makeFakeFs({ [filePath]: INTERMEDIATE_PEM });
    const result = trustStore.probeLinuxAnchorFile({ family: "debian", fingerprintSha256: CA_FINGERPRINT, fsImpl });
    assert.equal(result.present, "conflict");
  });
});

describe("trust-store: scanLinuxAnchorsDirectoryForFingerprint", () => {
  it("reports absent when the anchors directory has no matching entry", () => {
    const fsImpl = makeFakeFs({
      [path.join(trustStore.DEBIAN_ANCHORS_DIR, "unrelated.crt")]: INTERMEDIATE_PEM,
    });
    const result = trustStore.scanLinuxAnchorsDirectoryForFingerprint({
      family: "debian",
      fingerprintSha256: CA_FINGERPRINT,
      fsImpl,
    });
    assert.equal(result.present, false);
  });

  it("finds a match at TokenTimer's own deterministic path", () => {
    const filePath = trustStore.linuxAnchorFilePath("debian", CA_FINGERPRINT);
    const fsImpl = makeFakeFs({ [filePath]: CA_PEM });
    const result = trustStore.scanLinuxAnchorsDirectoryForFingerprint({
      family: "debian",
      fingerprintSha256: CA_FINGERPRINT,
      fsImpl,
    });
    assert.equal(result.present, true);
    assert.equal(result.matchedPath, filePath);
  });

  it("finds a match under an arbitrary, externally-installed filename", () => {
    const externalPath = path.join(trustStore.RHEL_ANCHORS_DIR, "arbitrary-name.pem");
    const fsImpl = makeFakeFs({ [externalPath]: CA_PEM });
    const result = trustStore.scanLinuxAnchorsDirectoryForFingerprint({
      family: "rhel",
      fingerprintSha256: CA_FINGERPRINT,
      fsImpl,
    });
    assert.equal(result.present, true);
    assert.equal(result.matchedPath, externalPath);
  });

  it("skips unparseable entries without throwing and keeps scanning for a real match", () => {
    const garbagePath = path.join(trustStore.DEBIAN_ANCHORS_DIR, "not-a-cert.crt");
    const matchPath = path.join(trustStore.DEBIAN_ANCHORS_DIR, "real-ca.crt");
    const fsImpl = makeFakeFs({
      [garbagePath]: "not a certificate at all",
      [matchPath]: CA_PEM,
    });
    const result = trustStore.scanLinuxAnchorsDirectoryForFingerprint({
      family: "debian",
      fingerprintSha256: CA_FINGERPRINT,
      fsImpl,
    });
    assert.equal(result.present, true);
    assert.equal(result.matchedPath, matchPath);
  });

  it("reports absent, not a throw, when the anchors directory does not exist yet", () => {
    const fsImpl = {
      readdirSync() {
        const err = new Error("ENOENT: no such directory");
        err.code = "ENOENT";
        throw err;
      },
    };
    const result = trustStore.scanLinuxAnchorsDirectoryForFingerprint({
      family: "debian",
      fingerprintSha256: CA_FINGERPRINT,
      fsImpl,
    });
    assert.equal(result.present, false);
  });
});

describe("trust-store: distributeTrust on Debian-family (install idempotency, fingerprint/CA re-validation)", () => {
  it("installs an absent root anchor: writes the deterministic file, runs update-ca-certificates, finalizes the receipt, reports outcome installed", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    const execFileImpl = makeFakeExecFile({ succeed: true });

    const result = await trustStore.distributeTrust({
      job: distributeJob(),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    assert.equal(result.outcome, "installed");
    assert.equal(result.mutationAttempted, true);
    assert.equal(result.mutationPerformed, true);
    // result.store is the wire-visible label (anchorType-derived, "Root" for
    // a root anchor), distinct from the Debian-specific osStore
    // (trustStore.DEBIAN_STORE_NAME) the receipt is actually keyed by below.
    assert.equal(result.store, "Root");
    assert.equal(result.observedFingerprintAfter, CA_FINGERPRINT);
    assert.equal(result.receipt.state, "finalized");
    assert.equal(execFileImpl.calls.length, 1);
    assert.equal(execFileImpl.calls[0][0], trustStore.DEBIAN_UPDATE_COMMAND);

    const persisted = receipt.readReceipt(receiptDir, trustStore.DEBIAN_STORE_NAME, CA_FINGERPRINT);
    assert.equal(persisted.row.state, "installed");

    const validation = validateTrustResult(result);
    assert.equal(validation.valid, true, JSON.stringify(validation.errors));
  });

  it("reports preexisting and performs no mutation when the exact fingerprint is already installed", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const filePath = trustStore.linuxAnchorFilePath("debian", CA_FINGERPRINT);
    const fsImpl = makeFakeFs({ [filePath]: CA_PEM });
    const execFileImpl = makeFakeExecFile({ succeed: true });

    const result = await trustStore.distributeTrust({
      job: distributeJob(),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    assert.equal(result.outcome, "preexisting");
    assert.equal(result.mutationAttempted, false);
    assert.equal(result.mutationPerformed, false);
    assert.equal(execFileImpl.calls.length, 0);

    const validation = validateTrustResult(result);
    assert.equal(validation.valid, true, JSON.stringify(validation.errors));
  });

  it("reports preexisting when the CA is already trusted under an unrelated filename (installed outside TokenTimer)", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const externalPath = path.join(trustStore.DEBIAN_ANCHORS_DIR, "some-other-vendor-ca.crt");
    const fsImpl = makeFakeFs({ [externalPath]: CA_PEM });
    const execFileImpl = makeFakeExecFile({ succeed: true });

    const result = await trustStore.distributeTrust({
      job: distributeJob(),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    assert.equal(result.outcome, "preexisting");
    assert.equal(result.mutationAttempted, false);
    assert.equal(result.mutationPerformed, false);
    assert.equal(execFileImpl.calls.length, 0);

    // No duplicate of TokenTimer's own deterministic file was written.
    const ownPath = trustStore.linuxAnchorFilePath("debian", CA_FINGERPRINT);
    assert.equal(fsImpl._files.has(ownPath), false);
    assert.equal(fsImpl._files.size, 1);

    // No ownership receipt for a CA this agent didn't install.
    const persisted = receipt.readReceipt(receiptDir, trustStore.DEBIAN_STORE_NAME, CA_FINGERPRINT);
    assert.equal(persisted, null);

    const validation = validateTrustResult(result);
    assert.equal(validation.valid, true, JSON.stringify(validation.errors));
  });

  it("proceeds to install normally when the fingerprint is truly absent everywhere in the anchors directory", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const unrelatedPath = path.join(trustStore.DEBIAN_ANCHORS_DIR, "unrelated-ca.crt");
    const fsImpl = makeFakeFs({ [unrelatedPath]: INTERMEDIATE_PEM });
    const execFileImpl = makeFakeExecFile({ succeed: true });

    const result = await trustStore.distributeTrust({
      job: distributeJob(),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    assert.equal(result.outcome, "installed");
    assert.equal(result.mutationAttempted, true);
    assert.equal(result.mutationPerformed, true);
    assert.equal(execFileImpl.calls.length, 1);

    const ownPath = trustStore.linuxAnchorFilePath("debian", CA_FINGERPRINT);
    assert.equal(fsImpl._files.has(ownPath), true);
  });

  it("treats a not-yet-existing anchors directory as not-present rather than throwing", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    const execFileImpl = makeFakeExecFile({ succeed: true });

    const result = await trustStore.distributeTrust({
      job: distributeJob(),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    assert.equal(result.outcome, "installed");
    assert.equal(result.mutationPerformed, true);
  });

  it("refuses to touch the store on fingerprint mismatch, performs no mutation", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    const execFileImpl = makeFakeExecFile({ succeed: true });

    const result = await trustStore.distributeTrust({
      job: distributeJob({ fingerprintSha256: INTERMEDIATE_FINGERPRINT, pem: CA_PEM }),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    assert.equal(result.mutationAttempted, false);
    assert.equal(result.mutationPerformed, false);
    assert.equal(result.failureCategory, "fingerprint_mismatch");
    assert.equal(execFileImpl.calls.length, 0);
    assert.equal(fsImpl._files.size, 0);
  });

  it("refuses a non-CA (leaf) certificate even with a matching fingerprint", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    const execFileImpl = makeFakeExecFile({ succeed: true });

    const result = await trustStore.distributeTrust({
      job: distributeJob({ fingerprintSha256: LEAF_FINGERPRINT, pem: LEAF_PEM }),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    assert.equal(result.mutationPerformed, false);
    assert.equal(result.failureCategory, "not_a_ca_certificate");
  });

  it("cross-signed-root independence: two different fingerprints get two fully independent receipts", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    const execFileImpl = makeFakeExecFile({ succeed: true });

    await trustStore.distributeTrust({
      job: distributeJob({ trustAnchorId: "anchor-ca", fingerprintSha256: CA_FINGERPRINT, pem: CA_PEM }),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });
    await trustStore.distributeTrust({
      job: distributeJob({
        trustAnchorId: "anchor-intermediate",
        anchorType: "intermediate",
        fingerprintSha256: INTERMEDIATE_FINGERPRINT,
        pem: INTERMEDIATE_PEM,
      }),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    const caReceipt = receipt.readReceipt(receiptDir, trustStore.DEBIAN_STORE_NAME, CA_FINGERPRINT);
    const intermediateReceipt = receipt.readReceipt(receiptDir, trustStore.DEBIAN_STORE_NAME, INTERMEDIATE_FINGERPRINT);
    assert.equal(caReceipt.row.state, "installed");
    assert.equal(intermediateReceipt.row.state, "installed");
    assert.notEqual(caReceipt.row.id, intermediateReceipt.row.id);
  });

  it("reports a failure when the update command itself fails, leaving the receipt at intent_written (not finalized)", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    const execFileImpl = makeFakeExecFile({ succeed: false });

    const result = await trustStore.distributeTrust({
      job: distributeJob(),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    assert.equal(result.mutationAttempted, true);
    assert.equal(result.mutationPerformed, false);
    assert.equal(result.failureCategory, "os_mutation_failed");
    assert.equal(result.receipt.state, "intent_written");

    const persisted = receipt.readReceipt(receiptDir, trustStore.DEBIAN_STORE_NAME, CA_FINGERPRINT);
    assert.equal(persisted.row.state, "pending_install");
  });

  it("reports RECEIPT_WRITE_CONFLICT when the intent write itself fails, with no mutation ever attempted (real mkdirSync fault, not a stubbed return)", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    const execFileImpl = makeFakeExecFile({ succeed: true });

    // Forces receipt.js's own ensureReceiptDir (called from inside
    // writeIntentReceipt) to throw for real, exercising tryReceiptStep's
    // catch path exactly as a genuine disk fault would - not a stand-in
    // that fakes distributeTrust's return value.
    const mkdirMock = mock.method(fs, "mkdirSync", () => {
      throw Object.assign(new Error("simulated mkdir failure"), { code: "EACCES" });
    });
    let result;
    try {
      result = await trustStore.distributeTrust({
        job: distributeJob(),
        family: "debian",
        receiptDir,
        seams: { fsImpl, execFileImpl },
      });
    } finally {
      mkdirMock.mock.restore();
    }

    assert.equal(result.outcome, "already_absent");
    assert.equal(result.mutationAttempted, false);
    assert.equal(result.mutationPerformed, false);
    assert.equal(result.failureCategory, "receipt_write_conflict");
    assert.equal(result.receipt.state, "missing");
    assert.equal(execFileImpl.calls.length, 0);

    const validation = validateTrustResult(result);
    assert.equal(validation.valid, true, JSON.stringify(validation.errors));
  });
});

describe("trust-store: distributeTrust on RHEL-family", () => {
  it("installs via update-ca-trust extract and writes a .pem file", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    const execFileImpl = makeFakeExecFile({ succeed: true });

    const result = await trustStore.distributeTrust({
      job: distributeJob(),
      family: "rhel",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    assert.equal(result.outcome, "installed");
    // result.store is the wire-visible label (anchorType-derived), distinct
    // from the RHEL-specific osStore (trustStore.RHEL_STORE_NAME) used for
    // the real OS mutation just below.
    assert.equal(result.store, "Root");
    assert.deepEqual(execFileImpl.calls[0], [trustStore.RHEL_UPDATE_COMMAND, ...trustStore.RHEL_UPDATE_ARGS]);

    const filePath = trustStore.linuxAnchorFilePath("rhel", CA_FINGERPRINT);
    assert.equal(fsImpl._files.get(filePath), CA_PEM);
  });
});

describe("trust-store: revokeTrust on Debian-family (ownership-proof-gated removal)", () => {
  async function installFirst(receiptDir, fsImpl) {
    const execFileImpl = makeFakeExecFile({ succeed: true });
    await trustStore.distributeTrust({
      job: distributeJob(),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });
  }

  it("refuses removal when no receipt exists at all (missing receipt fails safe)", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    const execFileImpl = makeFakeExecFile({ succeed: true });

    const result = await trustStore.revokeTrust({
      job: revokeJob(),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    assert.equal(result.mutationAttempted, false);
    assert.equal(result.mutationPerformed, false);
    assert.equal(result.failureCategory, "receipt_missing");
    assert.equal(result.receipt.state, "missing");
    assert.equal(execFileImpl.calls.length, 0);

    const validation = validateTrustResult(result);
    assert.equal(validation.valid, true, JSON.stringify(validation.errors));
  });

  it("refuses removal when the receipt on disk is corrupt", async () => {
    const receiptDirParent = makeTempDir("receipts");
    const receiptDir = path.join(receiptDirParent, "receipts");
    fs.mkdirSync(receiptDir, { recursive: true });
    const rowPath = receipt.receiptRowPath(receiptDir, trustStore.DEBIAN_STORE_NAME, CA_FINGERPRINT);
    fs.writeFileSync(rowPath, "not valid json", "utf8");
    const fsImpl = makeFakeFs({});
    const execFileImpl = makeFakeExecFile({ succeed: true });

    const result = await trustStore.revokeTrust({
      job: revokeJob(),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    assert.equal(result.mutationPerformed, false);
    assert.equal(result.failureCategory, "receipt_corrupt");
    assert.equal(result.receipt.state, "corrupt");
  });

  it("removes a properly-owned anchor, finalizes the receipt as removed, reports outcome removed", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    await installFirst(receiptDir, fsImpl);

    const removeExecFileImpl = makeFakeExecFile({ succeed: true });
    const result = await trustStore.revokeTrust({
      job: revokeJob(),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl: removeExecFileImpl },
    });

    assert.equal(result.outcome, "removed");
    assert.equal(result.mutationAttempted, true);
    assert.equal(result.mutationPerformed, true);
    assert.equal(result.observedFingerprintAfter, null);
    assert.equal(result.receipt.state, "finalized");

    const filePath = trustStore.linuxAnchorFilePath("debian", CA_FINGERPRINT);
    assert.equal(fsImpl._files.has(filePath), false);

    const persisted = receipt.readReceipt(receiptDir, trustStore.DEBIAN_STORE_NAME, CA_FINGERPRINT);
    assert.equal(persisted.row.state, "removed");

    const validation = validateTrustResult(result);
    assert.equal(validation.valid, true, JSON.stringify(validation.errors));
  });

  it("(main removal flow) reports RECEIPT_WRITE_CONFLICT when the intent write itself fails, before any OS mutation is attempted (real mkdirSync fault, not a stubbed return)", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    await installFirst(receiptDir, fsImpl); // anchor file stays present

    const removeExecFileImpl = makeFakeExecFile({ succeed: true });
    const mkdirMock = mock.method(fs, "mkdirSync", () => {
      throw Object.assign(new Error("simulated mkdir failure"), { code: "EACCES" });
    });
    let result;
    try {
      result = await trustStore.revokeTrust({
        job: revokeJob(),
        family: "debian",
        receiptDir,
        seams: { fsImpl, execFileImpl: removeExecFileImpl },
      });
    } finally {
      mkdirMock.mock.restore();
    }

    assert.equal(result.outcome, "installed");
    assert.equal(result.mutationAttempted, false);
    assert.equal(result.mutationPerformed, false);
    assert.equal(result.failureCategory, "receipt_write_conflict");
    assert.equal(result.receipt.state, "intent_written");
    assert.equal(removeExecFileImpl.calls.length, 0);
  });

  it("(main removal flow) reports a tagged RECEIPT_FINALIZE_CONFLICT failure, never throwing, if the intent receipt is stolen out from under it between the OS mutation and finalize", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    await installFirst(receiptDir, fsImpl); // anchor file stays present

    // Mirrors the distributeTrust race in the "receipt races never throw"
    // describe block below: a second process reclaims the same (store,
    // fingerprint) row for a different jobId between this call's own
    // writeIntentReceipt and finalizeReceipt, firing inside the
    // execFileImpl seam since that fires between those two writes on this
    // (isPresent) removal path (unlike the already-absent path, which has
    // no async gap to splice a genuine interloper write into).
    const interloperExecFileImpl = (file, args, options, callback) => {
      receipt.writeIntentReceipt({
        receiptDir,
        store: trustStore.DEBIAN_STORE_NAME,
        fingerprintSha256: CA_FINGERPRINT,
        jobId: "interloper-job",
        transitionGeneration: 99,
        intentState: "pending_remove",
        reclaimStalePending: true,
      });
      callback(null, "", "");
    };

    const result = await trustStore.revokeTrust({
      job: revokeJob(),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl: interloperExecFileImpl },
    });

    assert.equal(result.outcome, "removed");
    assert.equal(result.mutationAttempted, true);
    assert.equal(result.mutationPerformed, true);
    assert.equal(result.failureCategory, "receipt_finalize_conflict");
    assert.equal(result.receipt.state, "intent_written");

    // The interloper's row is what's actually on disk, untouched by this
    // call's own rejected finalize attempt.
    const onDisk = receipt.readReceipt(receiptDir, trustStore.DEBIAN_STORE_NAME, CA_FINGERPRINT);
    assert.equal(onDisk.row.jobId, "interloper-job");
  });

  it("idempotent removal: reports already_absent (success) when the file is already gone despite an owning receipt", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    await installFirst(receiptDir, fsImpl);

    const filePath = trustStore.linuxAnchorFilePath("debian", CA_FINGERPRINT);
    fsImpl._files.delete(filePath);

    const removeExecFileImpl = makeFakeExecFile({ succeed: true });
    const result = await trustStore.revokeTrust({
      job: revokeJob(),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl: removeExecFileImpl },
    });

    assert.equal(result.outcome, "already_absent");
    assert.equal(result.mutationAttempted, false);
    assert.equal(result.mutationPerformed, false);
    assert.equal(removeExecFileImpl.calls.length, 0);
    assert.equal(result.failureCategory, null);

    const persisted = receipt.readReceipt(receiptDir, trustStore.DEBIAN_STORE_NAME, CA_FINGERPRINT);
    assert.equal(persisted.row.state, "removed");
  });

  it("(already-absent path) reports RECEIPT_WRITE_CONFLICT when re-writing the pending_remove intent itself fails, with no mutation attempted (real mkdirSync fault, not a stubbed return)", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    await installFirst(receiptDir, fsImpl);

    // Delete the anchor file out from under the receipt (same setup as the
    // idempotent-removal test above) so revokeTrust takes the
    // already-absent branch, then force writeIntentReceipt's own
    // ensureReceiptDir to throw for real inside that branch.
    const filePath = trustStore.linuxAnchorFilePath("debian", CA_FINGERPRINT);
    fsImpl._files.delete(filePath);

    const removeExecFileImpl = makeFakeExecFile({ succeed: true });
    const mkdirMock = mock.method(fs, "mkdirSync", () => {
      throw Object.assign(new Error("simulated mkdir failure"), { code: "EACCES" });
    });
    let result;
    try {
      result = await trustStore.revokeTrust({
        job: revokeJob(),
        family: "debian",
        receiptDir,
        seams: { fsImpl, execFileImpl: removeExecFileImpl },
      });
    } finally {
      mkdirMock.mock.restore();
    }

    assert.equal(result.outcome, "already_absent");
    assert.equal(result.mutationAttempted, false);
    assert.equal(result.mutationPerformed, false);
    assert.equal(result.failureCategory, "receipt_write_conflict");
    assert.equal(result.receipt.state, "intent_written");
    assert.equal(removeExecFileImpl.calls.length, 0);
  });

  it("(already-absent path) reports RECEIPT_FINALIZE_CONFLICT, never throwing, when finalizing the pending_remove -> removed transition fails after the intent write succeeded", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    await installFirst(receiptDir, fsImpl);

    const filePath = trustStore.linuxAnchorFilePath("debian", CA_FINGERPRINT);
    fsImpl._files.delete(filePath);

    // Let the already-absent branch's own writeIntentReceipt call succeed
    // (mkdirSync unmocked for it), then fail only the finalizeReceipt call
    // right after: both funnel through receipt.js's ensureReceiptDir, so
    // counting calls distinguishes the intent write from the finalize.
    let mkdirCalls = 0;
    const mkdirMock = mock.method(fs, "mkdirSync", () => {
      mkdirCalls += 1;
      if (mkdirCalls === 1) return undefined;
      throw Object.assign(new Error("simulated mkdir failure on finalize"), { code: "EACCES" });
    });
    const removeExecFileImpl = makeFakeExecFile({ succeed: true });
    let result;
    try {
      result = await trustStore.revokeTrust({
        job: revokeJob(),
        family: "debian",
        receiptDir,
        seams: { fsImpl, execFileImpl: removeExecFileImpl },
      });
    } finally {
      mkdirMock.mock.restore();
    }

    assert.equal(result.outcome, "already_absent");
    assert.equal(result.mutationAttempted, false);
    assert.equal(result.mutationPerformed, false);
    assert.equal(result.failureCategory, "receipt_finalize_conflict");
    assert.equal(result.receipt.state, "intent_written");
    assert.equal(removeExecFileImpl.calls.length, 0);

    // The intent write from before the forced finalize failure did land on
    // disk, still in pending_remove (never reached removed).
    const onDisk = receipt.readReceipt(receiptDir, trustStore.DEBIAN_STORE_NAME, CA_FINGERPRINT);
    assert.equal(onDisk.row.state, "pending_remove");
  });

  it("reports outcome 'installed' (not 'removed') when the OS-level removal command fails, so a caller checking outcome alone never sees a false completion", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    await installFirst(receiptDir, fsImpl);

    const removeExecFileImpl = makeFakeExecFile({ succeed: false });
    const result = await trustStore.revokeTrust({
      job: revokeJob(),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl: removeExecFileImpl },
    });

    assert.equal(result.mutationAttempted, true);
    assert.equal(result.mutationPerformed, false);
    assert.equal(result.outcome, "installed");
    assert.equal(result.failureCategory, "os_mutation_failed");
    assert.equal(result.receipt.state, "intent_written");

    const persisted = receipt.readReceipt(receiptDir, trustStore.DEBIAN_STORE_NAME, CA_FINGERPRINT);
    assert.equal(persisted.row.state, "pending_remove");

    const validation = validateTrustResult(result);
    assert.equal(validation.valid, true, JSON.stringify(validation.errors));
  });

  it("refuses removal for a receipt still in pending_install (crash before install mutation ever completed)", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    receipt.writeIntentReceipt({
      receiptDir,
      store: trustStore.DEBIAN_STORE_NAME,
      fingerprintSha256: CA_FINGERPRINT,
      jobId: "job-install-crashed",
      transitionGeneration: 1,
      intentState: "pending_install",
    });
    const fsImpl = makeFakeFs({});
    const execFileImpl = makeFakeExecFile({ succeed: true });

    const result = await trustStore.revokeTrust({
      job: revokeJob(),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    assert.equal(result.mutationAttempted, false);
    assert.equal(result.mutationPerformed, false);
    assert.equal(result.failureCategory, "receipt_pending_install");
    assert.equal(execFileImpl.calls.length, 0);
  });

  it("reports already_absent idempotently when the receipt is already in the removed terminal state", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    await installFirst(receiptDir, fsImpl);
    await trustStore.revokeTrust({
      job: revokeJob(),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl: makeFakeExecFile({ succeed: true }) },
    });

    const secondExecFileImpl = makeFakeExecFile({ succeed: true });
    const result = await trustStore.revokeTrust({
      job: revokeJob({ jobId: "job-revoke-2" }),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl: secondExecFileImpl },
    });

    assert.equal(result.outcome, "already_absent");
    assert.equal(result.mutationAttempted, false);
    assert.equal(secondExecFileImpl.calls.length, 0);
  });

  it("reclaims a DIFFERENT jobId's stale pending_remove receipt rather than permanently refusing (TRU-10 symmetric fix)", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    await installFirst(receiptDir, fsImpl);
    receipt.writeIntentReceipt({
      receiptDir,
      store: trustStore.DEBIAN_STORE_NAME,
      fingerprintSha256: CA_FINGERPRINT,
      jobId: "crashed-job",
      transitionGeneration: 2,
      intentState: "pending_remove",
    });

    const execFileImpl = makeFakeExecFile({ succeed: true });
    const result = await trustStore.revokeTrust({
      job: revokeJob({ jobId: "this-job", transitionGeneration: 3 }),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    // The material is still physically present (the crashed job never
    // completed its removal), so this job proceeds to remove it for real,
    // exactly as if no stale receipt had existed.
    assert.equal(result.outcome, "removed");
    assert.equal(result.mutationPerformed, true);
    assert.equal(execFileImpl.calls.length, 1);

    const finalReceipt = receipt.readReceipt(receiptDir, trustStore.DEBIAN_STORE_NAME, CA_FINGERPRINT);
    assert.equal(finalReceipt.row.jobId, "this-job");
    assert.equal(finalReceipt.row.state, "removed");
  });

  it("reclaims a DIFFERENT jobId's stale pending_remove receipt when the material is already gone too", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    await installFirst(receiptDir, fsImpl);
    // Simulate the crashed job's removal having actually completed on the
    // OS side (file deleted) before it crashed, without ever finalizing.
    fsImpl.unlinkSync(trustStore.linuxAnchorFilePath("debian", CA_FINGERPRINT));
    receipt.writeIntentReceipt({
      receiptDir,
      store: trustStore.DEBIAN_STORE_NAME,
      fingerprintSha256: CA_FINGERPRINT,
      jobId: "crashed-job",
      transitionGeneration: 2,
      intentState: "pending_remove",
    });

    const execFileImpl = makeFakeExecFile({ succeed: true });
    const result = await trustStore.revokeTrust({
      job: revokeJob({ jobId: "this-job", transitionGeneration: 3 }),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    assert.equal(result.outcome, "already_absent");
    assert.equal(result.mutationPerformed, false);
    assert.equal(execFileImpl.calls.length, 0);

    const finalReceipt = receipt.readReceipt(receiptDir, trustStore.DEBIAN_STORE_NAME, CA_FINGERPRINT);
    assert.equal(finalReceipt.row.jobId, "this-job");
    assert.equal(finalReceipt.row.state, "removed");
  });

  it("resumes a crashed remove attempt for the SAME jobId (pending_remove for this job is valid ownership proof)", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    await installFirst(receiptDir, fsImpl);
    receipt.writeIntentReceipt({
      receiptDir,
      store: trustStore.DEBIAN_STORE_NAME,
      fingerprintSha256: CA_FINGERPRINT,
      jobId: "job-revoke-1",
      transitionGeneration: 2,
      intentState: "pending_remove",
    });

    const execFileImpl = makeFakeExecFile({ succeed: true });
    const result = await trustStore.revokeTrust({
      job: revokeJob({ jobId: "job-revoke-1", transitionGeneration: 2 }),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    assert.equal(result.outcome, "removed");
    assert.equal(result.mutationPerformed, true);
  });

  it("refuses on a malformed fingerprintSha256 in the job itself", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    const execFileImpl = makeFakeExecFile({ succeed: true });

    const result = await trustStore.revokeTrust({
      job: revokeJob({ fingerprintSha256: "not-a-fingerprint" }),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    assert.equal(result.mutationAttempted, false);
    assert.equal(result.failureCategory, "invalid_payload");
  });
});

describe("trust-store: no desired-state pruning", () => {
  it("distributeTrust never touches any fingerprint other than the one named in the job", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const unrelatedPath = trustStore.linuxAnchorFilePath("debian", INTERMEDIATE_FINGERPRINT);
    const fsImpl = makeFakeFs({ [unrelatedPath]: INTERMEDIATE_PEM });
    const execFileImpl = makeFakeExecFile({ succeed: true });

    await trustStore.distributeTrust({
      job: distributeJob(),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl },
    });

    assert.equal(fsImpl._files.get(unrelatedPath), INTERMEDIATE_PEM);
    assert.equal(receipt.readReceipt(receiptDir, trustStore.DEBIAN_STORE_NAME, INTERMEDIATE_FINGERPRINT), null);
  });
});

/** Fake spawnSync-shaped implementation matching what
 * ../discovery/windows.js's fetchRawCertificateDerByThumbprint expects:
 * a single call returning `{ status, stdout, stderr, error }`, where
 * stdout is `{ items: [...] }` JSON. Used to simulate the Windows
 * machine store's current contents for findWindowsStoreEntryByFingerprint
 * without ever spawning a real powershell process. */
function makeFakeSpawn(entries) {
  const items = entries.map(({ thumbprint, pem }) => ({
    Thumbprint: thumbprint,
    RawCertificateBase64: new (require("node:crypto").X509Certificate)(pem).raw.toString("base64"),
  }));
  return () => ({ status: 0, stdout: JSON.stringify({ items }), stderr: "", error: null });
}

describe("trust-store: findWindowsStoreEntryByFingerprint (SHA-1-thumbprint-to-SHA-256-fingerprint resolution)", () => {
  it("finds the thumbprint whose DER hashes to the target SHA-256 fingerprint", () => {
    const spawnImpl = makeFakeSpawn([{ thumbprint: "AABBCC00", pem: CA_PEM }]);
    const result = trustStore.findWindowsStoreEntryByFingerprint({
      store: "Root",
      fingerprintSha256: CA_FINGERPRINT,
      spawnImpl,
    });
    assert.equal(result.found, true);
    assert.equal(result.thumbprint, "AABBCC00");
  });

  it("reports not found when the store has no entry with the target fingerprint", () => {
    const spawnImpl = makeFakeSpawn([{ thumbprint: "AABBCC00", pem: INTERMEDIATE_PEM }]);
    const result = trustStore.findWindowsStoreEntryByFingerprint({
      store: "Root",
      fingerprintSha256: CA_FINGERPRINT,
      spawnImpl,
    });
    assert.equal(result.found, false);
  });

  it("reports not found on an empty store", () => {
    const spawnImpl = makeFakeSpawn([]);
    const result = trustStore.findWindowsStoreEntryByFingerprint({
      store: "Root",
      fingerprintSha256: CA_FINGERPRINT,
      spawnImpl,
    });
    assert.equal(result.found, false);
  });
});

describe("trust-store: addWindowsStoreEntry / removeWindowsStoreEntry (certutil argv, staging file cleanup)", () => {
  it("addWindowsStoreEntry writes a deterministically-named staging file, invokes certutil -addstore, then deletes the staging file", async () => {
    const workDir = makeTempDir("winwork");
    const execFileImpl = makeFakeExecFile({ succeed: true });

    const result = await trustStore.addWindowsStoreEntry({
      store: "Root",
      pem: CA_PEM,
      fingerprintSha256: CA_FINGERPRINT,
      workDir,
      execFileImpl,
    });

    assert.equal(result.ok, true);
    assert.equal(execFileImpl.calls.length, 1);
    const [certutilPath, flag, store, stagingPath] = execFileImpl.calls[0];
    assert.equal(certutilPath, "certutil.exe");
    assert.equal(flag, "-addstore");
    assert.equal(store, "Root");
    assert.equal(path.basename(stagingPath), trustStore.deterministicAnchorFilename(CA_FINGERPRINT, "cer"));
    assert.equal(fs.existsSync(stagingPath), false);
  });

  it("addWindowsStoreEntry still deletes the staging file when certutil fails", async () => {
    const workDir = makeTempDir("winwork");
    const execFileImpl = makeFakeExecFile({ succeed: false });

    const result = await trustStore.addWindowsStoreEntry({
      store: "Root",
      pem: CA_PEM,
      fingerprintSha256: CA_FINGERPRINT,
      workDir,
      execFileImpl,
    });

    assert.equal(result.ok, false);
    const entries = fs.readdirSync(workDir);
    assert.deepEqual(entries, []);
  });

  it("removeWindowsStoreEntry invokes certutil -delstore with the resolved thumbprint", async () => {
    const execFileImpl = makeFakeExecFile({ succeed: true });
    const result = await trustStore.removeWindowsStoreEntry({
      store: "Root",
      thumbprint: "AABBCC00",
      execFileImpl,
    });
    assert.equal(result.ok, true);
    assert.deepEqual(execFileImpl.calls[0], ["certutil.exe", "-delstore", "Root", "AABBCC00"]);
  });
});

describe("trust-store: distributeTrust / revokeTrust on Windows", () => {
  it("distributeTrust installs an absent root anchor into LocalMachine\\Root via certutil -addstore", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const workDir = makeTempDir("winwork");
    const spawnImpl = makeFakeSpawn([]);
    const execFileImpl = makeFakeExecFile({ succeed: true });

    const result = await trustStore.distributeTrust({
      job: distributeJob(),
      family: "windows",
      receiptDir,
      workDir,
      seams: { spawnImpl, execFileImpl },
    });

    assert.equal(result.outcome, "installed");
    assert.equal(result.store, "Root");
    assert.equal(result.mutationPerformed, true);
    assert.equal(execFileImpl.calls[0][1], "-addstore");

    const validation = validateTrustResult(result);
    assert.equal(validation.valid, true, JSON.stringify(validation.errors));
  });

  it("distributeTrust routes an intermediate anchor to LocalMachine\\CA", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const workDir = makeTempDir("winwork");
    const spawnImpl = makeFakeSpawn([]);
    const execFileImpl = makeFakeExecFile({ succeed: true });

    const result = await trustStore.distributeTrust({
      job: distributeJob({ anchorType: "intermediate", fingerprintSha256: INTERMEDIATE_FINGERPRINT, pem: INTERMEDIATE_PEM }),
      family: "windows",
      receiptDir,
      workDir,
      seams: { spawnImpl, execFileImpl },
    });

    assert.equal(result.store, "CA");
    assert.equal(execFileImpl.calls[0][2], "CA");
  });

  it("distributeTrust reports preexisting when the fingerprint is already enumerated in the target store", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const workDir = makeTempDir("winwork");
    const spawnImpl = makeFakeSpawn([{ thumbprint: "AABBCC00", pem: CA_PEM }]);
    const execFileImpl = makeFakeExecFile({ succeed: true });

    const result = await trustStore.distributeTrust({
      job: distributeJob(),
      family: "windows",
      receiptDir,
      workDir,
      seams: { spawnImpl, execFileImpl },
    });

    assert.equal(result.outcome, "preexisting");
    assert.equal(result.mutationAttempted, false);
    assert.equal(execFileImpl.calls.length, 0);
  });

  it("revokeTrust removes an owned anchor via certutil -delstore using the resolved SHA-1 thumbprint, then finalizes the receipt", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const workDir = makeTempDir("winwork");

    await trustStore.distributeTrust({
      job: distributeJob(),
      family: "windows",
      receiptDir,
      workDir,
      seams: { spawnImpl: makeFakeSpawn([]), execFileImpl: makeFakeExecFile({ succeed: true }) },
    });

    const removeExecFileImpl = makeFakeExecFile({ succeed: true });
    const result = await trustStore.revokeTrust({
      job: revokeJob(),
      family: "windows",
      receiptDir,
      seams: {
        spawnImpl: makeFakeSpawn([{ thumbprint: "AABBCC00", pem: CA_PEM }]),
        execFileImpl: removeExecFileImpl,
      },
    });

    assert.equal(result.outcome, "removed");
    assert.equal(result.mutationPerformed, true);
    assert.deepEqual(removeExecFileImpl.calls[0], ["certutil.exe", "-delstore", "Root", "AABBCC00"]);

    const validation = validateTrustResult(result);
    assert.equal(validation.valid, true, JSON.stringify(validation.errors));
  });

  it("revokeTrust reports already_absent when ownership is proven but the store no longer has the entry", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const workDir = makeTempDir("winwork");

    await trustStore.distributeTrust({
      job: distributeJob(),
      family: "windows",
      receiptDir,
      workDir,
      seams: { spawnImpl: makeFakeSpawn([]), execFileImpl: makeFakeExecFile({ succeed: true }) },
    });

    const removeExecFileImpl = makeFakeExecFile({ succeed: true });
    const result = await trustStore.revokeTrust({
      job: revokeJob(),
      family: "windows",
      receiptDir,
      seams: { spawnImpl: makeFakeSpawn([]), execFileImpl: removeExecFileImpl },
    });

    assert.equal(result.outcome, "already_absent");
    assert.equal(result.mutationAttempted, false);
    assert.equal(removeExecFileImpl.calls.length, 0);
  });
});

describe("trust-store: receipt races never throw (defense in depth against a shared receiptDir)", () => {
  it("distributeTrust reports a tagged failure, never throws, if the intent receipt is stolen out from under it before finalize", async () => {
    const receiptDir = path.join(makeTempDir("receipts"), "receipts");
    const fsImpl = makeFakeFs({});
    const execFileImpl = makeFakeExecFile({ succeed: true });

    // Simulate a second process racing on the identical (store, fingerprint):
    // once this call's own writeIntentReceipt has run (inside distributeTrust,
    // synchronously before the awaited mutation), a sibling process reclaims
    // the same row for a different jobId before this call's finalizeReceipt
    // runs. distributeTrust's own execFileImpl is where we splice in that
    // interloper write, since it fires between intent-write and finalize.
    const interloperExecFileImpl = (file, args, options, callback) => {
      receipt.writeIntentReceipt({
        receiptDir,
        store: trustStore.DEBIAN_STORE_NAME,
        fingerprintSha256: CA_FINGERPRINT,
        jobId: "interloper-job",
        transitionGeneration: 99,
        intentState: "pending_install",
        reclaimStalePending: true,
      });
      execFileImpl(file, args, options, callback);
    };

    const result = await trustStore.distributeTrust({
      job: distributeJob({ jobId: "victim-job" }),
      family: "debian",
      receiptDir,
      seams: { fsImpl, execFileImpl: interloperExecFileImpl },
    });

    assert.equal(result.outcome, "installed");
    assert.equal(result.mutationPerformed, true);
    assert.equal(result.failureCategory, "receipt_finalize_conflict");
    assert.equal(result.receipt.state, "intent_written");

    // The interloper's row is what's actually on disk, untouched by the
    // victim's rejected finalize attempt.
    const onDisk = receipt.readReceipt(receiptDir, trustStore.DEBIAN_STORE_NAME, CA_FINGERPRINT);
    assert.equal(onDisk.row.jobId, "interloper-job");
  });
});

