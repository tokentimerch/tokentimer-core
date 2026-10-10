"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");

const {
  resultForAdcsOutcome,
  resultForValidationOutcome,
  shouldRetainCngKey,
  shouldCleanupAbandonedCngKey,
  resolveCleanupOutcome,
  observeInstalledCertificateIdentity,
  withUniqueValidationLeafFile,
} = require("./adcs-windows-iis");

describe("AD CS renew evidence ordering", () => {
  it("persists classified CA outcomes before reportIssuanceEvidence and exposes fault injection", () => {
    const src = fs.readFileSync(require.resolve("./adcs-windows-iis.js"), "utf8");
    const renewFn = src.indexOf("async function executeWindowsIisAdcsRenewJob");
    assert.ok(renewFn >= 0);
    const renewSrc = src.slice(renewFn, src.indexOf("async function executeWindowsIisAdcsContinueJob"));
    function assertPersistBeforeReport(marker) {
      const persistAt = renewSrc.indexOf(marker);
      assert.ok(persistAt >= 0, `missing ${marker}`);
      const reportAt = renewSrc.indexOf('onBeforeMutation("report-issuance-evidence")', persistAt);
      const evidenceAt = renewSrc.indexOf("reportIssuanceEvidence", reportAt);
      assert.ok(reportAt > persistAt, `${marker} must precede report-issuance-evidence fault point`);
      assert.ok(evidenceAt > reportAt, "fault point must precede reportIssuanceEvidence");
    }
    assertPersistBeforeReport('state: "issued"');
    // denied-without-HRESULT journals submission_uncertain via issuanceOutcome.
    assertPersistBeforeReport("issuanceOutcome = caHresult ? \"denied\" : \"submission_uncertain\"");
    assertPersistBeforeReport('state: issuanceOutcome');
    assertPersistBeforeReport('state: "refused"');
  });
});

const ENROLLMENT = {
  enrollmentId: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  attempt: 1,
};

describe("resultForAdcsOutcome", () => {
  it("maps pending to awaiting_issuer with enrollmentResult", () => {
    const result = resultForAdcsOutcome(
      { outcome: "pending", requestId: 4242 },
      ENROLLMENT,
    );
    assert.equal(result.status, "awaiting_issuer");
    assert.deepEqual(result.enrollmentResult, {
      enrollmentId: ENROLLMENT.enrollmentId,
      attempt: 1,
      state: "pending_issuance",
      requestId: 4242,
    });
  });

  it("maps refused to rejected with enrollmentResult", () => {
    const result = resultForAdcsOutcome(
      {
        outcome: "refused",
        rejectionReason: "issuer_not_allowlisted",
        detail: "CA pin missing",
        errorCode: "ADCS_CA_PIN_MISSING",
      },
      ENROLLMENT,
    );
    assert.equal(result.status, "rejected");
    assert.equal(result.rejectionReason, "issuer_not_allowlisted");
    assert.equal(result.enrollmentResult.state, "refused");
  });

  it("maps denied with a contract-shaped caHresult", () => {
    const result = resultForAdcsOutcome(
      {
        outcome: "denied",
        detail: "denied",
        caHresult: "0x80094012",
        requestId: 4242,
      },
      ENROLLMENT,
    );
    assert.equal(result.status, "failed");
    assert.equal(result.enrollmentResult.state, "denied");
    assert.equal(result.enrollmentResult.caHresult, "0x80094012");
    assert.equal(result.enrollmentResult.requestId, 4242);
  });

  it("does not claim denied without a contract-shaped caHresult", () => {
    const result = resultForAdcsOutcome(
      { outcome: "denied", detail: "denied" },
      ENROLLMENT,
    );
    assert.equal(result.enrollmentResult.state, "submission_uncertain");
  });

  it("maps submit uncertain to submission_uncertain", () => {
    const result = resultForAdcsOutcome(
      { outcome: "uncertain", detail: "maybe" },
      ENROLLMENT,
    );
    assert.equal(result.status, "failed");
    assert.equal(result.enrollmentResult.state, "submission_uncertain");
    assert.equal(result.enrollmentResult.errorCode, "ADCS_DISPOSITION_UNKNOWN");
  });

  it("keeps pending_issuance when retrieve is uncertain for a known RequestId", () => {
    const result = resultForAdcsOutcome(
      { outcome: "uncertain", detail: "retrieve flaky" },
      ENROLLMENT,
      { knownRequestId: 4242 },
    );
    assert.equal(result.status, "failed");
    assert.deepEqual(result.enrollmentResult, {
      enrollmentId: ENROLLMENT.enrollmentId,
      attempt: 1,
      state: "pending_issuance",
      requestId: 4242,
    });
  });
});

describe("shouldRetainCngKey", () => {
  it("retains the key when a later continue-enrollment may need it", () => {
    for (const outcome of [
      "pending",
      "uncertain",
      "submission_uncertain",
      "issued",
      "validation_deferred",
      "not_submitted",
      "install_failed",
    ]) {
      assert.equal(shouldRetainCngKey(outcome), true, outcome);
    }
    // Denied / failed / rejected_invalid: no continuation needs this key.
    assert.equal(shouldRetainCngKey("denied"), false);
    assert.equal(shouldRetainCngKey("failed"), false);
    assert.equal(shouldRetainCngKey("rejected_invalid"), false);
  });
});

describe("shouldCleanupAbandonedCngKey", () => {
  it("frees the key on rejected_invalid even when certificate PEM was received", () => {
    assert.equal(
      shouldCleanupAbandonedCngKey({
        submitStarted: true,
        issuanceOutcome: "rejected_invalid",
        containerCreated: true,
      }),
      true,
    );
  });

  it("retains the key for validation_deferred and issued", () => {
    assert.equal(
      shouldCleanupAbandonedCngKey({
        submitStarted: true,
        issuanceOutcome: "validation_deferred",
        containerCreated: true,
      }),
      false,
    );
    assert.equal(
      shouldCleanupAbandonedCngKey({
        submitStarted: true,
        issuanceOutcome: "issued",
        containerCreated: true,
      }),
      false,
    );
  });

  it("retains the key when submit outcome is still unknown", () => {
    assert.equal(
      shouldCleanupAbandonedCngKey({
        submitStarted: true,
        issuanceOutcome: null,
        containerCreated: true,
      }),
      false,
    );
  });

  it("frees a key created before prepared when the job aborts pre-submit (lease)", () => {
    assert.equal(
      shouldCleanupAbandonedCngKey({
        submitStarted: false,
        issuanceOutcome: null,
        containerCreated: true,
        preparedJournalCommitted: false,
      }),
      true,
    );
  });

  it("retains a key after prepared is journaled even if submit never started", () => {
    assert.equal(
      shouldCleanupAbandonedCngKey({
        submitStarted: false,
        issuanceOutcome: null,
        containerCreated: true,
        preparedJournalCommitted: true,
      }),
      false,
    );
  });

  it("retains the key for not_submitted so resume-submit can reuse the CSR", () => {
    assert.equal(
      shouldCleanupAbandonedCngKey({
        submitStarted: true,
        issuanceOutcome: "not_submitted",
        containerCreated: true,
        preparedJournalCommitted: true,
      }),
      false,
    );
  });

  it("retains the key on install_failed", () => {
    assert.equal(
      shouldCleanupAbandonedCngKey({
        submitStarted: true,
        issuanceOutcome: "install_failed",
        containerCreated: true,
        preparedJournalCommitted: true,
      }),
      false,
    );
  });

  it("retains the key when denied lacks caHresult and journal is submission_uncertain", () => {
    // Raw issuer outcome is denied, but durable receipt is submission_uncertain.
    assert.equal(
      shouldCleanupAbandonedCngKey({
        submitStarted: true,
        issuanceOutcome: "denied",
        journalState: "submission_uncertain",
        containerCreated: true,
        preparedJournalCommitted: true,
      }),
      false,
    );
    // Terminal denied receipt (valid HRESULT path) still frees the key.
    assert.equal(
      shouldCleanupAbandonedCngKey({
        submitStarted: true,
        issuanceOutcome: "denied",
        journalState: "denied",
        containerCreated: true,
        preparedJournalCommitted: true,
      }),
      true,
    );
  });

  it("does nothing when no container was created", () => {
    assert.equal(
      shouldCleanupAbandonedCngKey({
        submitStarted: false,
        issuanceOutcome: null,
        containerCreated: false,
      }),
      false,
    );
  });
});

describe("resolveCleanupOutcome", () => {
  it("prefers durable journal state over a raw denied issuer outcome", async () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "adcs-cleanup-"));
    try {
      const enrollmentId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
      const {
        writeCsrArtifact,
        writeEnrollmentJournal,
      } = require("./issuers/adcs-enrollment-journal");
      const { csrSha256 } = await writeCsrArtifact({
        stateDir,
        enrollmentId,
        csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
      });
      await writeEnrollmentJournal(stateDir, enrollmentId, {
        state: "prepared",
        attempt: 1,
        containerName: `tokentimer-enr-${enrollmentId}`,
        snapshotSha256: "b".repeat(64),
        csrSha256,
        csrSpkiSha256: "c".repeat(64),
        templateOid: "1.3.6.1.4.1.311.21.8.1",
        jobId: "job:1",
      });
      await writeEnrollmentJournal(stateDir, enrollmentId, {
        state: "submitting",
        attempt: 1,
        containerName: `tokentimer-enr-${enrollmentId}`,
        snapshotSha256: "b".repeat(64),
        csrSha256,
        csrSpkiSha256: "c".repeat(64),
        templateOid: "1.3.6.1.4.1.311.21.8.1",
        jobId: "job:1",
      });
      await writeEnrollmentJournal(stateDir, enrollmentId, {
        state: "submission_uncertain",
        attempt: 1,
        containerName: `tokentimer-enr-${enrollmentId}`,
        snapshotSha256: "b".repeat(64),
        csrSha256,
        csrSpkiSha256: "c".repeat(64),
        templateOid: "1.3.6.1.4.1.311.21.8.1",
        jobId: "job:1",
      });
      assert.equal(resolveCleanupOutcome({ stateDir, enrollmentId }), "submission_uncertain");
      assert.equal(
        shouldCleanupAbandonedCngKey({
          submitStarted: true,
          issuanceOutcome: "denied",
          journalState: resolveCleanupOutcome({ stateDir, enrollmentId }),
          containerCreated: true,
          preparedJournalCommitted: true,
        }),
        false,
      );
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });
});

describe("observeInstalledCertificateIdentity", () => {
  const windowsTarget = {
    store: "WebHosting",
    binding: { site: "Default Web Site", port: 443 },
  };

  it("returns nulls when nothing is bound (first install)", async () => {
    const observed = await observeInstalledCertificateIdentity({
      windowsTarget,
      queryCurrentBindingImpl: async () => ({ ok: true, thumbprint: null }),
      listMachineStoreCertificatesImpl: async () => {
        throw new Error("store must not be queried when unbound");
      },
    });
    assert.equal(observed.existingNotAfter, null);
    assert.equal(observed.existingSerialHex, null);
  });

  it("reads serial and notAfter for the bound thumbprint", async () => {
    const observed = await observeInstalledCertificateIdentity({
      windowsTarget,
      queryCurrentBindingImpl: async () => ({ ok: true, thumbprint: "AA".repeat(20) }),
      listMachineStoreCertificatesImpl: async () => ({
        ok: true,
        certificates: [
          {
            thumbprint: "aa".repeat(20),
            serialNumber: "0abc",
            notAfter: "2027-01-01T00:00:00.000Z",
          },
        ],
      }),
    });
    assert.equal(observed.existingSerialHex, "0abc");
    assert.equal(observed.existingNotAfter, "2027-01-01T00:00:00.000Z");
  });

  it("queries the same selector shape as deploy (wildcard, explicit IP, SNI)", async () => {
    const seen = [];
    const observe = (target) =>
      observeInstalledCertificateIdentity({
        windowsTarget: target,
        queryCurrentBindingImpl: async ({ binding }) => {
          seen.push(binding);
          return { ok: true, thumbprint: null };
        },
        listMachineStoreCertificatesImpl: async () => ({ ok: true, certificates: [] }),
      });

    await observe({ store: "My", binding: { site: "s", port: 443 } });
    await observe({ store: "My", binding: { site: "s", port: 443, address: "10.0.0.5" } });
    await observe({
      store: "My",
      binding: { site: "s", port: 443, address: "*", sniHost: "app.example.com" },
    });

    assert.deepEqual(seen[0], { address: "*", port: 443 });
    assert.deepEqual(seen[1], { address: "10.0.0.5", port: 443 });
    assert.deepEqual(seen[2], { address: "*", port: 443, sniHost: "app.example.com" });
  });

  it("fails closed when a bound certificate has unreadable serial or notAfter", async () => {
    const incomplete = await observeInstalledCertificateIdentity({
      windowsTarget,
      queryCurrentBindingImpl: async () => ({ ok: true, thumbprint: "BB".repeat(20) }),
      listMachineStoreCertificatesImpl: async () => ({
        ok: true,
        certificates: [
          {
            thumbprint: "bb".repeat(20),
            serialNumber: null,
            notAfter: "2027-01-01T00:00:00.000Z",
          },
        ],
      }),
    });
    assert.ok(incomplete.error);
    assert.match(incomplete.error, /missing serial or notAfter/);

    const missingExpiry = await observeInstalledCertificateIdentity({
      windowsTarget,
      queryCurrentBindingImpl: async () => ({ ok: true, thumbprint: "CC".repeat(20) }),
      listMachineStoreCertificatesImpl: async () => ({
        ok: true,
        certificates: [
          {
            thumbprint: "cc".repeat(20),
            serialNumber: "0def",
            notAfter: null,
          },
        ],
      }),
    });
    assert.ok(missingExpiry.error);
    assert.match(missingExpiry.error, /missing serial or notAfter/);
  });
});

describe("withUniqueValidationLeafFile", () => {
  it("gives concurrent validations distinct leaf paths and cleans them up", async () => {
    const stateDir = await fsp.mkdtemp(path.join(os.tmpdir(), "adcs-val-"));
    const seen = [];
    await Promise.all([
      withUniqueValidationLeafFile(stateDir, "pem-a", async (certPath) => {
        seen.push(certPath);
        assert.equal(fs.readFileSync(certPath, "utf8"), "pem-a");
        await new Promise((r) => setTimeout(r, 20));
      }),
      withUniqueValidationLeafFile(stateDir, "pem-b", async (certPath) => {
        seen.push(certPath);
        assert.equal(fs.readFileSync(certPath, "utf8"), "pem-b");
        await new Promise((r) => setTimeout(r, 20));
      }),
    ]);
    assert.equal(seen.length, 2);
    assert.notEqual(seen[0], seen[1]);
    for (const certPath of seen) {
      assert.equal(fs.existsSync(certPath), false);
    }
    await fsp.rm(stateDir, { recursive: true, force: true });
  });
});

describe("resultForValidationOutcome", () => {
  it("maps deferred validation while retaining enrollment identity", () => {
    const result = resultForValidationOutcome(
      { state: "validation_deferred", detail: "offline CRL" },
      ENROLLMENT,
      99,
    );
    assert.equal(result.status, "failed");
    assert.equal(result.enrollmentResult.state, "validation_deferred");
    assert.equal(result.enrollmentResult.requestId, 99);
  });

  it("maps rejected_invalid with ADCS_CERTIFICATE_INVALID", () => {
    const result = resultForValidationOutcome(
      {
        state: "rejected_invalid",
        errorCode: "ADCS_CERTIFICATE_INVALID",
        detail: "bad SAN",
      },
      ENROLLMENT,
    );
    assert.equal(result.enrollmentResult.state, "rejected_invalid");
    assert.equal(result.enrollmentResult.errorCode, "ADCS_CERTIFICATE_INVALID");
  });
});
