"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");

const crypto = require("node:crypto");

const {
  createAdcsWindowsIisExecutors,
  resultForAdcsOutcome,
  resultForValidationOutcome,
  terminalEnrollmentResultExtras,
  shouldRetainCngKey,
  shouldCleanupAbandonedCngKey,
  resolveCleanupOutcome,
  isRetryableInstallInterrupt,
  observeInstalledCertificateIdentity,
  inspectAdcsInstallProgress,
  withUniqueValidationLeafFile,
} = require("./adcs-windows-iis");
const { computeSha1ThumbprintFromPem } = require("./windows-cert-store");
const {
  computeSpkiSha256Hex,
  writeEnrollmentJournal,
  writeCsrArtifact,
  writeIssuedCertificateArtifacts,
  readEnrollmentJournal,
} = require("./issuers/adcs-enrollment");

describe("AD CS renew evidence ordering", () => {
  it("persists classified CA outcomes before reportIssuanceEvidence and exposes fault injection", () => {
    const src = fs.readFileSync(require.resolve("./adcs-windows-iis.js"), "utf8");
    const renewFn = src.indexOf("async function executeWindowsIisAdcsRenewJob");
    assert.ok(renewFn >= 0);
    const renewSrc = src.slice(
      renewFn,
      src.indexOf("async function executeWindowsIisContinueEnrollmentJob"),
    );
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

  it("inspects install progress before decision-6 on installing recovery and validates tier-2 before issued", () => {
    const src = fs.readFileSync(require.resolve("./adcs-windows-iis.js"), "utf8");
    const validateFn = src.indexOf("async function validateAndInstallFromLeaf");
    assert.ok(validateFn >= 0);
    const validateSrc = src.slice(validateFn, src.indexOf("async function executeWindowsIisContinueEnrollmentJob"));
    const resumeGate = validateSrc.indexOf("resumeInstallStates");
    const inspectAt = validateSrc.indexOf("inspectImpl", resumeGate);
    const decision6At = validateSrc.indexOf("runDecision6Validation", resumeGate);
    assert.ok(inspectAt >= 0, "install recovery must inspect live progress");
    assert.ok(decision6At > inspectAt, "decision-6 must not run before install inspection on resume");
    assert.match(validateSrc, /startAtStep:\s*progress\.startAtStep/);
    assert.match(validateSrc, /finalizeWindowsIisDeployBookkeeping/);

    const continueFn = src.indexOf("async function executeWindowsIisContinueEnrollmentJob");
    const continueSrc = src.slice(continueFn);
    const tier2 = continueSrc.indexOf('journal.state === "submission_uncertain"');
    assert.ok(tier2 >= 0);
    const tier2End = continueSrc.indexOf(
      "// Issued / deferred / installing / install_failed",
      tier2,
    );
    const tier2Src = continueSrc.slice(tier2, tier2End > tier2 ? tier2End : tier2 + 20000);
    assert.match(tier2Src, /unique_candidate/);
    assert.match(tier2Src, /attachmentEligible/);
    assert.match(tier2Src, /reconcileCandidateRequestId/);
    assert.match(tier2Src, /validation_deferred/);
    assert.match(tier2Src, /reconcileSearchFrom:\s*reconciled\.nextSearchFrom/);
    assert.doesNotMatch(tier2Src, /requestId \+ 1/);
    // submission_uncertain may only reconcile / retrieve; never call submit again.
    assert.doesNotMatch(tier2Src, /issuer\.submit/);
    const candidateValidation = tier2Src.indexOf("const candidateValidation");
    assert.ok(candidateValidation >= 0);
    const attachAfterValidate = tier2Src.indexOf(
      "return attachIssuedCandidate(",
      candidateValidation,
    );
    assert.ok(attachAfterValidate > candidateValidation, "decision-6 must precede issued attach");
    assert.match(
      tier2Src.slice(attachAfterValidate, attachAfterValidate + 200),
      /candidateValidation/,
    );
  });

  it("keeps the last renew install step when journaling install_failed", () => {
    const src = fs.readFileSync(require.resolve("./adcs-windows-iis.js"), "utf8");
    const renewFn = src.indexOf("async function executeWindowsIisAdcsRenewJob");
    const renewSrc = src.slice(
      renewFn,
      src.indexOf("async function executeWindowsIisContinueEnrollmentJob"),
    );
    const failAt = renewSrc.lastIndexOf('state: "install_failed"');
    assert.ok(failAt >= 0);
    const block = renewSrc.slice(failAt, failAt + 600);
    assert.match(block, /installStep:\s*currentInstallStep/);
    assert.doesNotMatch(block, /installStep:\s*"accept"/);
  });

  it("captures reconcileSearchFrom at the submitting barrier before CA contact", () => {
    const src = fs.readFileSync(require.resolve("./adcs-windows-iis.js"), "utf8");
    const renewFn = src.indexOf("async function executeWindowsIisAdcsRenewJob");
    const renewSrc = src.slice(
      renewFn,
      src.indexOf("async function executeWindowsIisContinueEnrollmentJob"),
    );
    const barrier = renewSrc.indexOf("Durable submitting barrier");
    assert.ok(barrier >= 0);
    const barrierSrc = renewSrc.slice(barrier, barrier + 1200);
    assert.match(barrierSrc, /reconcileSearchFromForSubmit|captureEnrollmentReconcileSearchFrom/);
    assert.match(barrierSrc, /reconcileSearchFrom/);
    const submitCall = renewSrc.indexOf("issuer.submit", barrier);
    const reconcileAt = renewSrc.indexOf("reconcileSearchFrom", barrier);
    assert.ok(reconcileAt >= 0 && reconcileAt < submitCall);
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

  it("maps a new CA key to rejected_invalid", () => {
    const result = resultForAdcsOutcome(
      {
        outcome: "rejected_invalid",
        errorCode: "ADCS_CA_KEY_CHANGED",
        detail: "CMS signer key does not match caKeySha256",
      },
      ENROLLMENT,
      { knownRequestId: 4242 },
    );
    assert.equal(result.status, "failed");
    assert.equal(result.enrollmentResult.state, "rejected_invalid");
    assert.equal(result.enrollmentResult.errorCode, "ADCS_CA_KEY_CHANGED");
    assert.equal(result.enrollmentResult.requestId, 4242);
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

describe("isRetryableInstallInterrupt", () => {
  it("treats lease blocks and store-lock failures as non-terminal interrupts", () => {
    assert.equal(isRetryableInstallInterrupt({ status: "blocked" }), true);
    assert.equal(
      isRetryableInstallInterrupt({ status: "failed", retryableInterrupt: true }),
      true,
    );
    assert.equal(isRetryableInstallInterrupt({ status: "failed" }), false);
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

describe("inspectAdcsInstallProgress", () => {
  const fixturePem = fs.readFileSync(
    path.join(__dirname, "verify", "fixtures", "selfsigned.crt.pem"),
    "utf8",
  );
  const expectedThumbprint = computeSha1ThumbprintFromPem(fixturePem);
  const windowsTarget = {
    store: "WebHosting",
    binding: { site: "Default Web Site", port: 443 },
  };
  const containerName = "tokentimer-enr-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

  it("resumes at accept when the leaf is absent from every store", async () => {
    const progress = await inspectAdcsInstallProgress({
      certificatePem: fixturePem,
      windowsTarget,
      containerName,
      listMachineStoreCertificatesImpl: async () => ({ ok: true, certificates: [] }),
      queryCurrentBindingImpl: async () => {
        throw new Error("binding must not be queried before store presence");
      },
    });
    assert.equal(progress.status, "resume");
    assert.equal(progress.startAtStep, "accept");
  });

  it("resumes at mirror when the leaf is present but unkeyed (never re-accept)", async () => {
    const progress = await inspectAdcsInstallProgress({
      certificatePem: fixturePem,
      windowsTarget,
      containerName,
      listMachineStoreCertificatesImpl: async ({ store }) => {
        if (store === "My") {
          return {
            ok: true,
            certificates: [
              {
                thumbprint: expectedThumbprint,
                hasPrivateKey: false,
                keyContainer: null,
              },
            ],
          };
        }
        return { ok: true, certificates: [] };
      },
      queryCurrentBindingImpl: async () => {
        throw new Error("binding must not be queried before mirror completes");
      },
    });
    assert.equal(progress.status, "resume");
    assert.equal(progress.startAtStep, "mirror");
  });

  it("errors when an unkeyed leaf is already in My and the target store is My", async () => {
    const progress = await inspectAdcsInstallProgress({
      certificatePem: fixturePem,
      windowsTarget: {
        store: "My",
        binding: { site: "Default Web Site", port: 443 },
      },
      containerName,
      listMachineStoreCertificatesImpl: async () => ({
        ok: true,
        certificates: [
          {
            thumbprint: expectedThumbprint,
            hasPrivateKey: false,
            keyContainer: null,
          },
        ],
      }),
      queryCurrentBindingImpl: async () => {
        throw new Error("binding must not be queried for unkeyed My-only leaf");
      },
    });
    assert.equal(progress.status, "error");
    assert.match(progress.error, /refusing certreq -accept/);
  });

  it("resumes at mirror when accepted in My but missing from the target store", async () => {
    const progress = await inspectAdcsInstallProgress({
      certificatePem: fixturePem,
      windowsTarget,
      containerName,
      listMachineStoreCertificatesImpl: async ({ store }) => {
        if (store === "My") {
          return {
            ok: true,
            certificates: [
              {
                thumbprint: expectedThumbprint,
                hasPrivateKey: true,
                keyContainer: containerName,
              },
            ],
          };
        }
        return { ok: true, certificates: [] };
      },
      queryCurrentBindingImpl: async () => {
        throw new Error("binding must not be queried before mirror completes");
      },
    });
    assert.equal(progress.status, "resume");
    assert.equal(progress.startAtStep, "mirror");
  });

  it("resumes at bind when the target store has the keyed leaf but IIS is unbound", async () => {
    const progress = await inspectAdcsInstallProgress({
      certificatePem: fixturePem,
      windowsTarget,
      containerName,
      listMachineStoreCertificatesImpl: async () => ({
        ok: true,
        certificates: [
          {
            thumbprint: expectedThumbprint,
            hasPrivateKey: true,
            keyContainer: containerName,
          },
        ],
      }),
      queryCurrentBindingImpl: async () => ({ ok: true, thumbprint: null }),
    });
    assert.equal(progress.status, "resume");
    assert.equal(progress.startAtStep, "bind");
  });

  it("finalizes complete when binding and live TLS already match the leaf", async () => {
    const progress = await inspectAdcsInstallProgress({
      certificatePem: fixturePem,
      windowsTarget,
      containerName,
      listMachineStoreCertificatesImpl: async () => ({
        ok: true,
        certificates: [
          {
            thumbprint: expectedThumbprint,
            hasPrivateKey: true,
            keyContainer: containerName,
          },
        ],
      }),
      queryCurrentBindingImpl: async () => ({ ok: true, thumbprint: expectedThumbprint }),
      verifyDeployedCertificateImpl: async () => ({ verified: true }),
    });
    assert.equal(progress.status, "complete");
    assert.equal(progress.expectedThumbprint, expectedThumbprint);
  });

  it("resumes at verify when bound but live TLS does not match", async () => {
    const progress = await inspectAdcsInstallProgress({
      certificatePem: fixturePem,
      windowsTarget,
      containerName,
      listMachineStoreCertificatesImpl: async () => ({
        ok: true,
        certificates: [
          {
            thumbprint: expectedThumbprint,
            hasPrivateKey: true,
            keyContainer: containerName,
          },
        ],
      }),
      queryCurrentBindingImpl: async () => ({ ok: true, thumbprint: expectedThumbprint }),
      verifyDeployedCertificateImpl: async () => ({ verified: false, detail: "mismatch" }),
    });
    assert.equal(progress.status, "resume");
    assert.equal(progress.startAtStep, "verify");
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

describe("AD CS accept-failure key retention", () => {
  it("retains the enrollment CNG key on bare certreq -accept failure for AD CS retry", () => {
    const src = fs.readFileSync(require.resolve("./index.js"), "utf8");
    assert.match(src, /retainKeyOnAcceptFailure/);
    const acceptFail = src.indexOf("if (!acceptResult.ok)");
    assert.ok(acceptFail >= 0);
    const branch = src.slice(acceptFail, acceptFail + 2500);
    assert.match(branch, /retainKeyOnAcceptFailureEffective/);
    assert.match(branch, /retaining CNG key container/);
    assert.match(branch, /AD CS install recovery can retry/);
    // Deletion must be gated out when retain is effective.
    const retainBranch = branch.indexOf("retainKeyOnAcceptFailureEffective");
    const deleteCall = branch.indexOf("removeAbandonedKeyContainer", retainBranch);
    const elseDelete = branch.indexOf("} else {", retainBranch);
    assert.ok(elseDelete > retainBranch);
    assert.ok(deleteCall > elseDelete, "CNG delete must only run on the non-retain path");
  });

  it("journals predecessorThumbprint only before bind and preserves it on verify-only resume", () => {
    const src = fs.readFileSync(require.resolve("./index.js"), "utf8");
    assert.match(src, /async function finalizeWindowsIisDeployBookkeeping/);
    const bindRegion = src.indexOf("Journal predecessor identity before cutover");
    assert.ok(bindRegion >= 0);
    const region = src.slice(bindRegion, bindRegion + 4000);
    assert.match(region, /shouldRun\("bind"\)/);
    assert.match(region, /queryCurrentBinding/);
    assert.match(region, /onInstallStep\("verify", \{\}\)/);
    assert.match(region, /await finalizeWindowsIisDeployBookkeeping/);
  });

  it("passes AbortSignal into mirror-stage recovery as well as accept+mirror", () => {
    const src = fs.readFileSync(require.resolve("./index.js"), "utf8");
    const mirrorResume = src.indexOf("mirroring accepted certificate into store");
    assert.ok(mirrorResume >= 0);
    const block = src.slice(mirrorResume, mirrorResume + 1200);
    assert.match(block, /mirrorAcceptedCertificateToStore\(\{/);
    assert.match(block, /\bsignal\b/);
    const retention = src.indexOf("async function performCleanup(row, { signal, assertHeld })");
    assert.ok(retention >= 0);
    const retentionBlock = src.slice(retention, src.indexOf("const summary = await sweepLedger", retention));
    assert.match(retentionBlock, /removeCertificateAndKeyContainer\(\{[\s\S]*?signal,/);
    const lockBlock = src.slice(src.indexOf("withRowLock: async (row, work)", retention), src.indexOf("windows-retention sweep:", retention));
    assert.match(lockBlock, /acquireWindowsStoreLocks/);
    assert.match(lockBlock, /storeLock\.run\(signal => work\(\{ signal,/);
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

describe("AD CS keygen_intent and observation retryability", () => {
  it("continues keygen_intent by generating CSR and journals denied from pending retrieve", () => {
    const src = fs.readFileSync(require.resolve("./adcs-windows-iis.js"), "utf8");
    const continueFn = src.indexOf("async function executeWindowsIisContinueEnrollmentJob");
    assert.ok(continueFn >= 0);
    const continueSrc = src.slice(continueFn);
    assert.match(continueSrc, /journal\.state === "keygen_intent"/);
    assert.match(continueSrc, /enrollment_container_exists/);
    assert.match(continueSrc, /state: "prepared"/);
    const pendingRetrieve = continueSrc.indexOf("// Pending retrieve path");
    assert.ok(pendingRetrieve >= 0);
    const pendingSrc = continueSrc.slice(pendingRetrieve, pendingRetrieve + 2500);
    assert.match(pendingSrc, /issuance\.outcome === "denied"/);
    assert.match(pendingSrc, /writeEnrollmentJournal/);
  });

  it("maps installed-identity observation failures to retryable validation", () => {
    const src = fs.readFileSync(require.resolve("./adcs-windows-iis.js"), "utf8");
    const observeFail = src.indexOf("if (observed.error)");
    assert.ok(observeFail >= 0);
    const block = src.slice(observeFail, observeFail + 350);
    assert.match(block, /retryable:\s*true/);
    assert.doesNotMatch(block, /rejected_invalid/);
  });
});

describe("reject-A then attach-B provisional leaf replacement", () => {
  it("clears provisional leafSha256 and artifacts before a later unique candidate can attach", () => {
    const src = fs.readFileSync(require.resolve("./adcs-windows-iis.js"), "utf8");
    const continueFn = src.indexOf("async function executeWindowsIisContinueEnrollmentJob");
    assert.ok(continueFn >= 0);
    const continueSrc = src.slice(continueFn);
    const rejectBlock = continueSrc.indexOf(
      "Hard rejection: clear provisional candidate + leaf so a later",
    );
    assert.ok(rejectBlock >= 0, "hard-reject provisional clear block missing");
    const block = continueSrc.slice(rejectBlock, rejectBlock + 900);
    assert.match(block, /reconcileCandidateRequestId:\s*null/);
    assert.match(block, /leafSha256:\s*null/);
    assert.match(block, /clearProvisionalLeafArtifacts/);
    // Attach path must rewrite leaf artifacts under issued after uniqueness.
    const attachFn = continueSrc.indexOf("const attachIssuedCandidate = async");
    assert.ok(attachFn >= 0);
    const attachSrc = continueSrc.slice(attachFn, attachFn + 1200);
    assert.match(attachSrc, /writeIssuedCertificateArtifacts/);
    assert.match(attachSrc, /state:\s*"issued"/);
    assert.match(attachSrc, /leafSha256:\s*written\.leafSha256/);
  });
});

describe("terminalEnrollmentResultExtras", () => {
  it("replays contract-required denied and rejected_invalid fields", () => {
    assert.deepEqual(
      terminalEnrollmentResultExtras({
        state: "denied",
        caHresult: "0x80094012",
        requestId: 42,
      }),
      { requestId: 42, caHresult: "0x80094012" },
    );
    assert.deepEqual(
      terminalEnrollmentResultExtras({
        state: "rejected_invalid",
        errorCode: "ADCS_CERTIFICATE_INVALID",
      }),
      { errorCode: "ADCS_CERTIFICATE_INVALID" },
    );
  });

  it("continue-enrollment terminal replay uses terminalEnrollmentResultExtras", () => {
    const src = fs.readFileSync(require.resolve("./adcs-windows-iis.js"), "utf8");
    const continueFn = src.indexOf("async function executeWindowsIisContinueEnrollmentJob");
    assert.ok(continueFn >= 0);
    const continueSrc = src.slice(continueFn);
    const terminalBlock = continueSrc.indexOf(
      '["denied", "refused", "rejected_invalid", "validation_expired", "abandoned"]',
    );
    assert.ok(terminalBlock >= 0, "terminal journal replay branch missing");
    const block = continueSrc.slice(terminalBlock, terminalBlock + 800);
    assert.match(block, /terminalEnrollmentResultExtras\(journal\)/);
  });
});

describe("reject-A then attach-B continue-enrollment executor", () => {
  it("clears provisional leaf A then attaches a later unique candidate B through install", async () => {
    const stateDir = await fsp.mkdtemp(path.join(os.tmpdir(), "adcs-reject-attach-"));
    try {
      const helperPath = path.join(stateDir, "tokentimer-adcs-cmc.exe");
      fs.writeFileSync(helperPath, "");
      const caPem = fs.readFileSync(
        path.join(__dirname, "verify", "fixtures", "selfsigned.crt.pem"),
      );
      const caKeySha256 = computeSpkiSha256Hex(caPem);
      const caCertPath = path.join(stateDir, "ca.cer");
      fs.writeFileSync(caCertPath, caPem);

      const enrollmentId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
      const containerName = `tokentimer-enr-${enrollmentId}`;
      const snapshot = {
        kind: "adcs",
        caConfig: "ca.example.com\\Example CA",
        template: "WebServer",
        caKeySha256,
        authorizedDnsNames: ["app.example.com"],
        keyAlgorithm: "ecdsa",
        keySize: 256,
      };
      const snapshotBytes = Buffer.from(JSON.stringify(snapshot), "utf8");
      const snapshotSha256 = crypto.createHash("sha256").update(snapshotBytes).digest("hex");
      const snapshotB64 = snapshotBytes.toString("base64");
      const templateOid = "1.3.6.1.4.1.311.21.8.1";
      const csrPem =
        "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n";
      const leafA = "-----BEGIN CERTIFICATE-----\nLEAF-A\n-----END CERTIFICATE-----\n";
      const leafB = "-----BEGIN CERTIFICATE-----\nLEAF-B\n-----END CERTIFICATE-----\n";

      const { csrSha256 } = await writeCsrArtifact({
        stateDir,
        enrollmentId,
        csrPem,
      });
      const journalBase = {
        attempt: 1,
        containerName,
        snapshotSha256,
        jobId: "job:reject-attach",
        csrSha256,
        csrSpkiSha256: "c".repeat(64),
        templateOid,
        caConfig: snapshot.caConfig,
        template: snapshot.template,
      };
      await writeEnrollmentJournal(stateDir, enrollmentId, {
        state: "prepared",
        ...journalBase,
      });
      await writeEnrollmentJournal(stateDir, enrollmentId, {
        state: "submitting",
        ...journalBase,
        reconcileSearchFrom: 100,
      });
      const { leafSha256: hashA } = await writeIssuedCertificateArtifacts({
        stateDir,
        enrollmentId,
        leafPem: leafA,
      });
      await writeEnrollmentJournal(stateDir, enrollmentId, {
        state: "submission_uncertain",
        ...journalBase,
        reconcileSearchFrom: 100,
        reconcileCandidateRequestId: 105,
        leafSha256: hashA,
        validationDeadlineAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      });

      let deployCalls = 0;
      const { executeWindowsIisContinueEnrollmentJob } = createAdcsWindowsIisExecutors({
        resolveAgentStateDir: () => stateDir,
        renewJobLeaseOrAbort: async () => ({ ok: true }),
        reportIssuanceEvidence: async () => {},
        reportStepEvidence: async () => {},
        runWindowsIisDeployTail: async () => {
          deployCalls += 1;
          return { status: "succeeded", keyRotated: null };
        },
        finalizeWindowsIisDeployBookkeeping: async () => {},
        emitInfo: () => {},
        emitLog: () => {},
        recordWindowsCngContainer: () => {},
        isValidCertificateId: () => true,
      });

      const job = {
        certificateId: "11111111-1111-4111-8111-111111111111",
        keyMode: "os-store-managed",
        issuerKind: "adcs",
        target: {
          type: "windows-iis",
          reference: "app.example.com",
          store: "WebHosting",
          binding: { site: "Default Web Site", port: 443 },
        },
        enrollment: {
          enrollmentId,
          attempt: 1,
          snapshotB64,
          snapshotSha256,
        },
      };
      const client = {};
      const executionContext = {
        execution: { keysDir: path.join(stateDir, "keys") },
        adcsHelperPath: helperPath,
        adcsCaCertPath: caCertPath,
        adcsTemplateOid: templateOid,
        adcsEnrollmentRules:[{caConfig:snapshot.caConfig,template:snapshot.template,dnsScopes:["example.com"],keyAlgorithms:["ecdsa"]}],
        adcsRunDecision6ValidationImpl: async ({ certificatePem }) => {
          if (certificatePem.includes("LEAF-A")) {
            return {
              ok: false,
              state: "rejected_invalid",
              errorCode: "ADCS_CERTIFICATE_INVALID",
              detail: "reject provisional A",
            };
          }
          if (certificatePem.includes("LEAF-B")) {
            return { ok: true };
          }
          return {
            ok: false,
            state: "rejected_invalid",
            errorCode: "ADCS_CERTIFICATE_INVALID",
            detail: "unexpected leaf",
          };
        },
        adcsTryReconcileUncertainSubmissionImpl: async () => ({
          status: "unique_candidate",
          requestId: 110,
          certificatePem: leafB,
          nextSearchFrom: 111,
          probed: 1,
          attachmentEligible: true,
        }),
      };

      const rejectResult = await executeWindowsIisContinueEnrollmentJob({
        job,
        jobId: "job:reject-attach",
        client,
        executionContext,
        log: {},
      });
      assert.equal(rejectResult.status, "failed");
      assert.equal(rejectResult.enrollmentResult.state, "submission_uncertain");
      const afterReject = readEnrollmentJournal(stateDir, enrollmentId);
      assert.equal(afterReject.kind, "valid");
      assert.equal(afterReject.journal.state, "submission_uncertain");
      assert.equal(afterReject.journal.reconcileCandidateRequestId == null, true);
      assert.equal(afterReject.journal.leafSha256 == null, true);
      assert.equal(afterReject.artifacts.leafPem, null);

      const attachResult = await executeWindowsIisContinueEnrollmentJob({
        job,
        jobId: "job:reject-attach",
        client,
        executionContext,
        log: {},
      });
      assert.equal(attachResult.status, "succeeded");
      assert.equal(attachResult.enrollmentResult.state, "installed");
      assert.equal(attachResult.enrollmentResult.requestId, 110);
      assert.equal(deployCalls, 1);
      const afterAttach = readEnrollmentJournal(stateDir, enrollmentId);
      assert.equal(afterAttach.kind, "valid");
      assert.equal(afterAttach.journal.state, "installed");
      assert.equal(afterAttach.journal.requestId, 110);
      assert.notEqual(afterAttach.journal.leafSha256, hashA);
      assert.equal(afterAttach.artifacts.leafPem, leafB);
    } finally {
      await fsp.rm(stateDir, { recursive: true, force: true });
    }
  });
});

describe("continue-enrollment recovery executor", () => {
  const templateOid = "1.3.6.1.4.1.311.21.8.1";
  const csrPem =
    "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n";
  const leafPem = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n";

  async function seedEnrollment(stateDir, enrollmentId, states, csrSpkiSha256 = "c".repeat(64)) {
    const caPem = fs.readFileSync(
      path.join(__dirname, "verify", "fixtures", "selfsigned.crt.pem"),
    );
    const caKeySha256 = computeSpkiSha256Hex(caPem);
    const caCertPath = path.join(stateDir, "ca.cer");
    fs.writeFileSync(caCertPath, caPem);
    const helperPath = path.join(stateDir, "tokentimer-adcs-cmc.exe");
    fs.writeFileSync(helperPath, "");

    const snapshot = {
      kind: "adcs",
      caConfig: "ca.example.com\\Example CA",
      template: "WebServer",
      caKeySha256,
      authorizedDnsNames: ["app.example.com"],
      keyAlgorithm: "ecdsa",
      keySize: 256,
    };
    const snapshotBytes = Buffer.from(JSON.stringify(snapshot), "utf8");
    const snapshotSha256 = crypto.createHash("sha256").update(snapshotBytes).digest("hex");
    const containerName = `tokentimer-enr-${enrollmentId}`;
    const { csrSha256 } = await writeCsrArtifact({ stateDir, enrollmentId, csrPem });
    const journalBase = {
      attempt: 1,
      containerName,
      snapshotSha256,
      jobId: `job-${enrollmentId.slice(0, 8)}`,
      csrSha256,
      csrSpkiSha256,
      templateOid,
      caConfig: snapshot.caConfig,
      template: snapshot.template,
    };
    await writeEnrollmentJournal(stateDir, enrollmentId, {
      state: "prepared",
      ...journalBase,
    });
    await writeEnrollmentJournal(stateDir, enrollmentId, {
      state: "submitting",
      ...journalBase,
      reconcileSearchFrom: 100,
    });
    let leafSha256 = null;
    if (states !== "submitting") {
      const written = await writeIssuedCertificateArtifacts({
        stateDir,
        enrollmentId,
        leafPem,
      });
      leafSha256 = written.leafSha256;
    }
    if (states === "issued" || states === "installing" || states === "validation_deferred") {
      await writeEnrollmentJournal(stateDir, enrollmentId, {
        state: "issued",
        ...journalBase,
        leafSha256,
        requestId: 40,
      });
    }
    if (states === "installing") {
      await writeEnrollmentJournal(stateDir, enrollmentId, {
        state: "installing",
        ...journalBase,
        leafSha256,
        requestId: 40,
        installStep: "accept",
      });
    }
    if (states === "validation_deferred") {
      await writeEnrollmentJournal(stateDir, enrollmentId, {
        state: "validation_deferred",
        ...journalBase,
        leafSha256,
        requestId: 40,
        validationDeadlineAt: "2000-01-01T00:00:00.000Z",
      });
    }
    if (states === "tier2-expired") {
      await writeEnrollmentJournal(stateDir, enrollmentId, {
        state: "submission_uncertain",
        ...journalBase,
        reconcileSearchFrom: 100,
        reconcileCandidateRequestId: 105,
        leafSha256,
        validationDeadlineAt: "2000-01-01T00:00:00.000Z",
      });
    }

    const job = {
      certificateId: "11111111-1111-4111-8111-111111111111",
      keyMode: "os-store-managed",
      issuerKind: "adcs",
      target: {
        type: "windows-iis",
        reference: "app.example.com",
        store: "WebHosting",
        binding: { site: "Default Web Site", port: 443 },
      },
      enrollment: {
        enrollmentId,
        attempt: 1,
        snapshotB64: snapshotBytes.toString("base64"),
        snapshotSha256,
      },
    };
    return { job, journalBase, helperPath, caCertPath, leafSha256 };
  }

  function executorsFor(stateDir, extraDeps = {}) {
    return createAdcsWindowsIisExecutors({
      resolveAgentStateDir: () => stateDir,
      renewJobLeaseOrAbort: async () => ({ ok: true }),
      reportIssuanceEvidence: async () => {},
      reportStepEvidence: async () => {},
      runWindowsIisDeployTail: async () => ({ status: "succeeded", keyRotated: null }),
      finalizeWindowsIisDeployBookkeeping: async () => {},
      emitInfo: () => {},
      emitLog: () => {},
      recordWindowsCngContainer: () => {},
      isValidCertificateId: () => true,
      ...extraDeps,
    });
  }

  function contextFor(seed, extra = {}) {
    return {
      execution: { keysDir: path.join(path.dirname(seed.helperPath), "keys") },
      windowsKeySurvivorHelperPath: __filename,
      adcsHelperPath: seed.helperPath,
      adcsCaCertPath: seed.caCertPath,
      adcsTemplateOid: templateOid,
      adcsEnrollmentRules:[{caConfig:"ca.example.com\\Example CA",template:"WebServer",dnsScopes:["example.com"],keyAlgorithms:["ecdsa"]}],
      ...extra,
    };
  }

  async function withState(enrollmentId, fn) {
    const stateDir = await fsp.mkdtemp(path.join(os.tmpdir(), "adcs-continue-"));
    try {
      await fn(stateDir);
    } finally {
      await fsp.rm(stateDir, { recursive: true, force: true });
    }
  }

  it("signed operator proposal rejects a foreign key before validation then validates the matching candidate", async () => {
    const enrollmentId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa5";
    await withState(enrollmentId, async (stateDir) => {
      const matchingPem = fs.readFileSync(path.join(__dirname, "verify", "fixtures", "leaf.crt.pem"), "utf8");
      const foreignPem = fs.readFileSync(path.join(__dirname, "verify", "fixtures", "wrong-san.crt.pem"), "utf8");
      const expectedSpki = computeSpkiSha256Hex(matchingPem);
      assert.notEqual(computeSpkiSha256Hex(foreignPem), expectedSpki, "foreign fixture must actually use another key");
      const seed = await seedEnrollment(stateDir, enrollmentId, "submitting", expectedSpki);
      await writeEnrollmentJournal(stateDir, enrollmentId, { ...seed.journalBase,
        state: "submission_uncertain", reconcileSearchFrom: 100 });
      let candidatePem = foreignPem;
      let validations = 0;
      let deployments = 0;
      const retrieved = [];
      const { executeWindowsIisContinueEnrollmentJob } = executorsFor(stateDir, {
        runWindowsIisDeployTail: async () => { deployments++; return { status: "succeeded", keyRotated: null }; },
      });
      const executionContext = contextFor(seed, {
        adcsExecFileImpl: async (file, args) => {
          assert.equal(args.includes("-retrieve"), true, "operator reconcile never submits");
          retrieved.push(Number(args[args.indexOf("-config") + 2]));
          fs.writeFileSync(args.at(-1), "unit CMC response fixture");
          return { stdout: "", stderr: "" };
        },
        adcsDecodeCmcImpl: async () => ({ ok: true, result: { disposition: "issued",
          certificateDerB64: new crypto.X509Certificate(candidatePem).raw.toString("base64") } }),
        adcsTryReconcileUncertainSubmissionImpl: async () => { assert.fail("signed proposal must bypass automatic scan"); },
        adcsRunDecision6ValidationImpl: async ({ csrSpkiSha256: actualSpki, snapshot, templateOid: actualOid }) => {
          validations++;
          assert.equal(actualSpki, expectedSpki);
          assert.equal(snapshot.caConfig, "ca.example.com\\Example CA");
          assert.equal(actualOid, templateOid);
          return { ok: true };
        },
      });
      seed.job.enrollment.reconcileRequestId = 77;
      let result = await executeWindowsIisContinueEnrollmentJob({ job: seed.job,
        jobId: seed.journalBase.jobId, client: {}, log: {}, executionContext });
      assert.equal(result.status, "failed");
      assert.equal(result.enrollmentResult.state, "submission_uncertain");
      assert.equal(validations, 0);
      assert.equal(deployments, 0);
      assert.equal(readEnrollmentJournal(stateDir, enrollmentId).journal.state, "submission_uncertain");
      candidatePem = matchingPem;
      seed.job.enrollment.reconcileRequestId = 78;
      result = await executeWindowsIisContinueEnrollmentJob({ job: seed.job,
        jobId: seed.journalBase.jobId, client: {}, log: {}, executionContext });
      assert.equal(result.status, "succeeded", result.errorMessage);
      assert.equal(result.enrollmentResult.state, "installed");
      assert.equal(result.enrollmentResult.requestId, 78);
      assert.deepEqual(retrieved, [77, 78]);
      assert.ok(validations >= 1, "matching SPKI still requires frozen issuer/template validation");
      assert.equal(deployments, 1);
    });
  });

  for (const terminalState of ["expired", "cancelled", "abandoned"]) {
    it(`signed ${terminalState} continuation frees its pending key and replays without CA contact`, async () => {
      const enrollmentId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
      await withState(enrollmentId, async (stateDir) => {
        const seed = await seedEnrollment(stateDir, enrollmentId, "submitting");
        await writeEnrollmentJournal(stateDir, enrollmentId, {
          ...seed.journalBase, state: "pending_issuance", requestId: 42,
        });
        seed.job.enrollment.terminalState = terminalState;
        let exists = true;
        const calls = [];
        const executionContext = contextFor(seed, {
          windowsExecFileImpl: (file, args, opts, cb) => {
            calls.push(args);
            if (args[0] === "--key-survivors") {
              assert.equal(file,__filename);
              assert.deepEqual(args,["--key-survivors","--container",seed.journalBase.containerName]);
              cb(null,JSON.stringify({complete:true,shared:false,storesScanned:3,certificatesScanned:0,matches:0}),"");
              return {kill(){},once(){},pid:1};
            }
            assert.equal(file, "certutil.exe", "no CA helper or certreq may run");
            if (args.includes("-key")) cb(null, exists ? seed.journalBase.containerName + "\n" : "", "");
            else {
              assert.deepEqual(args.slice(-2), ["-delkey", seed.journalBase.containerName]);
              exists = false;
              cb(null, "", "");
            }
            return { kill() {}, once() {}, pid: 1 };
          },
        });
        const { executeWindowsIisContinueEnrollmentJob } = executorsFor(stateDir);
        for (let replay = 0; replay < 2; replay++) {
          const result = await executeWindowsIisContinueEnrollmentJob({ job: seed.job,
            jobId: seed.journalBase.jobId, client: {}, log: {}, executionContext });
          assert.equal(result.status, "succeeded");
          assert.equal(result.enrollmentResult.state, terminalState);
          assert.equal(readEnrollmentJournal(stateDir, enrollmentId).journal.state, terminalState);
          assert.equal(exists, false);
        }
        assert.equal(calls.filter((args) => args.includes("-delkey")).length, 1);
      });
    });
  }

  it("a missing journal acknowledges only independently absent keys and refuses any deletion", async () => {
    const enrollmentId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4";
    await withState(enrollmentId, async (stateDir) => {
      const snapshotBytes = Buffer.from(JSON.stringify({ kind: "adcs" }));
      const job = { keyMode: "os-store-managed", target: { type: "windows-iis", store: "My", reference: "app.example.com",
        binding: { site: "test-site", port: 443 } }, enrollment: {
        enrollmentId, attempt: 1, terminalState: "cancelled",
        snapshotB64: snapshotBytes.toString("base64"),
        snapshotSha256: crypto.createHash("sha256").update(snapshotBytes).digest("hex"),
      } };
      const { executeWindowsIisContinueEnrollmentJob } = executorsFor(stateDir);
      for (const exists of [false, true]) {
        const result = await executeWindowsIisContinueEnrollmentJob({ job, jobId: "cleanup-unclaimed",
          client: {}, log: {}, executionContext: {
            execution: { keysDir: path.join(stateDir, "keys") },
            windowsExecFileImpl: (file, args, opts, cb) => {
              assert.equal(file, "certutil.exe");
              assert.equal(args.includes("-key"), true, "no delkey without a receipt");
              cb(null, exists ? `tokentimer-enr-${enrollmentId}\n` : "", "");
              return { kill() {}, once() {}, pid: 1 };
            },
          } });
        assert.equal(result.status, exists ? "failed" : "succeeded", result.errorMessage);
        assert.equal(readEnrollmentJournal(stateDir, enrollmentId).kind, "not_found");
      }
    });
  });

  it("terminal cleanup preserves its journal and key when a cross-store reference exists or inventory is incomplete", async()=>{
    const enrollmentId="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa9";
    for(const complete of [true,false]) await withState(enrollmentId,async stateDir=>{
      const seed=await seedEnrollment(stateDir,enrollmentId,"submitting");seed.job.enrollment.terminalState="cancelled";
      const before=readEnrollmentJournal(stateDir,enrollmentId).journal;let deletes=0,probes=0;
      const result=await executorsFor(stateDir).executeWindowsIisContinueEnrollmentJob({job:seed.job,jobId:seed.journalBase.jobId,client:{},log:{},executionContext:contextFor(seed,{
        windowsExecFileImpl(file,args,options,callback){
          if(args.includes("-delkey"))deletes++;
          if(args.includes("-key"))callback(null,seed.journalBase.containerName+"\n","");
          else{assert.equal(args[0],"--key-survivors");probes++;callback(null,JSON.stringify({complete,shared:true,storesScanned:3,certificatesScanned:1,matches:1,...(!complete?{reason:"store_open_failed"}:{})}),"");}
          return {kill(){},once(){},pid:1};
        }
      })});
      assert.equal(result.status,"failed");assert.equal(result.enrollmentResult,undefined);assert.equal(deletes,0);assert.equal(probes,1);
      assert.deepEqual(readEnrollmentJournal(stateDir,enrollmentId).journal,before);
    });
  });

  it("terminal cleanup failure retains the journal for retry", async () => {
    const enrollmentId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2";
    await withState(enrollmentId, async (stateDir) => {
      const seed = await seedEnrollment(stateDir, enrollmentId, "submitting");
      seed.job.enrollment.terminalState = "expired";
      const { executeWindowsIisContinueEnrollmentJob } = executorsFor(stateDir);
      const result = await executeWindowsIisContinueEnrollmentJob({ job: seed.job,
        jobId: seed.journalBase.jobId, client: {}, log: {}, executionContext: contextFor(seed, {
          windowsExecFileImpl: (file, args, opts, cb) => {
            cb(new Error("denied"), "", ""); return { kill() {}, once() {}, pid: 1 };
          },
        }) });
      assert.equal(result.status, "failed");
      assert.equal(result.enrollmentResult, undefined);
      assert.equal(readEnrollmentJournal(stateDir, enrollmentId).journal.state, "submitting");
    });
  });

  it("terminal cleanup cannot delete a key after issuance may have begun", async () => {
    const enrollmentId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3";
    await withState(enrollmentId, async (stateDir) => {
      const seed = await seedEnrollment(stateDir, enrollmentId, "issued");
      seed.job.enrollment.terminalState = "cancelled";
      const { executeWindowsIisContinueEnrollmentJob } = executorsFor(stateDir);
      const result = await executeWindowsIisContinueEnrollmentJob({ job: seed.job,
        jobId: seed.journalBase.jobId, client: {}, log: {}, executionContext: contextFor(seed, {
          windowsExecFileImpl: () => { assert.fail("no native mutation allowed"); },
        }) });
      assert.equal(result.status, "failed");
      assert.match(result.errorMessage, /may back an installed certificate/);
      assert.equal(readEnrollmentJournal(stateDir, enrollmentId).journal.state, "issued");
    });
  });

  it("rewrites a crashed submitting journal to submission_uncertain and does not submit again", async () => {
    await withState("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1", async (stateDir) => {
      const enrollmentId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1";
      const seed = await seedEnrollment(stateDir, enrollmentId, "submitting");
      const submitArgs = [];
      let reconcileCalls = 0;
      const { executeWindowsIisContinueEnrollmentJob } = executorsFor(stateDir);
      const result = await executeWindowsIisContinueEnrollmentJob({
        job: seed.job,
        jobId: seed.journalBase.jobId,
        client: {},
        log: {},
        executionContext: contextFor(seed, {
          windowsExecFileImpl: (file, args, opts, cb) => {
            submitArgs.push(args);
            const err = new Error("submit must not run");
            if (typeof cb === "function") {
              cb(err);
              return { kill() {}, once() {}, pid: 1 };
            }
            return Promise.reject(err);
          },
          adcsTryReconcileUncertainSubmissionImpl: async () => {
            reconcileCalls += 1;
            return { status: "none", nextSearchFrom: 101, probed: 0 };
          },
        }),
      });
      assert.equal(result.status, "failed");
      assert.equal(result.enrollmentResult.state, "submission_uncertain");
      assert.equal(reconcileCalls, 1);
      assert.equal(submitArgs.some((args) => Array.isArray(args) && args.includes("-submit")), false);
      const read = readEnrollmentJournal(stateDir, enrollmentId);
      assert.equal(read.kind, "valid");
      assert.equal(read.journal.state, "submission_uncertain");
      assert.equal(read.journal.reconcileSearchFrom, 101);
    });
  });

  it("resumes an installing journal at the inspected step and does not re-run decision-6", async () => {
    await withState("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2", async (stateDir) => {
      const enrollmentId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2";
      const seed = await seedEnrollment(stateDir, enrollmentId, "installing");
      let startAtStep = null;
      let decision6 = 0;
      const { executeWindowsIisContinueEnrollmentJob } = executorsFor(stateDir, {
        runWindowsIisDeployTail: async (input) => {
          startAtStep = input.startAtStep;
          return { status: "succeeded", keyRotated: null };
        },
      });
      const result = await executeWindowsIisContinueEnrollmentJob({
        job: seed.job,
        jobId: seed.journalBase.jobId,
        client: {},
        log: {},
        executionContext: contextFor(seed, {
          adcsInspectInstallProgressImpl: async () => ({
            status: "resume",
            startAtStep: "bind",
            expectedThumbprint: "ab".repeat(20),
          }),
          adcsRunDecision6ValidationImpl: async () => {
            decision6 += 1;
            return { ok: true };
          },
        }),
      });
      assert.equal(result.status, "succeeded");
      assert.equal(result.enrollmentResult.state, "installed");
      assert.equal(startAtStep, "bind");
      assert.equal(decision6, 0);
      const read = readEnrollmentJournal(stateDir, enrollmentId);
      assert.equal(read.journal.state, "installed");
      assert.equal(read.journal.installStep, "complete");
    });
  });

  it("leaves the journal installing when a lease or lock abort interrupts deploy", async () => {
    await withState("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb3", async (stateDir) => {
      const enrollmentId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb3";
      const seed = await seedEnrollment(stateDir, enrollmentId, "installing");
      const { executeWindowsIisContinueEnrollmentJob } = executorsFor(stateDir, {
        runWindowsIisDeployTail: async () => ({
          status: "blocked",
          keyRotated: null,
          errorMessage: "lease renew aborted",
        }),
      });
      const result = await executeWindowsIisContinueEnrollmentJob({
        job: seed.job,
        jobId: seed.journalBase.jobId,
        client: {},
        log: {},
        executionContext: contextFor(seed, {
          adcsInspectInstallProgressImpl: async () => ({
            status: "resume",
            startAtStep: "accept",
            expectedThumbprint: "ab".repeat(20),
          }),
        }),
      });
      assert.equal(result.status, "blocked");
      assert.equal(result.enrollmentResult, undefined);
      const read = readEnrollmentJournal(stateDir, enrollmentId);
      assert.equal(read.kind, "valid");
      assert.equal(read.journal.state, "installing");
      assert.notEqual(read.journal.state, "install_failed");
    });
  });

  it("journals install_failed at the step deploy had reached", async () => {
    await withState("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb4", async (stateDir) => {
      const enrollmentId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb4";
      const seed = await seedEnrollment(stateDir, enrollmentId, "installing");
      const { executeWindowsIisContinueEnrollmentJob } = executorsFor(stateDir, {
        runWindowsIisDeployTail: async (input) => {
          await input.onInstallStep("mirror");
          return { status: "failed", keyRotated: null, errorMessage: "bind failed" };
        },
      });
      const result = await executeWindowsIisContinueEnrollmentJob({
        job: seed.job,
        jobId: seed.journalBase.jobId,
        client: {},
        log: {},
        executionContext: contextFor(seed, {
          adcsInspectInstallProgressImpl: async () => ({
            status: "resume",
            startAtStep: "mirror",
            expectedThumbprint: "ab".repeat(20),
          }),
        }),
      });
      assert.equal(result.status, "failed");
      assert.equal(result.enrollmentResult.state, "install_failed");
      const read = readEnrollmentJournal(stateDir, enrollmentId);
      assert.equal(read.journal.state, "install_failed");
      assert.equal(read.journal.installStep, "mirror");
    });
  });

  it("expires a validation_deferred journal without installing", async () => {
    await withState("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb5", async (stateDir) => {
      const enrollmentId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb5";
      const seed = await seedEnrollment(stateDir, enrollmentId, "validation_deferred");
      let deployCalls = 0;
      const { executeWindowsIisContinueEnrollmentJob } = executorsFor(stateDir, {
        runWindowsIisDeployTail: async () => {
          deployCalls += 1;
          return { status: "succeeded", keyRotated: null };
        },
      });
      const result = await executeWindowsIisContinueEnrollmentJob({
        job: seed.job,
        jobId: seed.journalBase.jobId,
        client: {},
        log: {},
        executionContext: contextFor(seed, {
          adcsRunDecision6ValidationImpl: async () => {
            throw new Error("decision-6 must not run after the deadline");
          },
        }),
      });
      assert.equal(result.status, "failed");
      assert.equal(result.enrollmentResult.state, "validation_expired");
      assert.equal(deployCalls, 0);
      const read = readEnrollmentJournal(stateDir, enrollmentId);
      assert.equal(read.journal.state, "validation_expired");
    });
  });

  it("drops an expired tier-2 candidate and stays submission_uncertain", async () => {
    await withState("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb6", async (stateDir) => {
      const enrollmentId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb6";
      const seed = await seedEnrollment(stateDir, enrollmentId, "tier2-expired");
      let reconcileCalls = 0;
      const { executeWindowsIisContinueEnrollmentJob } = executorsFor(stateDir);
      const result = await executeWindowsIisContinueEnrollmentJob({
        job: seed.job,
        jobId: seed.journalBase.jobId,
        client: {},
        log: {},
        executionContext: contextFor(seed, {
          adcsTryReconcileUncertainSubmissionImpl: async () => {
            reconcileCalls += 1;
            return { status: "unique_candidate", requestId: 105, certificatePem: leafPem, attachmentEligible: true };
          },
          adcsRunDecision6ValidationImpl: async () => {
            throw new Error("decision-6 must not run for an expired tier-2 candidate");
          },
        }),
      });
      assert.equal(result.status, "failed");
      assert.equal(result.enrollmentResult.state, "submission_uncertain");
      assert.equal(reconcileCalls, 0);
      const read = readEnrollmentJournal(stateDir, enrollmentId);
      assert.equal(read.kind, "valid");
      assert.equal(read.journal.state, "submission_uncertain");
      assert.equal(read.journal.reconcileCandidateRequestId == null, true);
      assert.equal(read.journal.leafSha256 == null, true);
      assert.equal(read.artifacts.leafPem, null);
    });
  });
});
