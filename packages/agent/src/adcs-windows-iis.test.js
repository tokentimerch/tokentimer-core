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
