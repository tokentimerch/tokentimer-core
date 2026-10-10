"use strict";

/**
 * Windows IIS AD CS renew + continue-enrollment executor (ADR-0014).
 * Holds acquireEnrollmentLock across CNG keygen, certreq submit/retrieve,
 * and (on issued) the deploy tail.
 */

const path = require("node:path");

const {
  createAdcsIssuer,
  assertIssuanceOutcome,
  decodeEnrollmentSnapshot,
  mapSnapshotKeyAlgorithm,
  resolveAdcsCmcHelperPath,
  resolvePinnedCaCertPath,
  writeEnrollmentRequestJournal,
  readEnrollmentRequestJournal,
} = require("./issuers");
const {
  generateCsrViaCng,
  acquireEnrollmentLock,
  removeAbandonedKeyContainer,
  recordIssuedContainer,
  removeIssuedContainerRecord,
} = require("./windows-cert-store");

const WINDOWS_CERT_STORE_WORK_DIR_NAME = "windows-cert-store-work";

function boundErrorMessage(message, max = 512) {
  const text = String(message || "");
  return text.length <= max ? text : text.slice(0, max);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function enrollmentResultFor(enrollmentId, attempt, state, extras = {}) {
  return {
    enrollmentId,
    attempt,
    state,
    ...extras,
  };
}

function resultForAdcsOutcome(issuance, { enrollmentId, attempt }) {
  if (issuance.outcome === "pending") {
    return {
      status: "awaiting_issuer",
      keyRotated: null,
      enrollmentResult: enrollmentResultFor(enrollmentId, attempt, "pending_issuance", {
        requestId: issuance.requestId,
      }),
    };
  }
  if (issuance.outcome === "refused") {
    return {
      status: "rejected",
      keyRotated: null,
      rejectionReason: issuance.rejectionReason,
      errorMessage: boundErrorMessage(issuance.detail),
      enrollmentResult: enrollmentResultFor(enrollmentId, attempt, "refused", {
        errorCode: issuance.errorCode || null,
      }),
    };
  }
  if (issuance.outcome === "denied") {
    return {
      status: "failed",
      keyRotated: null,
      errorMessage: boundErrorMessage(issuance.detail),
      enrollmentResult: enrollmentResultFor(enrollmentId, attempt, "denied", {
        caHresult: issuance.caHresult || null,
      }),
    };
  }
  if (issuance.outcome === "not_submitted") {
    return {
      status: "failed",
      keyRotated: null,
      errorMessage: boundErrorMessage(issuance.detail || "ADCS_CA_UNREACHABLE"),
      enrollmentResult: enrollmentResultFor(enrollmentId, attempt, "submitting", {
        errorCode: "ADCS_CA_UNREACHABLE",
      }),
    };
  }
  if (issuance.outcome === "uncertain") {
    return {
      status: "failed",
      keyRotated: null,
      errorMessage: boundErrorMessage(issuance.detail),
      enrollmentResult: enrollmentResultFor(enrollmentId, attempt, "submission_uncertain", {
        errorCode: "ADCS_DISPOSITION_UNKNOWN",
      }),
    };
  }
  return {
    status: "failed",
    keyRotated: null,
    errorMessage: boundErrorMessage(issuance.detail || `issuer returned ${issuance.outcome}`),
  };
}

function shouldRetainCngKey(outcome) {
  return (
    outcome === "pending" ||
    outcome === "not_submitted" ||
    outcome === "uncertain" ||
    outcome === "issued"
  );
}

async function resolveWindowsIisTarget(job) {
  if (job?.keyMode !== "os-store-managed" || job?.target?.type !== "windows-iis") {
    return {
      error:
        "AD CS jobs require keyMode os-store-managed and a windows-iis target",
    };
  }
  const commonName = job?.target?.reference;
  if (!isNonEmptyString(commonName)) {
    return { error: "renew job has no target.reference to use as the certificate CN" };
  }
  const store = job.target.store;
  const binding = job.target.binding;
  if (
    !isNonEmptyString(store) ||
    binding === null ||
    typeof binding !== "object" ||
    !isNonEmptyString(binding.site) ||
    !Number.isInteger(binding.port)
  ) {
    return { error: "windows-iis target requires target.store and target.binding.{site,port}" };
  }
  return {
    windowsTarget: {
      type: "windows-iis",
      store,
      binding,
      reference: commonName,
    },
    commonName,
  };
}

/**
 * @param {object} deps injected from packages/agent/src/index.js
 */
function createAdcsWindowsIisExecutors(deps) {
  const {
    resolveAgentStateDir,
    renewJobLeaseOrAbort,
    reportIssuanceEvidence,
    runWindowsIisDeployTail,
    emitInfo,
    emitLog,
    recordWindowsCngContainer,
    isValidCertificateId,
  } = deps;

  async function buildAdcsIssuerContext({
    job,
    jobId,
    executionContext,
    stateDir,
  }) {
    const decoded = decodeEnrollmentSnapshot(job);
    if (!decoded.ok) return { error: decoded.error };

    const keyMapped = mapSnapshotKeyAlgorithm(decoded.snapshot);
    if (keyMapped.error) return { error: keyMapped.error };

    const helper = resolveAdcsCmcHelperPath({
      overridePath: executionContext.adcsHelperPath,
      packageRoot: executionContext.adcsPackageRoot,
    });
    if (helper.error) return { error: helper.error };

    const ca = resolvePinnedCaCertPath({
      stateDir,
      caKeySha256: decoded.snapshot.caKeySha256,
      caCertPath: executionContext.adcsCaCertPath,
    });
    if (!ca.ok) {
      return {
        error: ca.error,
        errorCode: ca.errorCode,
        enrollmentId: decoded.enrollmentId,
        attempt: decoded.attempt,
      };
    }

    const domains = Array.isArray(decoded.snapshot.authorizedDnsNames)
      ? decoded.snapshot.authorizedDnsNames
      : null;
    if (!domains || domains.length === 0) {
      return { error: "enrollment snapshot authorizedDnsNames is empty" };
    }

    return {
      decoded,
      keyMapped,
      helperPath: helper.path,
      caCertPath: ca.caCertPath,
      domains,
      snapshot: decoded.snapshot,
    };
  }

  async function executeWindowsIisAdcsRenewJob({
    job,
    jobId,
    client,
    executionContext,
    log,
    leaseOpts = null,
    onBeforeMutation = null,
    journalCtx = null,
  }) {
    const { execution } = executionContext;
    if (!isValidCertificateId(job.certificateId)) {
      return {
        status: "failed",
        keyRotated: null,
        errorMessage: boundErrorMessage(
          `renew job has a missing or malformed certificateId (got ${JSON.stringify(job.certificateId)})`,
        ),
      };
    }

    const targetResolved = await resolveWindowsIisTarget(job);
    if (targetResolved.error) {
      return { status: "failed", keyRotated: null, errorMessage: targetResolved.error };
    }
    const { windowsTarget, commonName } = targetResolved;

    const stateDir = resolveAgentStateDir(executionContext) || path.dirname(execution.keysDir);
    const ctx = await buildAdcsIssuerContext({ job, jobId, executionContext, stateDir });
    if (ctx.error) {
      const base = {
        status: ctx.errorCode ? "rejected" : "failed",
        keyRotated: null,
        errorMessage: boundErrorMessage(ctx.error),
      };
      if (ctx.errorCode) base.rejectionReason = "issuer_not_allowlisted";
      if (ctx.enrollmentId) {
        base.enrollmentResult = enrollmentResultFor(
          ctx.enrollmentId,
          ctx.attempt,
          "refused",
          { errorCode: ctx.errorCode || null },
        );
      }
      return base;
    }

    const { decoded, keyMapped, helperPath, caCertPath, domains, snapshot } = ctx;
    const csrCommonName = domains.includes(commonName) ? commonName : domains[0];
    const cngWorkDir = path.join(stateDir, WINDOWS_CERT_STORE_WORK_DIR_NAME);
    const windowsExecFileImpl = executionContext.windowsExecFileImpl;
    const windowsConnectImpl = executionContext.windowsConnectImpl;

    let enrollmentLock;
    try {
      enrollmentLock = acquireEnrollmentLock(stateDir, decoded.enrollmentId);
    } catch (err) {
      return {
        status: "failed",
        keyRotated: null,
        errorMessage: boundErrorMessage(`could not acquire AD CS enrollment lock: ${err.message}`),
      };
    }

    let containerName = null;
    let certificatePem;
    let issuanceOutcome = null;
    try {
      {
        const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
        if (leaseGate && leaseGate.ok === false) return leaseGate.abort;
      }
      if (typeof onBeforeMutation === "function") onBeforeMutation("keygen");
      emitInfo(
        `job ${jobId}: generating CNG-native key + CSR for AD CS enrollment ${decoded.enrollmentId}`,
      );

      const csrResult = await generateCsrViaCng({
        commonName: csrCommonName,
        altNames: domains,
        jobId: job.certificateId,
        enrollmentId: decoded.enrollmentId,
        algorithm: keyMapped.algorithm,
        workDir: cngWorkDir,
        ...(windowsExecFileImpl ? { execFileImpl: windowsExecFileImpl } : {}),
      });
      if (!csrResult.ok) {
        return {
          status: "failed",
          keyRotated: null,
          errorMessage: boundErrorMessage(
            `CNG CSR generation failed (exit code ${csrResult.exitCode}): ${csrResult.stderrExcerpt}`,
          ),
        };
      }
      containerName = csrResult.containerName;

      if (journalCtx) {
        try {
          recordWindowsCngContainer({
            ...journalCtx,
            containerName,
            store: windowsTarget.store,
          });
        } catch (err) {
          emitLog(
            log,
            `job ${jobId}: failed to record CNG container ${containerName} in the job journal (non-fatal): ${err.message}`,
          );
        }
      }
      try {
        recordIssuedContainer({
          stateDir,
          containerName,
          jobId,
          certificateId: job.certificateId,
        });
      } catch (err) {
        emitLog(
          log,
          `job ${jobId}: failed to record CNG container issuance (non-fatal): ${err.message}`,
        );
      }

      const issuer = createAdcsIssuer({
        caConfig: snapshot.caConfig,
        template: snapshot.template,
        caKeySha256: snapshot.caKeySha256,
        caCertPath,
        helperPath,
        scratchDir: path.join(stateDir, "adcs-scratch"),
        jobId,
        enrollmentId: decoded.enrollmentId,
        execFileImpl: executionContext.adcsExecFileImpl || windowsExecFileImpl,
        decodeCmcImpl: executionContext.adcsDecodeCmcImpl,
        info: emitInfo,
      });

      {
        const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
        if (leaseGate && leaseGate.ok === false) return leaseGate.abort;
      }
      if (typeof onBeforeMutation === "function") onBeforeMutation(issuer.step);
      const issuance = assertIssuanceOutcome(
        await issuer.submit({ csrPem: csrResult.csrPem, domains }),
      );
      issuanceOutcome = issuance.outcome;
      await reportIssuanceEvidence(client, jobId, issuance);

      if (issuance.outcome === "pending") {
        await writeEnrollmentRequestJournal({
          stateDir,
          enrollmentId: decoded.enrollmentId,
          attempt: decoded.attempt,
          requestId: issuance.requestId,
          snapshotSha256: decoded.snapshotSha256,
          jobId,
        });
        return resultForAdcsOutcome(issuance, decoded);
      }
      if (issuance.outcome !== "issued") {
        return resultForAdcsOutcome(issuance, decoded);
      }
      certificatePem = issuance.certificatePem;
    } finally {
      if (certificatePem === undefined && containerName && !shouldRetainCngKey(issuanceOutcome)) {
        try {
          const cleanup = await removeAbandonedKeyContainer({
            containerName,
            ...(windowsExecFileImpl ? { execFileImpl: windowsExecFileImpl } : {}),
          });
          if (cleanup.ok === true) {
            removeIssuedContainerRecord({ stateDir, containerName });
          }
        } catch (err) {
          emitLog(
            log,
            `job ${jobId}: failed to delete abandoned CNG key after AD CS failure: ${err.message}`,
          );
        }
      }
      if (enrollmentLock) enrollmentLock.release();
    }

    // Re-acquire for accept/deploy so continue-enrollment cannot race cutover.
    try {
      enrollmentLock = acquireEnrollmentLock(stateDir, decoded.enrollmentId);
    } catch (err) {
      return {
        status: "failed",
        keyRotated: null,
        errorMessage: boundErrorMessage(`could not re-acquire AD CS enrollment lock: ${err.message}`),
      };
    }
    try {
      return await runWindowsIisDeployTail({
        jobId,
        client,
        certificatePem,
        target: windowsTarget,
        stateDir,
        cngWorkDir,
        log,
        containerName,
        leaseOpts,
        onBeforeMutation,
        windowsExecFileImpl,
        windowsConnectImpl,
      });
    } finally {
      enrollmentLock.release();
    }
  }

  async function executeWindowsIisContinueEnrollmentJob({
    job,
    jobId,
    client,
    executionContext,
    log,
    leaseOpts = null,
    onBeforeMutation = null,
  }) {
    const { execution } = executionContext;
    const targetResolved = await resolveWindowsIisTarget(job);
    if (targetResolved.error) {
      return { status: "failed", keyRotated: null, errorMessage: targetResolved.error };
    }
    const { windowsTarget } = targetResolved;
    const stateDir = resolveAgentStateDir(executionContext) || path.dirname(execution.keysDir);
    const ctx = await buildAdcsIssuerContext({ job, jobId, executionContext, stateDir });
    if (ctx.error) {
      return {
        status: "failed",
        keyRotated: null,
        errorMessage: boundErrorMessage(ctx.error),
      };
    }
    const { decoded, helperPath, caCertPath, snapshot } = ctx;
    const journal = readEnrollmentRequestJournal(stateDir, decoded.enrollmentId);
    if (!journal) {
      return {
        status: "failed",
        keyRotated: null,
        errorMessage: boundErrorMessage(
          `no local RequestId journal for enrollment ${decoded.enrollmentId}; cannot retrieve`,
        ),
      };
    }

    let enrollmentLock;
    try {
      enrollmentLock = acquireEnrollmentLock(stateDir, decoded.enrollmentId);
    } catch (err) {
      return {
        status: "failed",
        keyRotated: null,
        errorMessage: boundErrorMessage(`could not acquire AD CS enrollment lock: ${err.message}`),
      };
    }

    const cngWorkDir = path.join(stateDir, WINDOWS_CERT_STORE_WORK_DIR_NAME);
    const windowsExecFileImpl = executionContext.windowsExecFileImpl;
    const windowsConnectImpl = executionContext.windowsConnectImpl;
    const containerName = `tokentimer-enr-${decoded.enrollmentId}`;

    try {
      {
        const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
        if (leaseGate && leaseGate.ok === false) return leaseGate.abort;
      }

      const issuer = createAdcsIssuer({
        caConfig: snapshot.caConfig,
        template: snapshot.template,
        caKeySha256: snapshot.caKeySha256,
        caCertPath,
        helperPath,
        scratchDir: path.join(stateDir, "adcs-scratch"),
        jobId,
        enrollmentId: decoded.enrollmentId,
        execFileImpl: executionContext.adcsExecFileImpl || windowsExecFileImpl,
        decodeCmcImpl: executionContext.adcsDecodeCmcImpl,
        info: emitInfo,
      });

      if (typeof onBeforeMutation === "function") onBeforeMutation(issuer.step);
      const issuance = assertIssuanceOutcome(await issuer.retrieve(journal.requestId));
      await reportIssuanceEvidence(client, jobId, issuance);

      if (issuance.outcome === "pending") {
        return resultForAdcsOutcome(issuance, decoded);
      }
      if (issuance.outcome !== "issued") {
        return resultForAdcsOutcome(issuance, decoded);
      }

      return await runWindowsIisDeployTail({
        jobId,
        client,
        certificatePem: issuance.certificatePem,
        target: windowsTarget,
        stateDir,
        cngWorkDir,
        log,
        containerName,
        leaseOpts,
        onBeforeMutation,
        windowsExecFileImpl,
        windowsConnectImpl,
      });
    } finally {
      enrollmentLock.release();
    }
  }

  return {
    executeWindowsIisAdcsRenewJob,
    executeWindowsIisContinueEnrollmentJob,
  };
}

module.exports = {
  createAdcsWindowsIisExecutors,
  resultForAdcsOutcome,
  shouldRetainCngKey,
};
