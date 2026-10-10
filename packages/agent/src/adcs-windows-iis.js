"use strict";

/**
 * Windows IIS AD CS renew + continue-enrollment executor (ADR-0014).
 * Holds acquireEnrollmentLock across CNG keygen, certreq submit/retrieve,
 * and (on issued) the deploy tail.
 *
 * Executable selection remains gated off in IMPLEMENTED_ISSUER_KINDS until
 * durable journal recovery and continuation scheduling land; decision-6
 * validation runs on the dormant path before accept.
 */

const path = require("node:path");
const fsp = require("node:fs/promises");

const {
  createAdcsIssuer,
  assertIssuanceOutcome,
  decodeEnrollmentSnapshot,
  mapSnapshotKeyAlgorithm,
  resolveAdcsCmcHelperPath,
  resolvePinnedCaCertPath,
  resolveTemplateOid,
  writeEnrollmentRequestJournal,
  readEnrollmentRequestJournal,
} = require("./issuers");
const {
  validateIssuedCertificate,
  extractSpkiFromCsr,
  spkiSha256Hex,
} = require("./issuers/issued-certificate-validation");
const {
  resolveAdcsChainHelperPath,
  validateCertificateChain,
} = require("./issuers/chain-helper");
const {
  generateCsrViaCng,
  acquireEnrollmentLock,
  removeAbandonedKeyContainer,
  recordIssuedContainer,
  removeIssuedContainerRecord,
  buildEnrollmentContainerName,
  hasIssuedContainerRecord,
} = require("./windows-cert-store");

const WINDOWS_CERT_STORE_WORK_DIR_NAME = "windows-cert-store-work";
const CA_HRESULT_PATTERN = /^0x[0-9A-F]{8}$/;

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

function installedEnrollmentResult(enrollmentId, attempt, requestId) {
  const extras = { errorCode: null, caHresult: null };
  if (Number.isInteger(requestId) && requestId >= 1) {
    extras.requestId = requestId;
  }
  return enrollmentResultFor(enrollmentId, attempt, "installed", extras);
}

/**
 * @param {object} issuance issuer outcome
 * @param {{ enrollmentId: string, attempt: number }} enrollment
 * @param {{ knownRequestId?: number }} [options] set on continue-enrollment retrieve
 */
function resultForAdcsOutcome(issuance, { enrollmentId, attempt }, options = {}) {
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
    const caHresult =
      typeof issuance.caHresult === "string" && CA_HRESULT_PATTERN.test(issuance.caHresult)
        ? issuance.caHresult
        : null;
    if (!caHresult) {
      // Contract requires caHresult for denied; without it stay reconcilable.
      return {
        status: "failed",
        keyRotated: null,
        errorMessage: boundErrorMessage(issuance.detail || "CA denied without HRESULT"),
        enrollmentResult: enrollmentResultFor(enrollmentId, attempt, "submission_uncertain", {
          errorCode: "ADCS_DISPOSITION_UNKNOWN",
        }),
      };
    }
    return {
      status: "failed",
      keyRotated: null,
      errorMessage: boundErrorMessage(issuance.detail),
      enrollmentResult: enrollmentResultFor(enrollmentId, attempt, "denied", {
        caHresult,
        ...(Number.isInteger(issuance.requestId) ? { requestId: issuance.requestId } : {}),
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
    // A known pending RequestId stays pending_issuance (retry/retrieve), not
    // submission_uncertain (which is only for unclassified submit side effects).
    if (Number.isInteger(options.knownRequestId) && options.knownRequestId >= 1) {
      return {
        status: "failed",
        keyRotated: null,
        errorMessage: boundErrorMessage(issuance.detail),
        enrollmentResult: enrollmentResultFor(enrollmentId, attempt, "pending_issuance", {
          requestId: options.knownRequestId,
        }),
      };
    }
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
  // not_submitted: transport proved the CA never saw the CSR, so free the
  // container and let a later renew regenerate. pending/uncertain/issued and
  // validation_deferred keep the key (decision 6); rejected_invalid frees it.
  return (
    outcome === "pending" ||
    outcome === "uncertain" ||
    outcome === "issued" ||
    outcome === "validation_deferred"
  );
}

/**
 * @param {object} validation validateIssuedCertificate result
 * @param {{ enrollmentId: string, attempt: number }} enrollment
 * @param {number} [requestId]
 */
function resultForValidationOutcome(validation, { enrollmentId, attempt }, requestId) {
  const requestExtras =
    Number.isInteger(requestId) && requestId >= 1 ? { requestId } : {};
  if (validation.state === "validation_deferred") {
    return {
      status: "failed",
      keyRotated: null,
      errorMessage: boundErrorMessage(validation.detail || "revocation status unknown"),
      enrollmentResult: enrollmentResultFor(enrollmentId, attempt, "validation_deferred", {
        errorCode: null,
        ...requestExtras,
      }),
    };
  }
  return {
    status: "failed",
    keyRotated: null,
    errorMessage: boundErrorMessage(validation.detail || "issued certificate failed validation"),
    enrollmentResult: enrollmentResultFor(enrollmentId, attempt, "rejected_invalid", {
      errorCode: validation.errorCode || "ADCS_CERTIFICATE_INVALID",
      ...requestExtras,
    }),
  };
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

  async function runDecision6Validation({
    certificatePem,
    csrPem,
    csrSpkiSha256,
    snapshot,
    requiredDnsName,
    stateDir,
    executionContext,
    templateOidHint,
  }) {
    const oidResolved = resolveTemplateOid({
      stateDir,
      caConfig: snapshot.caConfig,
      template: snapshot.template,
      templateOid: templateOidHint || executionContext.adcsTemplateOid,
    });
    if (!oidResolved.ok) {
      return {
        ok: false,
        state: "rejected_invalid",
        errorCode: "ADCS_CERTIFICATE_INVALID",
        detail: oidResolved.error,
      };
    }

    const chainHelper = resolveAdcsChainHelperPath({
      overridePath: executionContext.adcsChainHelperPath,
    });
    const chainValidateImpl =
      executionContext.adcsChainValidateImpl ||
      (async (args) => {
        if (chainHelper.error) {
          return { verdict: "invalid", detail: chainHelper.error };
        }
        const workDir = path.join(stateDir, "adcs-scratch", "validate");
        await fsp.mkdir(workDir, { recursive: true });
        const certPath = path.join(workDir, `leaf-${process.pid}.pem`);
        await fsp.writeFile(certPath, args.certificatePem, "utf8");
        try {
          return await validateCertificateChain({
            helperPath: chainHelper.path,
            certPath,
            caKeySha256: args.caKeySha256,
            revocationCheck: args.revocationCheck,
            caCertPath: args.caCertPath,
            extraStorePath: args.extraStorePath,
            execFileImpl: executionContext.adcsExecFileImpl || executionContext.windowsExecFileImpl,
          });
        } finally {
          try {
            await fsp.unlink(certPath);
          } catch {
            // best-effort cleanup
          }
        }
      });

    return validateIssuedCertificate({
      certificatePem,
      csrPem,
      csrSpkiSha256,
      authorizedDnsNames: snapshot.authorizedDnsNames,
      requiredDnsName,
      templateOid: oidResolved.templateOid,
      caKeySha256: snapshot.caKeySha256,
      minimumRemainingValidity: snapshot.minimumRemainingValidity,
      requireLaterNotAfter: snapshot.requireLaterNotAfter === true,
      existingNotAfter: executionContext.adcsExistingNotAfter ?? null,
      existingSerialHex: executionContext.adcsExistingSerialHex ?? null,
      keyAlgorithm: snapshot.keyAlgorithm,
      chainValidateImpl,
      revocationCheck: executionContext.adcsRevocationCheck || "require",
      caCertPath: executionContext.adcsCaCertPath,
      helperPath: chainHelper.path,
    });
  }

  async function buildAdcsIssuerContext({ job, executionContext, stateDir }) {
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

  async function withAdcsIssuer(scratchRoot, factory) {
    await fsp.mkdir(scratchRoot, { recursive: true });
    return factory(scratchRoot);
  }

  function withInstalledEnrollmentResult(deployResult, enrollment, requestId) {
    if (deployResult?.status !== "succeeded") return deployResult;
    return {
      ...deployResult,
      enrollmentResult: installedEnrollmentResult(
        enrollment.enrollmentId,
        enrollment.attempt,
        requestId,
      ),
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
    const ctx = await buildAdcsIssuerContext({ job, executionContext, stateDir });
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
    if (!domains.includes(commonName)) {
      return {
        status: "failed",
        keyRotated: null,
        errorMessage: boundErrorMessage(
          `target.reference ${JSON.stringify(commonName)} is not in enrollment authorizedDnsNames`,
        ),
        enrollmentResult: enrollmentResultFor(decoded.enrollmentId, decoded.attempt, "refused", {
          errorCode: null,
        }),
      };
    }
    const csrCommonName = commonName;
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
    let submitStarted = false;
    try {
      {
        const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
        if (leaseGate && leaseGate.ok === false) return leaseGate.abort;
      }

      const existingJournal = readEnrollmentRequestJournal(stateDir, decoded.enrollmentId);
      if (existingJournal) {
        return {
          status: "blocked",
          keyRotated: null,
          errorMessage: boundErrorMessage(
            `enrollment ${decoded.enrollmentId} already has a local RequestId journal; use continue-enrollment`,
          ),
        };
      }
      const enrollmentContainer = buildEnrollmentContainerName(decoded.enrollmentId);
      if (hasIssuedContainerRecord({ stateDir, containerName: enrollmentContainer })) {
        return {
          status: "blocked",
          keyRotated: null,
          errorMessage: boundErrorMessage(
            `enrollment ${decoded.enrollmentId} already has a CNG key container; use continue-enrollment or abandon the enrollment before renewing`,
          ),
        };
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

      const scratchRoot = path.join(stateDir, "adcs-scratch");
      const issuer = await withAdcsIssuer(scratchRoot, (scratchDir) =>
        createAdcsIssuer({
          caConfig: snapshot.caConfig,
          template: snapshot.template,
          caKeySha256: snapshot.caKeySha256,
          caCertPath,
          helperPath,
          scratchDir,
          jobId,
          enrollmentId: decoded.enrollmentId,
          execFileImpl: executionContext.adcsExecFileImpl || windowsExecFileImpl,
          decodeCmcImpl: executionContext.adcsDecodeCmcImpl,
          info: emitInfo,
        }),
      );

      {
        const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
        if (leaseGate && leaseGate.ok === false) return leaseGate.abort;
      }
      if (typeof onBeforeMutation === "function") onBeforeMutation(issuer.step);
      // Once submit starts, an unclassified exception must retain the key.
      submitStarted = true;
      let issuance;
      try {
        issuance = assertIssuanceOutcome(
          await issuer.submit({ csrPem: csrResult.csrPem, domains }),
        );
      } catch (err) {
        issuanceOutcome = "uncertain";
        return {
          status: "failed",
          keyRotated: null,
          errorMessage: boundErrorMessage(`AD CS submit interrupted: ${err.message}`),
          enrollmentResult: enrollmentResultFor(
            decoded.enrollmentId,
            decoded.attempt,
            "submission_uncertain",
            { errorCode: "ADCS_DISPOSITION_UNKNOWN" },
          ),
        };
      }
      issuanceOutcome = issuance.outcome;
      await reportIssuanceEvidence(client, jobId, issuance);

      let csrSpkiSha256;
      try {
        csrSpkiSha256 = spkiSha256Hex(extractSpkiFromCsr(csrResult.csrPem));
      } catch (err) {
        return {
          status: "failed",
          keyRotated: null,
          errorMessage: boundErrorMessage(`could not hash CSR public key: ${err.message}`),
        };
      }
      const templateOidHint = resolveTemplateOid({
        stateDir,
        caConfig: snapshot.caConfig,
        template: snapshot.template,
        templateOid: executionContext.adcsTemplateOid,
      });

      if (issuance.outcome === "pending") {
        await writeEnrollmentRequestJournal({
          stateDir,
          enrollmentId: decoded.enrollmentId,
          attempt: decoded.attempt,
          requestId: issuance.requestId,
          snapshotSha256: decoded.snapshotSha256,
          jobId,
          csrSpkiSha256,
          templateOid: templateOidHint.ok ? templateOidHint.templateOid : undefined,
        });
        return resultForAdcsOutcome(issuance, decoded);
      }
      if (issuance.outcome !== "issued") {
        return resultForAdcsOutcome(issuance, decoded);
      }
      certificatePem = issuance.certificatePem;

      const validation = await runDecision6Validation({
        certificatePem,
        csrPem: csrResult.csrPem,
        csrSpkiSha256,
        snapshot,
        requiredDnsName: commonName,
        stateDir,
        executionContext: { ...executionContext, adcsCaCertPath: caCertPath },
        templateOidHint: templateOidHint.ok ? templateOidHint.templateOid : undefined,
      });
      if (!validation.ok) {
        issuanceOutcome =
          validation.state === "validation_deferred" ? "validation_deferred" : "rejected_invalid";
        return resultForValidationOutcome(validation, decoded, issuance.requestId);
      }

      // Hold the enrollment lock through accept/deploy so continue-enrollment
      // cannot race retrieve/accept on the same enrollmentId.
      const deployResult = await runWindowsIisDeployTail({
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
      return withInstalledEnrollmentResult(deployResult, decoded, issuance.requestId);
    } finally {
      const retainAfterSubmit =
        submitStarted && (issuanceOutcome === null || shouldRetainCngKey(issuanceOutcome));
      if (certificatePem === undefined && containerName && !retainAfterSubmit) {
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
    const ctx = await buildAdcsIssuerContext({ job, executionContext, stateDir });
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
    if (
      typeof journal.snapshotSha256 !== "string" ||
      journal.snapshotSha256 !== decoded.snapshotSha256
    ) {
      return {
        status: "rejected",
        rejectionReason: "enrollment_snapshot_mismatch",
        keyRotated: null,
        errorMessage: boundErrorMessage(
          `local RequestId journal snapshotSha256 does not match the signed enrollment snapshot for ${decoded.enrollmentId}`,
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
    const containerName = buildEnrollmentContainerName(decoded.enrollmentId);

    try {
      {
        const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
        if (leaseGate && leaseGate.ok === false) return leaseGate.abort;
      }

      const scratchRoot = path.join(stateDir, "adcs-scratch");
      const issuer = await withAdcsIssuer(scratchRoot, (scratchDir) =>
        createAdcsIssuer({
          caConfig: snapshot.caConfig,
          template: snapshot.template,
          caKeySha256: snapshot.caKeySha256,
          caCertPath,
          helperPath,
          scratchDir,
          jobId,
          enrollmentId: decoded.enrollmentId,
          execFileImpl: executionContext.adcsExecFileImpl || windowsExecFileImpl,
          decodeCmcImpl: executionContext.adcsDecodeCmcImpl,
          info: emitInfo,
        }),
      );

      if (typeof onBeforeMutation === "function") onBeforeMutation(issuer.step);
      const issuance = assertIssuanceOutcome(await issuer.retrieve(journal.requestId));
      await reportIssuanceEvidence(client, jobId, issuance);

      if (issuance.outcome === "pending") {
        return resultForAdcsOutcome(issuance, decoded, {
          knownRequestId: journal.requestId,
        });
      }
      if (issuance.outcome !== "issued") {
        return resultForAdcsOutcome(issuance, decoded, {
          knownRequestId: journal.requestId,
        });
      }

      if (typeof journal.csrSpkiSha256 !== "string" || !/^[a-f0-9]{64}$/.test(journal.csrSpkiSha256)) {
        return {
          status: "failed",
          keyRotated: null,
          errorMessage: boundErrorMessage(
            `local RequestId journal for enrollment ${decoded.enrollmentId} is missing csrSpkiSha256; cannot validate before accept`,
          ),
        };
      }

      const validation = await runDecision6Validation({
        certificatePem: issuance.certificatePem,
        csrSpkiSha256: journal.csrSpkiSha256,
        snapshot,
        requiredDnsName: windowsTarget.reference,
        stateDir,
        executionContext: { ...executionContext, adcsCaCertPath: caCertPath },
        templateOidHint: journal.templateOid,
      });
      if (!validation.ok) {
        return resultForValidationOutcome(validation, decoded, journal.requestId);
      }

      const deployResult = await runWindowsIisDeployTail({
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
      return withInstalledEnrollmentResult(deployResult, decoded, journal.requestId);
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
  resultForValidationOutcome,
  shouldRetainCngKey,
};
