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
  writeKeygenIntent,
  writeCsrArtifact,
  writeEnrollmentJournal,
  writeIssuedCertificateArtifacts,
  readEnrollmentJournal,
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
const { queryCurrentBinding } = require("./windows-iis");
const { listMachineStoreCertificates } = require("./windows-discovery");

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
  // Accepts issuer outcomes or durable journal states. Prefer journal state
  // when both disagree (e.g. denied without HRESULT → submission_uncertain).
  return (
    outcome === "pending" ||
    outcome === "pending_issuance" ||
    outcome === "uncertain" ||
    outcome === "submission_uncertain" ||
    outcome === "issued" ||
    outcome === "validation_deferred" ||
    outcome === "not_submitted" ||
    outcome === "install_failed" ||
    outcome === "prepared" ||
    outcome === "submitting" ||
    outcome === "installing" ||
    outcome === "keygen_intent" ||
    outcome === "installed"
  );
}

/**
 * Prefer the durable journal state for CNG cleanup when a receipt exists.
 * Returns undefined when no journal override applies (use issuer outcome).
 * Returns null when the journal is corrupt/unreadable (retain key).
 */
function resolveCleanupOutcome({ stateDir, enrollmentId }) {
  if (typeof stateDir !== "string" || typeof enrollmentId !== "string") {
    return undefined;
  }
  try {
    const read = readEnrollmentJournal(stateDir, enrollmentId);
    if (read.kind === "corrupt") return null;
    if (read.kind === "valid" || read.kind === "legacy") {
      return read.journal.state;
    }
  } catch {
    return null;
  }
  return undefined;
}

/**
 * Whether the CNG container created for this enrollment should be deleted.
 * Independent of whether certificate PEM was received: rejected_invalid must
 * free the key (ADR-0014 decision 6). After prepared is journaled, pre-submit
 * aborts retain the key so continue can resume-submit the same CSR.
 *
 * When `journalState` is present on the options object it overrides the raw
 * issuer outcome (including null = retain on unreadable journal).
 */
function shouldCleanupAbandonedCngKey(opts) {
  const {
    submitStarted,
    issuanceOutcome,
    containerCreated,
    preparedJournalCommitted = false,
  } = opts;
  const effectiveOutcome = Object.hasOwn(opts, "journalState")
    ? opts.journalState
    : issuanceOutcome;
  // Durable prepared (or later) journal owns the container until abandon.
  if (preparedJournalCommitted === true) {
    if (effectiveOutcome === null && !submitStarted) return false;
    if (effectiveOutcome === null) return false;
    return !shouldRetainCngKey(effectiveOutcome);
  }
  // Key exists but submit never started and prepared was never committed.
  if (!submitStarted) return containerCreated === true;
  if (effectiveOutcome === null) return false;
  return !shouldRetainCngKey(effectiveOutcome);
}

/**
 * Write the leaf PEM into a private temporary directory under adcs-scratch.
 * Concurrent validations must never share a filename.
 */
async function withUniqueValidationLeafFile(stateDir, certificatePem, fn) {
  const scratchRoot = path.join(stateDir, "adcs-scratch");
  await fsp.mkdir(scratchRoot, { recursive: true });
  const workDir = await fsp.mkdtemp(path.join(scratchRoot, "validate-"));
  const certPath = path.join(workDir, "leaf.pem");
  try {
    await fsp.writeFile(certPath, certificatePem, "utf8");
    return await fn(certPath, workDir);
  } finally {
    try {
      await fsp.rm(workDir, { recursive: true, force: true });
    } catch {
      // best-effort cleanup
    }
  }
}

/**
 * Observe the certificate currently bound at the IIS target (serial + notAfter).
 * Missing binding is a first install (nulls), not an error.
 */
async function observeInstalledCertificateIdentity({
  windowsTarget,
  execFileImpl,
  queryCurrentBindingImpl = queryCurrentBinding,
  listMachineStoreCertificatesImpl = listMachineStoreCertificates,
}) {
  // Match deploy's selector: explicit address when present, else IIS wildcard "*".
  const address =
    typeof windowsTarget.binding.address === "string" && windowsTarget.binding.address.length > 0
      ? windowsTarget.binding.address
      : "*";
  const binding = {
    address,
    port: windowsTarget.binding.port,
    ...(windowsTarget.binding.sniHost ? { sniHost: windowsTarget.binding.sniHost } : {}),
  };
  const current = await queryCurrentBindingImpl({
    binding,
    ...(execFileImpl ? { execFileImpl } : {}),
  });
  if (!current.ok) {
    return {
      error: current.stderrExcerpt || "could not query the current IIS binding",
    };
  }
  if (!current.thumbprint) {
    return { existingNotAfter: null, existingSerialHex: null };
  }
  const listed = await listMachineStoreCertificatesImpl({
    store: windowsTarget.store,
    ...(execFileImpl ? { execFileImpl } : {}),
  });
  if (!listed.ok) {
    return {
      error: listed.stderrExcerpt || "could not list the machine certificate store",
    };
  }
  const thumb = String(current.thumbprint).toUpperCase();
  const match = listed.certificates.find(
    (cert) => String(cert.thumbprint || "").toUpperCase() === thumb,
  );
  if (!match) {
    return {
      error: `bound thumbprint ${thumb} was not found in store ${windowsTarget.store}`,
    };
  }
  const existingNotAfter = match.notAfter ?? null;
  const existingSerialHex =
    typeof match.serialNumber === "string" && match.serialNumber.length > 0
      ? match.serialNumber
      : null;
  // Bound certificate present but unreadable metadata: fail closed. Do not
  // pretend this is a first install and skip serial / requireLaterNotAfter.
  if (existingNotAfter == null || existingSerialHex == null) {
    return {
      error: `bound certificate ${thumb} in store ${windowsTarget.store} is missing serial or notAfter metadata`,
    };
  }
  return { existingNotAfter, existingSerialHex };
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
    reportStepEvidence,
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
    templateOid,
    windowsTarget,
  }) {
    if (typeof templateOid !== "string" || !/^[0-2](\.(0|[1-9][0-9]{0,9})){1,63}$/.test(templateOid)) {
      return {
        ok: false,
        state: "rejected_invalid",
        errorCode: "ADCS_CERTIFICATE_INVALID",
        detail: "templateOid is required and must be bound to this enrollment",
      };
    }

    const observeImpl =
      executionContext.adcsObserveInstalledIdentityImpl || observeInstalledCertificateIdentity;
    const observed = await observeImpl({
      windowsTarget,
      execFileImpl: executionContext.windowsExecFileImpl,
      queryCurrentBindingImpl: executionContext.adcsQueryCurrentBindingImpl,
      listMachineStoreCertificatesImpl: executionContext.adcsListMachineStoreCertificatesImpl,
    });
    if (observed.error) {
      return {
        ok: false,
        state: "rejected_invalid",
        errorCode: "ADCS_CERTIFICATE_INVALID",
        detail: observed.error,
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
        return withUniqueValidationLeafFile(stateDir, args.certificatePem, async (certPath) =>
          validateCertificateChain({
            helperPath: chainHelper.path,
            certPath,
            caKeySha256: args.caKeySha256,
            revocationCheck: args.revocationCheck,
            caCertPath: args.caCertPath,
            extraStorePath: args.extraStorePath,
            execFileImpl: executionContext.adcsExecFileImpl || executionContext.windowsExecFileImpl,
          }),
        );
      });

    return validateIssuedCertificate({
      certificatePem,
      csrPem,
      csrSpkiSha256,
      authorizedDnsNames: snapshot.authorizedDnsNames,
      requiredDnsName,
      templateOid,
      caKeySha256: snapshot.caKeySha256,
      minimumRemainingValidity: snapshot.minimumRemainingValidity,
      requireLaterNotAfter: snapshot.requireLaterNotAfter === true,
      existingNotAfter: observed.existingNotAfter,
      existingSerialHex: observed.existingSerialHex,
      keyAlgorithm: snapshot.keyAlgorithm,
      chainValidateImpl,
      revocationCheck: executionContext.adcsRevocationCheck || "require",
      caCertPath: executionContext.adcsCaCertPath,
      helperPath: chainHelper.path,
    });
  }

  async function reportBestEffortRevocationEvidence(client, jobId, validation) {
    if (typeof reportStepEvidence !== "function") return;
    if (!validation || validation.revocationBestEffort !== true) return;
    await reportStepEvidence(client, jobId, [
      {
        eventType: "validation.passed",
        observedAt: new Date().toISOString(),
        summary:
          "AD CS issued certificate accepted under best-effort revocation policy (revocation status unknown)",
        metadata: [
          { name: "step", value: "adcs-decision6" },
          { name: "revocationCheck", value: "best-effort" },
          { name: "revocationVerdict", value: "revocation_unknown" },
          { name: "revocationBestEffort", value: true },
        ],
      },
    ]);
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
    if (deployResult?.status === "succeeded") {
      return {
        ...deployResult,
        enrollmentResult: installedEnrollmentResult(
          enrollment.enrollmentId,
          enrollment.attempt,
          requestId,
        ),
      };
    }
    return {
      ...deployResult,
      enrollmentResult: enrollmentResultFor(
        enrollment.enrollmentId,
        enrollment.attempt,
        "install_failed",
        Number.isInteger(requestId) && requestId >= 1 ? { requestId } : {},
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
    let preparedJournalCommitted = false;
    try {
      {
        const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
        if (leaseGate && leaseGate.ok === false) return leaseGate.abort;
      }

      {
        const existing = readEnrollmentJournal(stateDir, decoded.enrollmentId);
        if (existing.kind === "corrupt") {
          return {
            status: "failed",
            keyRotated: null,
            errorMessage: boundErrorMessage(
              `local AD CS enrollment journal is corrupt: ${existing.error}`,
            ),
          };
        }
        if (existing.kind === "valid" || existing.kind === "legacy") {
          return {
            status: "blocked",
            keyRotated: null,
            errorMessage: boundErrorMessage(
              `enrollment ${decoded.enrollmentId} already has a local enrollment journal (state ${existing.journal.state}); use continue-enrollment`,
            ),
          };
        }
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

      const templateOidResolved = resolveTemplateOid({
        stateDir,
        caConfig: snapshot.caConfig,
        template: snapshot.template,
        templateOid: executionContext.adcsTemplateOid,
      });
      if (!templateOidResolved.ok) {
        return {
          status: "failed",
          keyRotated: null,
          errorMessage: boundErrorMessage(templateOidResolved.error),
          enrollmentResult: enrollmentResultFor(
            decoded.enrollmentId,
            decoded.attempt,
            "rejected_invalid",
            { errorCode: "ADCS_CERTIFICATE_INVALID" },
          ),
        };
      }
      const templateOid = templateOidResolved.templateOid;

      // Durable keygen intent before certreq -new (crash window A1).
      await writeKeygenIntent({
        stateDir,
        enrollmentId: decoded.enrollmentId,
        containerName: enrollmentContainer,
        attempt: decoded.attempt,
        snapshotSha256: decoded.snapshotSha256,
        jobId,
      });

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

      let csrSpkiSha256;
      let csrSha256;
      try {
        csrSpkiSha256 = spkiSha256Hex(extractSpkiFromCsr(csrResult.csrPem));
        const csrWritten = await writeCsrArtifact({
          stateDir,
          enrollmentId: decoded.enrollmentId,
          csrPem: csrResult.csrPem,
        });
        csrSha256 = csrWritten.csrSha256;
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "prepared",
          attempt: decoded.attempt,
          containerName,
          snapshotSha256: decoded.snapshotSha256,
          jobId,
          csrSha256,
          csrSpkiSha256,
          templateOid,
          caConfig: snapshot.caConfig,
          template: snapshot.template,
        });
        preparedJournalCommitted = true;
      } catch (err) {
        return {
          status: "failed",
          keyRotated: null,
          errorMessage: boundErrorMessage(
            `failed to persist prepared enrollment journal/CSR: ${err.message}`,
          ),
        };
      }

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
      // Durable submitting barrier: must succeed before certreq -submit.
      try {
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "submitting",
          attempt: decoded.attempt,
          containerName,
          snapshotSha256: decoded.snapshotSha256,
          jobId,
          csrSha256,
          csrSpkiSha256,
          templateOid,
          caConfig: snapshot.caConfig,
          template: snapshot.template,
        });
      } catch (err) {
        return {
          status: "failed",
          keyRotated: null,
          errorMessage: boundErrorMessage(
            `failed to persist submitting journal before CA contact: ${err.message}`,
          ),
        };
      }
      // Once submit starts, an unclassified exception must retain the key.
      submitStarted = true;
      let issuance;
      try {
        issuance = assertIssuanceOutcome(
          await issuer.submit({ csrPem: csrResult.csrPem, domains }),
        );
      } catch (err) {
        issuanceOutcome = "uncertain";
        try {
          await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
            state: "submission_uncertain",
            attempt: decoded.attempt,
            containerName,
            snapshotSha256: decoded.snapshotSha256,
            jobId,
            csrSha256,
            csrSpkiSha256,
            templateOid,
            caConfig: snapshot.caConfig,
            template: snapshot.template,
          });
        } catch {
          // Key retention still applies via submitStarted.
        }
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

      // Persist classified CA outcome before evidence reporting so a crash or
      // report failure cannot leave submitting without a RequestId/leaf receipt.
      const journalTrustFields = {
        attempt: decoded.attempt,
        containerName,
        snapshotSha256: decoded.snapshotSha256,
        jobId,
        csrSha256,
        csrSpkiSha256,
        templateOid,
        caConfig: snapshot.caConfig,
        template: snapshot.template,
      };

      if (issuance.outcome === "not_submitted") {
        // Proven never reached the CA: return journal to prepared for resume-submit.
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "prepared",
          ...journalTrustFields,
        });
        if (typeof onBeforeMutation === "function") onBeforeMutation("report-issuance-evidence");
        await reportIssuanceEvidence(client, jobId, issuance);
        return resultForAdcsOutcome(issuance, decoded);
      }
      if (issuance.outcome === "pending") {
        await writeEnrollmentRequestJournal({
          stateDir,
          enrollmentId: decoded.enrollmentId,
          attempt: decoded.attempt,
          requestId: issuance.requestId,
          snapshotSha256: decoded.snapshotSha256,
          jobId,
          csrSpkiSha256,
          templateOid,
          containerName,
          csrPem: csrResult.csrPem,
        });
        if (typeof onBeforeMutation === "function") onBeforeMutation("report-issuance-evidence");
        await reportIssuanceEvidence(client, jobId, issuance);
        return resultForAdcsOutcome(issuance, decoded);
      }
      if (issuance.outcome === "denied") {
        const caHresult =
          typeof issuance.caHresult === "string" && CA_HRESULT_PATTERN.test(issuance.caHresult)
            ? issuance.caHresult
            : null;
        // Without HRESULT stay reconcilable (matches enrollmentResult mapping).
        // issuanceOutcome must follow the journalled state so finally cleanup
        // cannot free the key while submission_uncertain is durable.
        issuanceOutcome = caHresult ? "denied" : "submission_uncertain";
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: issuanceOutcome,
          ...journalTrustFields,
          ...(caHresult ? { caHresult } : {}),
          ...(Number.isInteger(issuance.requestId) ? { requestId: issuance.requestId } : {}),
        });
        if (typeof onBeforeMutation === "function") onBeforeMutation("report-issuance-evidence");
        await reportIssuanceEvidence(client, jobId, issuance);
        return resultForAdcsOutcome(issuance, decoded);
      }
      if (issuance.outcome === "refused") {
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "refused",
          ...journalTrustFields,
          ...(typeof issuance.errorCode === "string" ? { errorCode: issuance.errorCode } : {}),
        });
        if (typeof onBeforeMutation === "function") onBeforeMutation("report-issuance-evidence");
        await reportIssuanceEvidence(client, jobId, issuance);
        return resultForAdcsOutcome(issuance, decoded);
      }
      if (issuance.outcome === "uncertain") {
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "submission_uncertain",
          ...journalTrustFields,
        });
        if (typeof onBeforeMutation === "function") onBeforeMutation("report-issuance-evidence");
        await reportIssuanceEvidence(client, jobId, issuance);
        return resultForAdcsOutcome(issuance, decoded);
      }
      if (issuance.outcome !== "issued") {
        if (typeof onBeforeMutation === "function") onBeforeMutation("report-issuance-evidence");
        await reportIssuanceEvidence(client, jobId, issuance);
        return resultForAdcsOutcome(issuance, decoded);
      }
      certificatePem = issuance.certificatePem;

      // Persist issued leaf before evidence and decision-6 (recovery source of truth).
      let leafSha256;
      try {
        const written = await writeIssuedCertificateArtifacts({
          stateDir,
          enrollmentId: decoded.enrollmentId,
          leafPem: certificatePem,
        });
        leafSha256 = written.leafSha256;
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "issued",
          ...journalTrustFields,
          leafSha256,
          ...(Number.isInteger(issuance.requestId) ? { requestId: issuance.requestId } : {}),
        });
      } catch (err) {
        return {
          status: "failed",
          keyRotated: null,
          errorMessage: boundErrorMessage(
            `failed to persist issued certificate artifact: ${err.message}`,
          ),
        };
      }

      if (typeof onBeforeMutation === "function") onBeforeMutation("report-issuance-evidence");
      await reportIssuanceEvidence(client, jobId, issuance);

      const validation = await runDecision6Validation({
        certificatePem,
        csrPem: csrResult.csrPem,
        csrSpkiSha256,
        snapshot,
        requiredDnsName: commonName,
        stateDir,
        executionContext: { ...executionContext, adcsCaCertPath: caCertPath },
        templateOid,
        windowsTarget,
      });
      if (!validation.ok) {
        issuanceOutcome =
          validation.state === "validation_deferred" ? "validation_deferred" : "rejected_invalid";
        if (validation.state === "validation_deferred") {
          const deadline = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
          await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
            state: "validation_deferred",
            attempt: decoded.attempt,
            containerName,
            snapshotSha256: decoded.snapshotSha256,
            jobId,
            csrSha256,
            csrSpkiSha256,
            templateOid,
            caConfig: snapshot.caConfig,
            template: snapshot.template,
            leafSha256,
            validationDeadlineAt: deadline,
            ...(Number.isInteger(issuance.requestId) ? { requestId: issuance.requestId } : {}),
          });
        } else {
          await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
            state: "rejected_invalid",
            attempt: decoded.attempt,
            containerName,
            snapshotSha256: decoded.snapshotSha256,
            jobId,
            csrSha256,
            csrSpkiSha256,
            templateOid,
            caConfig: snapshot.caConfig,
            template: snapshot.template,
            leafSha256,
            ...(Number.isInteger(issuance.requestId) ? { requestId: issuance.requestId } : {}),
          });
        }
        return resultForValidationOutcome(validation, decoded, issuance.requestId);
      }
      await reportBestEffortRevocationEvidence(client, jobId, validation);

      await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
        state: "installing",
        attempt: decoded.attempt,
        containerName,
        snapshotSha256: decoded.snapshotSha256,
        jobId,
        csrSha256,
        csrSpkiSha256,
        templateOid,
        caConfig: snapshot.caConfig,
        template: snapshot.template,
        leafSha256,
        installStep: "accept",
        ...(Number.isInteger(issuance.requestId) ? { requestId: issuance.requestId } : {}),
      });

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
      if (deployResult.status === "succeeded") {
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "installed",
          attempt: decoded.attempt,
          containerName,
          snapshotSha256: decoded.snapshotSha256,
          jobId,
          csrSha256,
          csrSpkiSha256,
          templateOid,
          caConfig: snapshot.caConfig,
          template: snapshot.template,
          leafSha256,
          installStep: "complete",
          ...(Number.isInteger(issuance.requestId) ? { requestId: issuance.requestId } : {}),
        });
      } else {
        issuanceOutcome = "install_failed";
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "install_failed",
          attempt: decoded.attempt,
          containerName,
          snapshotSha256: decoded.snapshotSha256,
          jobId,
          csrSha256,
          csrSpkiSha256,
          templateOid,
          caConfig: snapshot.caConfig,
          template: snapshot.template,
          leafSha256,
          installStep: "accept",
          ...(Number.isInteger(issuance.requestId) ? { requestId: issuance.requestId } : {}),
        });
      }
      return withInstalledEnrollmentResult(deployResult, decoded, issuance.requestId);
    } finally {
      const journalledCleanupOutcome = resolveCleanupOutcome({
        stateDir,
        enrollmentId: decoded?.enrollmentId,
      });
      if (
        containerName &&
        shouldCleanupAbandonedCngKey({
          submitStarted,
          issuanceOutcome,
          containerCreated: true,
          preparedJournalCommitted,
          ...(journalledCleanupOutcome !== undefined
            ? { journalState: journalledCleanupOutcome }
            : {}),
        })
      ) {
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

    let journal;
    {
      const read = readEnrollmentJournal(stateDir, decoded.enrollmentId);
      if (read.kind === "corrupt") {
        if (enrollmentLock) enrollmentLock.release();
        return {
          status: "failed",
          keyRotated: null,
          errorMessage: boundErrorMessage(
            `local AD CS enrollment journal is corrupt: ${read.error}`,
          ),
        };
      }
      if (read.kind === "not_found") {
        if (enrollmentLock) enrollmentLock.release();
        return {
          status: "failed",
          keyRotated: null,
          errorMessage: boundErrorMessage(
            `no local enrollment journal for enrollment ${decoded.enrollmentId}; cannot continue`,
          ),
        };
      }
      journal = read.journal;
      if (!Number.isInteger(journal.requestId) || journal.requestId < 1) {
        if (enrollmentLock) enrollmentLock.release();
        return {
          status: "failed",
          keyRotated: null,
          errorMessage: boundErrorMessage(
            `local enrollment journal for ${decoded.enrollmentId} has no RequestId yet (state ${journal.state}); cannot retrieve`,
          ),
        };
      }
    }
    if (
      typeof journal.snapshotSha256 !== "string" ||
      journal.snapshotSha256 !== decoded.snapshotSha256
    ) {
      if (enrollmentLock) enrollmentLock.release();
      return {
        status: "rejected",
        rejectionReason: "enrollment_snapshot_mismatch",
        keyRotated: null,
        errorMessage: boundErrorMessage(
          `local enrollment journal snapshotSha256 does not match the signed enrollment snapshot for ${decoded.enrollmentId}`,
        ),
      };
    }

    const cngWorkDir = path.join(stateDir, WINDOWS_CERT_STORE_WORK_DIR_NAME);
    const windowsExecFileImpl = executionContext.windowsExecFileImpl;
    const windowsConnectImpl = executionContext.windowsConnectImpl;
    const containerName = buildEnrollmentContainerName(decoded.enrollmentId);
    let continueOutcome = null;

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
      if (
        typeof journal.templateOid !== "string" ||
        !/^[0-2](\.(0|[1-9][0-9]{0,9})){1,63}$/.test(journal.templateOid)
      ) {
        return {
          status: "failed",
          keyRotated: null,
          errorMessage: boundErrorMessage(
            `local RequestId journal for enrollment ${decoded.enrollmentId} is missing templateOid; cannot validate before accept`,
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
        templateOid: journal.templateOid,
        windowsTarget,
      });
      if (!validation.ok) {
        continueOutcome =
          validation.state === "validation_deferred" ? "validation_deferred" : "rejected_invalid";
        return resultForValidationOutcome(validation, decoded, journal.requestId);
      }
      await reportBestEffortRevocationEvidence(client, jobId, validation);
      continueOutcome = "issued";

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
      const journalledCleanupOutcome = resolveCleanupOutcome({
        stateDir,
        enrollmentId: decoded?.enrollmentId,
      });
      if (
        containerName &&
        continueOutcome &&
        shouldCleanupAbandonedCngKey({
          submitStarted: true,
          issuanceOutcome: continueOutcome,
          containerCreated: true,
          preparedJournalCommitted: true,
          ...(journalledCleanupOutcome !== undefined
            ? { journalState: journalledCleanupOutcome }
            : {}),
        })
      ) {
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
            `job ${jobId}: failed to delete abandoned CNG key after AD CS validation failure: ${err.message}`,
          );
        }
      }
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
  shouldCleanupAbandonedCngKey,
  resolveCleanupOutcome,
  observeInstalledCertificateIdentity,
  withUniqueValidationLeafFile,
};
