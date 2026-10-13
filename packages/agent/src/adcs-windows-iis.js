"use strict";

/**
 * Windows IIS AD CS renew + continue-enrollment executor (ADR-0014).
 * Holds acquireEnrollmentLock across CNG keygen, certreq submit/retrieve,
 * and (on issued) the deploy tail.
 *
 * Decision-6 validation runs before accept.
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
  writeKeygenIntent,
  writeCsrArtifact,
  writeEnrollmentJournal,
  writeIssuedCertificateArtifacts,
  clearProvisionalLeafArtifacts,
  readEnrollmentJournal,
  keygenIntentPath,
  recordHighestRequestId,
  captureEnrollmentReconcileSearchFrom,
  tryReconcileUncertainSubmission,
} = require("./issuers");
const fs = require("node:fs");
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
  computeSha1ThumbprintFromPem,
  CERTREQ_ACCEPT_DEFAULT_STORE,
} = require("./windows-cert-store");
const { queryCurrentBinding, resolveVerificationTarget } = require("./windows-iis");
const { listMachineStoreCertificates } = require("./windows-discovery");
const {
  computeCertificateFingerprint,
  verifyDeployedCertificate,
} = require("./verify");

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

/**
 * Contract-required extras when replaying a terminal journal on continue.
 * denied needs caHresult; rejected_invalid needs errorCode.
 */
function terminalEnrollmentResultExtras(journal) {
  const extras = {};
  if (Number.isInteger(journal.requestId) && journal.requestId >= 1) {
    extras.requestId = journal.requestId;
  }
  if (typeof journal.caHresult === "string" && CA_HRESULT_PATTERN.test(journal.caHresult)) {
    extras.caHresult = journal.caHresult;
  }
  if (typeof journal.errorCode === "string" && journal.errorCode.length > 0) {
    extras.errorCode = journal.errorCode;
  }
  return extras;
}

function installedEnrollmentResult(enrollmentId, attempt, requestId) {
  const extras = { errorCode: null, caHresult: null };
  if (Number.isInteger(requestId) && requestId >= 1) {
    extras.requestId = requestId;
  }
  return enrollmentResultFor(enrollmentId, attempt, "installed", extras);
}

/** Lease/lock aborts must not become durable install_failed terminals. */
function isRetryableInstallInterrupt(deployResult) {
  if (!deployResult || typeof deployResult !== "object") return false;
  if (deployResult.status === "blocked") return true;
  return deployResult.retryableInterrupt === true;
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
  if (issuance.outcome === "rejected_invalid") {
    return {
      status: "failed",
      keyRotated: null,
      errorMessage: boundErrorMessage(issuance.detail || "CMS signer key does not match caKeySha256"),
      enrollmentResult: enrollmentResultFor(enrollmentId, attempt, "rejected_invalid", {
        errorCode: "ADCS_CA_KEY_CHANGED",
        ...(Number.isInteger(options.knownRequestId) && options.knownRequestId >= 1
          ? { requestId: options.knownRequestId }
          : {}),
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

function findStoreCertificateByThumbprint(listed, thumbprint) {
  const thumb = String(thumbprint).toUpperCase();
  return (listed.certificates || []).find(
    (cert) => String(cert.thumbprint || "").toUpperCase() === thumb,
  );
}

/** True when the store entry has a usable private key for this enrollment. */
function storeCertHasEnrollmentKey(cert, containerName) {
  if (!cert || cert.hasPrivateKey !== true) return false;
  if (
    typeof containerName === "string" &&
    containerName.length > 0 &&
    typeof cert.keyContainer === "string" &&
    cert.keyContainer.length > 0
  ) {
    return cert.keyContainer === containerName;
  }
  return true;
}

/**
 * Inspect live store/binding/TLS state for AD CS install recovery.
 * Never infer progress only from journal installStep.
 *
 * @returns {Promise<
 *   | { status: "complete", expectedThumbprint: string }
 *   | { status: "resume", startAtStep: "accept"|"mirror"|"bind"|"verify", expectedThumbprint: string }
 *   | { status: "error", error: string }
 * >}
 */
async function inspectAdcsInstallProgress({
  certificatePem,
  windowsTarget,
  containerName = null,
  execFileImpl,
  connectImpl,
  listMachineStoreCertificatesImpl = listMachineStoreCertificates,
  queryCurrentBindingImpl = queryCurrentBinding,
  verifyDeployedCertificateImpl = verifyDeployedCertificate,
}) {
  let expectedThumbprint;
  try {
    expectedThumbprint = computeSha1ThumbprintFromPem(certificatePem);
  } catch (err) {
    return { status: "error", error: `cannot compute leaf thumbprint: ${err.message}` };
  }

  const defaultStore = CERTREQ_ACCEPT_DEFAULT_STORE;
  const targetStore = windowsTarget.store;
  const listOpts = execFileImpl ? { execFileImpl } : {};

  const listedDefault = await listMachineStoreCertificatesImpl({
    store: defaultStore,
    ...listOpts,
  });
  if (!listedDefault.ok) {
    return {
      status: "error",
      error: listedDefault.stderrExcerpt || `could not list machine store ${defaultStore}`,
    };
  }

  let listedTarget = listedDefault;
  if (targetStore !== defaultStore) {
    listedTarget = await listMachineStoreCertificatesImpl({
      store: targetStore,
      ...listOpts,
    });
    if (!listedTarget.ok) {
      return {
        status: "error",
        error: listedTarget.stderrExcerpt || `could not list machine store ${targetStore}`,
      };
    }
  }

  const inDefault = findStoreCertificateByThumbprint(listedDefault, expectedThumbprint);
  const inTarget = findStoreCertificateByThumbprint(listedTarget, expectedThumbprint);
  const defaultKeyed = storeCertHasEnrollmentKey(inDefault, containerName);
  const targetKeyed = storeCertHasEnrollmentKey(inTarget, containerName);
  const leafPresent = Boolean(inDefault || inTarget);

  if (!defaultKeyed && !targetKeyed) {
    if (!leafPresent) {
      return { status: "resume", startAtStep: "accept", expectedThumbprint };
    }
    if (targetStore !== defaultStore) {
      // Bytes are in a store; the pending request is consumed. Repair via
      // addstore + repairstore. Never re-run bare certreq -accept.
      return { status: "resume", startAtStep: "mirror", expectedThumbprint };
    }
    return {
      status: "error",
      error: `leaf ${expectedThumbprint} is in ${defaultStore} without a usable private key; refusing certreq -accept`,
    };
  }
  if (targetStore !== defaultStore && !targetKeyed) {
    // Accepted into My but mirror incomplete. Never re-run bare -accept.
    return { status: "resume", startAtStep: "mirror", expectedThumbprint };
  }

  const address =
    typeof windowsTarget.binding.address === "string" && windowsTarget.binding.address.length > 0
      ? windowsTarget.binding.address
      : "*";
  const binding = {
    address,
    port: windowsTarget.binding.port,
    ...(windowsTarget.binding.sniHost ? { sniHost: windowsTarget.binding.sniHost } : {}),
    store: targetStore,
    site: windowsTarget.binding.site,
  };
  const current = await queryCurrentBindingImpl({
    binding,
    ...listOpts,
  });
  if (!current.ok) {
    return {
      status: "error",
      error: current.stderrExcerpt || "could not query the current IIS binding",
    };
  }
  const boundMatches =
    typeof current.thumbprint === "string" &&
    current.thumbprint.length > 0 &&
    String(current.thumbprint).toUpperCase() === expectedThumbprint;
  if (!boundMatches) {
    return { status: "resume", startAtStep: "bind", expectedThumbprint };
  }

  let expectedFingerprint;
  try {
    expectedFingerprint = computeCertificateFingerprint(certificatePem);
  } catch (err) {
    return { status: "error", error: `cannot compute leaf fingerprint: ${err.message}` };
  }
  const { host, servername } = resolveVerificationTarget(binding);
  const verified = await verifyDeployedCertificateImpl({
    host,
    port: binding.port,
    servername,
    expectedFingerprintSha256: expectedFingerprint,
    ...(connectImpl !== undefined ? { connectImpl } : {}),
  });
  if (verified && verified.verified === true) {
    return { status: "complete", expectedThumbprint };
  }
  return { status: "resume", startAtStep: "verify", expectedThumbprint };
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
    finalizeWindowsIisDeployBookkeeping,
    emitInfo,
    emitLog,
    recordWindowsCngContainer,
    isValidCertificateId,
  } = deps;

  function logAdcs(jobId, message) {
    if (typeof emitInfo !== "function") return;
    const text = String(message || "").replace(/\s+/g, " ").trim();
    if (!text) return;
    emitInfo(`job ${jobId}: ${text}`);
  }

  function logValidation(jobId, validation) {
    if (!validation || typeof validation !== "object") return;
    const parts = [
      `AD CS certificate validation ${validation.ok === true ? "passed" : "failed"}`,
    ];
    if (typeof validation.state === "string" && validation.state) parts.push(`state=${validation.state}`);
    if (typeof validation.errorCode === "string" && validation.errorCode) {
      parts.push(`code=${validation.errorCode}`);
    }
    if (validation.revocationBestEffort === true) parts.push("revocation=best-effort");
    if (typeof validation.detail === "string" && validation.detail.trim()) {
      parts.push(validation.detail.replace(/\s+/g, " ").trim().slice(0, 180));
    }
    logAdcs(jobId, parts.join(" "));
  }

  function reconcileSearchFromForSubmit(stateDir, caConfig, journal) {
    if (Number.isInteger(journal?.reconcileSearchFrom) && journal.reconcileSearchFrom >= 1) {
      return journal.reconcileSearchFrom;
    }
    return captureEnrollmentReconcileSearchFrom(stateDir, caConfig);
  }

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

    if (typeof executionContext.adcsRunDecision6ValidationImpl === "function") {
      return executionContext.adcsRunDecision6ValidationImpl({
        certificatePem,
        csrPem,
        csrSpkiSha256,
        snapshot,
        requiredDnsName,
        stateDir,
        executionContext,
        templateOid,
        windowsTarget,
      });
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
      // Binding/store list failures are transient; do not terminal-reject or
      // free the CNG key (install inspect treats the same class as retryable).
      return {
        ok: false,
        retryable: true,
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
    if (isRetryableInstallInterrupt(deployResult)) {
      return deployResult;
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
    logAdcs(
      jobId,
      `AD CS renew enrollment ${decoded.enrollmentId} attempt ${decoded.attempt} CN ${commonName} ` +
        `template ${snapshot.template} CA ${snapshot.caConfig} key ${keyMapped.algorithm} ` +
        `site ${windowsTarget.binding.site}:${windowsTarget.binding.port} store ${windowsTarget.store} ` +
        `names=${domains.length}`,
    );
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
      return await enrollmentLock.run(async (signal) => {
      {
        const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
        if (leaseGate && leaseGate.ok === false) return leaseGate.abort;
      }
      enrollmentLock.assertHeld();

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
        signal,
        ...(windowsExecFileImpl ? { execFileImpl: windowsExecFileImpl } : {}),
      });
      if (!csrResult.ok && csrResult.reason === "aborted") {
        enrollmentLock.assertHeld();
      }
      if (!csrResult.ok) {
        // Clear keygen intent so renew can retry; finally deletes any orphan key.
        containerName =
          typeof csrResult.containerName === "string" && csrResult.containerName.length > 0
            ? csrResult.containerName
            : enrollmentContainer;
        try {
          fs.unlinkSync(keygenIntentPath(stateDir, decoded.enrollmentId));
        } catch (err) {
          if (!err || err.code !== "ENOENT") {
            emitLog(
              log,
              `job ${jobId}: failed to clear keygen intent after CNG CSR failure: ${err.message}`,
            );
          }
        }
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
        logAdcs(
          jobId,
          `AD CS CSR stored for enrollment ${decoded.enrollmentId} templateOid ${templateOid}`,
        );
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
      enrollmentLock.assertHeld();
      if (typeof onBeforeMutation === "function") onBeforeMutation(issuer.step);
      // Durable submitting barrier: must succeed before certreq -submit.
      // Capture enrollment reconcile cursor from the CA watermark here so later
      // watermark advances by other enrollments cannot skip this request's range.
      let reconcileSearchFrom;
      try {
        reconcileSearchFrom = reconcileSearchFromForSubmit(stateDir, snapshot.caConfig, null);
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
          reconcileSearchFrom,
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
        logAdcs(
          jobId,
          `AD CS submit interrupted for enrollment ${decoded.enrollmentId}: ${String(err && err.message ? err.message : err).slice(0, 180)}`,
        );
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
        await recordHighestRequestId(stateDir, snapshot.caConfig, issuance.requestId);
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
      if (issuance.outcome === "rejected_invalid") {
        issuanceOutcome = "rejected_invalid";
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "rejected_invalid",
          ...journalTrustFields,
          errorCode: "ADCS_CA_KEY_CHANGED",
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
        if (Number.isInteger(issuance.requestId)) {
          await recordHighestRequestId(stateDir, snapshot.caConfig, issuance.requestId);
        }
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
      logValidation(jobId, validation);
      if (!validation.ok) {
        if (validation.retryable === true) {
          return {
            status: "failed",
            keyRotated: null,
            retryableInterrupt: true,
            errorMessage: boundErrorMessage(
              validation.detail || "could not observe the installed certificate identity",
            ),
          };
        }
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
            errorCode: validation.errorCode || "ADCS_CERTIFICATE_INVALID",
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
      // Remember the last step actually entered. A hard failure must not
      // rewind the journal to accept, or the next resume looks like certreq
      // -accept never ran.
      let currentInstallStep = "accept";
      logAdcs(
        jobId,
        `AD CS install starting for enrollment ${decoded.enrollmentId} store ${windowsTarget.store} ` +
          `site ${windowsTarget.binding.site}:${windowsTarget.binding.port}`,
      );
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
        retainKeyOnAcceptFailure: true,
        onInstallStep: async (step, meta = {}) => {
          currentInstallStep = step;
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
            installStep: step,
            ...(Number.isInteger(issuance.requestId) ? { requestId: issuance.requestId } : {}),
            ...(typeof meta.predecessorThumbprint === "string"
              ? { predecessorThumbprint: meta.predecessorThumbprint }
              : {}),
          });
        },
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
      } else if (!isRetryableInstallInterrupt(deployResult)) {
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
          installStep: currentInstallStep,
          ...(Number.isInteger(issuance.requestId) ? { requestId: issuance.requestId } : {}),
        });
      }
      // Retryable lease/lock interrupts leave journal at installing.
      return withInstalledEnrollmentResult(deployResult, decoded, issuance.requestId);
      });
    } catch (err) {
      if (err && err.code === "ENROLLMENT_LOCK_LOST") {
        return {
          status: "failed",
          keyRotated: null,
          retryableInterrupt: true,
          errorMessage: boundErrorMessage(
            `AD CS enrollment lock lost mid-operation: ${err.message}`,
          ),
        };
      }
      throw err;
    } finally {
      // Never delkey after lock loss: a successor may already own the
      // enrollment mutex and be creating/using the same container.
      const lockLost = Boolean(enrollmentLock && enrollmentLock.lost);
      const journalledCleanupOutcome = resolveCleanupOutcome({
        stateDir,
        enrollmentId: decoded?.enrollmentId,
      });
      if (
        !lockLost &&
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

  async function validateAndInstallFromLeaf({
    certificatePem,
    journal,
    decoded,
    snapshot,
    windowsTarget,
    stateDir,
    caCertPath,
    executionContext,
    jobId,
    client,
    cngWorkDir,
    containerName,
    log,
    leaseOpts,
    onBeforeMutation,
    windowsExecFileImpl,
    windowsConnectImpl,
    continueOutcomeRef,
  }) {
    if (typeof journal.csrSpkiSha256 !== "string" || !/^[a-f0-9]{64}$/.test(journal.csrSpkiSha256)) {
      return {
        status: "failed",
        keyRotated: null,
        errorMessage: boundErrorMessage(
          `local enrollment journal for ${decoded.enrollmentId} is missing csrSpkiSha256; cannot validate before accept`,
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
          `local enrollment journal for ${decoded.enrollmentId} is missing templateOid; cannot validate before accept`,
        ),
      };
    }

    const journalBase = {
      attempt: decoded.attempt,
      containerName,
      snapshotSha256: decoded.snapshotSha256,
      jobId,
      csrSha256: journal.csrSha256,
      csrSpkiSha256: journal.csrSpkiSha256,
      templateOid: journal.templateOid,
      caConfig: snapshot.caConfig,
      template: snapshot.template,
      leafSha256: journal.leafSha256,
      ...(Number.isInteger(journal.requestId) ? { requestId: journal.requestId } : {}),
    };

    const resumeInstallStates = journal.state === "installing" || journal.state === "install_failed";

    // Crash recovery: inspect live deployment before any renewal validation.
    // An already-bound leaf must finalize as installed, never rejected_invalid.
    if (resumeInstallStates) {
      const inspectImpl =
        executionContext.adcsInspectInstallProgressImpl || inspectAdcsInstallProgress;
      const progress = await inspectImpl({
        certificatePem,
        windowsTarget,
        containerName,
        execFileImpl: windowsExecFileImpl || executionContext.windowsExecFileImpl,
        connectImpl: windowsConnectImpl || executionContext.windowsConnectImpl,
        listMachineStoreCertificatesImpl: executionContext.adcsListMachineStoreCertificatesImpl,
        queryCurrentBindingImpl: executionContext.adcsQueryCurrentBindingImpl,
        verifyDeployedCertificateImpl: executionContext.adcsVerifyDeployedCertificateImpl,
      });
      if (progress.status === "error") {
        return {
          status: "failed",
          keyRotated: null,
          errorMessage: boundErrorMessage(
            `cannot inspect AD CS install progress for enrollment ${decoded.enrollmentId}: ${progress.error}`,
          ),
        };
      }
      if (progress.status === "complete") {
        // Replay idempotent evidence + retention bookkeeping that may have
        // been skipped by a crash after TLS verify but before journal installed.
        if (typeof finalizeWindowsIisDeployBookkeeping === "function") {
          await finalizeWindowsIisDeployBookkeeping({
            jobId,
            client,
            certificatePem,
            target: windowsTarget,
            stateDir,
            log,
            boundThumbprint: progress.expectedThumbprint,
            outgoingThumbprint:
              typeof journal.predecessorThumbprint === "string"
                ? journal.predecessorThumbprint
                : null,
            skippedMutation: true,
            windowsExecFileImpl,
          });
        }
        continueOutcomeRef.value = "installed";
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "installed",
          ...journalBase,
          installStep: "complete",
        });
        return {
          status: "succeeded",
          keyRotated: null,
          enrollmentResult: installedEnrollmentResult(
            decoded.enrollmentId,
            decoded.attempt,
            journal.requestId,
          ),
        };
      }

      let currentInstallStep = progress.startAtStep;
      await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
        state: "installing",
        ...journalBase,
        installStep: currentInstallStep,
      });
      continueOutcomeRef.value = "issued";

      logAdcs(
        jobId,
        `AD CS install resuming for enrollment ${decoded.enrollmentId} step ${currentInstallStep} ` +
          `store ${windowsTarget.store} site ${windowsTarget.binding.site}:${windowsTarget.binding.port}`,
      );
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
        startAtStep: progress.startAtStep,
        retainKeyOnAcceptFailure: true,
        journaledPredecessorThumbprint:
          typeof journal.predecessorThumbprint === "string" &&
          journal.predecessorThumbprint.length > 0
            ? journal.predecessorThumbprint
            : null,
        onInstallStep: async (step, meta = {}) => {
          currentInstallStep = step;
          await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
            state: "installing",
            ...journalBase,
            installStep: step,
            // Only record predecessor on bind; verify-only resume must not
            // overwrite a journalled pre-cutover thumbprint with the new cert.
            ...(typeof meta.predecessorThumbprint === "string"
              ? { predecessorThumbprint: meta.predecessorThumbprint }
              : {}),
          });
        },
        windowsExecFileImpl,
        windowsConnectImpl,
      });
      if (deployResult.status === "succeeded") {
        continueOutcomeRef.value = "installed";
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "installed",
          ...journalBase,
          installStep: "complete",
        });
      } else if (!isRetryableInstallInterrupt(deployResult)) {
        continueOutcomeRef.value = "install_failed";
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "install_failed",
          ...journalBase,
          installStep: currentInstallStep,
        });
      }
      return withInstalledEnrollmentResult(deployResult, decoded, journal.requestId);
    }

    if (journal.state === "validation_deferred" && typeof journal.validationDeadlineAt === "string") {
      const deadlineMs = Date.parse(journal.validationDeadlineAt);
      if (Number.isFinite(deadlineMs) && Date.now() > deadlineMs) {
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "validation_expired",
          ...journalBase,
          validationDeadlineAt: journal.validationDeadlineAt,
        });
        continueOutcomeRef.value = "rejected_invalid";
        return {
          status: "failed",
          keyRotated: null,
          errorMessage: boundErrorMessage(
            `validation deadline ${journal.validationDeadlineAt} expired for enrollment ${decoded.enrollmentId}`,
          ),
          enrollmentResult: enrollmentResultFor(
            decoded.enrollmentId,
            decoded.attempt,
            "validation_expired",
            Number.isInteger(journal.requestId) ? { requestId: journal.requestId } : {},
          ),
        };
      }
    }

    const validation = await runDecision6Validation({
      certificatePem,
      csrSpkiSha256: journal.csrSpkiSha256,
      snapshot,
      requiredDnsName: windowsTarget.reference,
      stateDir,
      executionContext: { ...executionContext, adcsCaCertPath: caCertPath },
      templateOid: journal.templateOid,
      windowsTarget,
    });
    logValidation(jobId, validation);
    if (!validation.ok) {
      if (validation.retryable === true) {
        return {
          status: "failed",
          keyRotated: null,
          retryableInterrupt: true,
          errorMessage: boundErrorMessage(
            validation.detail || "could not observe the installed certificate identity",
          ),
        };
      }
      continueOutcomeRef.value =
        validation.state === "validation_deferred" ? "validation_deferred" : "rejected_invalid";
      if (validation.state === "validation_deferred") {
        const deadline =
          typeof journal.validationDeadlineAt === "string"
            ? journal.validationDeadlineAt
            : new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "validation_deferred",
          ...journalBase,
          validationDeadlineAt: deadline,
        });
      } else {
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "rejected_invalid",
          ...journalBase,
          errorCode: validation.errorCode || "ADCS_CERTIFICATE_INVALID",
        });
      }
      return resultForValidationOutcome(validation, decoded, journal.requestId);
    }
    await reportBestEffortRevocationEvidence(client, jobId, validation);
    continueOutcomeRef.value = "issued";

    await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
      state: "installing",
      ...journalBase,
      installStep: "accept",
    });

    let currentInstallStep = "accept";
    logAdcs(
      jobId,
      `AD CS install starting for enrollment ${decoded.enrollmentId} store ${windowsTarget.store} ` +
        `site ${windowsTarget.binding.site}:${windowsTarget.binding.port}`,
    );
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
      startAtStep: "accept",
      retainKeyOnAcceptFailure: true,
      journaledPredecessorThumbprint:
        typeof journal.predecessorThumbprint === "string" &&
        journal.predecessorThumbprint.length > 0
          ? journal.predecessorThumbprint
          : null,
      onInstallStep: async (step, meta = {}) => {
        currentInstallStep = step;
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "installing",
          ...journalBase,
          installStep: step,
          ...(typeof meta.predecessorThumbprint === "string"
            ? { predecessorThumbprint: meta.predecessorThumbprint }
            : {}),
        });
      },
      windowsExecFileImpl,
      windowsConnectImpl,
    });
    if (deployResult.status === "succeeded") {
      await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
        state: "installed",
        ...journalBase,
        installStep: "complete",
      });
    } else if (!isRetryableInstallInterrupt(deployResult)) {
      continueOutcomeRef.value = "install_failed";
      await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
        state: "install_failed",
        ...journalBase,
        installStep: currentInstallStep,
      });
    }
    return withInstalledEnrollmentResult(deployResult, decoded, journal.requestId);
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
    const { decoded, helperPath, caCertPath, snapshot, domains, keyMapped } = ctx;

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
    enrollmentLock.assertHeld();

    let journal;
    let artifacts = { csrPem: null, leafPem: null, chainPem: null };
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
      artifacts = read.artifacts || artifacts;
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
    const containerName =
      typeof journal.containerName === "string" && journal.containerName.length > 0
        ? journal.containerName
        : buildEnrollmentContainerName(decoded.enrollmentId);
    const continueOutcomeRef = { value: null };

    try {
      return await enrollmentLock.run(async (signal) => {
      {
        const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
        if (leaseGate && leaseGate.ok === false) return leaseGate.abort;
      }
      enrollmentLock.assertHeld();
      logAdcs(
        jobId,
        `AD CS continue enrollment ${decoded.enrollmentId} journal=${journal.state}` +
          (Number.isInteger(journal.requestId) ? ` requestId=${journal.requestId}` : "") +
          ` template ${snapshot.template} CA ${snapshot.caConfig}`,
      );

      // Terminal receipts: return recorded outcome without repeating CA contact.
      if (journal.state === "installed") {
        return {
          status: "succeeded",
          keyRotated: null,
          enrollmentResult: installedEnrollmentResult(
            decoded.enrollmentId,
            decoded.attempt,
            journal.requestId,
          ),
        };
      }
      if (["denied", "refused", "rejected_invalid", "validation_expired", "abandoned"].includes(journal.state)) {
        return {
          status: journal.state === "refused" ? "rejected" : "failed",
          keyRotated: null,
          errorMessage: boundErrorMessage(
            `enrollment ${decoded.enrollmentId} is terminal in state ${journal.state}`,
          ),
          enrollmentResult: enrollmentResultFor(
            decoded.enrollmentId,
            decoded.attempt,
            journal.state,
            terminalEnrollmentResultExtras(journal),
          ),
        };
      }

      // Crash between keygen intent and prepared: finish CSR then resume-submit.
      if (journal.state === "keygen_intent") {
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
          };
        }
        if (typeof onBeforeMutation === "function") onBeforeMutation("keygen");
        let csrResult = await generateCsrViaCng({
          commonName: windowsTarget.reference,
          altNames: domains,
          jobId: job.certificateId,
          enrollmentId: decoded.enrollmentId,
          algorithm: keyMapped.algorithm,
          workDir: cngWorkDir,
          signal,
          ...(windowsExecFileImpl ? { execFileImpl: windowsExecFileImpl } : {}),
        });
        if (!csrResult.ok && csrResult.reason === "enrollment_container_exists") {
          const cleanup = await removeAbandonedKeyContainer({
            containerName,
            signal,
            ...(windowsExecFileImpl ? { execFileImpl: windowsExecFileImpl } : {}),
          });
          if (cleanup.ok !== true) {
            if (cleanup.reason === "aborted") enrollmentLock.assertHeld();
            return {
              status: "failed",
              keyRotated: null,
              errorMessage: boundErrorMessage(
                `enrollment ${decoded.enrollmentId} has a stranded CNG container that could not be cleared for keygen resume`,
              ),
            };
          }
          removeIssuedContainerRecord({ stateDir, containerName });
          csrResult = await generateCsrViaCng({
            commonName: windowsTarget.reference,
            altNames: domains,
            jobId: job.certificateId,
            enrollmentId: decoded.enrollmentId,
            algorithm: keyMapped.algorithm,
            workDir: cngWorkDir,
            signal,
            ...(windowsExecFileImpl ? { execFileImpl: windowsExecFileImpl } : {}),
          });
        }
        if (!csrResult.ok) {
          if (csrResult.reason === "aborted") enrollmentLock.assertHeld();
          return {
            status: "failed",
            keyRotated: null,
            errorMessage: boundErrorMessage(
              `CNG CSR generation failed on keygen resume (exit code ${csrResult.exitCode}): ${csrResult.stderrExcerpt}`,
            ),
          };
        }
        const csrSpkiSha256 = spkiSha256Hex(extractSpkiFromCsr(csrResult.csrPem));
        const csrWritten = await writeCsrArtifact({
          stateDir,
          enrollmentId: decoded.enrollmentId,
          csrPem: csrResult.csrPem,
        });
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "prepared",
          attempt: decoded.attempt,
          containerName,
          snapshotSha256: decoded.snapshotSha256,
          jobId,
          csrSha256: csrWritten.csrSha256,
          csrSpkiSha256,
          templateOid: templateOidResolved.templateOid,
          caConfig: snapshot.caConfig,
          template: snapshot.template,
        });
        journal = {
          ...journal,
          state: "prepared",
          csrSha256: csrWritten.csrSha256,
          csrSpkiSha256,
          templateOid: templateOidResolved.templateOid,
        };
        artifacts = { ...artifacts, csrPem: csrResult.csrPem };
        logAdcs(
          jobId,
          `AD CS CSR stored on keygen resume for enrollment ${decoded.enrollmentId} templateOid ${templateOidResolved.templateOid}`,
        );
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
            `job ${jobId}: failed to record CNG container issuance on keygen resume (non-fatal): ${err.message}`,
          );
        }
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

      // Crash in submitting: never auto-resubmit; mark uncertain then tier-2.
      if (journal.state === "submitting") {
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "submission_uncertain",
          attempt: decoded.attempt,
          containerName,
          snapshotSha256: decoded.snapshotSha256,
          jobId,
          csrSha256: journal.csrSha256,
          csrSpkiSha256: journal.csrSpkiSha256,
          templateOid: journal.templateOid,
          caConfig: snapshot.caConfig,
          template: snapshot.template,
        });
        journal = { ...journal, state: "submission_uncertain" };
      }

      // Resume-submit from durable CSR (prepared after not_submitted).
      if (journal.state === "prepared") {
        if (typeof artifacts.csrPem !== "string" || !artifacts.csrPem.includes("BEGIN")) {
          return {
            status: "failed",
            keyRotated: null,
            errorMessage: boundErrorMessage(
              `prepared enrollment ${decoded.enrollmentId} has no durable CSR; cannot resume-submit`,
            ),
          };
        }
        let resumeReconcileSearchFrom;
        try {
          resumeReconcileSearchFrom = reconcileSearchFromForSubmit(
            stateDir,
            snapshot.caConfig,
            journal,
          );
        } catch (err) {
          return {
            status: "failed",
            keyRotated: null,
            errorMessage: boundErrorMessage(
              `failed to capture reconcileSearchFrom before resume-submit: ${err.message}`,
            ),
          };
        }
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "submitting",
          attempt: decoded.attempt,
          containerName,
          snapshotSha256: decoded.snapshotSha256,
          jobId,
          csrSha256: journal.csrSha256,
          csrSpkiSha256: journal.csrSpkiSha256,
          templateOid: journal.templateOid,
          caConfig: snapshot.caConfig,
          template: snapshot.template,
          reconcileSearchFrom: resumeReconcileSearchFrom,
        });
        if (typeof onBeforeMutation === "function") onBeforeMutation(issuer.step);
        let issuance;
        try {
          issuance = assertIssuanceOutcome(
            await issuer.submit({ csrPem: artifacts.csrPem, domains: snapshot.authorizedDnsNames }),
          );
        } catch (err) {
          await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
            state: "submission_uncertain",
            attempt: decoded.attempt,
            containerName,
            snapshotSha256: decoded.snapshotSha256,
            jobId,
            csrSha256: journal.csrSha256,
            csrSpkiSha256: journal.csrSpkiSha256,
            templateOid: journal.templateOid,
            caConfig: snapshot.caConfig,
            template: snapshot.template,
          });
          return {
            status: "failed",
            keyRotated: null,
            errorMessage: boundErrorMessage(`AD CS resume-submit interrupted: ${err.message}`),
            enrollmentResult: enrollmentResultFor(
              decoded.enrollmentId,
              decoded.attempt,
              "submission_uncertain",
              { errorCode: "ADCS_DISPOSITION_UNKNOWN" },
            ),
          };
        }

        if (issuance.outcome === "not_submitted") {
          await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
            state: "prepared",
            attempt: decoded.attempt,
            containerName,
            snapshotSha256: decoded.snapshotSha256,
            jobId,
            csrSha256: journal.csrSha256,
            csrSpkiSha256: journal.csrSpkiSha256,
            templateOid: journal.templateOid,
            caConfig: snapshot.caConfig,
            template: snapshot.template,
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
            csrSpkiSha256: journal.csrSpkiSha256,
            templateOid: journal.templateOid,
            containerName,
            csrPem: artifacts.csrPem,
          });
          await recordHighestRequestId(stateDir, snapshot.caConfig, issuance.requestId);
          if (typeof onBeforeMutation === "function") onBeforeMutation("report-issuance-evidence");
          await reportIssuanceEvidence(client, jobId, issuance);
          return resultForAdcsOutcome(issuance, decoded);
        }
        if (issuance.outcome === "rejected_invalid") {
          continueOutcomeRef.value = "rejected_invalid";
          await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
            state: "rejected_invalid",
            attempt: decoded.attempt,
            containerName,
            snapshotSha256: decoded.snapshotSha256,
            jobId,
            csrSha256: journal.csrSha256,
            csrSpkiSha256: journal.csrSpkiSha256,
            templateOid: journal.templateOid,
            caConfig: snapshot.caConfig,
            template: snapshot.template,
            errorCode: "ADCS_CA_KEY_CHANGED",
          });
          if (typeof onBeforeMutation === "function") onBeforeMutation("report-issuance-evidence");
          await reportIssuanceEvidence(client, jobId, issuance);
          return resultForAdcsOutcome(issuance, decoded);
        }
        if (issuance.outcome === "denied" || issuance.outcome === "refused" || issuance.outcome === "uncertain") {
          const caHresult =
            issuance.outcome === "denied" &&
            typeof issuance.caHresult === "string" &&
            CA_HRESULT_PATTERN.test(issuance.caHresult)
              ? issuance.caHresult
              : null;
          const terminalState =
            issuance.outcome === "refused"
              ? "refused"
              : issuance.outcome === "denied" && caHresult
                ? "denied"
                : "submission_uncertain";
          await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
            state: terminalState,
            attempt: decoded.attempt,
            containerName,
            snapshotSha256: decoded.snapshotSha256,
            jobId,
            csrSha256: journal.csrSha256,
            csrSpkiSha256: journal.csrSpkiSha256,
            templateOid: journal.templateOid,
            caConfig: snapshot.caConfig,
            template: snapshot.template,
            ...(caHresult ? { caHresult } : {}),
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

        const written = await writeIssuedCertificateArtifacts({
          stateDir,
          enrollmentId: decoded.enrollmentId,
          leafPem: issuance.certificatePem,
        });
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "issued",
          attempt: decoded.attempt,
          containerName,
          snapshotSha256: decoded.snapshotSha256,
          jobId,
          csrSha256: journal.csrSha256,
          csrSpkiSha256: journal.csrSpkiSha256,
          templateOid: journal.templateOid,
          caConfig: snapshot.caConfig,
          template: snapshot.template,
          leafSha256: written.leafSha256,
          ...(Number.isInteger(issuance.requestId) ? { requestId: issuance.requestId } : {}),
        });
        if (Number.isInteger(issuance.requestId)) {
          await recordHighestRequestId(stateDir, snapshot.caConfig, issuance.requestId);
        }
        if (typeof onBeforeMutation === "function") onBeforeMutation("report-issuance-evidence");
        await reportIssuanceEvidence(client, jobId, issuance);
        journal = {
          ...journal,
          state: "issued",
          leafSha256: written.leafSha256,
          ...(Number.isInteger(issuance.requestId) ? { requestId: issuance.requestId } : {}),
        };
        artifacts = { ...artifacts, leafPem: issuance.certificatePem };
        return validateAndInstallFromLeaf({
          certificatePem: issuance.certificatePem,
          journal,
          decoded,
          snapshot,
          windowsTarget,
          stateDir,
          caCertPath,
          executionContext,
          jobId,
          client,
          cngWorkDir,
          containerName,
          log,
          leaseOpts,
          onBeforeMutation,
          windowsExecFileImpl,
          windowsConnectImpl,
          continueOutcomeRef,
        });
      }

      // Tier-2 reconcile for uncertain submission (never resubmit).
      if (journal.state === "submission_uncertain") {
        if (typeof onBeforeMutation === "function") onBeforeMutation("adcs-reconcile");

        const uncertainBase = {
          attempt: decoded.attempt,
          containerName,
          snapshotSha256: decoded.snapshotSha256,
          jobId,
          csrSha256: journal.csrSha256,
          csrSpkiSha256: journal.csrSpkiSha256,
          templateOid: journal.templateOid,
          caConfig: snapshot.caConfig,
          template: snapshot.template,
        };

        const persistUncertain = async (fields) => {
          await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
            state: "submission_uncertain",
            ...uncertainBase,
            ...fields,
          });
        };

        const attachIssuedCandidate = async (certificatePem, requestId, validation) => {
          const written = await writeIssuedCertificateArtifacts({
            stateDir,
            enrollmentId: decoded.enrollmentId,
            leafPem: certificatePem,
          });
          await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
            state: "issued",
            ...uncertainBase,
            leafSha256: written.leafSha256,
            requestId,
            reconcileCandidateRequestId: null,
            validationDeadlineAt: null,
          });
          await recordHighestRequestId(stateDir, snapshot.caConfig, requestId);
          await reportBestEffortRevocationEvidence(client, jobId, validation);
          journal = {
            ...journal,
            state: "issued",
            leafSha256: written.leafSha256,
            requestId,
          };
          return validateAndInstallFromLeaf({
            certificatePem,
            journal,
            decoded,
            snapshot,
            windowsTarget,
            stateDir,
            caCertPath,
            executionContext,
            jobId,
            client,
            cngWorkDir,
            containerName,
            log,
            leaseOpts,
            onBeforeMutation,
            windowsExecFileImpl,
            windowsConnectImpl,
            continueOutcomeRef,
          });
        };

        // Retry a previously deferred unique candidate before scanning again.
        if (
          Number.isInteger(journal.reconcileCandidateRequestId) &&
          journal.reconcileCandidateRequestId >= 1 &&
          typeof artifacts.leafPem === "string" &&
          artifacts.leafPem.includes("BEGIN")
        ) {
          if (typeof journal.validationDeadlineAt === "string") {
            const deadlineMs = Date.parse(journal.validationDeadlineAt);
            if (Number.isFinite(deadlineMs) && Date.now() > deadlineMs) {
              const expiredCandidateId = journal.reconcileCandidateRequestId;
              await persistUncertain({
                reconcileSearchFrom: journal.reconcileSearchFrom,
                reconcileCandidateRequestId: null,
                validationDeadlineAt: null,
                leafSha256: null,
              });
              clearProvisionalLeafArtifacts(stateDir, decoded.enrollmentId);
              return {
                status: "failed",
                keyRotated: null,
                errorMessage: boundErrorMessage(
                  `tier-2 candidate RequestId ${expiredCandidateId} validation deadline expired; enrollment ${decoded.enrollmentId} remains submission_uncertain`,
                ),
                enrollmentResult: enrollmentResultFor(
                  decoded.enrollmentId,
                  decoded.attempt,
                  "submission_uncertain",
                  { errorCode: "ADCS_DISPOSITION_UNKNOWN" },
                ),
              };
            }
          }
          const retryValidation = await runDecision6Validation({
            certificatePem: artifacts.leafPem,
            csrSpkiSha256: journal.csrSpkiSha256,
            snapshot,
            requiredDnsName: windowsTarget.reference,
            stateDir,
            executionContext: { ...executionContext, adcsCaCertPath: caCertPath },
            templateOid: journal.templateOid,
            windowsTarget,
          });
          logValidation(jobId, retryValidation);
          if (retryValidation.ok) {
            return attachIssuedCandidate(
              artifacts.leafPem,
              journal.reconcileCandidateRequestId,
              retryValidation,
            );
          }
          if (retryValidation.retryable === true) {
            return {
              status: "failed",
              keyRotated: null,
              retryableInterrupt: true,
              errorMessage: boundErrorMessage(
                retryValidation.detail || "could not observe the installed certificate identity",
              ),
            };
          }
          if (retryValidation.state === "validation_deferred") {
            const deadline =
              typeof journal.validationDeadlineAt === "string"
                ? journal.validationDeadlineAt
                : new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
            await persistUncertain({
              reconcileSearchFrom: journal.reconcileSearchFrom,
              reconcileCandidateRequestId: journal.reconcileCandidateRequestId,
              leafSha256: journal.leafSha256,
              validationDeadlineAt: deadline,
            });
            return {
              status: "failed",
              keyRotated: null,
              errorMessage: boundErrorMessage(
                `tier-2 candidate RequestId ${journal.reconcileCandidateRequestId} still validation_deferred; enrollment ${decoded.enrollmentId} remains submission_uncertain`,
              ),
              enrollmentResult: enrollmentResultFor(
                decoded.enrollmentId,
                decoded.attempt,
                "submission_uncertain",
                { errorCode: "ADCS_DISPOSITION_UNKNOWN" },
              ),
            };
          }
          // Hard rejection: clear provisional candidate + leaf so a later
          // valid candidate B can replace hash(A) without immutable conflict.
          const rejectedCandidateId = journal.reconcileCandidateRequestId;
          await persistUncertain({
            reconcileSearchFrom: journal.reconcileSearchFrom,
            reconcileCandidateRequestId: null,
            validationDeadlineAt: null,
            leafSha256: null,
          });
          clearProvisionalLeafArtifacts(stateDir, decoded.enrollmentId);
          return {
            status: "failed",
            keyRotated: null,
            errorMessage: boundErrorMessage(
              `tier-2 candidate RequestId ${rejectedCandidateId} failed validation; enrollment ${decoded.enrollmentId} remains submission_uncertain`,
            ),
            enrollmentResult: enrollmentResultFor(
              decoded.enrollmentId,
              decoded.attempt,
              "submission_uncertain",
              { errorCode: "ADCS_DISPOSITION_UNKNOWN" },
            ),
          };
        }

        const reconcileImpl =
          typeof executionContext.adcsTryReconcileUncertainSubmissionImpl === "function"
            ? executionContext.adcsTryReconcileUncertainSubmissionImpl
            : tryReconcileUncertainSubmission;
        const reconciled = await reconcileImpl({
          issuer,
          stateDir,
          caConfig: snapshot.caConfig,
          csrSpkiSha256: journal.csrSpkiSha256,
          reconcileSearchFrom: Number.isInteger(journal.reconcileSearchFrom)
            ? journal.reconcileSearchFrom
            : null,
          windowSize: executionContext.adcsReconcileWindowSize,
          assertIssuanceOutcome,
        });

        if (reconciled.status === "error") {
          return {
            status: "failed",
            keyRotated: null,
            errorMessage: boundErrorMessage(
              `AD CS tier-2 reconcile failed for enrollment ${decoded.enrollmentId}: ${reconciled.error}`,
            ),
            enrollmentResult: enrollmentResultFor(
              decoded.enrollmentId,
              decoded.attempt,
              "submission_uncertain",
              { errorCode: "ADCS_DISPOSITION_UNKNOWN" },
            ),
          };
        }

        if (reconciled.status !== "unique_candidate") {
          await persistUncertain({ reconcileSearchFrom: reconciled.nextSearchFrom });
          return {
            status: "failed",
            keyRotated: null,
            errorMessage: boundErrorMessage(
              reconciled.status === "ambiguous"
                ? `AD CS tier-2 reconcile found ${reconciled.matchCount} SPKI matches for enrollment ${decoded.enrollmentId}; operator RequestId or abandon required`
                : `AD CS submission remains uncertain for enrollment ${decoded.enrollmentId}; operator RequestId or abandon required`,
            ),
            enrollmentResult: enrollmentResultFor(
              decoded.enrollmentId,
              decoded.attempt,
              "submission_uncertain",
              { errorCode: "ADCS_DISPOSITION_UNKNOWN" },
            ),
          };
        }

        // Visible uniqueness is not attachment eligibility when earlier ids remain open.
        if (reconciled.attachmentEligible !== true) {
          await persistUncertain({ reconcileSearchFrom: reconciled.nextSearchFrom });
          return {
            status: "failed",
            keyRotated: null,
            errorMessage: boundErrorMessage(
              `AD CS tier-2 found RequestId ${reconciled.requestId} but earlier unresolved RequestIds remain; enrollment ${decoded.enrollmentId} stays submission_uncertain`,
            ),
            enrollmentResult: enrollmentResultFor(
              decoded.enrollmentId,
              decoded.attempt,
              "submission_uncertain",
              { errorCode: "ADCS_DISPOSITION_UNKNOWN" },
            ),
          };
        }

        // Decision-6 before attaching RequestId / journaling issued.
        const candidateValidation = await runDecision6Validation({
          certificatePem: reconciled.certificatePem,
          csrSpkiSha256: journal.csrSpkiSha256,
          snapshot,
          requiredDnsName: windowsTarget.reference,
          stateDir,
          executionContext: { ...executionContext, adcsCaCertPath: caCertPath },
          templateOid: journal.templateOid,
          windowsTarget,
        });
        logValidation(jobId, candidateValidation);
        if (!candidateValidation.ok) {
          if (candidateValidation.retryable === true) {
            return {
              status: "failed",
              keyRotated: null,
              retryableInterrupt: true,
              errorMessage: boundErrorMessage(
                candidateValidation.detail ||
                  "could not observe the installed certificate identity",
              ),
            };
          }
          if (candidateValidation.state === "validation_deferred") {
            const written = await writeIssuedCertificateArtifacts({
              stateDir,
              enrollmentId: decoded.enrollmentId,
              leafPem: reconciled.certificatePem,
            });
            const deadline = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
            await persistUncertain({
              // Keep earliest unresolved cursor (includes this candidate).
              reconcileSearchFrom: reconciled.nextSearchFrom,
              reconcileCandidateRequestId: reconciled.requestId,
              leafSha256: written.leafSha256,
              validationDeadlineAt: deadline,
            });
            return {
              status: "failed",
              keyRotated: null,
              errorMessage: boundErrorMessage(
                `AD CS tier-2 candidate RequestId ${reconciled.requestId} is validation_deferred; enrollment ${decoded.enrollmentId} remains submission_uncertain`,
              ),
              enrollmentResult: enrollmentResultFor(
                decoded.enrollmentId,
                decoded.attempt,
                "submission_uncertain",
                { errorCode: "ADCS_DISPOSITION_UNKNOWN" },
              ),
            };
          }
          // Hard validation failure: do not skip unresolved ids.
          await persistUncertain({ reconcileSearchFrom: reconciled.nextSearchFrom });
          return {
            status: "failed",
            keyRotated: null,
            errorMessage: boundErrorMessage(
              `AD CS tier-2 candidate RequestId ${reconciled.requestId} failed validation; enrollment ${decoded.enrollmentId} remains submission_uncertain`,
            ),
            enrollmentResult: enrollmentResultFor(
              decoded.enrollmentId,
              decoded.attempt,
              "submission_uncertain",
              { errorCode: "ADCS_DISPOSITION_UNKNOWN" },
            ),
          };
        }

        return attachIssuedCandidate(
          reconciled.certificatePem,
          reconciled.requestId,
          candidateValidation,
        );
      }

      // Issued / deferred / installing / install_failed: use durable leaf (RequestId optional).
      if (
        ["issued", "validation_deferred", "installing", "install_failed"].includes(journal.state)
      ) {
        if (typeof artifacts.leafPem !== "string" || !artifacts.leafPem.includes("BEGIN")) {
          return {
            status: "failed",
            keyRotated: null,
            errorMessage: boundErrorMessage(
              `enrollment ${decoded.enrollmentId} state ${journal.state} has no durable issued certificate; cannot continue`,
            ),
          };
        }
        return validateAndInstallFromLeaf({
          certificatePem: artifacts.leafPem,
          journal,
          decoded,
          snapshot,
          windowsTarget,
          stateDir,
          caCertPath,
          executionContext,
          jobId,
          client,
          cngWorkDir,
          containerName,
          log,
          leaseOpts,
          onBeforeMutation,
          windowsExecFileImpl,
          windowsConnectImpl,
          continueOutcomeRef,
        });
      }

      // Pending retrieve path (RequestId required).
      if (!Number.isInteger(journal.requestId) || journal.requestId < 1) {
        return {
          status: "failed",
          keyRotated: null,
          errorMessage: boundErrorMessage(
            `local enrollment journal for ${decoded.enrollmentId} has no RequestId yet (state ${journal.state}); cannot retrieve`,
          ),
        };
      }

      if (typeof onBeforeMutation === "function") onBeforeMutation(issuer.step);
      const issuance = assertIssuanceOutcome(await issuer.retrieve(journal.requestId));
      if (typeof onBeforeMutation === "function") onBeforeMutation("report-issuance-evidence");
      await reportIssuanceEvidence(client, jobId, issuance);

      if (issuance.outcome === "pending") {
        return resultForAdcsOutcome(issuance, decoded, {
          knownRequestId: journal.requestId,
        });
      }
      if (issuance.outcome === "rejected_invalid") {
        continueOutcomeRef.value = "rejected_invalid";
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: "rejected_invalid",
          attempt: decoded.attempt,
          containerName,
          snapshotSha256: decoded.snapshotSha256,
          jobId,
          csrSha256: journal.csrSha256,
          csrSpkiSha256: journal.csrSpkiSha256,
          templateOid: journal.templateOid,
          caConfig: snapshot.caConfig,
          template: snapshot.template,
          requestId: journal.requestId,
          errorCode: "ADCS_CA_KEY_CHANGED",
        });
        return resultForAdcsOutcome(issuance, decoded, {
          knownRequestId: journal.requestId,
        });
      }
      if (issuance.outcome === "denied" || issuance.outcome === "refused") {
        const caHresult =
          issuance.outcome === "denied" &&
          typeof issuance.caHresult === "string" &&
          CA_HRESULT_PATTERN.test(issuance.caHresult)
            ? issuance.caHresult
            : null;
        if (issuance.outcome === "denied" && !caHresult) {
          // Contract requires caHresult for denied; keep reconcilable locally.
          return resultForAdcsOutcome(issuance, decoded, {
            knownRequestId: journal.requestId,
          });
        }
        continueOutcomeRef.value = issuance.outcome;
        await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
          state: issuance.outcome,
          attempt: decoded.attempt,
          containerName,
          snapshotSha256: decoded.snapshotSha256,
          jobId,
          csrSha256: journal.csrSha256,
          csrSpkiSha256: journal.csrSpkiSha256,
          templateOid: journal.templateOid,
          caConfig: snapshot.caConfig,
          template: snapshot.template,
          requestId: journal.requestId,
          ...(caHresult ? { caHresult } : {}),
          ...(typeof issuance.errorCode === "string" ? { errorCode: issuance.errorCode } : {}),
        });
        return resultForAdcsOutcome(issuance, decoded, {
          knownRequestId: journal.requestId,
        });
      }
      if (issuance.outcome !== "issued") {
        return resultForAdcsOutcome(issuance, decoded, {
          knownRequestId: journal.requestId,
        });
      }

      const written = await writeIssuedCertificateArtifacts({
        stateDir,
        enrollmentId: decoded.enrollmentId,
        leafPem: issuance.certificatePem,
      });
      await writeEnrollmentJournal(stateDir, decoded.enrollmentId, {
        state: "issued",
        attempt: decoded.attempt,
        containerName,
        snapshotSha256: decoded.snapshotSha256,
        jobId,
        csrSha256: journal.csrSha256,
        csrSpkiSha256: journal.csrSpkiSha256,
        templateOid: journal.templateOid,
        caConfig: snapshot.caConfig,
        template: snapshot.template,
        leafSha256: written.leafSha256,
        requestId: journal.requestId,
      });
      await recordHighestRequestId(stateDir, snapshot.caConfig, journal.requestId);
      journal = { ...journal, state: "issued", leafSha256: written.leafSha256 };

      return validateAndInstallFromLeaf({
        certificatePem: issuance.certificatePem,
        journal,
        decoded,
        snapshot,
        windowsTarget,
        stateDir,
        caCertPath,
        executionContext,
        jobId,
        client,
        cngWorkDir,
        containerName,
        log,
        leaseOpts,
        onBeforeMutation,
        windowsExecFileImpl,
        windowsConnectImpl,
        continueOutcomeRef,
      });
      });
    } catch (err) {
      if (err && err.code === "ENROLLMENT_LOCK_LOST") {
        return {
          status: "failed",
          keyRotated: null,
          retryableInterrupt: true,
          errorMessage: boundErrorMessage(
            `AD CS enrollment lock lost mid-continue: ${err.message}`,
          ),
        };
      }
      throw err;
    } finally {
      const lockLost = Boolean(enrollmentLock && enrollmentLock.lost);
      const continueOutcome = continueOutcomeRef.value;
      const journalledCleanupOutcome = resolveCleanupOutcome({
        stateDir,
        enrollmentId: decoded?.enrollmentId,
      });
      if (
        !lockLost &&
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
  terminalEnrollmentResultExtras,
  shouldRetainCngKey,
  shouldCleanupAbandonedCngKey,
  resolveCleanupOutcome,
  isRetryableInstallInterrupt,
  observeInstalledCertificateIdentity,
  inspectAdcsInstallProgress,
  withUniqueValidationLeafFile,
};
