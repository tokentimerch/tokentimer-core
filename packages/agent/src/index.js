"use strict";

/**
 * TokenTimer Agent - execution-plane entry.
 *
 * Structural scope note (docs/certops/CONTEXT.md): this package is the
 * execution plane, the only component that touches private keys. It holds
 * keys on the host it runs on; TokenTimer's control plane never receives or
 * stores them. Every module here must stay safe to run against an untrusted
 * or compromised control plane (agent-local policy wins, ADR-0002).
 *
 * Bootstrap scope (current): this file wires the landed modules together
 * into a runnable outbound-only process:
 *   - config: config.json + secure credential storage (src/config)
 *   - policy: agent-local allowlist engine, default-deny (src/policy)
 *   - protocol: register/heartbeat/claim/result/evidence client (src/protocol)
 *   - evidence: schema-safe evidence construction + final key-material scan
 *     (src/evidence)
 *   - discovery: observe-only filesystem certificate inventory, reported as
 *     certificate.observed evidence (src/discovery)
 *
 * signed-job dispatch (current, opt-in via config.execution.enabled):
 * jobs claimed from the control plane run through the full trust chain
 * before any execution: Ed25519 signature verification against the pinned
 * signing key (src/signing) -> replay-cache check (src/replay) -> clock
 * window check with drift compensation (src/clock) -> agent-local policy
 * (src/policy) -> replay consume -> execute. Execution modules: src/keys,
 * src/acme, src/deploy, src/reload, src/verify.
 *
 * When execution is NOT enabled (config.execution absent or enabled:false),
 * the agent runs observe-only: register, heartbeat, and filesystem discovery
 * remain fully active, but the agent advertises zero executable/mutating
 * actions and never polls the claim endpoint. Claiming production jobs while
 * unable to execute them previously stranded leases (blocked reports lacked
 * claimId/nonce). handleClaimedJob still treats an unexpected claim as
 * "blocked"/"rejected" defense-in-depth if one ever arrives.
 *
 * Known base-payload deviations (job-payload.schema.json / signed-job contract;
 * documented for the control-plane backend contract):
 *   - No sans / domains list => the CSR CN and ACME -d domain(s) come from
 *     job.target.reference as a single-name fallback. When job.sans (or
 *     renewalProfile.sanPolicy.sans) is present, the agent uses the full
 *     approved SAN list for CSR + ACME + post-issuance validation.
 *   - No keyAlgorithm/keySize => renew uses the keys module default (ec-p256).
 *     When both are present they map onto generateKeyPairToFile algorithm ids
 *     (rsa-NNNN / ec-pNNN); unrecognized combinations fail the job (no silent remap).
 *   - No keyRotation flag => renew reuses an existing key at
 *     <keysDir>/<certificateId>.key.pem and generates one only when absent;
 *     keyRotated reports whether a new key was generated. A truthy
 *     job.keyRotation (forward-compatible) forces regeneration.
 *   - No certPath / deploymentTargets => job.certPath is honored when present;
 *     otherwise target.reference is used as the deploy destination when it is
 *     an absolute path. When job.deploymentTargets is a non-empty array, the
 *     agent deploys (reload/verify) once per target; any target failure fails
 *     the job (all-or-nothing), with per-target evidence. Neither present =>
 *     renew deploys nowhere it can name, so the job fails with a clear message.
 *   - No preferredChain / eabRef / accountRef => ACME uses CA defaults and no
 *     External Account Binding. When eabRef (or accountRef) is set, the agent
 *     resolves {eabKid,eabHmacKey} from local config.acmeAccounts only.
 *   - "deploy" jobs need certificatePem from the control plane; the base
 *     payload has no such field, so deploy without it reports "blocked"
 *     (awaiting the deploy job-type contract).
 *   - "revoke" execution is out of scope for this agent build => always "blocked".
 *   - Wildcard policy (sanPolicy.allowWildcards) is enforced at profile
 *     validation on the control plane; the agent does not re-check it unless
 *     the nested renewalProfile happens to carry allowWildcards (best-effort).
 */

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const tls = require("node:tls");
const crypto = require("node:crypto");

const {
  resolveConfigDir,
  loadAgentConfig,
  writeSigningKeyPin,
  readSigningKeyPin,
  readCredential,
  persistRegistration,
  recoverPendingRegistration,
  ensureRegistrationId,
  clearRegistrationId,
  readCaBundle,
  createSequenceAllocator,
  deleteBootstrapEnvFile,
  listConfiguredDnsProviderIds,
  resolveAcmeAccountCredentials,
} = require("./config");
const { loadPolicyConfig, createPolicyEngine } = require("./policy");
const { isWindows, clearWindowsServiceBootstrapToken } = require("./platform");
const { filterQualifiedCapabilities } = require("./capabilities");
const {
  createProtocolClient,
  createCaAwareFetch,
  startPollLoop,
  validateRegistrationResponse,
} = require("./protocol");
const {
  buildPolicyRejectionEvidence,
  buildEvidenceItem,
  buildEvidenceBody,
  assertEvidencePayloadSafe,
} = require("./evidence");
const { discoverCertificates } = require("./discovery");
const {
  validateClaimedJob,
  hasReportableJobId,
} = require("./claimed-job");
const { defaultAgentLogger } = require("./logging");
const { verifyJobEnvelope, checkJobTimeWindow, checkAgentIdBinding, AGENT_ID_BINDING_CAPABILITY, AGENT_ID_BINDING_REJECTION_REASONS } = require("./signing");
const { createReplayCache } = require("./replay");
const { createClockOffsetEstimator } = require("./clock");
const { checkNtpSynced } = require("./ntp");
const { generateKeyPairToFile, discardStagedKey, generateCsr } = require("./keys");
const {
  createAcmeAdapter,
  resolveCertificateOutputPaths,
} = require("./acme");
const {
  deployCertificate,
  deployCertificateAndKey,
  discardDeployBackups,
  removeDeployedArtifacts,
  getDeployMetrics,
} = require("./deploy");
const { durabilityMetadataEntries } = require("./platform/durability.js");
const {
  markSideEffectReached,
  scanUnresolvedJournalEntries,
  hasUnresolvedJournalForJob,
  clearJournalOnTerminal,
  formatUnresolvedJournalReport,
} = require("./job-journal");
const { reloadService } = require("./reload");
const {
  verifyDeployedCertificate,
  computeCertificateFingerprint,
  describeDeployedCertificate,
  validateCertificateForDeploy,
  splitCertificatePems,
} = require("./verify");
const {
  enqueueOutboxEntry,
  transmitOutboxEntry,
  acknowledgeOutboxEntry,
  drainOutbox,
  createEvidenceBuffer,
} = require("./outbox");
const {
  generateCsrViaCng,
  acceptCertificateViaCng,
  acquireStoreLock,
  removeAbandonedKeyContainer,
  removeCertificateAndKeyContainer,
  isAgentOwnedContainerName,
  buildContainerName,
} = require("./windows-cert-store");
const { deployIisBinding, resolveVerificationTarget } = require("./windows-iis");
const {
  createLedgerRow,
  readLedgerRow,
  sweepLedger,
  normalizeThumbprint: normalizeRetentionThumbprint,
} = require("./windows-retention");
const { listMachineStoreCertificates, listHttpSysBindings } = require("./windows-discovery");

const { version: AGENT_VERSION } = require("../package.json");

/**
 * Maps a claimed job payload (packages/contracts/certops/job-payload.
 * schema.json shape) onto the policy engine's jobDescriptor vocabulary.
 *
 * The claimed-job validator checks the full frozen public job shape first.
 * Action-specific policy dimensions are required in public metadata and are
 * never silently omitted. Signed-dispatch execution fields are additionally
 * verified by the signing/replay/clock modules before any execution.
 *
 * @param {object} job claimed job payload
 * @returns {object} policy jobDescriptor
 */
function buildJobPolicyDescriptor(job) {
  return validateClaimedJob(job).policyDescriptor;
}

/**
 * Policy descriptor mapping for the signed-dispatch path. Signed jobs carry
 * execution fields (issuedAt/expiresAt/nonce/signature/commandRef/...) that
 * the frozen bootstrap job shape does not allow; their full field validation
 * happens inside verifyJobEnvelope (verifyJobSignature's findSignedFieldProblem
 * for v1, or the v2 envelope checks for v2) BEFORE this mapping runs, so only
 * the policy-dimension projection is done here.
 *
 * @param {object} job signature-verified claimed job payload
 * @returns {object} policy jobDescriptor
 */
function buildSignedJobPolicyDescriptor(job) {
  const descriptor = {};
  if (job?.target?.reference !== undefined) {
    descriptor.targetSelector = job.target.reference;
  }
  for (const field of ["commandRef", "path", "caEndpoint", "dnsZone", "dnsProvider"]) {
    if (job?.[field] !== undefined) descriptor[field] = job[field];
  }
  // Any custody-shaped intent on a job maps onto the engine's single
  // unconditional key-export rejection flag. No job payload field is
  // expected to carry this today (the schema forbids custody fields), but
  // if a compromised control plane smuggled one in, this is the belt to
  // the schema's suspenders.
  if (
    job?.requestsKeyExport === true ||
    job?.exportPrivateKey === true ||
    job?.keyExport === true
  ) {
    descriptor.requestsKeyExport = true;
  }
  return descriptor;
}

function emitLog(log, message, details) {
  if (typeof log === "function") {
    log(message, details);
    return;
  }
  defaultAgentLogger.error(message, details);
}

/**
 * Non-error progress logging for job claim/step-start/finish points.
 * Deliberately independent of the `log` callback threaded through the rest
 * of this file (which is wired for error/rejection reporting, including in
 * tests that assert on its calls): this always goes to defaultAgentLogger's
 * info sink (stdout by default), so enabling progress visibility can never
 * change error-path behavior or test expectations.
 *
 * @param {string} message
 * @param {object} [details]
 */
function emitInfo(message, details) {
  defaultAgentLogger.info(message, details);
}

function localAttemptId(jobId) {
  return `local-${jobId}-${Date.now()}`;
}

/**
 * Bound applied to errorMessage strings reported through reportResult so a
 * failing step can never flood the control plane (and pre-redacted module
 * excerpts stay small). The evidence module separately enforces its own
 * summary bounds.
 */
const EXECUTION_ERROR_MESSAGE_MAX_CHARS = 512;

/** ACME adapter kinds executeJob accepts from a job payload. */
const SUPPORTED_ACME_KINDS = ["certbot", "acme.sh"];

/** Scratch directory (under the agent state dir) for CNG certreq INF/CSR
 * artifacts (../windows-cert-store) and IIS-bind accept-certificate temp
 * files. Never holds private key material -- the CNG key never leaves the
 * store -- only public CSR/certificate bytes, briefly. */
const WINDOWS_CERT_STORE_WORK_DIR_NAME = "windows-cert-store-work";

/** Ledger directory (under the agent state dir) for ../windows-retention's
 * superseded-certificate rows, per decision 18. */
const WINDOWS_RETENTION_LEDGER_DIR_NAME = "windows-retention";

function isNonEmptyStringValue(value) {
  return typeof value === "string" && value.length > 0;
}

/**
 * Actions this agent build can actually execute (executeJob): "revoke" is
 * deliberately absent (always blocked in this build). Sent as the claim's
 * supportedActions when execution is enabled so the control plane's claim
 * query only leases jobs this agent can run.
 */
const EXECUTABLE_JOB_ACTIONS = Object.freeze(["noop", "renew", "deploy", "reload"]);

/**
 * Named behaviours this agent build supports, declared at registration and
 * re-declared on every heartbeat (`heartbeatBody` now also
 * admits `declaredCapabilities`, see ADR-0002's addendum). Re-declaration on
 * heartbeat means an in-place binary upgrade advertises a newly-supported
 * capability without re-enrollment, which previously cost the agent its
 * identity and signing-key pin.
 *
 * This build's "verify" step already reports validation.passed evidence carrying
 * fingerprintSha256 and validTo for every ACME run (see runRenewal's verify tail
 * below), which is exactly what issuance reconciliation requires to promote a
 * provisioning certificate, so it is safe to declare unconditionally here rather
 * than gating it on execution.enabled: an observe-only agent never claims work
 * regardless (resolveClaimSupportedActions returns []), so the declaration
 * is inert until execution is actually turned on.
 *
 * windows-cert-store-v1 and iis-binding-v1 are platform-gated in addition to
 * the manifest gate below: this same cross-platform build binary runs on
 * both Linux and Windows, and a Linux process can never execute
 * certreq.exe/certutil.exe/netsh.exe, so those two strings are only ever
 * CANDIDATES when isWindows() is true for the running process. This is
 * evaluated once at module load (the platform of a running process does not
 * change), unlike the manifest gate immediately below, which additionally
 * requires real-host evidence per build before either string reaches
 * AGENT_DECLARED_CAPABILITIES even on a Windows host.
 */
const AGENT_CANDIDATE_CAPABILITIES = Object.freeze(
  isWindows()
    ? ["evidence-claim-binding-v1", "windows-cert-store-v1", "iis-binding-v1"]
    : ["evidence-claim-binding-v1"],
);

/**
 * Capabilities this build actually advertises, after the build-time
 * qualified-capabilities manifest gate (ADR-0012 decision 14; see
 * ./capabilities). evidence-claim-binding-v1 is not one of the
 * manifest-gated strings, so today this is identical to
 * AGENT_CANDIDATE_CAPABILITIES; the filter exists so that when a future
 * change adds windows-cert-store-v1, iis-binding-v1, or
 * trust-anchor-deploy-v1 to the candidate list, they pass through this
 * same gate rather than a new one being invented at that point.
 */
const AGENT_DECLARED_CAPABILITIES = filterQualifiedCapabilities(
  AGENT_CANDIDATE_CAPABILITIES,
);

/**
 * ADR-0012 decision 3, step 4: agent-id-binding-v1 is advertised only from
 * the EFFECTIVE runtime value of requireSignedAgentId (config.requireSignedAgentId,
 * itself already resolved from env/config.json against the compiled-in
 * default inside packages/agent/src/config/index.js), never from that
 * compiled-in default directly. This matters because the same build binary
 * ships with the flag defaulting to false but must correctly advertise the
 * capability the moment an operator flips it to true at runtime, and must
 * stop advertising it if a config override brings it back to false, with no
 * rebuild in either direction. When effective value is false, absence of
 * agentId is still tolerated by the compatibility decoder (see
 * checkAgentIdBinding), so advertising the capability then would overclaim.
 */
function resolveDeclaredCapabilities(requireSignedAgentId) {
  return requireSignedAgentId
    ? Object.freeze([...AGENT_DECLARED_CAPABILITIES, AGENT_ID_BINDING_CAPABILITY])
    : AGENT_DECLARED_CAPABILITIES;
}

/**
 * Claim scope in observe-only mode (execution disabled): empty. An
 * observe-only agent must never advertise mutating/executable actions and
 * must never poll claim; an empty list is the wire-level expression of
 * "no executable actions" if a claim call is ever made in error.
 */
const OBSERVE_ONLY_CLAIM_ACTIONS = Object.freeze([]);

/**
 * Actions advertised on claim polls. Observe-only agents return [].
 *
 * @param {object|null|undefined} executionContext
 * @returns {readonly string[]}
 */
function resolveClaimSupportedActions(executionContext) {
  if (executionContext !== null && executionContext !== undefined && executionContext.enabled === true) {
    return EXECUTABLE_JOB_ACTIONS;
  }
  return OBSERVE_ONLY_CLAIM_ACTIONS;
}

/**
 * Whether this process should poll the jobs/claim endpoint. Observe-only
 * agents must not claim: discovery and heartbeat stay independent.
 *
 * @param {object|null|undefined} executionContext
 * @returns {boolean}
 */
function shouldPollForJobs(executionContext) {
  return executionContext !== null && executionContext !== undefined && executionContext.enabled === true;
}

/**
 * Exit code used when the control plane retires this agent. Paired with
 * RestartPreventExitStatus in scripts/tokentimer-agent.service so systemd
 * (Restart=on-failure/always) does not respawn a decommissioned agent into
 * a heartbeat 410 loop (ADR-0002 clean retirement).
 */
const AGENT_RETIRED_EXIT_CODE = 86;

/**
 * Resolves the authoritative job mode from a signed dispatch payload.
 * Per COORDINATION-B4: prefer top-level `job.mode`, then `job.payload.mode`,
 * default `"real"` when BOTH are omitted (dry-run is never an ambient
 * default for a job that never specified a mode at all).
 *
 * Fails CLOSED, not open, on a present-but-unrecognized value: only the
 * exact strings "real" and "dry_run" are ever treated as "real". Any other
 * non-empty string (a typo, a future mode this build predates, or a
 * malformed/tampered value) resolves to "dry_run" -- the no-side-effect
 * mode -- rather than silently defaulting to "real" and running live
 * ACME/DNS/deploy operations against a value nobody asked for. The agent
 * has no independent schema validation of the raw job body before this
 * runs, so this function is the last line of defense against exactly that
 * failure mode.
 *
 * @param {object} job
 * @returns {"real"|"dry_run"}
 */
function resolveJobMode(job) {
  const topLevel = job?.mode;
  const nested = job?.payload?.mode;
  const raw =
    typeof topLevel === "string" && topLevel.length > 0
      ? topLevel
      : typeof nested === "string" && nested.length > 0
        ? nested
        : null;
  if (raw === null) return "real";
  return raw === "real" ? "real" : "dry_run";
}

/**
 * Default assumed lease TTL when the control plane omits leaseExpiresAt
 * (mirrors apps/api/services/certops/leaseTiming.DEFAULT_JOB_LEASE_SECONDS).
 */
const DEFAULT_JOB_LEASE_MS = 900 * 1000;
/** Max consecutive transient renew failures before abort (subsequent renews). */
const MAX_LEASE_TRANSIENT_RETRIES = 3;
/** Base backoff between transient renew retries (ms). */
const LEASE_TRANSIENT_BACKOFF_MS = 200;
/**
 * Periodic lease heartbeat interval while a side-effecting stage runs.
 * ACME DEFAULT_TIMEOUT_MS is 10 minutes; default lease TTL is 15 minutes.
 * Stage-boundary renews alone are not enough if a single ACME/DNS stage
 * approaches the TTL with no mid-stage renew, hence a lightweight timer.
 */
const LEASE_HEARTBEAT_INTERVAL_MS = 60 * 1000;

/**
 * VERIFY-RACE-01: max retries for a live verify probe that connects fine
 * but reports the *previous* certificate's fingerprint. `maybeReloadForJob`
 * returns as soon as `systemctl reload`/equivalent exits, which only
 * guarantees the reload was requested, not that every worker/connection has
 * cut over to the new certificate. On some services (multi-worker nginx
 * with long-lived keepalive connections, blue/green LBs, etc.) a probe run
 * immediately after reload can land on a worker that has not yet rotated,
 * observed empirically at ~9ms post-reload while ~1500ms post-reload was
 * reliably safe. Retrying only this specific outcome absorbs that gap
 * without masking a genuinely wrong deploy.
 */
const MAX_VERIFY_TRANSIENT_RETRIES = 4;
/**
 * Fixed backoff schedule between transient verify-mismatch retries (ms).
 * Cumulative worst case is 2500ms, comfortably past the ~1500ms
 * empirically-safe mark with margin for slower reload paths.
 */
const VERIFY_TRANSIENT_RETRY_DELAYS_MS = [250, 500, 750, 1000];

/**
 * Mutable lease session shared across accept + execute for one job attempt.
 * @returns {{ lastConfirmedExpiresAtMs: number|null, consecutiveTransientFailures: number, abort: object|null }}
 */
function createLeaseState() {
  return {
    lastConfirmedExpiresAtMs: null,
    consecutiveTransientFailures: 0,
    abort: null,
  };
}

function sleepMs(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * VERIFY-RACE-01 mitigation: retries `probeImpl` (defaults to the real
 * `verifyDeployedCertificate`) when, and only when, the probe connected
 * successfully and got back an actual certificate whose fingerprint simply
 * does not match yet. That specific shape (`actualFingerprintSha256` is a
 * non-null string different from the expected one) is the signature of the
 * reload-cutover race: the endpoint is reachable and serving *some*
 * certificate, it just has not rotated to the new one on every path yet.
 *
 * Every other failure shape -- connect failures, handshake timeouts, no
 * certificate presented at all (`actualFingerprintSha256 === null`) -- is
 * NOT retried. Those are not known to self-heal on a short timer and
 * retrying them would only extend a genuinely broken deploy's failure
 * latency by several seconds for no benefit.
 *
 * Authorization/policy rejections never reach this function at all: the
 * `checkVerifyHost` gate at the call site runs first and returns its own
 * fail-fast outcome before `probeImpl` is ever invoked.
 *
 * @param {object} probeOptions forwarded verbatim to `probeImpl`.
 * @param {object} [opts]
 * @param {Function} [opts.probeImpl] injection point for tests; defaults to
 *   `verifyDeployedCertificate`.
 * @param {number} [opts.maxRetries] defaults to MAX_VERIFY_TRANSIENT_RETRIES.
 * @param {number[]} [opts.retryDelaysMs] defaults to
 *   VERIFY_TRANSIENT_RETRY_DELAYS_MS.
 * @param {Function} [opts.sleep] injection point for tests; defaults to
 *   sleepMs.
 * @returns {Promise<ReturnType<typeof verifyDeployedCertificate>>}
 */
async function verifyDeployedCertificateWithRetry(
  probeOptions,
  {
    probeImpl = verifyDeployedCertificate,
    maxRetries = MAX_VERIFY_TRANSIENT_RETRIES,
    retryDelaysMs = VERIFY_TRANSIENT_RETRY_DELAYS_MS,
    sleep = sleepMs,
  } = {},
) {
  let result;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    result = await probeImpl(probeOptions);
    if (result.verified === true) return result;

    const isTransientMismatch =
      typeof result.actualFingerprintSha256 === "string" &&
      result.actualFingerprintSha256.length > 0;
    if (!isTransientMismatch || attempt === maxRetries) return result;

    const delay = retryDelaysMs[attempt] ?? retryDelaysMs[retryDelaysMs.length - 1];
    await sleep(delay);
  }
  return result;
}

function extractLeaseExpiresAtMs(response, nowMs) {
  if (response && typeof response.leaseExpiresAt === "string") {
    const parsed = Date.parse(response.leaseExpiresAt);
    if (Number.isFinite(parsed)) return parsed;
  }
  return nowMs + DEFAULT_JOB_LEASE_MS;
}

/**
 * B6 lease renew with fail-closed semantics.
 *
 * - `required: true` (first accept confirmation): ANY failure aborts:
 *   network/transient, 5xx, 409/410, ownership mismatch. Execution must not
 *   proceed past a failed first confirmation.
 * - Subsequent renews (`required: false`): 409/410/ownership loss abort
 *   immediately with no retry. Transient network/5xx may retry a bounded
 *   number of times only while the next attempt is still before the last
 *   confirmed lease expiry (grace deadline). Never sleeps past that deadline.
 *
 * Soft-continue on first confirmation is intentionally removed.
 *
 * @param {object} params
 * @param {object|null|undefined} params.leaseClient protocol client with renewLease
 * @param {string} params.jobId
 * @param {string|null} params.claimId
 * @param {(msg: string) => void} [params.log]
 * @param {object} [params.leaseState] from createLeaseState()
 * @param {boolean} [params.required] when true, any failure aborts
 * @param {() => number} [params.now]
 * @returns {Promise<{ ok: true, skipped?: boolean, softFailure?: boolean, response?: object }|{ ok: false, retired: boolean, abort: { status: "blocked", errorMessage: string, retired?: boolean } }>}
 */
async function renewJobLeaseOrAbort({
  leaseClient,
  jobId,
  claimId,
  log = console.error,
  leaseState = null,
  required = false,
  now = () => Date.now(),
} = {}) {
  if (!leaseClient || typeof leaseClient.renewLease !== "function") {
    if (required) {
      return {
        ok: false,
        retired: false,
        abort: {
          status: "blocked",
          errorMessage: boundErrorMessage(
            "lease renew aborted: lease client unavailable for mandatory confirmation",
          ),
        },
      };
    }
    return { ok: true, skipped: true };
  }
  if (typeof claimId !== "string" || claimId.length === 0) {
    // Observe-only / unsigned paths may lack a claim id; nothing to renew.
    // Mandatory confirmation applies only when a claimId is present to renew.
    return { ok: true, skipped: true };
  }

  while (true) {
    let response;
    try {
      response = await leaseClient.renewLease({ jobId, claimId });
    } catch (err) {
      if (required) {
        emitLog(
          log,
          `tokentimer-agent: mandatory lease confirmation for job ${jobId} failed: ${err.message}`,
        );
        const abort = {
          status: "blocked",
          errorMessage: boundErrorMessage(
            `lease renew aborted: mandatory confirmation failed (${err.message})`,
          ),
        };
        if (leaseState) leaseState.abort = abort;
        return { ok: false, retired: false, abort };
      }

      const nowMs = now();
      const graceDeadline =
        leaseState && Number.isFinite(leaseState.lastConfirmedExpiresAtMs)
          ? leaseState.lastConfirmedExpiresAtMs
          : null;
      if (graceDeadline === null || nowMs >= graceDeadline) {
        emitLog(
          log,
          `tokentimer-agent: lease renew for job ${jobId} failed at/after confirmed expiry: ${err.message}`,
        );
        const abort = {
          status: "blocked",
          errorMessage: boundErrorMessage(
            `lease renew aborted: transient failure at or past confirmed lease expiry (${err.message})`,
          ),
        };
        if (leaseState) leaseState.abort = abort;
        return { ok: false, retired: false, abort };
      }

      const failures =
        leaseState && typeof leaseState.consecutiveTransientFailures === "number"
          ? leaseState.consecutiveTransientFailures + 1
          : 1;
      if (leaseState) leaseState.consecutiveTransientFailures = failures;

      if (failures > MAX_LEASE_TRANSIENT_RETRIES) {
        const abort = {
          status: "blocked",
          errorMessage: boundErrorMessage(
            `lease renew aborted: exceeded ${MAX_LEASE_TRANSIENT_RETRIES} consecutive transient failures (${err.message})`,
          ),
        };
        if (leaseState) leaseState.abort = abort;
        return { ok: false, retired: false, abort };
      }

      const backoff = LEASE_TRANSIENT_BACKOFF_MS * 2 ** (failures - 1);
      if (nowMs + backoff >= graceDeadline) {
        const abort = {
          status: "blocked",
          errorMessage: boundErrorMessage(
            `lease renew aborted: next retry would exceed confirmed lease expiry (${err.message})`,
          ),
        };
        if (leaseState) leaseState.abort = abort;
        return { ok: false, retired: false, abort };
      }

      emitLog(
        log,
        `tokentimer-agent: lease renew for job ${jobId} transient failure ` +
          `${failures}/${MAX_LEASE_TRANSIENT_RETRIES} (retrying before expiry): ${err.message}`,
      );
      const beforeSleep = now();
      await sleepMs(backoff);
      // Guard against frozen-clock loops (tests injecting a constant now()).
      if (now() <= beforeSleep && failures >= MAX_LEASE_TRANSIENT_RETRIES) {
        const abort = {
          status: "blocked",
          errorMessage: boundErrorMessage(
            `lease renew aborted: exceeded ${MAX_LEASE_TRANSIENT_RETRIES} consecutive transient failures (${err.message})`,
          ),
        };
        if (leaseState) leaseState.abort = abort;
        return { ok: false, retired: false, abort };
      }
      continue;
    }

    if (
      response &&
      response.ok === false &&
      (response.status === 409 || response.status === 410)
    ) {
      const codeSuffix =
        typeof response.code === "string" && response.code.length > 0
          ? ` (${response.code})`
          : "";
      const retired = response.status === 410;
      const abort = {
        status: "blocked",
        errorMessage: boundErrorMessage(
          retired
            ? `lease renew aborted: agent is retired (HTTP 410)${codeSuffix}`
            : `lease renew aborted: claim ownership lost or lease conflict (HTTP 409)${codeSuffix}`,
        ),
        ...(retired ? { retired: true } : {}),
      };
      if (leaseState) leaseState.abort = abort;
      return { ok: false, retired, abort };
    }

    const nowMs = now();
    if (leaseState) {
      leaseState.lastConfirmedExpiresAtMs = extractLeaseExpiresAtMs(
        response,
        nowMs,
      );
      leaseState.consecutiveTransientFailures = 0;
      leaseState.abort = null;
    }
    return { ok: true, response };
  }
}

/**
 * Starts a lightweight periodic lease renew while execution is active.
 * Cleared via stopPeriodicLeaseRenewal — never leave timers leaked.
 *
 * @param {object} leaseOpts renewJobLeaseOrAbort params (incl. leaseState)
 * @param {{ intervalMs?: number, onAbort?: (abort: object) => void }} [options]
 * @returns {{ stop: () => void, getAbort: () => object|null }}
 */
function startPeriodicLeaseRenewal(leaseOpts, { intervalMs = LEASE_HEARTBEAT_INTERVAL_MS, onAbort } = {}) {
  let stopped = false;
  let inFlight = null;
  let lastAbort = null;

  const timer = setInterval(() => {
    if (stopped) return;
    if (inFlight) return;
    inFlight = renewJobLeaseOrAbort({
      ...leaseOpts,
      required: false,
    })
      .then((result) => {
        if (result && result.ok === false) {
          lastAbort = result.abort;
          if (typeof onAbort === "function") onAbort(result.abort);
        } else if (result && result.ok === true) {
          // A successful renew means ownership/liveness is confirmed as of
          // now; a PRIOR transient abort must not survive it. Without this,
          // one recovered heartbeat blip would permanently reclassify a
          // later genuine success as "blocked" (see getAbort()) and the
          // job-journal cleanup for terminal "blocked" outcomes would then
          // erase the durable record of side effects that actually
          // executed.
          lastAbort = null;
        }
      })
      .catch((err) => {
        emitLog(
          leaseOpts.log || console.error,
          `tokentimer-agent: periodic lease renew error: ${err.message}`,
        );
      })
      .finally(() => {
        inFlight = null;
      });
  }, intervalMs);
  if (typeof timer.unref === "function") timer.unref();

  return {
    stop() {
      stopped = true;
      clearInterval(timer);
    },
    getAbort() {
      return lastAbort || (leaseOpts.leaseState && leaseOpts.leaseState.abort) || null;
    },
  };
}

function stopPeriodicLeaseRenewal(handle) {
  if (handle && typeof handle.stop === "function") handle.stop();
}

/**
 * Resolves the agent state directory from execution context (parent of keysDir).
 * @param {object|null|undefined} executionContext
 * @returns {string|null}
 */
function resolveAgentStateDir(executionContext) {
  const keysDir = executionContext?.execution?.keysDir;
  if (typeof keysDir === "string" && keysDir.length > 0) {
    return path.dirname(keysDir);
  }
  const outboxDir = executionContext?.outboxDir || executionContext?.execution?.outboxDir;
  if (typeof outboxDir === "string" && outboxDir.length > 0) {
    return path.dirname(outboxDir);
  }
  return null;
}

/**
 * H3: adopt a pending signing-key rotation advertised on a heartbeat
 * response. The only runtime path (besides initial registration) that
 * passes allowRepin: true — the pending key MUST come from
 * heartbeat.signingKeyRotation, never from arbitrary job data.
 *
 * @param {object} params
 * @param {object|null|undefined} params.rotation heartbeat.signingKeyRotation
 * @param {string} params.configDir
 * @param {object|null|undefined} params.executionContext
 * @param {(msg: string) => void} [params.log]
 * @returns {{ adopted: boolean, reason?: string }}
 */
function adoptSigningKeyRotation({
  rotation,
  configDir,
  executionContext,
  log = console.error,
}) {
  if (rotation === null || rotation === undefined) {
    return { adopted: false, reason: "absent" };
  }
  if (typeof rotation !== "object" || Array.isArray(rotation)) {
    return { adopted: false, reason: "malformed" };
  }
  const pendingSigningKeyId = rotation.pendingSigningKeyId;
  const pendingPublicKeyPem = rotation.pendingPublicKeyPem;
  if (
    typeof pendingSigningKeyId !== "string" ||
    pendingSigningKeyId.length === 0 ||
    typeof pendingPublicKeyPem !== "string" ||
    pendingPublicKeyPem.length === 0
  ) {
    return { adopted: false, reason: "incomplete" };
  }
  const currentId = executionContext?.pinnedSigningKey?.signingKeyId ?? null;
  if (currentId === pendingSigningKeyId) {
    return { adopted: false, reason: "already_pinned" };
  }
  try {
    // Controlled rotation adoption IS the explicit re-pin flow the pin
    // writer guards for (alongside first-run registration).
    writeSigningKeyPin(
      configDir,
      {
        signingKeyId: pendingSigningKeyId,
        signingPublicKeyPem: pendingPublicKeyPem,
      },
      { allowRepin: true },
    );
  } catch (err) {
    emitLog(
      log,
      `tokentimer-agent: refusing signing-key rotation adoption: ${err.message}`,
    );
    return { adopted: false, reason: "invalid_pem" };
  }
  if (executionContext) {
    executionContext.pinnedSigningKey = {
      signingKeyId: pendingSigningKeyId,
      publicKeyPem: pendingPublicKeyPem,
    };
  }
  emitLog(
    log,
    `tokentimer-agent: adopted signing key rotation to ${pendingSigningKeyId}`,
  );
  return { adopted: true };
}

/**
 * POSIX-or-Windows absolute path check (same rationale as the acme
 * module's isAbsolutePathLike: agents primarily target POSIX hosts but
 * tests run on Windows too).
 *
 * @param {unknown} candidate
 * @returns {boolean}
 */
function isAbsolutePathLike(candidate) {
  return (
    typeof candidate === "string" &&
    (/^\//.test(candidate) ||
      /^[A-Za-z]:[\\/]/.test(candidate) ||
      /^\\\\/.test(candidate))
  );
}

/**
 * Structural check mirroring job-payload.schema.json's certificateId
 * pattern/length (1-128 chars, `^[A-Za-z0-9_.:-]+$`). The signature on a
 * signed job only proves the control plane's key produced these exact
 * bytes -- it says nothing about whether the CONTENT is well-formed. Every
 * real usage of job.certificateId builds a filesystem path under keysDir
 * (`${certificateId}.key.pem`) via plain string interpolation with no
 * further containment check downstream, so this is the one place that
 * stands between an untrusted/compromised control plane naming a
 * certificateId like "../../../etc/cron.d/x" and the agent writing (or
 * reading, for the deploy-side lookup) outside keysDir entirely (ADR-0002:
 * agent-local policy/validation wins even against a compromised server).
 *
 * @param {unknown} candidate
 * @returns {boolean}
 */
function isValidCertificateId(candidate) {
  return (
    typeof candidate === "string" &&
    candidate.length > 0 &&
    candidate.length <= 128 &&
    /^[A-Za-z0-9_.:-]+$/.test(candidate)
  );
}

/**
 * @param {unknown} message
 * @returns {string} message bounded to EXECUTION_ERROR_MESSAGE_MAX_CHARS
 */
function boundErrorMessage(message) {
  return String(message).slice(0, EXECUTION_ERROR_MESSAGE_MAX_CHARS);
}

/** Evidence metadata values cap at 512 chars (evidence/index.js
 * METADATA_VALUE_MAX_LENGTH); acme adapter excerpts cap at 1024, so they
 * must be re-truncated here or buildEvidenceItem throws and the real ACME
 * failure is lost behind a generic evidence-write error instead of reported. */
const EVIDENCE_METADATA_VALUE_MAX_CHARS = 512;

/**
 * @param {string} value
 * @returns {string|null}
 */
function boundMetadataExcerpt(value) {
  if (typeof value !== "string" || value.length === 0) return null;
  return value.slice(0, EVIDENCE_METADATA_VALUE_MAX_CHARS);
}

/**
 * Picks the most useful diagnostic text out of a failed ACME adapter run.
 * acme.sh (unlike certbot) writes most of its diagnostic detail, including
 * the reason a run was skipped or rejected, to stdout via its own `_info`
 * logger; only messages routed through `_err` land on stderr. A failure
 * message that only ever looks at stderrExcerpt therefore reports
 * "no stderr" for the exact acme.sh failures an operator most needs
 * explained (e.g. `RENEW_SKIP`), even though the real explanation was
 * captured and redacted right there in stdoutExcerpt. Prefers stderr when
 * both are present since certbot's own errors are conventionally there.
 * @param {{ stderrExcerpt?: string, stdoutExcerpt?: string }} renewal
 * @returns {string}
 */
function acmeFailureDetail(renewal) {
  const stderr = renewal.stderrExcerpt || "";
  const stdout = renewal.stdoutExcerpt || "";
  if (stderr) return stderr;
  if (stdout) return stdout;
  return "no output captured";
}

/**
 * Resolves the deploy destination for a job. base-payload deviation
 * (documented in the module docblock): the payload has no certPath field,
 * so an explicit job.certPath wins, then target.reference when it is an
 * absolute path, else null (the caller fails the job with a clear message).
 *
 * @param {object} job
 * @returns {string|null}
 */
function resolveJobCertPath(job) {
  if (isAbsolutePathLike(job?.certPath)) return job.certPath;
  if (isAbsolutePathLike(job?.target?.reference)) return job.target.reference;
  return null;
}

/**
 * Profile/job keyAlgorithm+keySize -> keys.generateKeyPairToFile algorithm id.
 * Returns null when both fields are absent (caller keeps the module default).
 * Returns { error } for an unrecognized / unmapped combination (fail closed;
 * never silently pick a different algorithm than the approved profile).
 *
 * @param {object} job
 * @returns {{ algorithm: string }|{ error: string }|null}
 */
function mapJobKeyAlgorithm(job) {
  const algorithm = job?.keyAlgorithm ?? job?.renewalProfile?.keyAlgorithm;
  const keySize = job?.keySize ?? job?.renewalProfile?.keySize;
  if (algorithm === undefined && keySize === undefined) return null;
  if (algorithm === undefined || keySize === undefined) {
    return {
      error:
        "renew job carries only one of keyAlgorithm/keySize; both are required together",
    };
  }
  const map = {
    "ecdsa:256": "ec-p256",
    "ecdsa:384": "ec-p384",
    "rsa:2048": "rsa-2048",
    "rsa:3072": "rsa-3072",
    "rsa:4096": "rsa-4096",
  };
  const mapped = map[`${algorithm}:${keySize}`];
  if (!mapped) {
    return {
      error:
        `unsupported keyAlgorithm/keySize combination: ${JSON.stringify(algorithm)}/${JSON.stringify(keySize)} ` +
        "(allowed: ecdsa 256|384, rsa 2048|3072|4096)",
    };
  }
  return { algorithm: mapped };
}

/**
 * Resolves the approved SAN list for renew. Prefers flattened job.sans
 * (scheduler execution fields), then nested renewalProfile.sanPolicy.sans.
 * Absent => null (caller falls back to single CN). Present but empty/malformed
 * => { error } so the job fails cleanly instead of trusting a buggy payload.
 *
 * @param {object} job
 * @returns {{ sans: string[] }|{ error: string }|null}
 */
function resolveJobSans(job) {
  const fromFlat = job?.sans;
  const fromProfile = job?.renewalProfile?.sanPolicy?.sans;
  const raw = Array.isArray(fromFlat)
    ? fromFlat
    : Array.isArray(fromProfile)
      ? fromProfile
      : null;
  if (raw === null) return null;
  if (raw.length === 0) {
    return { error: "renew job.sans is present but empty" };
  }
  const sans = [];
  for (let i = 0; i < raw.length; i += 1) {
    const entry = raw[i];
    if (typeof entry !== "string" || entry.trim().length === 0) {
      return {
        error: `renew job.sans[${i}] must be a non-empty string`,
      };
    }
    sans.push(entry.trim());
  }

  // Best-effort wildcard gate when the nested profile carries allowWildcards.
  const allowWildcards = job?.renewalProfile?.sanPolicy?.allowWildcards;
  if (
    allowWildcards === false &&
    sans.some((san) => san.includes("*"))
  ) {
    return {
      error:
        "renew job SAN list includes a wildcard but renewalProfile.sanPolicy.allowWildcards is false",
    };
  }
  return { sans };
}

/**
 * Splits a fullchain-style PEM into leaf + remaining chain blocks.
 * @param {string} pem
 * @returns {{ leafPem: string, chainPem: string|null }}
 */
function splitLeafAndChainPem(pem) {
  const blocks = splitCertificatePems(pem);
  if (blocks.length === 0) {
    return { leafPem: pem, chainPem: null };
  }
  if (blocks.length === 1) {
    return { leafPem: blocks[0], chainPem: null };
  }
  return {
    leafPem: blocks[0],
    chainPem: `${blocks.slice(1).join("\n")}\n`,
  };
}

/**
 * Reads the certificate material an ACME run staged, preferring the
 * fullchain artifact: nearly every server expects leaf plus intermediates at
 * its certificate path, and a leaf-only deployment is what makes clients
 * report an incomplete chain. The leaf-only file stays a fallback for tools
 * (or CAs) that produced no chain artifact at all.
 *
 * @param {{ leafPath: string, fullchainPath: string }} paths
 * @returns {{ pem: string }|{ error: string }}
 */
function readStagedCertificateChain(paths) {
  const candidates = [paths.fullchainPath, paths.leafPath];
  const errors = [];
  for (const candidate of candidates) {
    try {
      const pem = fs.readFileSync(candidate, "utf8");
      if (pem.trim().length > 0) {
        return { pem };
      }
      errors.push(`${candidate} is empty`);
    } catch (err) {
      errors.push(err.message);
    }
  }
  return { error: errors.join("; ") };
}

/**
 * Resolves deploy destinations for a job. Non-empty job.deploymentTargets
 * wins; otherwise a single destination from resolveJobCertPath.
 *
 * Per-target fields (keyPath, chainPath, modes, owner/group, backupDir) are
 * preserved when present. Job-level keyPath/chainPath act as fallbacks.
 *
 * @param {object} job
 * @returns {{ targets: Array<object> }|{ error: string }}
 */
function resolveJobDeployTargets(job) {
  const jobKeyPath = isAbsolutePathLike(job?.keyPath) ? job.keyPath : null;
  const jobChainPath = isAbsolutePathLike(job?.chainPath) ? job.chainPath : null;

  function pickTargetFields(item, fallbackCertPath) {
    const resolvedType = typeof item?.type === "string" ? item.type : job?.target?.type ?? "endpoint";
    // windows-iis has no filesystem certPath/keyPath/chainPath/reload service
    // and no owner/group/backupDir (deploy/index.js's validateWindowsIisTarget
    // never validates those fields for it either): its destination is a
    // machine cert store + IIS binding (store/binding/thumbprintSha1),
    // carried through unchanged instead of run through the path-fallback
    // logic below, which would either wrongly require a certPath or wrongly
    // apply a job-level keyPath/chainPath meant for a filesystem target.
    if (resolvedType === "windows-iis") {
      return {
        type: "windows-iis",
        reference: typeof item?.reference === "string" && item.reference.length > 0 ? item.reference : null,
        certPath: null,
        keyPath: null,
        chainPath: null,
        reloadService: null,
        certMode: null,
        keyMode: null,
        chainMode: null,
        owner: null,
        group: null,
        backupDir: null,
        backupRetentionCount: null,
        store: item?.store ?? null,
        binding: item?.binding ?? null,
        thumbprintSha1: item?.thumbprintSha1 ?? null,
      };
    }
    const certPath = isAbsolutePathLike(item?.certPath)
      ? item.certPath
      : fallbackCertPath;
    const keyPath = isAbsolutePathLike(item?.keyPath)
      ? item.keyPath
      : jobKeyPath;
    const chainPath = isAbsolutePathLike(item?.chainPath)
      ? item.chainPath
      : jobChainPath;
    return {
      type: resolvedType,
      reference:
        typeof item?.reference === "string" && item.reference.length > 0
          ? item.reference
          : certPath,
      certPath,
      keyPath,
      chainPath,
      reloadService:
        typeof item?.reloadService === "string" && item.reloadService.length > 0
          ? item.reloadService
          : typeof job.reloadService === "string" && job.reloadService.length > 0
            ? job.reloadService
            : null,
      certMode: item?.certMode ?? null,
      keyMode: item?.keyMode ?? null,
      chainMode: item?.chainMode ?? null,
      owner: item?.owner ?? null,
      group: item?.group ?? null,
      backupDir: isAbsolutePathLike(item?.backupDir) ? item.backupDir : null,
      backupRetentionCount:
        Number.isInteger(item?.backupRetentionCount) ? item.backupRetentionCount : null,
    };
  }

  if (Array.isArray(job?.deploymentTargets) && job.deploymentTargets.length > 0) {
    const targets = [];
    for (let i = 0; i < job.deploymentTargets.length; i += 1) {
      const item = job.deploymentTargets[i];
      if (!item || typeof item !== "object" || Array.isArray(item)) {

        return { error: `job.deploymentTargets[${i}] must be an object` };
      }
      // windows-iis carries no filesystem certPath at all (its destination
      // is store/binding); pickTargetFields' windows-iis branch below
      // ignores the fallbackCertPath argument entirely, so this loop must
      // not reject the target for lacking one.
      if (item.type === "windows-iis") {
        targets.push(pickTargetFields(item, null));
        continue;
      }
      const fallbackCert = isAbsolutePathLike(item.reference) ? item.reference : null;
      const certPath = isAbsolutePathLike(item.certPath)
        ? item.certPath
        : fallbackCert;
      if (certPath === null) {
        return {
          error:
            `job.deploymentTargets[${i}] names no deploy destination ` +
            "(need absolute certPath or absolute reference)",
        };
      }
      targets.push(pickTargetFields(item, certPath));
    }
    return { targets };
  }

  if (job?.target?.type === "windows-iis") {
    return {
      targets: [
        pickTargetFields(
          {
            type: "windows-iis",
            reference: job?.target?.reference,
            store: job?.target?.store,
            binding: job?.target?.binding,
            thumbprintSha1: job?.target?.thumbprintSha1,
          },
          null,
        ),
      ],
    };
  }

  const certPath = resolveJobCertPath(job);
  if (certPath === null) {
    return {
      error:
        "job names no deploy destination: neither job.certPath, " +
        "job.deploymentTargets, nor an absolute-path target.reference is present",
    };
  }
  return {
    targets: [
      pickTargetFields(
        {
          type: job?.target?.type,
          reference: job?.target?.reference,
          certPath,
          keyPath: jobKeyPath,
          chainPath: jobChainPath,
          reloadService: job.reloadService,
        },
        certPath,
      ),
    ],
  };
}

/**
 * Opaque EAB/account ref from flattened job fields or nested renewalProfile.ca.
 * @param {object} job
 * @returns {string|null}
 */
function resolveJobEabAccountRef(job) {
  if (typeof job?.eabRef === "string" && job.eabRef.trim().length > 0) {
    return job.eabRef.trim();
  }
  if (typeof job?.accountRef === "string" && job.accountRef.trim().length > 0) {
    return job.accountRef.trim();
  }
  const ca = job?.renewalProfile?.ca;
  if (typeof ca?.eabRef === "string" && ca.eabRef.trim().length > 0) {
    return ca.eabRef.trim();
  }
  if (typeof ca?.accountRef === "string" && ca.accountRef.trim().length > 0) {
    return ca.accountRef.trim();
  }
  return null;
}

/**
 * Persists a terminal job outcome (+ evidence) to the durable outbox, then
 * attempts transmission. Transmission failures leave the entry on disk for
 * retry and never rewrite a persisted success as a failure.
 *
 * @param {object} params
 * @param {string} params.outboxDir
 * @param {object} params.client live protocol client (network)
 * @param {object} params.result reportResult payload
 * @param {object[]} [params.evidence] reportEvidence bodies, in order
 * @param {(msg: string, details?: *) => void} [params.log]
 * @returns {Promise<{ status: string, rejectionReason: string|null }>}
 */
async function persistAndTransmitOutcome({
  outboxDir,
  client,
  result,
  evidence = [],
  log = null,
}) {
  const entry = enqueueOutboxEntry(outboxDir, { result, evidence });
  try {
    await transmitOutboxEntry(entry, client);
    acknowledgeOutboxEntry(outboxDir, entry.id);
  } catch (err) {
    emitLog(
      log,
      `tokentimer-agent: failed to transmit outbox entry for job ${result.jobId}; ` +
        "persisted outcome retained for retry (execution result unchanged)",
      err,
    );
  }
  return {
    status: result.status,
    rejectionReason: result.rejectionReason ?? null,
  };
}

/**
 * Reports a trust-layer or policy rejection uniformly: policy.checked
 * evidence built from the { allowed:false, rejectionReason, detail } shape
 * (shared by signing/replay/clock/policy modules), then a "rejected"
 * result. Evidence is deep-scanned for key material before every persist.
 *
 * @param {object} params
 * @param {object} params.client
 * @param {string} params.jobId
 * @param {string} params.attemptId
 * @param {{ rejectionReason: string, detail: string }} params.verdict
 * @param {(msg: string) => void} params.log
 * @param {string} params.outboxDir
 * @returns {Promise<{ status: "rejected", rejectionReason: string }>}
 */
async function reportJobRejection({
  client,
  jobId,
  attemptId,
  claimId = null,
  nonce = null,
  verdict,
  log,
  outboxDir,
}) {
  emitLog(
    log,
    `tokentimer-agent: job ${jobId} rejected: ${verdict.rejectionReason}`,
  );
  const evidenceBody = buildPolicyRejectionEvidence({
    rejectionReason: verdict.rejectionReason,
    detail: verdict.detail,
    jobId,
    claimId,
  });
  assertEvidencePayloadSafe(evidenceBody);
  return await persistAndTransmitOutcome({
    outboxDir,
    client,
    result: {
      jobId,
      attemptId,
      claimId,
      nonce,
      status: "rejected",
      rejectionReason: verdict.rejectionReason,
    },
    evidence: [evidenceBody],
    log,
  });
}

/**
 * Wraps a protocol client so every reportEvidence call made through it for
 * this job attempt is automatically bound to claimId (evidence-claim-binding-v1).
 *
 * executeJob's action branches (renew/deploy/reload/dry-run) each receive
 * `client` as a plain parameter and pass it, unmodified, deep into their own
 * helper functions, which is where the many per-step reportStepEvidence calls
 * actually happen. Rather than threading claimId through every one of those
 * intermediate signatures, this wraps `client` once, at the single point
 * where claimId is known, so every reportStepEvidence(client, jobId, items)
 * call anywhere in the execution tree reports claim-bound evidence for free.
 *
 * Only reportEvidence is overridden; every other client method (reportResult,
 * renewLease, etc.) is passed through unchanged.
 *
 * @param {object} client protocol client from createProtocolClient
 * @param {string|null} claimId
 * @returns {object} client, or a claim-bound wrapper when claimId is set
 */
function bindEvidenceClientToClaim(client, claimId) {
  if (typeof claimId !== "string" || claimId.length === 0) return client;
  return {
    ...client,
    reportEvidence: (body) => client.reportEvidence({ ...body, claimId }),
  };
}

/**
 * Builds + safety-scans + reports one evidence body of pre-built items.
 *
 * @param {object} client
 * @param {string} jobId
 * @param {object[]} items evidence items (buildEvidenceItem inputs)
 * @param {string|null} [claimId] binds this evidence to the claim/attempt
 *   that produced it (evidence-claim-binding-v1); omitted for jobless or
 *   unclaimed (bootstrap/observe-only) evidence
 * @returns {Promise<void>}
 */
async function reportStepEvidence(client, jobId, items, claimId = null) {
  const body = buildEvidenceBody({ jobId, evidenceItems: items, claimId });
  assertEvidencePayloadSafe(body);
  await client.reportEvidence(body);
}

/**
 * Handles a single claimed job.
 *
 * ADR-0012 decision 2: "There is no observe-only carve-out from this
 * order." Verification (steps 1-14 of the one normative order) runs
 * UNCONDITIONALLY and IDENTICALLY regardless of executionEnabled; the
 * fields a report is built from are never read from the raw wire object
 * (`job`) in either branch. `executionEnabled` matters only at step 15
 * ("act"): execute the verified job, or report a policy
 * rejection/`blocked` from the verified job's own fields instead.
 *
 * This function itself reads no identifier off `job` at all (not
 * `job.jobId`, not `job.attemptId`, not `job.claimId`): it hands the RAW,
 * unverified job straight to handleSignedJob, which performs signature
 * verification FIRST and derives jobId/attemptId from the verified payload
 * only after a verdict is available (ADR-0012 decision 16 -- the fix for
 * the previously-misattributed unsafe read that lived here). The one
 * documented exception, reporting "blocked" when no signing key is pinned
 * at all, is handled inside handleSignedJob itself (see its doc comment);
 * that path never proves or disproves a signature, so it is not part of
 * the verification order this function must not short-circuit.
 *
 * A signature-verdict failure (which includes a job missing its
 * signed-dispatch fields) is terminal and SILENT in both branches: no
 * result and no evidence are submitted, because claimId/nonce would have
 * to come from the payload the verdict just declared untrustworthy. Below
 * the gate, execution-enabled mode runs the job; observe-only mode reports
 * a policy rejection (or "blocked" if policy allows but execution is not
 * configured) built from the now-verified payload's own fields.
 *
 * Never throws for per-job failures; errors are reported through the
 * protocol client and logged.
 *
 * Exported for direct unit testing.
 *
 * @param {object} params
 * @param {object} params.job claimed job payload (RAW, unverified; v1 flat
 *   signed job object or v2 { envelopeVersion: 2, payloadB64, ... }
 *   envelope -- either way, no field of it is read here)
 * @param {object} params.policyEngine from createPolicyEngine
 * @param {object} params.client from createProtocolClient
 * @param {object|null} [params.executionContext] from
 *   buildExecutionContext; null or { enabled: false } means "observe-only":
 *   verification still runs, only the post-verdict action differs
 * @param {string} params.boundAgentId this agent's own registered agentId
 *   (ADR-0012 decision 3, gate step 11)
 * @param {boolean} [params.requireSignedAgentId] effective runtime value
 *   of CERTOPS_AGENT_REQUIRE_SIGNED_AGENT_ID (default false)
 * @param {(msg: string) => void} [params.log]
 * @returns {Promise<{ status: string, rejectionReason: string|null }>}
 */
async function handleClaimedJob({
  job,
  policyEngine,
  client,
  executionContext = null,
  boundAgentId,
  requireSignedAgentId = false,
  log = null,
}) {
  const executionEnabled =
    executionContext !== null && executionContext.enabled === true;

  return handleSignedJob({
    job,
    policyEngine,
    client,
    executionContext,
    executionEnabled,
    boundAgentId,
    requireSignedAgentId,
    log,
  });
}

/**
 * jobId placeholder used ONLY for the no-pinned-key "blocked" report, and
 * only when the raw wire object carries no usable outer jobId at all (a v2
 * envelope never does -- ADR-0012 decision 1 -- and a v1 job's jobId can
 * always be missing/malformed too). A fixed, LOCAL-ONLY string, never
 * derived from wire content, so it is not attacker-influenced content:
 * agent-protocol.schema.json's resultBody.jobId requires a non-empty
 * `^[A-Za-z0-9_.:-]+$` string, so "no jobId available" cannot itself be
 * represented on the wire and needs a stand-in that obviously is one.
 */
const UNVERIFIED_JOB_ID_PLACEHOLDER = "unverified-no-pinned-key";

/**
 * Best-effort identifiers read from the RAW, UNVERIFIED job/envelope, for
 * the no-pinned-key "blocked" report ONLY (ADR-0012 decision 2's one
 * documented exception to "verify before reading"). Reading `claimed`
 * directly is safe here, and ONLY here, because no signature has proven
 * the payload false: no verdict will ever be computed while no key is
 * pinned, so these values are merely echoed back to the authority that
 * issued them, and the server's own nonce ledger (bound to
 * (jobId, workspaceId, agentRowId)) decides whether the report binds. A
 * fabricated value therefore cannot cause a false state transition; it
 * simply fails to consume and the submission is refused.
 *
 * For a v2 envelope, claimId/nonce/jobId are always absent here (those
 * fields live inside the unverified payloadB64); that is a strictly more
 * conservative outcome than v1's, not a regression.
 *
 * @param {object} claimed raw, unverified claimed job/envelope
 * @returns {{ jobId: string|null, claimId: string|null, nonce: string|null }}
 */
function rawBestEffortIdentity(claimed) {
  return {
    jobId: hasReportableJobId(claimed?.jobId) ? claimed.jobId : null,
    claimId:
      typeof claimed?.claimId === "string" && claimed.claimId.length > 0
        ? claimed.claimId
        : null,
    nonce:
      typeof claimed?.nonce === "string" && claimed.nonce.length > 0
        ? claimed.nonce
        : null,
  };
}

/**
 * Derives the identifiers every post-gate report is built from, from the
 * VERIFIED job object ONLY (ADR-0012 decision 2 trusted-identity gate /
 * decision 16's fix). NEVER call this with the raw, pre-verification job.
 *
 * @param {object} verifiedJob job returned by an "allowed" verifyJobEnvelope verdict
 * @returns {{ jobId: string|null, claimId: string|null, nonce: string|null, attemptId: string }}
 */
function verifiedJobIdentity(verifiedJob) {
  const jobId = hasReportableJobId(verifiedJob?.jobId) ? verifiedJob.jobId : null;
  const claimId =
    typeof verifiedJob?.claimId === "string" && verifiedJob.claimId.length > 0
      ? verifiedJob.claimId
      : null;
  const nonce =
    typeof verifiedJob?.nonce === "string" && verifiedJob.nonce.length > 0
      ? verifiedJob.nonce
      : null;
  // Signed dispatch assigns attemptId server-side (mirroring claimId);
  // prefer it, then claimId itself, then a local fallback so result
  // reporting stays schema-valid and idempotency-debuggable.
  const attemptId =
    typeof verifiedJob?.attemptId === "string" && verifiedJob.attemptId.length > 0
      ? verifiedJob.attemptId
      : claimId || localAttemptId(jobId || UNVERIFIED_JOB_ID_PLACEHOLDER);
  return { jobId, claimId, nonce, attemptId };
}

/**
 * Runs ADR-0012 decision 2's one normative verification order (steps
 * 1-14) against a RAW, unverified claimed job/envelope, given whatever
 * pinned signing key context is available. Shared by handleSignedJob
 * (execution-enabled) and handleObserveOnlyJob (observe-only) so neither
 * branch implements its own copy of the verify-then-derive-identity
 * boundary -- "there is no observe-only carve-out from this order"
 * (decision 2), closing the finding recorded against handleClaimedJob in
 * decision 16.
 *
 * Callers must not read ANY field from `job` themselves. Every trustworthy
 * field is on the returned `job` after a "verified" outcome.
 *
 * @param {object} params
 * @param {object} params.job raw, unverified claimed job/envelope
 * @param {{signingKeyId: string, publicKeyPem: string}|null} params.pinnedSigningKey
 * @param {string} params.boundAgentId this agent's own registered agentId
 *   (ADR-0012 decision 3, gate step 11)
 * @param {boolean} params.requireSignedAgentId effective runtime value of
 *   CERTOPS_AGENT_REQUIRE_SIGNED_AGENT_ID (never the compiled-in default)
 * @returns {
 *   { outcome: "no_pinned_key" } |
 *   { outcome: "rejected", rejectionReason: string, detail: string } |
 *   { outcome: "verified", job: object }
 * }
 */
function verifyClaimedJobEnvelope({
  job,
  pinnedSigningKey,
  boundAgentId,
  requireSignedAgentId,
}) {
  // No pinned key => integrity of ANY job cannot be established in either
  // direction. This sits ABOVE the gate (ADR-0012 decision 2): it is a
  // local agent-side precondition failure ("this agent cannot execute or
  // verify anything yet"), not a verdict about the job itself, which is
  // why the caller may still report it (using ONLY rawBestEffortIdentity,
  // never anything derived here).
  if (!pinnedSigningKey) {
    return { outcome: "no_pinned_key" };
  }

  // Signature/envelope verification, strictly first, over the job exactly
  // as received (ADR-0012 decision 1: dual-format dispatch). No field of
  // `job` is read before this returns allowed. For a v1 job this verifies
  // the canonical-JSON signature over the object itself; for a v2 envelope
  // this verifies the Ed25519 signature over payloadB64's raw decoded
  // bytes BEFORE ever parsing them as JSON, then returns the
  // decoded-and-parsed job.
  const verdict = verifyJobEnvelope({
    claimed: job,
    publicKeyPem: pinnedSigningKey.publicKeyPem,
    pinnedSigningKeyId: pinnedSigningKey.signingKeyId,
  });
  if (!verdict.allowed) {
    return {
      outcome: "rejected",
      rejectionReason: verdict.rejectionReason,
      detail: verdict.detail,
    };
  }

  // ADR-0012 decision 3, gate step 11: agentId binding, still ABOVE the
  // report boundary -- same "no result on failure" rule as the signature
  // verdict above, because a mismatch or (flag-gated) absence is exactly
  // as untrustworthy as a bad signature for the purpose of building a
  // report. checkAgentIdBinding never reads anything from `job` except
  // agentId, and only from the now-verified job object.
  const bindingVerdict = checkAgentIdBinding({
    job: verdict.job,
    boundAgentId,
    requireSignedAgentId,
  });
  if (!bindingVerdict.allowed) {
    return {
      outcome: "rejected",
      rejectionReason: bindingVerdict.rejectionReason,
      detail: bindingVerdict.detail,
    };
  }

  return { outcome: "verified", job: verdict.job };
}

/**
 * Trust chain for a claimed job, execution-enabled OR observe-only alike.
 * Order per ADR-0003 and ADR-0012 decision 2 (the one normative
 * verification order): signature verify -> trusted-identity extraction ->
 * replay check -> clock window check -> policy -> replay consume ->
 * execute. The replay nonce is consumed only after every gate passed, so a
 * rejected job does not burn its nonce, but it IS consumed before
 * execution starts, so a crash mid-execution can never allow a replay.
 *
 * TRUSTED-IDENTITY GATE (ADR-0012 decision 2 / decision 16): jobId,
 * claimId and nonce are read only AFTER verifyClaimedJobEnvelope has
 * returned a "verified" outcome, and ONLY from its returned job -- never
 * from `claimedJob` (the raw wire object) or from a caller-supplied
 * jobId/attemptId, because those would be exactly the previously-shipped
 * unsafe read this decision closes. Nothing above that gate may construct
 * a result of any kind, because in a signature-failure mode the very
 * fields a report would be built from are what an attacker controls. A
 * signature failure therefore fails locally and lets the lease expire
 * rather than submitting a rejected result; there is no unsigned claim
 * handle in the claim response to bind such a report to. Integrity-failure
 * telemetry would require a separate opaque handle, which is a protocol
 * addition and deliberately out of scope here.
 *
 * `executionEnabled` affects nothing above the gate; it only selects step
 * 15 ("act") below it: execute the verified job (via the outbox-backed
 * reporting path), or delegate to handleObserveOnlyJob for the exact same
 * post-gate reporting a legitimate observe-only agent needs (policy
 * rejection or "blocked"), using direct client calls since observe-only
 * mode has no outbox.
 *
 * @param {object} params
 * @param {object} params.job RAW, unverified claimed job payload (v1 flat
 *   signed job object or v2 envelope) -- no field of it is read here
 *   before a verdict exists
 * @param {object} params.policyEngine
 * @param {object} params.client
 * @param {object|null} params.executionContext
 * @param {boolean} params.executionEnabled
 * @param {string} params.boundAgentId this agent's own registered agentId
 *   (ADR-0012 decision 3, gate step 11)
 * @param {boolean} [params.requireSignedAgentId] effective runtime value
 *   of CERTOPS_AGENT_REQUIRE_SIGNED_AGENT_ID (default false)
 * @param {(msg: string, details?: *) => void} [params.log]
 * @returns {Promise<{ status: string, rejectionReason: string|null }>}
 */
async function handleSignedJob({
  job: claimedJob,
  policyEngine,
  client,
  executionContext,
  executionEnabled,
  boundAgentId,
  requireSignedAgentId = false,
  log,
}) {
  const pinnedSigningKey = executionEnabled
    ? executionContext.pinnedSigningKey
    : (executionContext?.pinnedSigningKey ?? null);

  const verifyResult = verifyClaimedJobEnvelope({
    job: claimedJob,
    pinnedSigningKey,
    boundAgentId,
    requireSignedAgentId,
  });

  if (verifyResult.outcome === "no_pinned_key") {
    const raw = rawBestEffortIdentity(claimedJob);
    const jobId = raw.jobId || UNVERIFIED_JOB_ID_PLACEHOLDER;
    const attemptId = raw.claimId || localAttemptId(jobId);
    const blockedResult = {
      jobId,
      attemptId,
      claimId: raw.claimId,
      nonce: raw.nonce,
      status: "blocked",
      errorMessage:
        (executionEnabled
          ? "execution is enabled but no control-plane signing key is pinned "
          : "no control-plane signing key is pinned ") +
        "yet (the register response did not carry one); unsigned or " +
        "unverifiable jobs are never executed",
    };
    if (!executionEnabled) {
      await client.reportResult(blockedResult);
      return { status: "blocked", rejectionReason: null };
    }
    const { execution, outboxDir } = executionContext;
    const resolvedOutboxDir = outboxDir || execution.outboxDir;
    if (typeof resolvedOutboxDir !== "string" || resolvedOutboxDir.length === 0) {
      throw new Error(
        "tokentimer-agent: execution outboxDir is required when execution is enabled",
      );
    }
    return persistAndTransmitOutcome({
      outboxDir: resolvedOutboxDir,
      client,
      result: blockedResult,
      log,
    });
  }

  if (verifyResult.outcome === "rejected") {
    // Deliberately no result and no evidence: see the trusted-identity
    // gate note above. Fail locally and let the lease expire. No jobId is
    // available to log here (that is the entire point -- nothing on the
    // wire object is trusted yet), so the message stays job-agnostic.
    //
    // Mismatch observability (ADR-0012 decision 3, gate step 11): an
    // agentId MISMATCH gets its own stable, distinct log line, never the
    // generic "failed signature verification" one below. That generic
    // message is actively wrong for a mismatch -- the signature verified
    // fine; the check AFTER it rejected the job for being signed for a
    // different agent, which is exactly the misdelivery-or-control-plane-
    // bug signal this gate exists to surface. checkAgentIdBinding already
    // incremented the paired agentIdBindingMetrics.mismatches counter (see
    // packages/agent/src/signing/index.js); this is the log-side half of
    // the same observability improvement, so an operator can notice a
    // recurring mismatch at scale (grep/alert on the stable message and
    // rejectionReason code below) without needing evidence or a result,
    // neither of which exists for a rejection above the trusted-identity
    // gate.
    if (verifyResult.rejectionReason === AGENT_ID_BINDING_REJECTION_REASONS.AGENT_ID_MISMATCH) {
      emitLog(
        log,
        "tokentimer-agent: agent-id binding gate rejected a claimed job for " +
          "an agentId mismatch; submitting no result and letting the lease " +
          "expire. The job's signature verified but it was signed for a " +
          "different agent than this one -- investigate if this recurs.",
        { rejectionReason: verifyResult.rejectionReason, boundAgentId },
      );
    } else {
      emitLog(
        log,
        "tokentimer-agent: claimed job failed signature verification; " +
          "submitting no result and letting the lease expire " +
          `(${verifyResult.rejectionReason})`,
      );
    }
    return {
      status: "failed",
      rejectionReason: verifyResult.rejectionReason,
    };
  }

  // TRUSTED-IDENTITY GATE PASSED. Only now are jobId, the server-assigned
  // claim id, and the single-use dispatch nonce read -- and only from the
  // VERIFIED job -- so every result built below is bound to identifiers
  // that carry a verified signature (ADR-0003 / ADR-0012 decision 16).
  const job = verifyResult.job;
  const { jobId, claimId, nonce, attemptId } = verifiedJobIdentity(job);
  if (!jobId) {
    // The signature verified, but the authenticated payload itself has no
    // usable jobId (a control-plane contract violation, not an attack --
    // decision 3 requires jobId in the shared signed payload, so this is
    // defense in depth). reportResult requires a non-empty jobId, so there
    // is nothing safe to report with; fail locally like a verdict failure.
    emitLog(
      log,
      "tokentimer-agent: verified job carries no reportable jobId; " +
        "submitting no result and letting the lease expire",
    );
    return { status: "failed", rejectionReason: "job_integrity_failed" };
  }

  if (!executionEnabled) {
    return handleObserveOnlyJob({ job, jobId, claimId, nonce, attemptId, policyEngine, client, log });
  }

  const { replayCache, clockEstimator, execution, outboxDir } = executionContext;
  const resolvedOutboxDir = outboxDir || execution.outboxDir;
  if (typeof resolvedOutboxDir !== "string" || resolvedOutboxDir.length === 0) {
    throw new Error(
      "tokentimer-agent: execution outboxDir is required when execution is enabled",
    );
  }

  const rejectionArgs = {
    client,
    jobId,
    attemptId,
    claimId,
    nonce,
    log,
    outboxDir: resolvedOutboxDir,
  };

  // 3. Replay check (no consume yet).
  const replayVerdict = replayCache.check({
    nonce: job.nonce,
    jobId,
    expiresAt: job.expiresAt,
  });
  if (!replayVerdict.allowed) {
    return reportJobRejection({ ...rejectionArgs, verdict: replayVerdict });
  }

  // 4. Clock window with drift compensation.
  const windowVerdict = checkJobTimeWindow({
    job,
    nowMs: Date.now(),
    clockOffsetMs: clockEstimator.getOffsetMs(),
    toleranceMs: execution.clockDriftToleranceMs,
  });
  if (!windowVerdict.allowed) {
    return reportJobRejection({ ...rejectionArgs, verdict: windowVerdict });
  }

  // 5. Agent-local policy (default deny; ADR-0002 local policy wins).
  const policyVerdict = policyEngine.evaluateJob(buildSignedJobPolicyDescriptor(job));
  if (!policyVerdict.allowed) {
    return reportJobRejection({ ...rejectionArgs, verdict: policyVerdict });
  }

  // 6. Consume the nonce before executing (see function doc comment).
  const consumeVerdict = replayCache.consume({
    nonce: job.nonce,
    jobId,
    expiresAt: job.expiresAt,
  });
  if (!consumeVerdict.allowed) {
    return reportJobRejection({ ...rejectionArgs, verdict: consumeVerdict });
  }

  // 5b. Refuse auto re-execution when unresolved local side-effect journal
  // exists for this jobId (crash-safety; operator reconciliation required).
  const stateDir = resolveAgentStateDir(executionContext);
  if (stateDir && hasUnresolvedJournalForJob(stateDir, jobId)) {
    const msg =
      `unresolved local side-effect journal exists for job ${jobId}; ` +
      `refusing automatic re-execution pending operator reconciliation`;
    emitLog(log, `tokentimer-agent: ${msg}`);
    return persistAndTransmitOutcome({
      outboxDir: resolvedOutboxDir,
      client,
      result: {
        jobId,
        attemptId,
        claimId,
        nonce,
        status: "orphaned_unknown_effect",
        errorMessage: boundErrorMessage(
          `${msg} (needsOperatorReconciliation=true)`,
        ),
      },
      log,
    });
  }

  // 6. B6: first lease renew after accept transitions claimed→running.
  // Mandatory fail-closed confirmation: any failure (including network)
  // aborts before execution. 409/410 abort as a reported "blocked" result.
  const leaseState = createLeaseState();
  const acceptLease = await renewJobLeaseOrAbort({
    leaseClient: client,
    jobId,
    claimId,
    log,
    leaseState,
    required: true,
  });
  if (acceptLease && acceptLease.ok === false) {
    const blocked = await persistAndTransmitOutcome({
      outboxDir: resolvedOutboxDir,
      client,
      result: {
        jobId,
        attemptId,
        claimId,
        nonce,
        status: acceptLease.abort.status,
        errorMessage: acceptLease.abort.errorMessage,
      },
      log,
    });
    return {
      ...blocked,
      retired: acceptLease.retired === true,
    };
  }

  // 7. Execute. Step evidence is buffered locally; the terminal outcome and
  // evidence are persisted to the durable outbox BEFORE any network
  // transmission so a reportResult failure cannot reclassify a real-world
  // success as "failed". Periodic lease heartbeat covers long ACME/DNS
  // stages that can approach the 15-minute lease TTL without stage-boundary
  // renews.
  emitInfo(
    `job ${jobId}: passed signature/replay/clock/policy verification, starting execution ` +
      `(action=${job?.action || "unknown"}, mode=${resolveJobMode(job)})`,
  );
  const evidenceBuffer = createEvidenceBuffer();
  const leaseOpts = {
    leaseClient: client,
    jobId,
    claimId,
    log,
    leaseState,
  };
  const leaseHeartbeat = startPeriodicLeaseRenewal(leaseOpts);
  let outcome;
  try {
    outcome = await executeJob({
      job,
      jobId,
      attemptId,
      claimId,
      policyEngine,
      client: evidenceBuffer,
      leaseClient: client,
      leaseState,
      executionContext,
      log,
    });
    const heartbeatAbort = leaseHeartbeat.getAbort();
    if (
      heartbeatAbort &&
      outcome &&
      (outcome.status === "succeeded" || outcome.status === "dry_run_complete")
    ) {
      outcome = heartbeatAbort;
    }
  } catch (err) {
    emitLog(log, `tokentimer-agent: job ${jobId} execution error: ${err.message}`);
    outcome = {
      status: "failed",
      errorMessage: boundErrorMessage(`job execution failed: ${err.message}`),
    };
  } finally {
    stopPeriodicLeaseRenewal(leaseHeartbeat);
  }
  emitInfo(`job ${jobId}: execution finished with status ${outcome?.status || "unknown"}`);

  const evidenceBodies = evidenceBuffer.takeEvidence();
  for (const body of evidenceBodies) {
    assertEvidencePayloadSafe(body);
  }

  const transmitted = await persistAndTransmitOutcome({
    outboxDir: resolvedOutboxDir,
    client,
    result: {
      jobId,
      attemptId,
      claimId,
      nonce,
      status: outcome.status,
      rejectionReason: outcome.rejectionReason ?? null,
      keyRotated: outcome.keyRotated ?? null,
      errorMessage: outcome.errorMessage ?? null,
      clockOffsetMs: clockEstimator.getOffsetMs(),
    },
    evidence: evidenceBodies,
    log,
  });

  if (stateDir && outcome && typeof outcome.status === "string") {
    try {
      clearJournalOnTerminal({
        stateDir,
        jobId,
        attemptId,
        status: outcome.status,
      });
    } catch (err) {
      emitLog(
        log,
        `tokentimer-agent: could not clear job journal for ${jobId}: ${err.message}`,
      );
    }
  }

  return {
    ...transmitted,
    retired: outcome.retired === true,
  };
}

/**
 * Post-gate action for observe-only mode (executionContext null or
 * `enabled: false`): report a policy rejection, or "blocked" when policy
 * allows the job but execution is not configured on this agent. Always
 * called AFTER handleSignedJob's trusted-identity gate has passed, so
 * `jobId`/`claimId`/`nonce` here are already verified-payload values, not
 * raw wire content (ADR-0012 decision 2's closure of the observe-only
 * carve-out finding against decision 16).
 *
 * Mirrors byte-for-byte what the previous observe-only branch reported for
 * a legitimately-validated job; only the verification-gating around it
 * changed (this function is never reached on a signature-verdict failure).
 *
 * @param {object} params
 * @param {object} params.job VERIFIED job payload
 * @param {string} params.jobId verified jobId
 * @param {string|null} params.claimId verified claimId
 * @param {string|null} params.nonce verified nonce
 * @param {string} params.attemptId
 * @param {object} params.policyEngine
 * @param {object} params.client
 * @param {(msg: string, details?: *) => void} [params.log]
 * @returns {Promise<{ status: string, rejectionReason: string|null }>}
 */
async function handleObserveOnlyJob({
  job,
  jobId,
  claimId,
  nonce,
  attemptId,
  policyEngine,
  client,
  log,
}) {
  try {
    const policyDescriptor = buildSignedJobPolicyDescriptor(job);
    const verdict = policyEngine.evaluateJob(policyDescriptor);
    if (!verdict.allowed) {
      emitLog(log, `job ${jobId} rejected by agent-local policy`, {
        rejectionReason: verdict.rejectionReason,
      });
      const evidenceBody = buildPolicyRejectionEvidence({
        rejectionReason: verdict.rejectionReason,
        detail: verdict.detail,
        jobId,
        claimId,
      });
      assertEvidencePayloadSafe(evidenceBody);
      await client.reportEvidence(evidenceBody);
      await client.reportResult({
        jobId,
        attemptId,
        claimId,
        nonce,
        status: "rejected",
        rejectionReason: verdict.rejectionReason,
      });
      return { status: "rejected", rejectionReason: verdict.rejectionReason };
    }

    // Execution is not configured on this agent: report "blocked" rather
    // than silently dropping so the control plane sees an explicit
    // terminal state.
    await client.reportResult({
      jobId,
      attemptId,
      claimId,
      nonce,
      status: "blocked",
      errorMessage: "agent execution is not enabled on this agent",
    });
    return { status: "blocked", rejectionReason: null };
  } catch (err) {
    emitLog(log, `failed while handling claimed job ${jobId}`, err);
    return { status: "failed", rejectionReason: null };
  }
}

/**
 * Executes a fully verified + policy-approved job. Never reports the
 * terminal result itself (handleSignedJob does); it DOES report per-step
 * evidence. Returns the fields for reportResult.
 *
 * Job mode (COORDINATION-B4) is AUTHORITATIVE:
 *   - mode "dry_run" → preflight/plan only, status "dry_run_complete"
 *   - mode "real" (or absent) → real side effects, status "succeeded" on ok
 *
 * Local `execution.dryRun` is a safety refusal knob only: when true, a
 * mode:"real" job is blocked with an explicit reason (never silently
 * downgraded to a plan-only "succeeded" report). It cannot turn a real
 * job into a no-op while still reporting success.
 *
 * Exported for direct unit testing.
 *
 * @param {object} params
 * @param {object} params.job verified job payload
 * @param {string} params.jobId
 * @param {string|null} [params.claimId]
 * @param {object} params.policyEngine
 * @param {object} params.client evidence-reporting client
 * @param {object} [params.leaseClient] protocol client for B6 lease renew
 * @param {object} params.executionContext from buildExecutionContext
 * @param {(msg: string) => void} [params.log]
 * @returns {Promise<{ status: string, rejectionReason?: string|null, keyRotated?: boolean|null, errorMessage?: string|null }>}
 */
async function executeJob({
  job,
  jobId,
  attemptId = null,
  claimId = null,
  policyEngine,
  client,
  leaseClient = null,
  leaseState = null,
  executionContext,
  log = console.error,
}) {
  const { execution } = executionContext;
  const action = job.action;
  const observedAt = new Date().toISOString();
  const jobMode = resolveJobMode(job);
  const leaseOpts = { leaseClient, jobId, claimId, log, leaseState };
  const stateDir = resolveAgentStateDir(executionContext);
  const journalCtx =
    stateDir && typeof attemptId === "string" && attemptId.length > 0
      ? { stateDir, jobId, attemptId, claimId }
      : null;

  function markMutation(stage) {
    if (!journalCtx) return;
    markSideEffectReached({ ...journalCtx, stage });
  }

  // Bind every reportEvidence call made through `client` for the rest of this
  // job attempt to claimId, so the evidence-claim-binding-v1 capability
  // declared at registration is actually honored end to end (see
  // bindEvidenceClientToClaim above for why this is done once, here, rather
  // than threading claimId through every downstream execute*Job helper).
  const claimBoundClient = bindEvidenceClientToClaim(client, claimId);

  if (action === "noop") {
    await reportStepEvidence(claimBoundClient, jobId, [
      buildEvidenceItem({
        eventType: "validation.passed",
        observedAt,
        summary: `Noop job ${jobId} executed: signature, replay, clock window, and policy gates all passed; no side effects requested.`,
        metadata: [{ name: "action", value: "noop" }],
      }),
    ]);
    // Dry-run noop still reports dry_run_complete (no real effects).
    if (jobMode === "dry_run") {
      return { status: "dry_run_complete", keyRotated: null };
    }
    return { status: "succeeded", keyRotated: null };
  }

  if (action === "revoke") {
    // Revocation execution is out of scope for this agent build.
    return {
      status: "blocked",
      errorMessage:
        "revoke jobs are not executable by this agent version (revocation " +
        "execution is not supported yet)",
    };
  }

  if (action === "deploy" && typeof job.certificatePem !== "string") {
    // Base-payload deviation: deploy needs certificate bytes from the control
    // plane and the base payload has no such field (awaiting the deploy
    // job-type contract).
    return {
      status: "blocked",
      errorMessage:
        "deploy job carries no certificatePem field; the job payload " +
        "does not define one yet (awaiting the deploy job contract), so " +
        "there is nothing to deploy",
    };
  }

  if (action !== "renew" && action !== "deploy" && action !== "reload") {
    return {
      status: "blocked",
      errorMessage: `unsupported job action "${String(action)}"`,
    };
  }

  // B4: signed job.mode wins. Local execution.dryRun may only refuse a
  // real job outright — never silently swap in the dry-run code path.
  if (jobMode === "dry_run") {
    return executeDryRunPlan({
      job,
      jobId,
      action,
      client: claimBoundClient,
      policyEngine,
      observedAt,
    });
  }

  if (execution.dryRun === true) {
    return {
      status: "blocked",
      errorMessage:
        "refusing mode:\"real\" job because local execution.dryRun is true; " +
        "set execution.dryRun to false to perform real side effects, or ask " +
        "the control plane for a mode:\"dry_run\" job",
    };
  }

  if (action === "renew") {
    // ADR-0012 decisions 9/13: a renew job whose custody is
    // os-store-managed against a windows-iis target takes the CNG-native
    // path (key generated inside the CNG store, IIS/http.sys rebind,
    // retention-ledger bookkeeping) instead of the file-based
    // key/CSR/deploy path every other keyMode uses. keyMode gating here is
    // defense in depth: apps/api/services/certops/jobs.js's
    // AGENT_DEPLOYABLE_KEY_MODES is the control-plane's own gate on
    // dispatching such a job at all.
    if (job.keyMode === "os-store-managed" && job?.target?.type === "windows-iis") {
      return executeWindowsIisRenewJob({
        job,
        jobId,
        policyEngine,
        client: claimBoundClient,
        executionContext,
        log,
        leaseOpts,
        onBeforeMutation: markMutation,
      });
    }
    return executeRenewJob({
      job,
      jobId,
      policyEngine,
      client: claimBoundClient,
      executionContext,
      log,
      leaseOpts,
      onBeforeMutation: markMutation,
    });
  }
  if (action === "deploy") {
    return executeDeployJob({
      job,
      jobId,
      policyEngine,
      client: claimBoundClient,
      executionContext,
      log,
      leaseOpts,
      onBeforeMutation: markMutation,
    });
  }
  return executeReloadJob({
    job,
    jobId,
    policyEngine,
    client: claimBoundClient,
    log,
    leaseOpts,
    onBeforeMutation: markMutation,
  });
}

/**
 * Dry-run preflight/plan (job.mode === "dry_run"): validate the steps that
 * WOULD run (CA endpoint, command ref, deploy path, etc.) without any
 * mutation (no key generation, ACME order, DNS mutation, deploy write, or
 * reload). Returns dry_run_complete — never succeeded (COORDINATION-B4).
 *
 * @param {object} params
 * @returns {Promise<{ status: "dry_run_complete"|"rejected"|"failed"|"blocked", keyRotated: null, errorMessage: null|string, rejectionReason?: string }>}
 */
async function executeDryRunPlan({
  job,
  jobId,
  action,
  client,
  policyEngine,
  observedAt,
}) {
  const plannedSteps = {
    renew: [
      "keys: reuse or generate the certificate key under the configured keysDir",
      "csr: build a CSR with CN from target.reference",
      "acme: run the allowlisted ACME command against job.caEndpoint",
      "deploy: atomically install the renewed certificate at the resolved certPath",
      "reload: validate-then-reload the target service when the job requests it",
      "verify: fingerprint the deployed certificate",
    ],
    deploy: [
      "deploy: atomically install the job-supplied certificate at the resolved certPath",
      "reload: validate-then-reload the target service when the job requests it",
      "verify: fingerprint the deployed certificate",
    ],
    reload: [
      "reload: validate-then-reload the target service via allowlisted command profiles",
    ],
  }[action];

  const preflightIssues = [];

  if (action === "renew" || action === "deploy") {
    if (job?.target?.type === "windows-iis") {
      if (
        !isNonEmptyStringValue(job?.target?.store) ||
        job?.target?.binding === null ||
        typeof job?.target?.binding !== "object" ||
        !isNonEmptyStringValue(job?.target?.binding?.site) ||
        !Number.isInteger(job?.target?.binding?.port)
      ) {
        preflightIssues.push(
          "windows-iis target requires target.store and target.binding.{site,port}",
        );
      }
    } else {
      const certPath = resolveJobCertPath(job);
      if (certPath === null) {
        preflightIssues.push(
          "no deploy destination (neither job.certPath nor an absolute-path target.reference)",
        );
      } else {
        const pathVerdict = policyEngine.checkPath(certPath);
        if (!pathVerdict.allowed) {
          return {
            status: "rejected",
            rejectionReason: pathVerdict.rejectionReason,
            keyRotated: null,
            errorMessage: boundErrorMessage(pathVerdict.detail),
          };
        }
      }
    }
  }

  if (action === "renew") {
    if (typeof job?.target?.reference !== "string" || job.target.reference.length === 0) {
      preflightIssues.push("renew job has no target.reference for the certificate CN");
    }
    if (typeof job.commandRef !== "string" || job.commandRef.length === 0) {
      preflightIssues.push("renew job carries no commandRef");
    } else {
      const commandVerdict = policyEngine.checkCommandRef(job.commandRef);
      if (!commandVerdict.allowed) {
        return {
          status: "rejected",
          rejectionReason: commandVerdict.rejectionReason,
          keyRotated: null,
          errorMessage: boundErrorMessage(commandVerdict.detail),
        };
      }
    }
    if (typeof job.caEndpoint !== "string" || job.caEndpoint.length === 0) {
      preflightIssues.push("renew job carries no caEndpoint");
    } else {
      const caVerdict = policyEngine.checkCaEndpoint(job.caEndpoint);
      if (!caVerdict.allowed) {
        return {
          status: "rejected",
          rejectionReason: caVerdict.rejectionReason,
          keyRotated: null,
          errorMessage: boundErrorMessage(caVerdict.detail),
        };
      }
    }
    if (typeof job.dnsProvider === "string" && job.dnsProvider.length > 0) {
      const dnsVerdict = policyEngine.checkDnsProvider(job.dnsProvider);
      if (!dnsVerdict.allowed) {
        return {
          status: "rejected",
          rejectionReason: dnsVerdict.rejectionReason,
          keyRotated: null,
          errorMessage: boundErrorMessage(dnsVerdict.detail),
        };
      }
    }
    if (typeof job.dnsZone === "string" && job.dnsZone.length > 0) {
      const zoneVerdict = policyEngine.checkDnsZone(job.dnsZone);
      if (!zoneVerdict.allowed) {
        return {
          status: "rejected",
          rejectionReason: zoneVerdict.rejectionReason,
          keyRotated: null,
          errorMessage: boundErrorMessage(zoneVerdict.detail),
        };
      }
    }
  }

  if (action === "reload" || (action !== "reload" && typeof job.reloadService === "string" && job.reloadService.length > 0)) {
    const refs = job.reloadCommandRefs;
    if (refs && typeof refs === "object") {
      for (const refName of ["validate", "reload"]) {
        if (typeof refs[refName] === "string" && refs[refName].length > 0) {
          const verdict = policyEngine.checkCommandRef(refs[refName]);
          if (!verdict.allowed) {
            return {
              status: "rejected",
              rejectionReason: verdict.rejectionReason,
              keyRotated: null,
              errorMessage: boundErrorMessage(verdict.detail),
            };
          }
        }
      }
    } else if (action === "reload") {
      preflightIssues.push("reload job carries no reloadCommandRefs");
    }
  }

  if (preflightIssues.length > 0) {
    return {
      status: "failed",
      keyRotated: null,
      errorMessage: boundErrorMessage(
        `dry-run preflight failed: ${preflightIssues.join("; ")}`,
      ),
    };
  }

  const items = plannedSteps.map((description, index) =>
    buildEvidenceItem({
      eventType: "policy.checked",
      observedAt,
      summary: `Dry run plan for ${action} job ${jobId}, step ${index + 1}/${plannedSteps.length}: ${description}. No side effects were performed.`,
      metadata: [
        { name: "dryRun", value: true },
        { name: "jobMode", value: "dry_run" },
        { name: "action", value: action },
        { name: "planStep", value: index + 1 },
      ],
    }),
  );
  await reportStepEvidence(client, jobId, items);
  return { status: "dry_run_complete", keyRotated: null, errorMessage: null };
}

/**
 * discardStagedKey is best-effort by design (see its docblock: throwing on the
 * failure paths that call it is what orphaned keys in the first place). That
 * makes an unremovable staging file silent, which is the opposite problem. This
 * wrapper is the single place that turns a residual private key into an operator
 * -visible warning, naming the path so it can be removed by hand. It never
 * throws, so it is safe in catch blocks and after a failed tail.
 *
 * @param {object} input
 * @returns {void}
 */
function discardStagedKeyReportingResidue({ keyPath, stagedKeyPath, log, jobId }) {
  const outcome = discardStagedKey({ keyPath, stagedKeyPath });
  if (outcome && outcome.residualPath && log && typeof log.warn === "function") {
    log.warn(
      `job ${jobId}: staged private key could not be removed and remains on disk ` +
        `at ${outcome.residualPath}; delete it manually (${outcome.error})`,
    );
  }
}

/**
 * Full renew chain: keys -> csr -> acme -> deploy -> reload (optional) ->
 * verify. Honors flattened renewal-profile execution fields when present
 * (sans, keyAlgorithm/keySize, preferredChain, eabRef/accountRef,
 * deploymentTargets); falls back to single-CN / default key / single
 * certPath for base payloads (see module docblock).
 *
 * @param {object} params
 * @returns {Promise<object>} reportResult fields
 */
async function executeRenewJob({
  job,
  jobId,
  policyEngine,
  client,
  executionContext,
  log,
  leaseOpts = null,
  onBeforeMutation = null,
}) {
  const { execution } = executionContext;
  const commonName = job?.target?.reference;
  if (typeof commonName !== "string" || commonName.length === 0) {
    return {
      status: "failed",
      errorMessage: "renew job has no target.reference to use as the certificate CN",
    };
  }

  // Structural gate on certificateId BEFORE it is ever interpolated into a
  // keysDir filesystem path (see isValidCertificateId doc comment): the
  // Ed25519 signature proves provenance of the bytes, not that the content
  // matches job-payload.schema.json's certificateId pattern/length.
  if (!isValidCertificateId(job.certificateId)) {
    return {
      status: "failed",
      errorMessage: boundErrorMessage(
        `renew job has a missing or malformed certificateId (expected 1-128 chars ` +
          `matching ^[A-Za-z0-9_.:-]+$, got ${JSON.stringify(job.certificateId)})`,
      ),
    };
  }

  const sansResolved = resolveJobSans(job);
  if (sansResolved && sansResolved.error) {
    return { status: "failed", errorMessage: sansResolved.error };
  }
  const domains =
    sansResolved && Array.isArray(sansResolved.sans)
      ? sansResolved.sans
      : [commonName];
  // CN is the first SAN by convention; prefer target.reference when it is
  // already in the approved SAN list so inventory CN and SAN stay aligned.
  const csrCommonName = domains.includes(commonName) ? commonName : domains[0];

  const deployTargetsResolved = resolveJobDeployTargets(job);
  if (deployTargetsResolved.error) {
    return { status: "failed", errorMessage: deployTargetsResolved.error };
  }
  const deployTargets = deployTargetsResolved.targets;

  // Fail-fast policy preflight, BEFORE any mutation (keygen/ACME order/
  // lease renew): mirrors executeDryRunPlan's dnsProvider/dnsZone/path
  // checks so a policy-disallowed job never burns an ACME rate-limit slot
  // or generates a key it can never deploy. buildSignedJobPolicyDescriptor
  // already gated job.dnsZone/dnsProvider/target.reference once at claim
  // time (handleSignedJob step 4) against the SAME policy engine; this is
  // deliberate defense-in-depth re-verification at the point closest to
  // the actual mutating steps, and also extends coverage to every
  // deployTargets[] destination (claim-time only sees target.reference).
  for (const deployTarget of deployTargets) {
    if (typeof deployTarget.certPath === "string" && deployTarget.certPath.length > 0) {
      const pathVerdict = policyEngine.checkPath(deployTarget.certPath);
      if (!pathVerdict.allowed) {
        return {
          status: "rejected",
          rejectionReason: pathVerdict.rejectionReason,
          errorMessage: boundErrorMessage(pathVerdict.detail),
        };
      }
    }
  }
  if (typeof job.dnsProvider === "string" && job.dnsProvider.length > 0) {
    const dnsVerdict = policyEngine.checkDnsProvider(job.dnsProvider);
    if (!dnsVerdict.allowed) {
      return {
        status: "rejected",
        rejectionReason: dnsVerdict.rejectionReason,
        errorMessage: boundErrorMessage(dnsVerdict.detail),
      };
    }
  }
  if (typeof job.dnsZone === "string" && job.dnsZone.length > 0) {
    const zoneVerdict = policyEngine.checkDnsZone(job.dnsZone);
    if (!zoneVerdict.allowed) {
      return {
        status: "rejected",
        rejectionReason: zoneVerdict.rejectionReason,
        errorMessage: boundErrorMessage(zoneVerdict.detail),
      };
    }
  }

  if (typeof job.commandRef !== "string" || job.commandRef.length === 0) {
    return {
      status: "failed",
      errorMessage: "renew job carries no commandRef naming an allowlisted ACME command",
    };
  }
  const commandVerdict = policyEngine.checkCommandRef(job.commandRef);
  if (!commandVerdict.allowed) {
    return {
      status: "rejected",
      rejectionReason: commandVerdict.rejectionReason,
      errorMessage: boundErrorMessage(commandVerdict.detail),
    };
  }

  if (typeof job.caEndpoint !== "string" || job.caEndpoint.length === 0) {
    return {
      status: "failed",
      errorMessage: "renew job carries no caEndpoint",
    };
  }

  const keyAlgMapped = mapJobKeyAlgorithm(job);
  if (keyAlgMapped && keyAlgMapped.error) {
    return { status: "failed", errorMessage: keyAlgMapped.error };
  }

  let eabCredentials = null;
  const eabAccountRef = resolveJobEabAccountRef(job);
  if (eabAccountRef !== null) {
    try {
      eabCredentials = resolveAcmeAccountCredentials(eabAccountRef, {
        acmeAccounts: executionContext.acmeAccounts,
      });
    } catch (err) {
      return {
        status: "failed",
        errorMessage: boundErrorMessage(
          `renew job requires ACME account/EAB credentials for ref ${JSON.stringify(eabAccountRef)} ` +
            `but they are not available locally: ${err.message}`,
        ),
      };
    }
  }

  const acmeKind = SUPPORTED_ACME_KINDS.includes(job.acmeKind) ? job.acmeKind : "certbot";

  // Step 1: keys. Reuse-if-exists unless job.keyRotation is truthy
  // (forward-compatible field, absent from the base schema). Rotation
  // stages the new key alongside the live path and never overwrites it
  // until deployCertificateAndKey promotes the matched pair.
  {
    const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
    if (leaseGate && leaseGate.ok === false) return leaseGate.abort;
  }
  if (typeof onBeforeMutation === "function") onBeforeMutation("keygen");
  emitInfo(`job ${jobId}: generating/reusing private key for CN ${csrCommonName}`);
  fs.mkdirSync(execution.keysDir, { recursive: true });
  const keyPath = path.join(execution.keysDir, `${job.certificateId}.key.pem`);
  const forceRotation = job.keyRotation === true;
  const keyExisted = fs.existsSync(keyPath);
  const keyRotated = forceRotation || !keyExisted;
  let stagedKeyPath = keyPath;
  if (keyRotated) {
    const generateOpts = {
      keyPath,
      overwrite: forceRotation,
    };
    if (keyAlgMapped && keyAlgMapped.algorithm) {
      generateOpts.algorithm = keyAlgMapped.algorithm;
    }
    const generated = generateKeyPairToFile(generateOpts);
    stagedKeyPath = generated.stagedKeyPath;
  }

  // Step 2: CSR, written to a job-scoped temp path under keysDir (0600).
  // Always signed with the key that will be deployed (staged on rotation).
  const { csrPem } = generateCsr({
    keyPath: stagedKeyPath,
    subject: { commonName: csrCommonName },
    altNames: domains,
  });
  const csrPath = path.join(execution.keysDir, `${jobId}.csr.pem`);
  fs.writeFileSync(csrPath, csrPem, { mode: 0o600 });

  // The ACME client writes to job-scoped staging paths; the deploy module
  // then owns the atomic install (with backup/rollback) to certPath. The
  // chain and fullchain artifacts are siblings of the leaf, named by the
  // same helper the adapter uses to build its argv.
  const stagedCertPath = path.join(execution.keysDir, `${jobId}.cert.pem`);
  const stagedCertPaths = resolveCertificateOutputPaths(stagedCertPath);

  let certificatePem;
  try {
    // Step 3: ACME renewal via the policy-resolved command profile.
    {
      const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
      if (leaseGate && leaseGate.ok === false) {
        discardStagedKeyReportingResidue({ keyPath, stagedKeyPath, log, jobId });
        return leaseGate.abort;
      }
    }
    if (typeof onBeforeMutation === "function") onBeforeMutation("acme");
    emitInfo(
      `job ${jobId}: starting ACME order (${acmeKind}) against ${job.caEndpoint} for ${domains.join(", ")}`,
    );
    const adapter = createAcmeAdapter({
      kind: acmeKind,
      commandProfile: { argv: commandVerdict.argv },
      execFileImpl: executionContext.acmeExecFileImpl,
    });
    // ACME account/state nests under the agent config/state dir. keysDir
    // defaults to <configDir>/keys, so its parent is that state dir.
    const stateDir = path.dirname(execution.keysDir);
    const renewalOpts = {
      caEndpoint: job.caEndpoint,
      domains,
      csrPath,
      outCertPath: stagedCertPath,
      stateDir,
      checkCaEndpoint: (endpoint) => policyEngine.checkCaEndpoint(endpoint),
    };
    if (typeof job.preferredChain === "string" && job.preferredChain.length > 0) {
      renewalOpts.preferredChain = job.preferredChain;
    } else if (
      typeof job?.renewalProfile?.preferredChain === "string" &&
      job.renewalProfile.preferredChain.length > 0
    ) {
      renewalOpts.preferredChain = job.renewalProfile.preferredChain;
    }
    if (eabCredentials) {
      renewalOpts.eabKid = eabCredentials.eabKid;
      renewalOpts.eabHmacKey = eabCredentials.eabHmacKey;
    }
    const renewal = await adapter.runRenewal(renewalOpts);
    if (renewal.allowed === false) {
      discardStagedKeyReportingResidue({ keyPath, stagedKeyPath, log, jobId });
      return {
        status: "rejected",
        rejectionReason: renewal.rejectionReason,
        errorMessage: boundErrorMessage(renewal.detail),
      };
    }
    if (renewal.renewed !== true) {
      discardStagedKeyReportingResidue({ keyPath, stagedKeyPath, log, jobId });
      await reportStepEvidence(client, jobId, [
        buildEvidenceItem({
          eventType: "validation.failed",
          observedAt: new Date().toISOString(),
          summary: `ACME renewal step failed for job ${jobId} (exit code ${renewal.exitCode}).`,
          metadata: [
            { name: "step", value: "acme" },
            { name: "exitCode", value: renewal.exitCode },
            { name: "stderrExcerpt", value: boundMetadataExcerpt(renewal.stderrExcerpt) },
            { name: "stdoutExcerpt", value: boundMetadataExcerpt(renewal.stdoutExcerpt) },
          ],
        }),
      ]);
      return {
        status: "failed",
        keyRotated,
        errorMessage: boundErrorMessage(
          `acme step failed with exit code ${renewal.exitCode}: ${acmeFailureDetail(renewal)}`,
        ),
      };
    }
    await reportStepEvidence(client, jobId, [
      buildEvidenceItem({
        eventType: "validation.passed",
        observedAt: new Date().toISOString(),
        summary: `ACME renewal step succeeded for job ${jobId}.`,
        metadata: [{ name: "step", value: "acme" }, { name: "exitCode", value: renewal.exitCode }],
      }),
    ]);
    emitInfo(`job ${jobId}: ACME order succeeded`);

    // Steps 4-6 are shared with the deploy action (possibly multi-target).
    const staged = readStagedCertificateChain(stagedCertPaths);
    if (staged.error) {
      discardStagedKeyReportingResidue({ keyPath, stagedKeyPath, log, jobId });
      return {
        status: "failed",
        keyRotated,
        errorMessage: boundErrorMessage(
          `acme step reported success but produced no certificate file: ${staged.error}`,
        ),
      };
    }
    certificatePem = staged.pem;
  } catch (err) {
    // Every *returned* failure above discards the staged key explicitly, but a
    // thrown one skipped it: the finally below cleans the CSR and the staged
    // chain, never the key. An exception here (adapter crash, unreadable
    // staging dir, lease transport error) therefore left a 0600 private key in
    // keysDir forever, since nothing else knows the path. The key is worthless
    // without the certificate that was never issued, but a private key that
    // outlives its job is residue on the one boundary this agent exists to
    // keep clean, so it goes before the error propagates.
    discardStagedKeyReportingResidue({ keyPath, stagedKeyPath, log, jobId });
    throw err;
  } finally {
    // The CSR is public material, but it is job-scoped scratch: remove it.
    fs.rmSync(csrPath, { force: true });
    // Every route out of the block above, success or failure, lands here, so
    // a partially written chain never survives a failed renewal.
    for (const stagedArtifact of Object.values(stagedCertPaths)) {
      fs.rmSync(stagedArtifact, { force: true });
    }
  }

  let tail;
  try {
    tail = await runDeployReloadVerifyForTargets({
      job,
      jobId,
      policyEngine,
      client,
      certificatePem,
      deployTargets,
      keyPath,
      stagedKeyPath,
      keyRotated,
      requestedSans: domains,
      log,
      leaseOpts,
      onBeforeMutation,
    });
  } catch (err) {
    // Same reasoning as above, for the deploy tail. A multi-target run retains
    // the staging file until the last destination, so a throw part-way through
    // is precisely the case that leaves it behind. Discard is a no-op once the
    // key has been promoted, because promotion consumes the staging file.
    discardStagedKeyReportingResidue({ keyPath, stagedKeyPath, log, jobId });
    throw err;
  }
  if (tail.status !== "succeeded") {
    discardStagedKeyReportingResidue({ keyPath, stagedKeyPath, log, jobId });
  }
  return { ...tail, keyRotated };
}

/**
 * Steps 4-6 of the CNG-native windows-iis renewal path: complete CNG
 * enrollment (`certreq -accept`), rebind IIS/http.sys and verify with a
 * real TLS handshake, then persist a retention-ledger row for the
 * certificate the binding previously pointed at, all under the per-store
 * mutex (decision 13: "the per-target mutex covers the store as well as
 * the binding, since two jobs racing on the same machine store is as
 * damaging as two racing on one binding").
 *
 * Rollback: deployIisBinding already restores outgoingThumbprint on its
 * own BIND_FAILED/VERIFY_FAILED paths (see ../windows-iis's own doc
 * comment); this function does not attempt a second, redundant rollback
 * on top of that, and never creates a ledger row for a deploy that did
 * not report ok:true (a ledger row records a cutover that happened, not
 * an attempt).
 *
 * @param {object} params
 * @param {object} params.target the single resolved windows-iis deploy target.
 * @param {string} params.stateDir agent state dir (mutex lock file location).
 * @param {string} params.cngWorkDir CNG accept scratch dir.
 * @param {string|null} [params.containerName] the CNG key container
 *   generateCsrViaCng created for this job, if known. Used ONLY to free an
 *   orphaned container on a bare `certreq -accept` failure (see the
 *   accept-failure branch below); never touched on any success path or on
 *   a later addstore/repairstore/delstore-stage failure, since by then the
 *   container is legitimately bound to an enrolled certificate.
 * @returns {Promise<{status: string, keyRotated: null, errorMessage?: string, rejectionReason?: string}>}
 */
async function runWindowsIisDeployTail({
  jobId,
  client,
  certificatePem,
  target,
  stateDir,
  cngWorkDir,
  log,
  containerName = null,
  leaseOpts = null,
  onBeforeMutation = null,
  windowsExecFileImpl,
  windowsConnectImpl,
}) {
  {
    const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
    if (leaseGate && leaseGate.ok === false) return leaseGate.abort;
  }
  if (typeof onBeforeMutation === "function") onBeforeMutation("deploy");

  let storeLock;
  try {
    storeLock = acquireStoreLock(stateDir, target.store);
  } catch (err) {
    return {
      status: "failed",
      keyRotated: null,
      errorMessage: boundErrorMessage(`could not acquire windows-iis store lock: ${err.message}`),
    };
  }

  try {
    emitInfo(`job ${jobId}: completing CNG enrollment (certreq -accept) into store ${target.store}`);
    const acceptResult = await acceptCertificateViaCng({
      certificatePem,
      workDir: cngWorkDir,
      store: target.store,
      ...(windowsExecFileImpl ? { execFileImpl: windowsExecFileImpl } : {}),
    });
    if (!acceptResult.ok) {
      // Only a bare-accept failure (no `stage`) leaves the CNG key
      // container genuinely orphaned: `certreq -accept` itself never ran,
      // or ran and failed before binding any certificate to the key, so
      // there is no enrolled certificate anywhere referencing this
      // container yet. A failure at the addstore/repairstore/delstore
      // mirroring stage is different -- accept already SUCCEEDED, so the
      // key is bound to a real certificate sitting in the store (at least
      // in "My"); deleting the container there would corrupt that
      // certificate's key reference instead of freeing dead weight. Same
      // best-effort, non-fatal cleanup discipline as the ACME-failure path
      // in executeWindowsIisRenewJob's finally block.
      if (acceptResult.stage === undefined && isNonEmptyStringValue(containerName)) {
        try {
          const cleanup = await removeAbandonedKeyContainer({
            containerName,
            ...(windowsExecFileImpl ? { execFileImpl: windowsExecFileImpl } : {}),
          });
          if (cleanup.ok !== true) {
            emitLog(
              log,
              `tokentimer-agent: job ${jobId}: failed to delete abandoned CNG key container ` +
                `${containerName} after certreq -accept failure (exit code ${cleanup.exitCode}); ` +
                `it will remain orphaned in the CNG key store until manually removed.`,
            );
          }
        } catch (err) {
          emitLog(
            log,
            `tokentimer-agent: job ${jobId}: failed to delete abandoned CNG key container ` +
              `${containerName} after certreq -accept failure: ${err.message}`,
          );
        }
      }
      await reportStepEvidence(client, jobId, [
        buildEvidenceItem({
          eventType: "validation.failed",
          observedAt: new Date().toISOString(),
          summary: `CNG certificate acceptance failed for job ${jobId} (exit code ${acceptResult.exitCode}).`,
          metadata: [
            { name: "step", value: "cng-accept" },
            { name: "exitCode", value: acceptResult.exitCode },
            { name: "stderrExcerpt", value: boundMetadataExcerpt(acceptResult.stderrExcerpt) },
          ],
        }),
      ]);
      return {
        status: "failed",
        keyRotated: null,
        errorMessage: boundErrorMessage(
          `CNG certificate acceptance failed (exit code ${acceptResult.exitCode}): ${acceptResult.stderrExcerpt}`,
        ),
      };
    }
    emitInfo(`job ${jobId}: CNG enrollment complete, thumbprint ${acceptResult.thumbprint}`);

    // job-payload.schema.json's windowsIisBinding carries only
    // {site, port, sniHost} -- no explicit address -- so every windows-iis
    // job binds the IIS-conventional wildcard listener ("*", matching
    // ../windows-iis's WILDCARD_BINDING_ADDRESSES), with sniHost (when
    // present) selecting the certificate under that shared listener.
    const binding = {
      address: "*",
      port: target.binding.port,
      ...(target.binding.sniHost ? { sniHost: target.binding.sniHost } : {}),
      store: target.store,
      site: target.binding.site,
    };

    emitInfo(`job ${jobId}: deploying IIS binding at ${binding.address}:${binding.port}`);
    const deployResult = await deployIisBinding({
      binding,
      certificatePem,
      ...(windowsExecFileImpl ? { execFileImpl: windowsExecFileImpl } : {}),
      ...(windowsConnectImpl ? { connectImpl: windowsConnectImpl } : {}),
    });

    if (deployResult.ok !== true) {
      await reportStepEvidence(client, jobId, [
        buildEvidenceItem({
          eventType: "validation.failed",
          observedAt: new Date().toISOString(),
          summary: `IIS binding deploy failed for job ${jobId} (${deployResult.code}), rolledBack=${deployResult.rolledBack === true}.`,
          metadata: [
            { name: "step", value: "iis-bind" },
            { name: "code", value: String(deployResult.code) },
            { name: "rolledBack", value: deployResult.rolledBack === true },
          ],
        }),
      ]);
      return {
        status: "failed",
        keyRotated: null,
        errorMessage: boundErrorMessage(
          `IIS binding deploy failed (${deployResult.code}): ${deployResult.detail} ` +
            `(rolledBack: ${deployResult.rolledBack === true})`,
        ),
      };
    }

    emitInfo(`job ${jobId}: IIS binding deploy succeeded, verified at ${JSON.stringify(deployResult.verifiedAt)}`);
    if (deployResult.precedenceWarning) {
      emitInfo(`job ${jobId}: WARNING: ${deployResult.precedenceWarning}`);
    }
    await reportStepEvidence(client, jobId, [
      buildEvidenceItem({
        eventType: "deployment.updated",
        observedAt: new Date().toISOString(),
        summary: deployResult.skippedMutation === true
          ? `IIS binding deploy skipped for job ${jobId}: binding already pointed at this certificate (idempotent); TLS handshake re-verified.`
          : `IIS binding deploy succeeded for job ${jobId}: certificate rebound and TLS-verified.`,
        metadata: [
          { name: "step", value: "iis-bind" },
          { name: "idempotentSkip", value: deployResult.skippedMutation === true },
          { name: "boundThumbprint", value: deployResult.boundThumbprint },
          ...(deployResult.precedenceWarning
            ? [{ name: "precedenceWarning", value: deployResult.precedenceWarning }]
            : []),
        ],
      }),
    ]);

    // The control plane's reconciliation (apps/api's reconcileProvisionedCertificate
    // for an "issue" job, refreshRenewedCertificateEvidence for a later "renew")
    // looks for a claim-bound validation.passed event with metadata.step === "verify"
    // carrying fingerprintSha256 and validTo -- the file-based path's runDeployTail
    // always emits this after a successful live-endpoint check, but deployIisBinding's
    // own TLS handshake verification above was never surfaced in that shape, so a
    // windows-iis certificate would deploy correctly on the host and then sit
    // forever in status 'provisioning' (or with a frozen not_after after a later
    // renewal), invisible to expiry tracking and the renewal scheduler. Emitting the
    // same evidence shape here, from the same already-verified certificatePem, closes
    // that gap without re-running any verification deployIisBinding already did.
    const deployedFacts = describeDeployedCertificate(certificatePem);
    const verifyFingerprint = computeCertificateFingerprint(certificatePem);
    const verifyMetadata = [{ name: "step", value: "verify" }];
    if (deployedFacts) {
      for (const [name, value] of [
        ["serialNumber", deployedFacts.serialNumber],
        ["validFrom", deployedFacts.validFrom],
        ["validTo", deployedFacts.validTo],
        ["subject", deployedFacts.subject],
        ["issuer", deployedFacts.issuer],
        [
          "subjectAltNames",
          deployedFacts.dnsSans.length > 0 ? deployedFacts.dnsSans.join(",") : null,
        ],
      ]) {
        if (value !== null) verifyMetadata.push({ name, value });
      }
    }
    await reportStepEvidence(client, jobId, [
      buildEvidenceItem({
        eventType: "validation.passed",
        observedAt: new Date().toISOString(),
        fingerprintSha256: verifyFingerprint,
        summary: `Verified deployed certificate fingerprint for job ${jobId} against the live IIS endpoint.`,
        metadata: verifyMetadata,
      }),
    ]);

    // Retention ledger row (decision 18): only for a genuine predecessor
    // this deploy just superseded. A first-ever bind (outgoingThumbprint
    // null) or an idempotent skip (outgoing === new) has nothing to retire.
    if (
      isNonEmptyStringValue(deployResult.outgoingThumbprint) &&
      deployResult.outgoingThumbprint !== deployResult.boundThumbprint
    ) {
      try {
        await recordSupersededWindowsCertificate({
          jobId,
          stateDir,
          store: target.store,
          oldThumbprint: deployResult.outgoingThumbprint,
          replacementThumbprint: deployResult.boundThumbprint,
          log,
          ...(windowsExecFileImpl ? { execFileImpl: windowsExecFileImpl } : {}),
        });
      } catch (err) {
        // A ledger-write failure must never turn an already-succeeded,
        // TLS-verified cutover into a reported job failure: decision 18's
        // ledger governs LATER cleanup timing, not whether this renewal
        // succeeded. The predecessor material simply stays in the store
        // (the safe failure mode) until an operator or a future sweep
        // notices; this is logged, not swallowed silently.
        emitLog(
          log,
          `tokentimer-agent: job ${jobId}: failed to record retention-ledger row for ` +
            `superseded thumbprint ${deployResult.outgoingThumbprint}; predecessor material ` +
            `remains in the store (safe failure mode): ${err.message}`,
        );
      }
    }

    return { status: "succeeded", keyRotated: null };
  } finally {
    storeLock.release();
  }
}

/**
 * Persists a ../windows-retention ledger row for the certificate an IIS
 * bind just superseded (decision 18: "written in the same operation that
 * completes cutover verification"). `cngKeyContainerId` and `oldNotAfter`
 * are looked up from the live machine store rather than threaded through
 * from the job, since the predecessor's own container/validity are facts
 * about ITS certificate object, not this job's.
 *
 * Ownership is decided by isAgentOwnedContainerName, not merely by
 * container PRESENCE: any non-exportable CNG certificate (one an operator
 * or a different tool enrolled directly on this host, not just one this
 * agent installed) also reports a "Key Container =" line in certutil's
 * output, so presence alone is not evidence this agent may delete it. Only
 * a container name matching this agent's own buildContainerName naming
 * convention counts as tokentimer_installed.
 *
 * A predecessor whose store entry cannot be found (already removed by a
 * prior sweep), one with no key container at all (e.g. an operator-
 * imported PFX cert), or one with a key container this agent did not
 * create, is recorded with ownershipProvenance "preexisting" and a
 * placeholder container id, which ../windows-retention's
 * evaluateEligibility's ownership check then keeps permanently ineligible
 * for automated cleanup -- never deleting material this agent cannot prove
 * it installed.
 *
 * @param {object} params
 * @returns {Promise<void>}
 */
async function recordSupersededWindowsCertificate({
  jobId,
  stateDir,
  store,
  oldThumbprint,
  replacementThumbprint,
  log,
  execFileImpl,
}) {
  const ledgerDir = path.join(stateDir, WINDOWS_RETENTION_LEDGER_DIR_NAME);
  const normalizedOld = normalizeRetentionThumbprint(oldThumbprint);

  // Idempotent: a retried/duplicate-dispatched job that already recorded
  // this exact supersession must not throw ROW_ALREADY_EXISTS.
  const existing = readLedgerRow(ledgerDir, normalizedOld);
  if (existing !== null) {
    emitLog(
      log,
      `tokentimer-agent: job ${jobId}: retention-ledger row for ${normalizedOld} already exists, skipping (idempotent)`,
    );
    return;
  }

  const storeResult = await listMachineStoreCertificates({
    store,
    ...(execFileImpl ? { execFileImpl } : {}),
  });
  const predecessor =
    storeResult.ok === true
      ? storeResult.certificates.find((cert) => cert.thumbprint === normalizedOld)
      : null;

  const ownershipProvenance =
    predecessor && isAgentOwnedContainerName(predecessor.keyContainer)
      ? "tokentimer_installed"
      : "preexisting";
  const cngKeyContainerId =
    predecessor && isAgentOwnedContainerName(predecessor.keyContainer)
      ? predecessor.keyContainer
      : buildContainerName(`unknown-${normalizedOld.slice(0, 16)}`);
  const oldNotAfter =
    predecessor && isIsoParseable(predecessor.notAfter)
      ? new Date(predecessor.notAfter).toISOString()
      : new Date().toISOString();

  createLedgerRow({
    ledgerDir,
    oldThumbprint: normalizedOld,
    replacementThumbprint: normalizeRetentionThumbprint(replacementThumbprint),
    cngKeyContainerId,
    verifiedCutoverAt: new Date().toISOString(),
    oldNotAfter,
    ownershipProvenance,
    store,
    jobOrRollbackJournalRefs: [{ ref: jobId, active: false }],
  });
}

function isIsoParseable(value) {
  return typeof value === "string" && value.length > 0 && Number.isFinite(Date.parse(value));
}

/**
 * Parses one ../windows-discovery `listHttpSysBindings` entry's `ipPort`
 * string (an `IP:port` or `Hostname:port` literal, per that module's own
 * `keyedBy` field) into the `{ address, port }` shape ../windows-iis's
 * `resolveVerificationTarget` expects. Splits on the LAST colon so a
 * bracketed IPv6 literal (`[::1]:443`) is not mis-split on one of its own
 * embedded colons.
 * @param {string} ipPort
 * @returns {{ address: string, port: number }|null} null if unparseable.
 */
function splitIpPortLiteral(ipPort) {
  if (!isNonEmptyStringValue(ipPort)) return null;
  const lastColon = ipPort.lastIndexOf(":");
  if (lastColon <= 0 || lastColon === ipPort.length - 1) return null;
  const address = ipPort.slice(0, lastColon);
  const port = Number(ipPort.slice(lastColon + 1));
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
  return { address, port };
}

/**
 * Resolves the real TCP host/port/SNI a retention sweep should re-probe
 * for one ../windows-discovery binding entry, reusing ../windows-iis's own
 * `resolveVerificationTarget` (the exact same wildcard-to-loopback mapping
 * decision 13's own bind-time verification step uses) rather than
 * inventing a second address-resolution policy for the sweep.
 * @param {{ ipPort: string, keyedBy: "ipport"|"hostnameport" }} binding
 * @returns {{ host: string, port: number, servername: string|undefined }|null}
 */
function resolveSweepVerificationTarget(binding) {
  const parsed = splitIpPortLiteral(binding.ipPort);
  if (parsed === null) return null;
  const isHostnameKeyed = binding.keyedBy === "hostnameport";
  const target = resolveVerificationTarget({
    address: isHostnameKeyed ? "*" : parsed.address,
    ...(isHostnameKeyed ? { sniHost: parsed.address } : {}),
  });
  return { host: target.host, port: parsed.port, servername: target.servername };
}

/**
 * Opens a real TLS handshake against `host:port` (optionally with SNI) and
 * returns the sha1(DER) thumbprint of whatever certificate is presented --
 * the same identifier space every thumbprint in this module and
 * ../windows-retention's ledger already lives in -- or null on any
 * connect/handshake failure or timeout. Deliberately does not validate the
 * chain (`rejectUnauthorized: false`): like ../verify's own fingerprint-
 * pinned verification, the thumbprint COMPARISON the caller makes against
 * a known-expected value is the actual verification here, not anything
 * TLS's own trust store would decide.
 * @param {object} input
 * @param {string} input.host
 * @param {number} input.port
 * @param {string} [input.servername]
 * @param {Function} [input.connectImpl] defaults to tls.connect.
 * @param {number} [input.timeoutMs]
 * @returns {Promise<string|null>} uppercase 40-hex-char thumbprint, or null.
 */
function probeTlsSha1Thumbprint({ host, port, servername, connectImpl = tls.connect, timeoutMs = 5000 }) {
  return new Promise((resolve) => {
    let settled = false;
    let timer = null;
    let socket = null;

    function settle(value) {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      if (socket) {
        try {
          socket.destroy();
        } catch {
          // best-effort teardown
        }
      }
      resolve(value);
    }

    timer = setTimeout(() => settle(null), timeoutMs);

    try {
      socket = connectImpl({
        host,
        port,
        ...(servername !== undefined ? { servername } : {}),
        rejectUnauthorized: false,
      });
    } catch {
      settle(null);
      return;
    }

    socket.on("secureConnect", () => {
      try {
        const peerCert = socket.getPeerCertificate();
        if (!peerCert || !peerCert.raw) {
          settle(null);
          return;
        }
        settle(crypto.createHash("sha1").update(peerCert.raw).digest("hex").toUpperCase());
      } catch {
        settle(null);
      }
    });
    socket.on("error", () => settle(null));
  });
}

/**
 * Runs one pass of the ADR-0012 decision 18 retention sweep over every row
 * in this agent's superseded-certificate ledger (../windows-retention),
 * re-gathering the live facts evaluateEligibility needs from this host --
 * this is the periodic caller ../windows-retention's own doc comment
 * flags as the one piece it deliberately does not own -- and performing
 * the actual store/key-container deletion for whatever comes back
 * eligible.
 *
 * Fail-safe posture: when a fact-gathering step itself cannot complete
 * (http.sys or the store cannot be queried), this treats the corresponding
 * eligibility condition as NOT satisfied (still bound / shared / failed
 * handshake) rather than as "unknown, assume fine" -- decision 18's own
 * "a still-bound predecessor is the safe failure mode" principle applied
 * to the sweep's own fact-gathering, not just to the six conditions
 * themselves.
 *
 * @param {object} input
 * @param {string} input.stateDir agent state dir (ledger + store-mutex location).
 * @param {number} input.retentionHours validated `windows.supersededRetentionHours`.
 * @param {object} [input.log]
 * @param {Function} [input.execFileImpl] injection point for certutil.exe/netsh.exe.
 * @param {Function} [input.connectImpl] injection point for the replacement handshake probe.
 * @returns {Promise<{removed: string[], deferred: object[], deferredCountByReason: Record<string, number>}|null>}
 *   null when there is no ledger directory yet (nothing has ever been superseded).
 */
async function runWindowsRetentionSweep({ stateDir, retentionHours, log, execFileImpl, connectImpl }) {
  const ledgerDir = path.join(stateDir, WINDOWS_RETENTION_LEDGER_DIR_NAME);
  if (!fs.existsSync(ledgerDir)) return null;

  async function gatherContext(row) {
    const store = row.store || "My";

    const bindingsResult = await listHttpSysBindings({
      ...(execFileImpl ? { execFileImpl } : {}),
    });
    const bindingStillReferencesOldThumbprint =
      bindingsResult.ok !== true
        ? true
        : bindingsResult.bindings.some(
            (binding) =>
              isNonEmptyStringValue(binding.thumbprint) &&
              normalizeRetentionThumbprint(binding.thumbprint) === row.oldThumbprint,
          );

    const storeResult = await listMachineStoreCertificates({
      store,
      ...(execFileImpl ? { execFileImpl } : {}),
    });
    const keyContainerSharedWithSurvivor =
      storeResult.ok !== true
        ? true
        : storeResult.certificates.some(
            (cert) =>
              cert.thumbprint !== row.oldThumbprint &&
              isNonEmptyStringValue(cert.keyContainer) &&
              cert.keyContainer === row.cngKeyContainerId,
          );

    let replacementPassesHandshakeNow = false;
    if (bindingsResult.ok === true) {
      const replacementBinding = bindingsResult.bindings.find(
        (binding) =>
          isNonEmptyStringValue(binding.thumbprint) &&
          normalizeRetentionThumbprint(binding.thumbprint) === row.replacementThumbprint,
      );
      const target = replacementBinding ? resolveSweepVerificationTarget(replacementBinding) : null;
      if (target !== null) {
        const observedThumbprint = await probeTlsSha1Thumbprint({
          host: target.host,
          port: target.port,
          servername: target.servername,
          ...(connectImpl ? { connectImpl } : {}),
        });
        replacementPassesHandshakeNow = observedThumbprint === row.replacementThumbprint;
      }
    }

    return { bindingStillReferencesOldThumbprint, keyContainerSharedWithSurvivor, replacementPassesHandshakeNow };
  }

  async function performCleanup(row) {
    const store = row.store || "My";
    const storeLock = acquireStoreLock(stateDir, store);
    try {
      const result = await removeCertificateAndKeyContainer({
        thumbprint: row.oldThumbprint,
        store,
        containerName: row.cngKeyContainerId,
        ...(execFileImpl ? { execFileImpl } : {}),
      });
      if (result.ok !== true) {
        throw new Error(
          `removeCertificateAndKeyContainer failed at stage ${result.stage} (exit code ${result.exitCode}): ` +
            result.stderrExcerpt,
        );
      }
    } finally {
      storeLock.release();
    }
  }

  const summary = await sweepLedger({ ledgerDir, retentionHours, gatherContext, performCleanup });
  emitLog(
    log,
    `tokentimer-agent: windows-retention sweep: removed=${summary.removed.length} ` +
      `deferred=${summary.deferred.length}`,
  );
  return summary;
}

/**
 * Executes a "renew" job whose custody is `os-store-managed` against a
 * `windows-iis` target (ADR-0012 decisions 9 and 13): the
 * CNG-native counterpart to executeRenewJob's file-based key/deploy path.
 *
 * Steps 1-2 (key + CSR) use ../windows-cert-store's generateCsrViaCng
 * instead of keys/generateKeyPairToFile + generateCsr: the private key is
 * generated directly inside the CNG machine key store and never exists as
 * a file. Step 3 (ACME order) is otherwise IDENTICAL to executeRenewJob's:
 * the CNG-generated CSR is written to the same job-scoped csrPath the ACME
 * adapter already expects, so the adapter itself has no CNG-specific
 * branch at all. Steps 4-6 (runWindowsIisDeployTail) replace
 * deployCertificate/deployCertificateAndKey with ../windows-cert-store's
 * acceptCertificateViaCng (completes CNG enrollment) and ../windows-iis's
 * deployIisBinding (rebind + verify + rollback), then persist a
 * ../windows-retention ledger row for whatever certificate the binding
 * previously pointed at.
 *
 * Single-target only: a windows-iis job resolving to more than one deploy
 * target is rejected rather than partially handled, since decision 13's
 * per-store/binding mutex model is defined for one target at a time.
 *
 * @returns {Promise<{status: string, keyRotated: null, errorMessage?: string|null, rejectionReason?: string}>}
 */
async function executeWindowsIisRenewJob({
  job,
  jobId,
  policyEngine,
  client,
  executionContext,
  log,
  leaseOpts = null,
  onBeforeMutation = null,
}) {
  const { execution } = executionContext;
  const commonName = job?.target?.reference;
  if (typeof commonName !== "string" || commonName.length === 0) {
    return {
      status: "failed",
      keyRotated: null,
      errorMessage: "renew job has no target.reference to use as the certificate CN",
    };
  }
  if (!isValidCertificateId(job.certificateId)) {
    return {
      status: "failed",
      keyRotated: null,
      errorMessage: boundErrorMessage(
        `renew job has a missing or malformed certificateId (expected 1-128 chars ` +
          `matching ^[A-Za-z0-9_.:-]+$, got ${JSON.stringify(job.certificateId)})`,
      ),
    };
  }

  const sansResolved = resolveJobSans(job);
  if (sansResolved && sansResolved.error) {
    return { status: "failed", keyRotated: null, errorMessage: sansResolved.error };
  }
  const domains =
    sansResolved && Array.isArray(sansResolved.sans) ? sansResolved.sans : [commonName];
  const csrCommonName = domains.includes(commonName) ? commonName : domains[0];

  const deployTargetsResolved = resolveJobDeployTargets(job);
  if (deployTargetsResolved.error) {
    return { status: "failed", keyRotated: null, errorMessage: deployTargetsResolved.error };
  }
  const deployTargets = deployTargetsResolved.targets;
  if (deployTargets.length !== 1 || deployTargets[0].type !== "windows-iis") {
    return {
      status: "failed",
      keyRotated: null,
      errorMessage:
        "renew job keyMode is os-store-managed but does not resolve to exactly one " +
        "windows-iis deploy target (multi-target windows-iis renewal is not supported yet)",
    };
  }
  const windowsTarget = deployTargets[0];
  if (
    !isNonEmptyStringValue(windowsTarget.store) ||
    windowsTarget.binding === null ||
    typeof windowsTarget.binding !== "object" ||
    !isNonEmptyStringValue(windowsTarget.binding.site) ||
    !Number.isInteger(windowsTarget.binding.port)
  ) {
    return {
      status: "failed",
      keyRotated: null,
      errorMessage: "windows-iis target requires target.store and target.binding.{site,port}",
    };
  }

  if (typeof job.commandRef !== "string" || job.commandRef.length === 0) {
    return {
      status: "failed",
      keyRotated: null,
      errorMessage: "renew job carries no commandRef naming an allowlisted ACME command",
    };
  }
  const commandVerdict = policyEngine.checkCommandRef(job.commandRef);
  if (!commandVerdict.allowed) {
    return {
      status: "rejected",
      keyRotated: null,
      rejectionReason: commandVerdict.rejectionReason,
      errorMessage: boundErrorMessage(commandVerdict.detail),
    };
  }
  if (typeof job.caEndpoint !== "string" || job.caEndpoint.length === 0) {
    return { status: "failed", keyRotated: null, errorMessage: "renew job carries no caEndpoint" };
  }
  if (typeof job.dnsProvider === "string" && job.dnsProvider.length > 0) {
    const dnsVerdict = policyEngine.checkDnsProvider(job.dnsProvider);
    if (!dnsVerdict.allowed) {
      return {
        status: "rejected",
        keyRotated: null,
        rejectionReason: dnsVerdict.rejectionReason,
        errorMessage: boundErrorMessage(dnsVerdict.detail),
      };
    }
  }
  if (typeof job.dnsZone === "string" && job.dnsZone.length > 0) {
    const zoneVerdict = policyEngine.checkDnsZone(job.dnsZone);
    if (!zoneVerdict.allowed) {
      return {
        status: "rejected",
        keyRotated: null,
        rejectionReason: zoneVerdict.rejectionReason,
        errorMessage: boundErrorMessage(zoneVerdict.detail),
      };
    }
  }

  const keyAlgMapped = mapJobKeyAlgorithm(job);
  if (keyAlgMapped && keyAlgMapped.error) {
    return { status: "failed", keyRotated: null, errorMessage: keyAlgMapped.error };
  }
  const cngAlgorithm = keyAlgMapped && keyAlgMapped.algorithm ? keyAlgMapped.algorithm : "rsa-2048";

  let eabCredentials = null;
  const eabAccountRef = resolveJobEabAccountRef(job);
  if (eabAccountRef !== null) {
    try {
      eabCredentials = resolveAcmeAccountCredentials(eabAccountRef, {
        acmeAccounts: executionContext.acmeAccounts,
      });
    } catch (err) {
      return {
        status: "failed",
        keyRotated: null,
        errorMessage: boundErrorMessage(
          `renew job requires ACME account/EAB credentials for ref ${JSON.stringify(eabAccountRef)} ` +
            `but they are not available locally: ${err.message}`,
        ),
      };
    }
  }
  const acmeKind = SUPPORTED_ACME_KINDS.includes(job.acmeKind) ? job.acmeKind : "certbot";

  const stateDir = resolveAgentStateDir(executionContext) || path.dirname(execution.keysDir);
  const cngWorkDir = path.join(stateDir, WINDOWS_CERT_STORE_WORK_DIR_NAME);
  const windowsExecFileImpl = executionContext.windowsExecFileImpl;
  const windowsConnectImpl = executionContext.windowsConnectImpl;

  // Steps 1-2: CNG-native key + CSR. The private key never exists as a
  // file (it is a CNG key handle inside containerName); only the CSR
  // (public material) is ever written to disk, at the same job-scoped
  // csrPath the ACME adapter already expects below.
  {
    const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
    if (leaseGate && leaseGate.ok === false) return leaseGate.abort;
  }
  if (typeof onBeforeMutation === "function") onBeforeMutation("keygen");
  emitInfo(`job ${jobId}: generating CNG-native key + CSR for CN ${csrCommonName}`);
  const csrResult = await generateCsrViaCng({
    commonName: csrCommonName,
    altNames: domains,
    jobId: job.certificateId,
    algorithm: cngAlgorithm,
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
  const containerName = csrResult.containerName;
  fs.mkdirSync(execution.keysDir, { recursive: true });
  const csrPath = path.join(execution.keysDir, `${jobId}.csr.pem`);
  fs.writeFileSync(csrPath, csrResult.csrPem, { mode: 0o600 });

  const stagedCertPath = path.join(execution.keysDir, `${jobId}.cert.pem`);
  const stagedCertPaths = resolveCertificateOutputPaths(stagedCertPath);

  let certificatePem;
  try {
    // Step 3: ACME renewal, unmodified from executeRenewJob's file-based
    // path -- the adapter only ever sees a csrPath file, never how the CSR
    // inside it was produced.
    {
      const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
      if (leaseGate && leaseGate.ok === false) return leaseGate.abort;
    }
    if (typeof onBeforeMutation === "function") onBeforeMutation("acme");
    emitInfo(
      `job ${jobId}: starting ACME order (${acmeKind}) against ${job.caEndpoint} for ${domains.join(", ")}`,
    );
    const adapter = createAcmeAdapter({
      kind: acmeKind,
      commandProfile: { argv: commandVerdict.argv },
      execFileImpl: executionContext.acmeExecFileImpl,
    });
    const renewalOpts = {
      caEndpoint: job.caEndpoint,
      domains,
      csrPath,
      outCertPath: stagedCertPath,
      stateDir,
      checkCaEndpoint: (endpoint) => policyEngine.checkCaEndpoint(endpoint),
    };
    if (typeof job.preferredChain === "string" && job.preferredChain.length > 0) {
      renewalOpts.preferredChain = job.preferredChain;
    } else if (
      typeof job?.renewalProfile?.preferredChain === "string" &&
      job.renewalProfile.preferredChain.length > 0
    ) {
      renewalOpts.preferredChain = job.renewalProfile.preferredChain;
    }
    if (eabCredentials) {
      renewalOpts.eabKid = eabCredentials.eabKid;
      renewalOpts.eabHmacKey = eabCredentials.eabHmacKey;
    }
    const renewal = await adapter.runRenewal(renewalOpts);
    if (renewal.allowed === false) {
      return {
        status: "rejected",
        keyRotated: null,
        rejectionReason: renewal.rejectionReason,
        errorMessage: boundErrorMessage(renewal.detail),
      };
    }
    if (renewal.renewed !== true) {
      await reportStepEvidence(client, jobId, [
        buildEvidenceItem({
          eventType: "validation.failed",
          observedAt: new Date().toISOString(),
          summary: `ACME renewal step failed for job ${jobId} (exit code ${renewal.exitCode}).`,
          metadata: [
            { name: "step", value: "acme" },
            { name: "exitCode", value: renewal.exitCode },
            { name: "stderrExcerpt", value: boundMetadataExcerpt(renewal.stderrExcerpt) },
            { name: "stdoutExcerpt", value: boundMetadataExcerpt(renewal.stdoutExcerpt) },
          ],
        }),
      ]);
      return {
        status: "failed",
        keyRotated: null,
        errorMessage: boundErrorMessage(
          `acme step failed with exit code ${renewal.exitCode}: ${acmeFailureDetail(renewal)}`,
        ),
      };
    }
    await reportStepEvidence(client, jobId, [
      buildEvidenceItem({
        eventType: "validation.passed",
        observedAt: new Date().toISOString(),
        summary: `ACME renewal step succeeded for job ${jobId}.`,
        metadata: [{ name: "step", value: "acme" }, { name: "exitCode", value: renewal.exitCode }],
      }),
    ]);
    emitInfo(`job ${jobId}: ACME order succeeded`);

    const staged = readStagedCertificateChain(stagedCertPaths);
    if (staged.error) {
      return {
        status: "failed",
        keyRotated: null,
        errorMessage: boundErrorMessage(
          `acme step reported success but produced no certificate file: ${staged.error}`,
        ),
      };
    }
    certificatePem = staged.pem;
  } finally {
    // The CSR is public material, but it is job-scoped scratch: remove it.
    // Unlike the file-based path, there is no staged private key to worry
    // about leaking here -- the CNG key never left the store.
    fs.rmSync(csrPath, { force: true });
    for (const stagedArtifact of Object.values(stagedCertPaths)) {
      fs.rmSync(stagedArtifact, { force: true });
    }
    // certificatePem is only ever assigned on the success path above,
    // just before this finally runs; if the ACME step was rejected,
    // failed, or produced no certificate (every early `return` above), the
    // CNG key container generateCsrViaCng just created is now orphaned --
    // never enrolled, never bound to anything, and (unlike a superseded
    // cert handled by ../windows-retention's ledger/sweep) never recorded
    // anywhere else, so this is the only place that can ever free it.
    // Best-effort and non-fatal: a cleanup failure here must not turn an
    // already-reported ACME failure into a second, different failure, and
    // the orphaned container itself is inert (non-exportable, unbound,
    // and safely re-attemptable) rather than a security or correctness
    // problem if it is briefly leaked.
    if (certificatePem === undefined) {
      try {
        const cleanup = await removeAbandonedKeyContainer({
          containerName,
          ...(windowsExecFileImpl ? { execFileImpl: windowsExecFileImpl } : {}),
        });
        if (cleanup.ok !== true) {
          emitLog(
            log,
            `tokentimer-agent: job ${jobId}: failed to delete abandoned CNG key container ` +
              `${containerName} after ACME failure (exit code ${cleanup.exitCode}); it will remain ` +
              `orphaned in the CNG key store until manually removed.`,
          );
        }
      } catch (err) {
        emitLog(
          log,
          `tokentimer-agent: job ${jobId}: failed to delete abandoned CNG key container ` +
            `${containerName} after ACME failure: ${err.message}`,
        );
      }
    }
  }

  // Steps 4-6: CNG accept + IIS bind + retention, under the store mutex
  // (decision 13: "the per-target mutex covers the store as well as the
  // binding").
  return runWindowsIisDeployTail({
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
}

/**
 * Rolls back a completed deploy after a later tail step (reload or verify)
 * failed. Without this, a reload/verify failure would leave the NEW
 * certificate installed while the job reports failure -- the operator sees
 * "failed" but the destination silently changed.
 *
 * Only applies when the deploy actually wrote (deployed: true) AND left a
 * backup of the previous content (backupPath / backupPaths.cert). An
 * idempotent skip changed nothing (nothing to roll back). A first-ever
 * deploy has no previous certificate to restore: deleting the fresh file
 * would be worse (the service may already have loaded it), so the cert is
 * retained and the return value sets `orphanedFirstDeploy` so the caller
 * can report `orphaned_unknown_effect` instead of an ordinary failure.
 *
 * The restore goes through deployCertificate itself, so it gets the same
 * policy re-check, atomic write, and metrics as any deploy. After a
 * successful restore, the service reload (when the job requested one and
 * the refs resolve) is re-run best-effort so the service picks the old
 * content back up; its outcome is reported in the rollback evidence but
 * never changes the job's (already failed) result.
 *
 * @param {object} params
 * @returns {Promise<{ rolledBack: boolean, reason: string|null, orphanedFirstDeploy?: boolean }>}
 */
async function rollbackAfterFailedTail({
  job,
  jobId,
  policyEngine,
  client,
  deployResult,
  failedStep,
  log,
}) {
  if (deployResult?.deployed !== true) {
    return { rolledBack: false, reason: "deploy step made no change (idempotent skip)" };
  }

  const certBackup =
    typeof deployResult.backupPath === "string" && deployResult.backupPath.length > 0
      ? deployResult.backupPath
      : deployResult.backupPaths &&
          typeof deployResult.backupPaths.cert === "string" &&
          deployResult.backupPaths.cert.length > 0
        ? deployResult.backupPaths.cert
        : null;

  if (certBackup === null) {
    // First-ever deploy: nothing to restore. Retain the new cert and flag
    // the ambiguous live state for operator reconciliation.
    await reportStepEvidence(client, jobId, [
      buildEvidenceItem({
        eventType: "deployment.updated",
        observedAt: new Date().toISOString(),
        summary:
          `Orphaned first-ever deployment for job ${jobId} after the ${failedStep} step failed: ` +
          `no previous certificate existed to restore. The new certificate may be live on disk ` +
          `and the service may already have loaded it; operator reconciliation is required.`,
        metadata: [
          { name: "step", value: "rollback" },
          { name: "failedStep", value: String(failedStep) },
          { name: "restored", value: false },
          { name: "orphanedFirstDeploy", value: true },
        ],
      }),
    ]);
    return {
      rolledBack: false,
      reason: "no previous certificate existed to restore",
      orphanedFirstDeploy: true,
    };
  }

  let previousPem;
  try {
    previousPem = fs.readFileSync(certBackup, "utf8");
  } catch (err) {
    emitLog(log, `tokentimer-agent: rollback for job ${jobId} could not read the backup: ${err.message}`);
    return { rolledBack: false, reason: "backup file could not be read" };
  }

  const keyBackupPath =
    deployResult.backupPaths && typeof deployResult.backupPaths.key === "string"
      ? deployResult.backupPaths.key
      : null;
  const liveKeyPath =
    typeof deployResult.keyDestination === "string" ? deployResult.keyDestination : null;

  let restore;
  if (keyBackupPath && liveKeyPath) {
    // Matched pair was deployed: restore cert+key together from backups.
    const stagedRestoreKey = `${keyBackupPath}.restore-staging`;
    try {
      fs.copyFileSync(keyBackupPath, stagedRestoreKey);
      restore = await deployCertificateAndKey({
        target: {
          type: job?.target?.type ?? "endpoint",
          reference: job?.target?.reference ?? deployResult.destination,
          certPath: deployResult.destination,
          keyPath: liveKeyPath,
        },
        certificatePem: previousPem,
        privateKeyPath: stagedRestoreKey,
        checkPath: (candidate) => policyEngine.checkPath(candidate),
      });
    } finally {
      fs.rmSync(stagedRestoreKey, { force: true });
    }
  } else {
    restore = await deployCertificate({
      target: {
        type: job?.target?.type ?? "endpoint",
        reference: job?.target?.reference ?? deployResult.destination,
        certPath: deployResult.destination,
      },
      certificatePem: previousPem,
      checkPath: (candidate) => policyEngine.checkPath(candidate),
    });
  }
  const restored = restore.deployed === true || restore.skipped === true;
  if (!restored) {
    emitLog(log, `tokentimer-agent: rollback restore failed for job ${jobId} at stage ${restore.stage}`);
  }

  // Best-effort re-reload so the service serves the restored content again.
  let reloadNote = "not requested";
  if (restored && typeof job.reloadService === "string" && job.reloadService.length > 0) {
    reloadNote = "skipped (command refs unavailable)";
    const refs = job.reloadCommandRefs;
    if (refs && typeof refs === "object" && typeof refs.validate === "string" && typeof refs.reload === "string") {
      const validateVerdict = policyEngine.checkCommandRef(refs.validate);
      const reloadVerdict = policyEngine.checkCommandRef(refs.reload);
      if (validateVerdict.allowed && reloadVerdict.allowed) {
        try {
          const outcome = await reloadService({
            service: job.reloadService,
            commandProfiles: {
              validateArgv: validateVerdict.argv,
              reloadArgv: reloadVerdict.argv,
            },
          });
          reloadNote = outcome.reloaded === true ? "reloaded" : `reload failed at stage ${outcome.stage}`;
        } catch (err) {
          reloadNote = `reload errored: ${err.message}`;
        }
      }
    }
  }

  await reportStepEvidence(client, jobId, [
    buildEvidenceItem({
      eventType: "deployment.updated",
      observedAt: new Date().toISOString(),
      summary: restored
        ? `Rolled back job ${jobId}: previous certificate restored after the ${failedStep} step failed.`
        : `Rollback attempted for job ${jobId} after the ${failedStep} step failed, but the restore did not complete; the backup file still holds the previous content.`,
      metadata: [
        { name: "step", value: "rollback" },
        { name: "failedStep", value: String(failedStep) },
        { name: "restored", value: restored },
        { name: "reloadAfterRestore", value: reloadNote },
      ],
    }),
  ]);

  return restored
    ? { rolledBack: true, reason: null }
    : { rolledBack: false, reason: "restore write failed; backup retained" };
}

/**
 * Appends a rollback disposition note to a failed/rejected tail outcome's
 * errorMessage so the reported result states what is on disk. First-ever
 * deploys with no backup are promoted to `orphaned_unknown_effect`.
 *
 * @param {object} outcome reportResult fields
 * @param {{ rolledBack: boolean, reason: string|null, orphanedFirstDeploy?: boolean }} rollback
 * @returns {object}
 */
function withRollbackNote(outcome, rollback) {
  if (rollback?.orphanedFirstDeploy === true) {
    const failedDetail =
      typeof outcome.errorMessage === "string" && outcome.errorMessage.length > 0
        ? outcome.errorMessage
        : "a post-deploy step failed";
    return {
      ...outcome,
      status: "orphaned_unknown_effect",
      // Orphaned is a distinct terminal status, not a policy rejection.
      rejectionReason: undefined,
      errorMessage: boundErrorMessage(
        `${failedDetail} (first-ever deployment: no previous certificate existed to restore; ` +
          `the new certificate may be live on disk and the service may already have loaded it; ` +
          `operator reconciliation is required)`,
      ),
    };
  }
  const note = rollback.rolledBack
    ? "rolled back to the previous certificate"
    : `not rolled back: ${rollback.reason}`;
  return {
    ...outcome,
    errorMessage: boundErrorMessage(`${outcome.errorMessage} (${note})`),
  };
}

/**
 * Multi-target deploy/reload/verify as a transactional coordinator.
 *
 * Phases:
 *   1. Preflight ALL targets (no writes): resolve paths, validate cert/SANs/
 *      key-match, path policy, modes/ownership shape, reload refs; renew lease.
 *   2. Apply+verify each target in turn (renew lease before each mutation),
 *      retaining ALL backups until the whole operation commits.
 *   3. On any apply/verify failure: stop; roll back previously-changed
 *      targets in reverse order (restore backup or remove first-deploy files);
 *      reload each restored target. If every changed target is restored =>
 *      `failed`. If any rollback is uncertain => `orphaned_unknown_effect`
 *      (reconciliation details in errorMessage / evidence; no new schema fields).
 *   4. Commit: discard all retained backups only after every target succeeds.
 *
 * @param {object} params
 * @returns {Promise<object>}
 */
async function runDeployReloadVerifyForTargets({
  job,
  jobId,
  policyEngine,
  client,
  certificatePem,
  deployTargets,
  keyPath,
  stagedKeyPath,
  keyRotated = false,
  requestedSans = [],
  log,
  leaseOpts = null,
  onBeforeMutation = null,
}) {
  // Single-target keeps the existing per-target rollback / first-deploy
  // orphaned_unknown_effect semantics. Multi-target uses the transactional
  // coordinator below (retain backups across targets; reverse rollback).
  if (!Array.isArray(deployTargets) || deployTargets.length <= 1) {
    const target = deployTargets[0];
    const jobView = target
      ? {
          ...job,
          target: { type: target.type, reference: target.reference },
          certPath: target.certPath,
          chainPath: target.chainPath || undefined,
          reloadService: target.reloadService || undefined,
          keyPath: target.keyPath || undefined,
          certMode: target.certMode,
          keyMode: target.keyMode,
          chainMode: target.chainMode,
          owner: target.owner,
          group: target.group,
          backupDir: target.backupDir,
          backupRetentionCount: target.backupRetentionCount,
        }
      : job;
    const targetKeyPath =
      target && typeof target.keyPath === "string" && target.keyPath.length > 0
        ? target.keyPath
        : keyPath;
    return runDeployReloadVerify({
      job: jobView,
      jobId,
      policyEngine,
      client,
      certificatePem,
      certPath: target ? target.certPath : job.certPath,
      chainPath: target ? target.chainPath : job.chainPath,
      keyPath: targetKeyPath,
      stagedKeyPath,
      keyRotated:
        keyRotated === true ||
        (typeof targetKeyPath === "string" &&
          targetKeyPath.length > 0 &&
          typeof stagedKeyPath === "string" &&
          stagedKeyPath.length > 0 &&
          path.normalize(path.resolve(targetKeyPath)) !==
            path.normalize(path.resolve(stagedKeyPath))),
      requestedSans,
      log,
      leaseOpts,
      retainBackups: false,
      onBeforeMutation,
    });
  }

  const checkPath = (candidate) => policyEngine.checkPath(candidate);
  const sans =
    Array.isArray(requestedSans) && requestedSans.length > 0
      ? requestedSans
      : typeof job?.target?.reference === "string" && job.target.reference.length > 0
        ? [job.target.reference]
        : [];

  // --- Preflight (all-or-nothing; no writes) ---------------------------------
  {
    const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
    if (leaseGate && leaseGate.ok === false) return leaseGate.abort;
  }

  const keyForValidation =
    typeof stagedKeyPath === "string" && stagedKeyPath.length > 0
      ? stagedKeyPath
      : typeof keyPath === "string" && keyPath.length > 0
        ? keyPath
        : null;
  let privateKeyPem = null;
  const anyTargetNeedsKey = deployTargets.some(
    (t) => typeof t.keyPath === "string" && t.keyPath.length > 0,
  );
  if (anyTargetNeedsKey || keyRotated === true) {
    if (!keyForValidation) {
      return {
        status: "failed",
        errorMessage: boundErrorMessage(
          "preflight failed: deployment requires a permitted local key reference " +
            "but none was resolved (keysDir staging is not an implicit production destination)",
        ),
      };
    }
    try {
      privateKeyPem = fs.readFileSync(keyForValidation, "utf8");
    } catch (err) {
      return {
        status: "failed",
        errorMessage: boundErrorMessage(
          `preflight failed: could not read private key for validation: ${err.message}`,
        ),
      };
    }
  } else if (keyForValidation) {
    try {
      privateKeyPem = fs.readFileSync(keyForValidation, "utf8");
    } catch (err) {
      return {
        status: "failed",
        errorMessage: boundErrorMessage(
          `preflight failed: could not read private key for validation: ${err.message}`,
        ),
      };
    }
  }

  const preDeploy = validateCertificateForDeploy({
    certificatePem,
    privateKeyPem,
    requestedSans: sans,
  });
  if (preDeploy.valid !== true) {
    await reportStepEvidence(client, jobId, [
      buildEvidenceItem({
        eventType: "validation.failed",
        observedAt: new Date().toISOString(),
        summary: `Multi-target preflight certificate validation failed for job ${jobId}: ${preDeploy.code}.`,
        metadata: [
          { name: "step", value: "preflight" },
          { name: "code", value: String(preDeploy.code) },
        ],
      }),
    ]);
    return {
      status: "failed",
      errorMessage: boundErrorMessage(
        `preflight validation failed (${preDeploy.code}): ${preDeploy.detail}`,
      ),
    };
  }

  for (let i = 0; i < deployTargets.length; i += 1) {
    const target = deployTargets[i];
    const pathVerdict = checkPath(target.certPath);
    if (!pathVerdict || pathVerdict.allowed !== true) {
      return {
        status: "rejected",
        rejectionReason: pathVerdict?.rejectionReason || "path_not_allowlisted",
        errorMessage: boundErrorMessage(
          `preflight: target ${i + 1} certPath rejected by policy`,
        ),
      };
    }
    if (typeof target.keyPath === "string" && target.keyPath.length > 0) {
      const keyVerdict = checkPath(target.keyPath);
      if (!keyVerdict || keyVerdict.allowed !== true) {
        return {
          status: "rejected",
          rejectionReason: keyVerdict?.rejectionReason || "path_not_allowlisted",
          errorMessage: boundErrorMessage(
            `preflight: target ${i + 1} keyPath rejected by policy`,
          ),
        };
      }
    }
    if (typeof target.chainPath === "string" && target.chainPath.length > 0) {
      const chainVerdict = checkPath(target.chainPath);
      if (!chainVerdict || chainVerdict.allowed !== true) {
        return {
          status: "rejected",
          rejectionReason: chainVerdict?.rejectionReason || "path_not_allowlisted",
          errorMessage: boundErrorMessage(
            `preflight: target ${i + 1} chainPath rejected by policy`,
          ),
        };
      }
    }
    if (typeof target.reloadService === "string" && target.reloadService.length > 0) {
      const refs = job.reloadCommandRefs;
      if (
        refs &&
        typeof refs === "object" &&
        typeof refs.validate === "string" &&
        typeof refs.reload === "string"
      ) {
        const validateVerdict = policyEngine.checkCommandRef(refs.validate);
        const reloadVerdict = policyEngine.checkCommandRef(refs.reload);
        if (!validateVerdict.allowed || !reloadVerdict.allowed) {
          return {
            status: "rejected",
            rejectionReason:
              (!validateVerdict.allowed && validateVerdict.rejectionReason) ||
              reloadVerdict.rejectionReason ||
              "command_not_allowlisted",
            errorMessage: boundErrorMessage(
              `preflight: target ${i + 1} reload command refs not allowlisted`,
            ),
          };
        }
      }
    }
  }

  // --- Apply / verify with retained backups ----------------------------------
  const applied = [];
  const targetOutcomes = [];
  const liveStagedKeyPath = stagedKeyPath;

  for (let i = 0; i < deployTargets.length; i += 1) {
    const target = deployTargets[i];
    const jobView = {
      ...job,
      target: {
        type: target.type,
        reference: target.reference,
      },
      certPath: target.certPath,
      chainPath: target.chainPath || undefined,
      reloadService: target.reloadService || undefined,
      keyPath: target.keyPath || undefined,
      certMode: target.certMode,
      keyMode: target.keyMode,
      chainMode: target.chainMode,
      owner: target.owner,
      group: target.group,
      backupDir: target.backupDir,
      backupRetentionCount: target.backupRetentionCount,
    };

    const targetKeyPath =
      typeof target.keyPath === "string" && target.keyPath.length > 0
        ? target.keyPath
        : typeof keyPath === "string" && keyPath.length > 0
          ? keyPath
          : null;

    const result = await runDeployReloadVerify({
      job: jobView,
      jobId,
      policyEngine,
      client,
      certificatePem,
      certPath: target.certPath,
      chainPath: target.chainPath,
      keyPath: targetKeyPath,
      stagedKeyPath: liveStagedKeyPath,
      keyRotated:
        keyRotated === true ||
        (typeof targetKeyPath === "string" &&
          targetKeyPath.length > 0 &&
          typeof liveStagedKeyPath === "string" &&
          liveStagedKeyPath.length > 0 &&
          path.normalize(path.resolve(targetKeyPath)) !==
            path.normalize(path.resolve(liveStagedKeyPath))),
      requestedSans: sans,
      log,
      leaseOpts,
      retainBackups: true,
      onBeforeMutation,
      retainPrivateKeyStaging: i < deployTargets.length - 1,
    });

    targetOutcomes.push({
      index: i,
      reference: target.reference,
      certPath: target.certPath,
      status: result.status,
      errorMessage: result.errorMessage || null,
    });

    if (result.deployResult && result.deployResult.deployed === true) {
      applied.push({
        index: i,
        target,
        jobView,
        deployResult: result.deployResult,
      });
    }

    await reportStepEvidence(client, jobId, [
      buildEvidenceItem({
        eventType:
          result.status === "succeeded" ? "deployment.updated" : "validation.failed",
        observedAt: new Date().toISOString(),
        summary:
          `Deployment target ${i + 1}/${deployTargets.length} ` +
          `(${target.reference}) finished with status ${result.status}.`,
        metadata: [
          { name: "step", value: "multi-target" },
          { name: "targetIndex", value: i },
          { name: "targetCount", value: deployTargets.length },
          { name: "targetReference", value: String(target.reference) },
          { name: "targetStatus", value: String(result.status) },
        ],
      }),
    ]);

    if (result.status !== "succeeded") {
      const rollbackOutcome = await rollbackAppliedTargets({
        applied,
        job,
        jobId,
        policyEngine,
        client,
        log,
        failedIndex: i,
        failedResult: result,
      });
      return {
        ...rollbackOutcome,
        targetOutcomes,
      };
    }
  }

  // --- Commit: discard all retained backups ----------------------------------
  for (const entry of applied) {
    try {
      await discardDeployBackups({
        backupPaths: entry.deployResult.backupPaths,
        backupPath: entry.deployResult.backupPath,
      });
    } catch (err) {
      emitLog(
        log,
        `tokentimer-agent: could not discard deploy backups for job ${jobId} target ${entry.index}: ${err.message}`,
      );
    }
  }

  return {
    status: "succeeded",
    errorMessage: null,
    targetOutcomes,
  };
}

/**
 * Rolls back previously-applied multi-target deploys in reverse order.
 * First-deploy targets (no backup) have newly written files removed.
 */
async function rollbackAppliedTargets({
  applied,
  job: _job,
  jobId,
  policyEngine,
  client,
  log,
  failedIndex,
  failedResult,
}) {
  let uncertain = false;
  const notes = [];

  for (let r = applied.length - 1; r >= 0; r -= 1) {
    const entry = applied[r];
    const deployResult = entry.deployResult;
    const isFirstDeploy =
      deployResult.firstDeploy === true ||
      (!(
        (typeof deployResult.backupPath === "string" && deployResult.backupPath.length > 0) ||
        (deployResult.backupPaths &&
          typeof deployResult.backupPaths.cert === "string" &&
          deployResult.backupPaths.cert.length > 0)
      ));

    if (isFirstDeploy && deployResult.deployed === true) {
      const destinations = [
        deployResult.destination,
        deployResult.keyDestination,
        deployResult.chainDestination,
      ];
      const removal = await removeDeployedArtifacts({
        destinations,
        checkPath: (candidate) => policyEngine.checkPath(candidate),
      });
      if (removal.failed.length > 0) {
        uncertain = true;
        notes.push(
          `target ${entry.index + 1} first-deploy rollback incomplete (files retained for operator recovery)`,
        );
      } else {
        notes.push(`target ${entry.index + 1} first-deploy files removed`);
      }
      // Best-effort reload after removal.
      if (typeof entry.jobView.reloadService === "string") {
        try {
          await maybeReloadForJob({
            job: entry.jobView,
            jobId,
            policyEngine,
            client,
            log,
            leaseOpts: null,
          });
        } catch (_err) {
          // best-effort
        }
      }
      continue;
    }

    const rollback = await rollbackAfterFailedTail({
      job: entry.jobView,
      jobId,
      policyEngine,
      client,
      deployResult,
      failedStep: `multi-target-rollback-after-target-${failedIndex + 1}`,
      log,
    });
    if (rollback.rolledBack !== true) {
      uncertain = true;
      notes.push(
        `target ${entry.index + 1} rollback failed (${rollback.reason || "unknown"}); backup retained`,
      );
    } else {
      notes.push(`target ${entry.index + 1} rolled back`);
    }
  }

  const baseMessage =
    failedResult.errorMessage ||
    `deployment target ${failedIndex + 1} failed with status ${failedResult.status}`;

  if (uncertain) {
    return {
      status: "orphaned_unknown_effect",
      errorMessage: boundErrorMessage(
        `${baseMessage} (multi-target rollback uncertain: ${notes.join("; ")}; ` +
          `needsOperatorReconciliation=true; reconciliationReason=multi_target_rollback_uncertain)`,
      ),
    };
  }

  if (applied.length === 0) {
    return {
      status: failedResult.status === "orphaned_unknown_effect"
        ? "orphaned_unknown_effect"
        : failedResult.status || "failed",
      rejectionReason: failedResult.rejectionReason,
      errorMessage: boundErrorMessage(baseMessage),
    };
  }

  return {
    status: "failed",
    errorMessage: boundErrorMessage(
      `${baseMessage} (prior targets rolled back successfully: ${notes.join("; ")})`,
    ),
  };
}

async function runDeployReloadVerify({
  job,
  jobId,
  policyEngine,
  client,
  certificatePem,
  certPath,
  chainPath = null,
  keyPath,
  stagedKeyPath,
  keyRotated = false,
  requestedSans = [],
  log,
  leaseOpts = null,
  retainBackups = false,
  onBeforeMutation = null,
  retainPrivateKeyStaging = false,
  skipPreDeployValidation = false,
}) {
  // Pre-deploy X.509 validation always runs unless the multi-target
  // coordinator already preflighted. When a local key path is available,
  // full validation includes key-match; otherwise privateKeyPem is null so
  // validateCertificateForDeploy still enforces parse / SAN / validity /
  // chain without requiring a key (standalone deploy path without keyPath).
  const keyForValidation =
    typeof stagedKeyPath === "string" && stagedKeyPath.length > 0
      ? stagedKeyPath
      : typeof keyPath === "string" && keyPath.length > 0
        ? keyPath
        : null;
  let privateKeyPem = null;
  if (!skipPreDeployValidation) {
    if (keyForValidation) {
      try {
        privateKeyPem = fs.readFileSync(keyForValidation, "utf8");
      } catch (err) {
        return {
          status: "failed",
          errorMessage: boundErrorMessage(
            `pre-deploy validation could not read private key: ${err.message}`,
          ),
        };
      }
    }
    const sans =
      Array.isArray(requestedSans) && requestedSans.length > 0
        ? requestedSans
        : typeof job?.target?.reference === "string" && job.target.reference.length > 0
          ? [job.target.reference]
          : [];
    const preDeploy = validateCertificateForDeploy({
      certificatePem,
      privateKeyPem,
      requestedSans: sans,
    });
    if (preDeploy.valid !== true) {
      await reportStepEvidence(client, jobId, [
        buildEvidenceItem({
          eventType: "validation.failed",
          observedAt: new Date().toISOString(),
          summary: `Pre-deploy certificate validation failed for job ${jobId}: ${preDeploy.code}.`,
          metadata: [
            { name: "step", value: "pre-deploy-validate" },
            { name: "code", value: String(preDeploy.code) },
          ],
        }),
      ]);
      return {
        status: "failed",
        errorMessage: boundErrorMessage(
          `pre-deploy validation failed (${preDeploy.code}): ${preDeploy.detail}`,
        ),
      };
    }
  }

  // Deploy step. When a production keyPath is named and a staging key is
  // available, install the matched key+certificate pair atomically for
  // EVERY such target (not only the first). keysDir remains staging only.
  {
    const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
    if (leaseGate && leaseGate.ok === false) return leaseGate.abort;
  }
  if (typeof onBeforeMutation === "function") onBeforeMutation("deploy");
  emitInfo(`job ${jobId}: deploying certificate to ${certPath}`);
  const checkPath = (candidate) => policyEngine.checkPath(candidate);
  const resolvedChainPath =
    typeof chainPath === "string" && chainPath.length > 0
      ? chainPath
      : isAbsolutePathLike(job?.chainPath)
        ? job.chainPath
        : null;

  let deployCertificatePem = certificatePem;
  let deployChainPem;
  if (resolvedChainPath) {
    const split = splitLeafAndChainPem(certificatePem);
    if (!split.chainPem) {
      return {
        status: "failed",
        errorMessage:
          "deploy target.chainPath is configured but the certificate PEM has no intermediate chain blocks to write",
      };
    }
    deployCertificatePem = split.leafPem;
    deployChainPem = split.chainPem;
  }

  const usePairedDeploy =
    typeof keyPath === "string" &&
    keyPath.length > 0 &&
    typeof stagedKeyPath === "string" &&
    stagedKeyPath.length > 0 &&
    (keyRotated === true ||
      path.normalize(path.resolve(keyPath)) !==
        path.normalize(path.resolve(stagedKeyPath)));

  const deployTarget = {
    type: job?.target?.type ?? "endpoint",
    reference: job?.target?.reference ?? certPath,
    certPath,
    ...(resolvedChainPath ? { chainPath: resolvedChainPath } : {}),
    ...(usePairedDeploy ? { keyPath } : {}),
    ...(job?.backupDir ? { backupDir: job.backupDir } : {}),
    ...(Number.isInteger(job?.backupRetentionCount)
      ? { backupRetentionCount: job.backupRetentionCount }
      : {}),
    ...(job?.certMode != null ? { certMode: job.certMode } : {}),
    ...(job?.keyMode != null ? { keyMode: job.keyMode } : {}),
    ...(job?.chainMode != null ? { chainMode: job.chainMode } : {}),
    ...(job?.owner ? { owner: job.owner } : {}),
    ...(job?.group ? { group: job.group } : {}),
  };

  const deployResult = usePairedDeploy
    ? await deployCertificateAndKey({
        target: deployTarget,
        certificatePem: deployCertificatePem,
        privateKeyPath: stagedKeyPath,
        chainPem: deployChainPem,
        checkPath,
        retainPrivateKeyStaging,
      })
    : await deployCertificate({
        target: deployTarget,
        certificatePem: deployCertificatePem,
        chainPem: deployChainPem,
        checkPath,
      });

  if (deployResult.deployed !== true && deployResult.skipped !== true) {
    await reportStepEvidence(client, jobId, [
      buildEvidenceItem({
        eventType: "validation.failed",
        observedAt: new Date().toISOString(),
        summary: `Deploy step failed for job ${jobId} at stage ${deployResult.stage} (rolledBack: ${deployResult.rolledBack === true}).`,
        metadata: [
          { name: "step", value: "deploy" },
          { name: "stage", value: String(deployResult.stage) },
          { name: "rolledBack", value: deployResult.rolledBack === true },
        ],
      }),
    ]);
    return {
      status: "failed",
      errorMessage: boundErrorMessage(
        `deploy step failed at stage ${deployResult.stage}: ${deployResult.error}`,
      ),
      deployResult,
    };
  }

  // Deploy metrics counters for this job's target type, flattened to
  // numeric publicMetadataEntry items (the evidence module only accepts
  // scalar values).
  const targetTypeForMetrics =
    typeof job?.target?.type === "string" ? job.target.type : "unknown";
  const metricsForType = getDeployMetrics()[targetTypeForMetrics] || {};
  emitInfo(
    deployResult.skipped === true
      ? `job ${jobId}: deploy skipped, destination already up to date`
      : `job ${jobId}: deploy succeeded at ${certPath}`,
  );
  await reportStepEvidence(client, jobId, [
    buildEvidenceItem({
      eventType: "deployment.updated",
      observedAt: new Date().toISOString(),
      summary:
        deployResult.skipped === true
          ? `Deploy step skipped for job ${jobId}: destination already holds this certificate (idempotent).`
          : `Deploy step succeeded for job ${jobId}: certificate installed atomically.`,
      metadata: [
        { name: "step", value: "deploy" },
        { name: "idempotentSkip", value: deployResult.skipped === true },
        ...Object.entries(metricsForType)
          .filter(([, value]) => typeof value === "number")
          .map(([name, value]) => ({ name: `deployMetric_${name}`, value })),
        ...durabilityMetadataEntries(),
      ],
    }),
  ]);

  // Optional reload step: only when the job names a service AND both
  // command profile refs resolve through the agent-local allowlist.
  const reloadOutcome = await maybeReloadForJob({
    job,
    jobId,
    policyEngine,
    client,
    log,
    leaseOpts,
  });
  if (reloadOutcome !== null && reloadOutcome.status !== "succeeded") {
    if (retainBackups === true) {
      return {
        ...reloadOutcome,
        deployResult,
      };
    }
    const rollback = await rollbackAfterFailedTail({
      job,
      jobId,
      policyEngine,
      client,
      deployResult,
      failedStep: "reload",
      log,
    });
    return { ...withRollbackNote(reloadOutcome, rollback), deployResult };
  }

  // Verify step: always fingerprint the deployed PEM; probe the live
  // endpoint only when the job provides a host (job.verifyHost).
  emitInfo(`job ${jobId}: verifying deployed certificate at ${certPath}`);
  const deployedPem = fs.readFileSync(certPath, "utf8");
  const fingerprint = computeCertificateFingerprint(deployedPem);
  let verifySummary = `Verified deployed certificate fingerprint for job ${jobId}.`;
  if (typeof job.verifyHost === "string" && job.verifyHost.length > 0) {
    // Authorization gate: verifyHost/verifyPort are job-controlled and
    // direct the agent to open a TLS connection, so the destination must
    // pass agent-local policy (metadata/link-local hard-denied, loopback
    // and off-target hosts require an explicit allowlist entry).
    const destinationVerdict = policyEngine.checkVerifyHost(job.verifyHost, {
      targetReference: job?.target?.reference,
    });
    if (!destinationVerdict.allowed) {
      await reportStepEvidence(client, jobId, [
        buildEvidenceItem({
          eventType: "validation.failed",
          observedAt: new Date().toISOString(),
          summary: `Verify step rejected for job ${jobId}: the verify destination is not authorized by agent-local policy.`,
          metadata: [{ name: "step", value: "verify" }],
        }),
      ]);
      const failedOutcome = {
        status: "rejected",
        rejectionReason: destinationVerdict.rejectionReason,
        errorMessage: boundErrorMessage(destinationVerdict.detail),
        deployResult,
      };
      if (retainBackups === true) return failedOutcome;
      const rollback = await rollbackAfterFailedTail({
        job,
        jobId,
        policyEngine,
        client,
        deployResult,
        failedStep: "verify-authorization",
        log,
      });
      return { ...withRollbackNote(failedOutcome, rollback), deployResult };
    }

    const probe = await verifyDeployedCertificateWithRetry({
      host: job.verifyHost,
      port: typeof job.verifyPort === "number" ? job.verifyPort : undefined,
      expectedFingerprintSha256: fingerprint,
    });
    if (probe.verified !== true) {
      await reportStepEvidence(client, jobId, [
        buildEvidenceItem({
          eventType: "validation.failed",
          observedAt: new Date().toISOString(),
          fingerprintSha256: fingerprint,
          summary: `Live endpoint verification failed for job ${jobId}: the served certificate does not match the deployed one.`,
          metadata: [{ name: "step", value: "verify" }],
        }),
      ]);
      const failedOutcome = {
        status: "failed",
        errorMessage: boundErrorMessage(
          "verify step failed: live endpoint does not serve the deployed certificate",
        ),
        deployResult,
      };
      if (retainBackups === true) return failedOutcome;
      const rollback = await rollbackAfterFailedTail({
        job,
        jobId,
        policyEngine,
        client,
        deployResult,
        failedStep: "verify",
        log,
      });
      return { ...withRollbackNote(failedOutcome, rollback), deployResult };
    }
    verifySummary = `Verified deployed certificate fingerprint for job ${jobId} against live endpoint.`;
  }
  // Public x509 facts about what was actually deployed. The control plane
  // needs these to populate a certificate whose material it never sees: an
  // issue job's inventory row is created before the certificate exists, so
  // this evidence is the only authoritative source for its serial, validity
  // window, subject and SANs. Enrichment is strictly best-effort; an
  // unparseable PEM must not turn a verified deploy into a failure.
  const deployedFacts = describeDeployedCertificate(deployedPem);
  const verifyMetadata = [{ name: "step", value: "verify" }];
  if (deployedFacts) {
    for (const [name, value] of [
      ["serialNumber", deployedFacts.serialNumber],
      ["validFrom", deployedFacts.validFrom],
      ["validTo", deployedFacts.validTo],
      ["subject", deployedFacts.subject],
      ["issuer", deployedFacts.issuer],
      [
        "subjectAltNames",
        deployedFacts.dnsSans.length > 0
          ? deployedFacts.dnsSans.join(",")
          : null,
      ],
    ]) {
      if (value !== null) verifyMetadata.push({ name, value });
    }
  }
  await reportStepEvidence(client, jobId, [
    buildEvidenceItem({
      eventType: "validation.passed",
      observedAt: new Date().toISOString(),
      fingerprintSha256: fingerprint,
      summary: verifySummary,
      metadata: verifyMetadata,
    }),
  ]);
  emitInfo(`job ${jobId}: verify succeeded (fingerprint ${fingerprint})`);

  // Post-verify: only now is it safe to discard the previous key/cert backups
  // (unless the multi-target coordinator retains them until full commit).
  if (retainBackups !== true) {
    try {
      await discardDeployBackups({
        backupPaths: deployResult.backupPaths,
        backupPath: deployResult.backupPath,
      });
    } catch (err) {
      emitLog(
        log,
        `tokentimer-agent: could not discard deploy backups for job ${jobId}: ${err.message}`,
      );
    }
  }

  return { status: "succeeded", errorMessage: null, deployResult };
}

/**
 * Runs the reload step when the job requests one. Returns null when the
 * job carries no reloadService (step skipped), otherwise reportResult
 * fields for the step outcome.
 *
 * @param {object} params
 * @returns {Promise<object|null>}
 */
async function maybeReloadForJob({ job, jobId, policyEngine, client, log, leaseOpts = null }) {
  if (typeof job.reloadService !== "string" || job.reloadService.length === 0) {
    return null;
  }
  const refs = job.reloadCommandRefs;
  if (
    refs === null ||
    typeof refs !== "object" ||
    typeof refs.validate !== "string" ||
    typeof refs.reload !== "string"
  ) {
    return {
      status: "failed",
      errorMessage:
        "job requests a service reload but reloadCommandRefs.validate/.reload " +
        "command references are missing",
    };
  }
  const validateVerdict = policyEngine.checkCommandRef(refs.validate);
  if (!validateVerdict.allowed) {
    return {
      status: "rejected",
      rejectionReason: validateVerdict.rejectionReason,
      errorMessage: boundErrorMessage(validateVerdict.detail),
    };
  }
  const reloadVerdict = policyEngine.checkCommandRef(refs.reload);
  if (!reloadVerdict.allowed) {
    return {
      status: "rejected",
      rejectionReason: reloadVerdict.rejectionReason,
      errorMessage: boundErrorMessage(reloadVerdict.detail),
    };
  }

  {
    const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
    if (leaseGate && leaseGate.ok === false) return leaseGate.abort;
  }
  emitInfo(`job ${jobId}: reloading service ${job.reloadService}`);
  const outcome = await reloadService({
    service: job.reloadService,
    commandProfiles: {
      validateArgv: validateVerdict.argv,
      reloadArgv: reloadVerdict.argv,
    },
  });
  if (outcome.reloaded !== true) {
    emitLog(log, `tokentimer-agent: reload step failed for job ${jobId}`);
    await reportStepEvidence(client, jobId, [
      buildEvidenceItem({
        eventType: "validation.failed",
        observedAt: new Date().toISOString(),
        summary: `Reload step failed for job ${jobId} at stage ${outcome.stage}.`,
        metadata: [
          { name: "step", value: "reload" },
          { name: "stage", value: String(outcome.stage) },
        ],
      }),
    ]);
    return {
      status: "failed",
      errorMessage: boundErrorMessage(`reload step failed at stage ${outcome.stage}`),
    };
  }
  emitInfo(`job ${jobId}: reload succeeded for service ${job.reloadService}`);
  await reportStepEvidence(client, jobId, [
    buildEvidenceItem({
      eventType: "validation.passed",
      observedAt: new Date().toISOString(),
      summary: `Reload step succeeded for job ${jobId} (service validated then reloaded).`,
      metadata: [{ name: "step", value: "reload" }],
    }),
  ]);
  return { status: "succeeded" };
}

/**
 * Deploy action: deploy + optional reload + verify. certificatePem comes
 * from the job (its presence is checked by executeJob before this runs).
 * When an agent-local key exists at keysDir/<certificateId>.key.pem, it is
 * passed through for full pre-deploy key-match validation; otherwise
 * validation still runs key-less (parse/SAN/validity/chain only).
 *
 * @param {object} params
 * @returns {Promise<object>}
 */
async function executeDeployJob({
  job,
  jobId,
  policyEngine,
  client,
  log,
  leaseOpts = null,
  executionContext = null,
  onBeforeMutation = null,
}) {
  const deployTargetsResolved = resolveJobDeployTargets(job);
  if (deployTargetsResolved.error) {
    return {
      status: "failed",
      errorMessage: deployTargetsResolved.error.replace(
        /^job names/,
        "deploy job names",
      ),
    };
  }

  // The windows-iis executor (executeWindowsIisRenewJob / 
  // runWindowsIisDeployTail) only covers the "renew" action's CNG
  // CSR->accept->bind sequence, where acceptCertificateViaCng's certreq
  // -accept has a matching pending request (from the CSR this same job
  // just generated) to complete. A standalone "deploy" job carries an
  // arbitrary job.certificatePem with no such pending request, and
  // certreq -accept matches by public key against one -- there is no
  // "just rebind an already-in-store certificate to this binding" path
  // yet (that would need to read the certificate out of the store by
  // thumbprint, which no module here does). Rather than run this target
  // through the file-based runDeployReloadVerifyForTargets path below
  // (which would misbehave: windows-iis targets carry certPath: null),
  // fail loudly and specifically.
  if (deployTargetsResolved.targets.some((t) => t.type === "windows-iis")) {
    return {
      status: "failed",
      errorMessage:
        "deploy action does not yet support windows-iis targets (only renew, " +
        "via the CNG-native os-store-managed path, does); rebinding an " +
        "already-issued certificate to a different IIS binding without " +
        "re-issuing is not implemented",
    };
  }

  // keysDir is staging/custody only — never an implicit production destination.
  // Resolve a permitted agent-local key for validation / paired install when
  // any target (or the job) names a keyPath, or when a certificateId key exists.
  let keyPath = null;
  const keysDir = executionContext?.execution?.keysDir;
  const needsKey =
    deployTargetsResolved.targets.some(
      (t) => typeof t.keyPath === "string" && t.keyPath.length > 0,
    ) || isAbsolutePathLike(job?.keyPath);

  if (
    typeof keysDir === "string" &&
    keysDir.length > 0 &&
    isValidCertificateId(job.certificateId)
  ) {
    const candidate = path.join(keysDir, `${job.certificateId}.key.pem`);
    if (fs.existsSync(candidate)) {
      keyPath = candidate;
    }
  }

  if (needsKey && !keyPath) {
    return {
      status: "failed",
      errorMessage: boundErrorMessage(
        "deploy job requires key-matching validation / keyPath install but no " +
          "permitted local key reference exists under keysDir",
      ),
    };
  }

  const sansResolved = resolveJobSans(job);
  const requestedSans =
    sansResolved && Array.isArray(sansResolved.sans)
      ? sansResolved.sans
      : typeof job?.target?.reference === "string" && job.target.reference.length > 0
        ? [job.target.reference]
        : [];

  return await runDeployReloadVerifyForTargets({
    job,
    jobId,
    policyEngine,
    client,
    certificatePem: job.certificatePem,
    deployTargets: deployTargetsResolved.targets,
    keyPath,
    stagedKeyPath: keyPath,
    keyRotated: false,
    requestedSans,
    log,
    leaseOpts,
    onBeforeMutation,
  });
}

/**
 * Reload action: reload only. The job must request a reloadService.
 *
 * @param {object} params
 * @returns {Promise<object>}
 */
async function executeReloadJob({
  job,
  jobId,
  policyEngine,
  client,
  log,
  leaseOpts = null,
  onBeforeMutation = null,
}) {
  if (typeof onBeforeMutation === "function") onBeforeMutation("reload");
  const outcome = await maybeReloadForJob({
    job,
    jobId,
    policyEngine,
    client,
    log,
    leaseOpts,
  });
  if (outcome === null) {
    return {
      status: "failed",
      errorMessage: "reload job carries no reloadService field",
    };
  }
  return outcome;
}

/**
 * Runs one observe-only discovery scan over the configured directories and
 * reports parsed certificates as `certificate.observed` evidence. Only
 * public fields ever leave the host: the discovery module never reads key
 * bytes, and metadata here is limited to schema-safe names/values matching
 * the control-plane observation ingestion contract (filePath required).
 * Evidence bodies are chunked to the schema's 16-item maximum.
 *
 * Exported for direct unit testing.
 *
 * @param {object} params
 * @param {string[]} params.directories
 * @param {object} params.client from createProtocolClient
 * @param {(msg: string) => void} [params.log]
 * @returns {Promise<{ observed: number, warnings: number }>}
 */
async function runDiscoveryScan({ directories, client, log = null }) {
  const { certificates, warnings, truncated } = discoverCertificates(directories, {
    onWarning: (message) => emitLog(log, message),
  });
  if (truncated) {
    emitLog(log, "discovery scan hit a bound and was truncated");
  }

  const targetHost = os.hostname();
  const items = [];
  const observedAt = new Date().toISOString();
  for (const cert of certificates) {
    if (!cert.parsed) continue;
    // Structured metadata for control-plane ingestion. subjectAltName from
    // Node's X509Certificate is already a comma-separated string (or null
    // when the extension is absent); omit the entry when null rather than
    // sending an empty/null value the ingest path does not need.
    const metadata = [
      { name: "filePath", value: cert.path },
      { name: "targetHost", value: targetHost },
      { name: "subject", value: cert.subject },
      { name: "issuer", value: cert.issuer },
      { name: "serialNumber", value: cert.serialNumber },
      { name: "validFrom", value: cert.validFrom },
      { name: "validTo", value: cert.validTo },
      { name: "coLocatedKeyDetected", value: cert.coLocatedKeyDetected === true },
    ];
    if (typeof cert.subjectAltName === "string" && cert.subjectAltName.length > 0) {
      metadata.splice(5, 0, { name: "subjectAltNames", value: cert.subjectAltName });
    }
    items.push(
      buildEvidenceItem({
        eventType: "certificate.observed",
        observedAt,
        fingerprintSha256: cert.fingerprintSha256,
        summary: `Observed certificate at ${cert.path} (subject: ${cert.subject})`,
        metadata,
      }),
    );
  }

  const EVIDENCE_CHUNK_SIZE = 16;
  for (let start = 0; start < items.length; start += EVIDENCE_CHUNK_SIZE) {
    const body = buildEvidenceBody({
      jobId: null,
      evidenceItems: items.slice(start, start + EVIDENCE_CHUNK_SIZE),
    });
    assertEvidencePayloadSafe(body);
    await client.reportEvidence(body);
  }

  return { observed: items.length, warnings: warnings.length };
}

/**
 * Performs first-run registration when no credential is stored yet.
 * Requires TOKENTIMER_AGENT_BOOTSTRAP_TOKEN (and optionally
 * TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID) in the environment; the bootstrap
 * token is single-use and never persisted by the agent (plan section 7.2).
 *
 * @param {object} params
 * @param {object} params.client
 * @param {object} params.config from loadAgentConfig
 * @param {string} params.configDir
 * @param {NodeJS.ProcessEnv} [params.env]
 * @param {(...args: unknown[]) => void} [params.log]
 * @param {{ isWindows: Function, clearWindowsServiceBootstrapToken: Function }} [params.platformModule]
 *   injection seam for tests; defaults to the real ./platform module.
 * @returns {Promise<string>} the assigned agentId
 */
async function registerIfNeeded({
  client,
  config,
  configDir,
  env = process.env,
  log = console.error,
  platformModule = { isWindows, clearWindowsServiceBootstrapToken },
}) {
  // Already-registered paths: an earlier run exchanged the bootstrap token,
  // but systemd may still have re-exported it from a leftover bootstrap.env.
  // Scrub it here too so a registered agent never keeps the (already spent)
  // token in its environment, on disk, or (Windows service installs) in the
  // service's own registry Environment value.
  const scrubBootstrapToken = () => {
    if (env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN !== undefined) {
      delete env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN;
      delete env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID;
    }
    deleteBootstrapEnvFile(configDir);
    if (platformModule.isWindows()) {
      const result = platformModule.clearWindowsServiceBootstrapToken({ configDir });
      if (result.attempted && !result.cleared) {
        log(
          `tokentimer-agent: could not confirm the Windows service registry ` +
            `Environment value no longer holds the bootstrap token (${result.reason}); ` +
            "if this agent runs as the TokenTimerAgent service, check " +
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent\\Environment manually.",
        );
      }
    }
  };

  const recovered = recoverPendingRegistration(configDir);
  if (recovered !== null) {
    clearRegistrationId(configDir);
    scrubBootstrapToken();
    return recovered.agentId;
  }

  const existingCredential = readCredential(configDir);
  if (existingCredential !== null) {
    if (!config.agentId) {
      throw new Error(
        "tokentimer-agent: found a stored credential but no agentId in " +
          "config.json; the config directory is inconsistent. Re-register " +
          "with a fresh bootstrap token or restore config.json.",
      );
    }
    clearRegistrationId(configDir);
    scrubBootstrapToken();
    return config.agentId;
  }

  const bootstrapToken = env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN;
  if (!bootstrapToken) {
    throw new Error(
      "tokentimer-agent: no stored credential and no " +
        "TOKENTIMER_AGENT_BOOTSTRAP_TOKEN set. Obtain a bootstrap token " +
        "from the dashboard and export it to register this agent.",
    );
  }

  // H1: persist a client-generated registrationId BEFORE the register
  // request so a crash after the server consumes the bootstrap token can
  // retry with the same id and accept an idempotent replayed response.
  const registrationId = ensureRegistrationId(configDir);

  const registration = validateRegistrationResponse(await client.register({
    bootstrapToken,
    bootstrapTokenId: env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID || "unknown",
    agentVersion: AGENT_VERSION,
    hostname: os.hostname(),
    platform: process.platform,
    nodeVersion: process.version,
    declaredTargetSelectors: config.declaredTargetSelectors,
    declaredCommandProfileNames: config.declaredCommandProfileNames,
    declaredCapabilities: resolveDeclaredCapabilities(config.requireSignedAgentId),
    registrationId,
    supportedDnsProviders: listConfiguredDnsProviderIds(config.dnsProviders),
  }), config.protocolVersion);

  persistRegistration(configDir, {
    agentId: registration.agentId,
    credential: registration.credential,
  });
  clearRegistrationId(configDir);
  // The bootstrap token is single-use and has now been exchanged for a
  // stored per-agent credential. Scrub it from this process's environment
  // (so it can never leak into child processes or diagnostics), remove the
  // installer-written bootstrap.env file (so systemd/the Windows service
  // stop re-exporting it on every later start), and clear it out of the
  // Windows service's own registry Environment value if this is a service
  // install.
  scrubBootstrapToken();
  // Trust-on-first-use pinning (ADR-0003): when the register response
  // carries the control plane's job-signing key info, persist it so every
  // later run verifies jobs against the same key. Public material only.
  // allowRepin: this IS the explicit registration flow, the only place a
  // pin rotation is legitimate (a fresh bootstrap token was presented);
  // writeSigningKeyPin refuses silent re-pins everywhere else.
  if (registration.signingKeyId && registration.signingPublicKeyPem) {
    writeSigningKeyPin(
      configDir,
      {
        signingKeyId: registration.signingKeyId,
        signingPublicKeyPem: registration.signingPublicKeyPem,
      },
      { allowRepin: true },
    );
  }
  return registration.agentId;
}

function createCandidateAgentId(hostname = os.hostname(), pid = process.pid) {
  const normalizedHostname = String(hostname || "host")
    .normalize("NFKD")
    .replace(/[^A-Za-z0-9_.:-]+/g, "-")
    .replace(/[-_.:]+$/g, "")
    .slice(0, 96) || "host";
  const normalizedPid = Number.isInteger(pid) && pid >= 0 ? String(pid) : "0";
  return `candidate-${normalizedHostname}-${normalizedPid}`.slice(0, 128);
}

/**
 * Builds the execution context from a loaded config. Returns null when
 * execution is not configured or not enabled, which callers treat as "run
 * in observe-only bootstrap mode".
 *
 * Startup fail-loud: a corrupted replay store throws here (surfacing as a
 * startup failure) instead of being silently recreated -- see the replay
 * module's rationale (a tampered store is a security signal).
 *
 * Exported for direct unit testing; tests may inject acmeExecFileImpl to
 * stub the ACME child process, and windowsExecFileImpl/windowsConnectImpl
 * to stub the certreq.exe/certutil.exe/netsh.exe child processes and the
 * TLS handshake the CNG/IIS/retention modules invoke
 * (executeWindowsIisRenewJob, runWindowsIisDeployTail).
 *
 * @param {object} params
 * @param {object} params.config from loadAgentConfig
 * @param {Function} [params.acmeExecFileImpl] test-only execFile override
 * @param {Function} [params.windowsExecFileImpl] test-only execFile override
 *   for certreq.exe/certutil.exe/netsh.exe
 * @param {Function} [params.windowsConnectImpl] test-only tls.connect
 *   override for the post-bind verification handshake
 * @returns {{
 *   enabled: true,
 *   execution: object,
 *   outboxDir: string,
 *   replayCache: object,
 *   clockEstimator: object,
 *   pinnedSigningKey: {signingKeyId: string, publicKeyPem: string}|null,
 *   acmeExecFileImpl: Function|undefined,
 *   windowsExecFileImpl: Function|undefined,
 *   windowsConnectImpl: Function|undefined,
 * }|null}
 */
function buildExecutionContext({ config, acmeExecFileImpl, windowsExecFileImpl, windowsConnectImpl } = {}) {
  if (!config?.execution || config.execution.enabled !== true) {
    return null;
  }
  if (typeof config.execution.outboxDir !== "string" || config.execution.outboxDir.length === 0) {
    throw new Error(
      "tokentimer-agent: execution.outboxDir is required when execution is enabled",
    );
  }
  const clockEstimator = createClockOffsetEstimator();
  let replayCache;
  try {
    replayCache = createReplayCache({
      storePath: config.execution.replayStorePath,
      // Retention must cover the same tolerance tail checkJobTimeWindow
      // accepts (expiresAt + tolerance), and the sweep must run on the
      // same offset-adjusted timeline as the acceptance decision --
      // otherwise a nonce could be evicted while its job is still
      // acceptable, reopening the replay window. clockDriftToleranceMs is
      // operator-configurable (config.execution.clockDriftToleranceMs), so
      // it must be threaded through here rather than assuming the default.
      retentionToleranceMs: config.execution.clockDriftToleranceMs,
      now: () => Date.now() + (clockEstimator.getOffsetMs() ?? 0),
    });
  } catch (err) {
    throw new Error(
      "tokentimer-agent: failed to load the replay store at " +
        `${config.execution.replayStorePath}: ${err.message}. A corrupted ` +
        "replay store may indicate tampering; refusing to start execution " +
        "until an operator inspects it.",
    );
  }
  return {
    enabled: true,
    execution: config.execution,
    outboxDir: config.execution.outboxDir,
    replayCache,
    clockEstimator,
    pinnedSigningKey: config.pinnedSigningKey,
    acmeAccounts: config.acmeAccounts || null,
    acmeExecFileImpl,
    windowsExecFileImpl,
    windowsConnectImpl,
  };
}

/**
 * Runs the agent process: load config, register if needed, then run the
 * heartbeat and claim loops until SIGINT/SIGTERM or until the control plane
 * retires this agent (heartbeat HTTP 410 -> clean exit, no respawn loop,
 * ADR-0002).
 *
 * @param {string[]} _argv CLI arguments (none supported yet; configuration
 *   is via config.json and TOKENTIMER_AGENT_* env vars)
 * @param {{ signal?: AbortSignal }} [options] optional external abort
 *   signal, used by tests to stop the loops deterministically
 * @returns {Promise<void>}
 */
async function runAgent(_argv, { signal: externalSignal } = {}) {
  const configDir = resolveConfigDir();
  const config = loadAgentConfig({ configDir });

  // Execution context (null in bootstrap/observe-only mode). Built before
  // any network call so a corrupted replay store fails startup immediately.
  const executionContext = buildExecutionContext({ config });

  // Crash-safety: surface unresolved side-effect journals for operator
  // reconciliation. Do not auto-re-execute those jobIds.
  try {
    const unresolved = scanUnresolvedJournalEntries(configDir);
    if (unresolved.length > 0) {
      console.error(
        `tokentimer-agent: ${formatUnresolvedJournalReport(unresolved)}`,
      );
    }
  } catch (err) {
    console.error(
      `tokentimer-agent: job-journal scan failed at startup: ${err.message}`,
    );
  }

  const controller = new AbortController();
  const stop = () => controller.abort();
  if (externalSignal) {
    if (externalSignal.aborted) return;
    externalSignal.addEventListener("abort", stop, { once: true });
  }
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);

  // Default deny: with no policy block in config.json every allowlist is
  // empty, so the engine rejects all command/path/CA/DNS dimensions. The
  // agent still runs (heartbeats, claims, reports rejections as evidence)
  // so operators can see policy conflicts instead of silent failures.
  const policyEngine = createPolicyEngine(loadPolicyConfig(config.policy || {}), {
    declaredTargetSelectors: config.declaredTargetSelectors,
  });

  const fetchImpl = config.caBundlePath
    ? createCaAwareFetch({ caBundlePem: readCaBundle(config.caBundlePath) })
    : undefined;

  const onServerDate = executionContext
    ? (dateHeaderValue, localNowMs) =>
        executionContext.clockEstimator.estimateFromResponseDate(
          dateHeaderValue,
          localNowMs,
        )
    : undefined;

  // One persisted, crash-safe sequence stream shared by EVERY protocol
  // client this process creates (candidate/registration client included):
  // the control plane hard-rejects sequence regressions, so all outbound
  // messages must draw from a single counter that survives restarts.
  const sequenceAllocator = createSequenceAllocator(configDir);

  const clientForAgentId = (agentId) =>
    createProtocolClient({
      serverUrl: config.serverUrl,
      agentId,
      protocolVersion: config.protocolVersion,
      getCredential: () => readCredential(configDir),
      signal: controller.signal,
      fetchImpl,
      allowInsecureLocalHttp: config.allowInsecureLocalHttp,
      onServerDate,
      sequenceAllocator,
    });

  // For a not-yet-registered agent the envelope needs a client-generated
  // candidate id; the control plane echoes back the assigned id (schema
  // note on agentId). A registered agent uses its stored id.
  let registeredAgentId;
  try {
    const candidateAgentId = config.agentId || createCandidateAgentId();
    registeredAgentId = await registerIfNeeded({
      client: clientForAgentId(candidateAgentId),
      config,
      configDir,
    });
  } catch (err) {
    process.removeListener("SIGINT", stop);
    process.removeListener("SIGTERM", stop);
    if (externalSignal) externalSignal.removeEventListener("abort", stop);
    throw err;
  }

  const client = clientForAgentId(registeredAgentId);

  // Registration may have just pinned the signing key; reload it so a
  // first-run agent can execute without a restart.
  if (executionContext && !executionContext.pinnedSigningKey) {
    executionContext.pinnedSigningKey = readSigningKeyPin(configDir);
  }

  // B8: drain any un-acknowledged outbox entries from a prior run before
  // new job polling resumes, so a crash after successful execution but
  // before transmission cannot leave a success stranded or re-executed.
  if (executionContext) {
    await drainOutbox(executionContext.outboxDir, client, {
      onError: (err, entry) =>
        defaultAgentLogger.error(
          `tokentimer-agent: outbox drain failed for ${entry.id}; will retry`,
          err,
        ),
    });
  }

  const startedAtMs = Date.now();
  const supportedDnsProviders = listConfiguredDnsProviderIds(config.dnsProviders);

  const heartbeatLoop = startPollLoop({
    intervalMs: config.heartbeatIntervalMs,
    signal: controller.signal,
    startImmediately: true,
    onTick: async () => {
      // Independent of execution mode: this reports host-level NTP sync
      // health (observe-only agents benefit from the drift signal just as
      // much as execution-enabled ones). checkNtpSynced never throws; a
      // missing timedatectl/w32tm binary or an unsupported/stopped time
      // service resolves to null ("unknown") rather than stalling or
      // failing the heartbeat. Platform detection (timedatectl vs. w32tm)
      // is internal to checkNtpSynced.
      const ntpSynced = await checkNtpSynced();
      const response = await client.heartbeat({
        agentVersion: AGENT_VERSION,
        ntpSynced,
        uptimeSeconds: Math.floor((Date.now() - startedAtMs) / 1000),
        supportedDnsProviders,
        // Re-declared on every heartbeat so an in-place binary
        // upgrade's new capabilities reach the control plane without
        // re-enrollment, and so a runtime flip of
        // CERTOPS_AGENT_REQUIRE_SIGNED_AGENT_ID (ADR-0012 decision 3, step 4)
        // is reflected without a restart. Sending [] here would be a
        // declaration that this build supports nothing, which the control
        // plane honours by clearing the stored set; resolveDeclaredCapabilities
        // never returns an empty set, only the base set or the base set plus
        // agent-id-binding-v1.
        declaredCapabilities: resolveDeclaredCapabilities(config.requireSignedAgentId),
        // With execution enabled, report the measured clock offset and the
        // pinned signing key id so the control plane can spot drift and
        // key-rotation lag. in observe-only bootstrap mode these stay null.
        ...(executionContext
          ? {
              clockOffsetMs: executionContext.clockEstimator.getOffsetMs(),
              pinnedSigningKeyId:
                executionContext.pinnedSigningKey?.signingKeyId ?? null,
            }
          : {}),
      });
      if (response && response.retired === true) {
        defaultAgentLogger.error("control plane retired this agent; exiting cleanly");
        // Distinct exit status so systemd's RestartPreventExitStatus stops
        // respawning a decommissioned agent into a heartbeat 410 loop.
        process.exitCode = AGENT_RETIRED_EXIT_CODE;
        stop();
        return;
      }
      // H3: adopt a pending signing-key rotation when advertised. The next
      // heartbeat will naturally ack via pinnedSigningKeyId once the
      // in-memory + on-disk pin reflects the new key.
      if (executionContext && response && Object.prototype.hasOwnProperty.call(response, "signingKeyRotation")) {
        adoptSigningKeyRotation({
          rotation: response.signingKeyRotation,
          configDir,
          executionContext,
          log: (msg) => defaultAgentLogger.error(msg),
        });
      }
    },
  });

  // Observe-only discovery loop (filesystem certificate inventory).
  // Only started when config.json opts in with a discovery.directories list;
  // scans run immediately on start, then on the configured interval.
  const loops = [heartbeatLoop];

  // B3: observe-only agents never poll claim (and advertise no actions).
  // Heartbeat + discovery stay fully independent of the execution plane.
  if (shouldPollForJobs(executionContext)) {
    loops.push(
      startPollLoop({
        intervalMs: config.pollIntervalMs,
        signal: controller.signal,
        startImmediately: true,
        onTick: async () => {
          // Retry any outbox entries that failed to transmit before claiming
          // more work (idempotent; never re-executes).
          await drainOutbox(executionContext.outboxDir, client, {
            onError: (err, entry) =>
              defaultAgentLogger.error(
                `tokentimer-agent: outbox drain failed for ${entry.id}; will retry`,
                err,
              ),
          });
          const jobs = await client.claim({
            maxJobs: 1,
            supportedActions: resolveClaimSupportedActions(executionContext),
            supportedDnsProviders,
          });
          for (const job of jobs) {
            if (controller.signal.aborted) break;
            emitInfo(
              `claimed job ${job?.jobId || "(unknown)"} (action=${job?.action || "unknown"})`,
            );
            const outcome = await handleClaimedJob({
              job,
              policyEngine,
              client,
              executionContext,
              boundAgentId: registeredAgentId,
              requireSignedAgentId: config.requireSignedAgentId,
              log: (msg) => defaultAgentLogger.error(msg),
            });
            if (outcome && outcome.retired === true) {
              process.exitCode = AGENT_RETIRED_EXIT_CODE;
              stop();
              break;
            }
          }
        },
      }),
    );
  }

  if (config.discovery && config.discovery.directories.length > 0) {
    loops.push(
      startPollLoop({
        intervalMs: config.discovery.intervalMs,
        signal: controller.signal,
        startImmediately: true,
        onTick: () =>
          runDiscoveryScan({
            directories: config.discovery.directories,
            client,
          }),
      }),
    );
  }

  // Windows superseded-certificate retention sweep (ADR-0012 decision 18):
  // only meaningful with execution enabled, since without it no windows-iis
  // renewal can ever have written a ledger row in the first place.
  // runWindowsRetentionSweep itself no-ops (returns null) until the ledger
  // directory exists, so this loop is harmless to start unconditionally on
  // an execution-enabled agent that has never touched Windows targets.
  if (executionContext) {
    const retentionStateDir = resolveAgentStateDir(executionContext);
    if (retentionStateDir) {
      loops.push(
        startPollLoop({
          intervalMs: config.windows.sweepIntervalMs,
          signal: controller.signal,
          startImmediately: true,
          onTick: () =>
            runWindowsRetentionSweep({
              stateDir: retentionStateDir,
              retentionHours: config.windows.supersededRetentionHours,
              log: defaultAgentLogger,
              ...(executionContext.windowsExecFileImpl
                ? { execFileImpl: executionContext.windowsExecFileImpl }
                : {}),
              ...(executionContext.windowsConnectImpl
                ? { connectImpl: executionContext.windowsConnectImpl }
                : {}),
            }).catch((err) => {
              defaultAgentLogger.error(
                `tokentimer-agent: windows-retention sweep failed: ${err.message}`,
              );
            }),
        }),
      );
    }
  }

  try {
    await Promise.all(loops);
  } finally {
    process.removeListener("SIGINT", stop);
    process.removeListener("SIGTERM", stop);
    if (externalSignal) externalSignal.removeEventListener("abort", stop);
  }
}

module.exports = {
  runAgent,
  handleClaimedJob,
  UNVERIFIED_JOB_ID_PLACEHOLDER,
  executeJob,
  executeDeployJob,
  executeRenewJob,
  executeWindowsIisRenewJob,
  runWindowsIisDeployTail,
  recordSupersededWindowsCertificate,
  runDeployReloadVerify,
  runDeployReloadVerifyForTargets,
  buildExecutionContext,
  buildJobPolicyDescriptor,
  resolveJobCertPath,
  resolveJobDeployTargets,
  resolveJobSans,
  mapJobKeyAlgorithm,
  resolveJobMode,
  isValidCertificateId,
  runDiscoveryScan,
  runWindowsRetentionSweep,
  registerIfNeeded,
  createCandidateAgentId,
  resolveClaimSupportedActions,
  shouldPollForJobs,
  persistAndTransmitOutcome,
  adoptSigningKeyRotation,
  renewJobLeaseOrAbort,
  createLeaseState,
  startPeriodicLeaseRenewal,
  stopPeriodicLeaseRenewal,
  AGENT_VERSION,
  AGENT_RETIRED_EXIT_CODE,
  EXECUTABLE_JOB_ACTIONS,
  OBSERVE_ONLY_CLAIM_ACTIONS,
  DEFAULT_JOB_LEASE_MS,
  MAX_LEASE_TRANSIENT_RETRIES,
  LEASE_HEARTBEAT_INTERVAL_MS,
  verifyDeployedCertificateWithRetry,
  MAX_VERIFY_TRANSIENT_RETRIES,
  VERIFY_TRANSIENT_RETRY_DELAYS_MS,
  AGENT_CANDIDATE_CAPABILITIES,
  AGENT_DECLARED_CAPABILITIES,
  resolveDeclaredCapabilities,
};
