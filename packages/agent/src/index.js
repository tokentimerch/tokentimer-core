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
const { verifyJobSignature, checkJobTimeWindow } = require("./signing");
const { createReplayCache } = require("./replay");
const { createClockOffsetEstimator } = require("./clock");
const { generateKeyPairToFile, discardStagedKey, generateCsr } = require("./keys");
const { createAcmeAdapter } = require("./acme");
const {
  deployCertificate,
  deployCertificateAndKey,
  discardDeployBackups,
  removeDeployedArtifacts,
  getDeployMetrics,
} = require("./deploy");
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
 * happens inside verifyJobSignature (findSignedFieldProblem) BEFORE this
 * mapping runs, so only the policy-dimension projection is done here.
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

/**
 * Actions this agent build can actually execute (executeJob): "revoke" is
 * deliberately absent (always blocked in this build). Sent as the claim's
 * supportedActions when execution is enabled so the control plane's claim
 * query only leases jobs this agent can run.
 */
const EXECUTABLE_JOB_ACTIONS = Object.freeze(["noop", "renew", "deploy", "reload"]);

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
 * agents must not claim (B3): discovery and heartbeat stay independent.
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
      type: typeof item?.type === "string" ? item.type : job?.target?.type ?? "endpoint",
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
 * retry and never rewrite a persisted success as a failure (B8).
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
  log(
    `tokentimer-agent: job ${jobId} rejected: ${verdict.rejectionReason}`,
  );
  const evidenceBody = buildPolicyRejectionEvidence({
    rejectionReason: verdict.rejectionReason,
    detail: verdict.detail,
    jobId,
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
 * Builds + safety-scans + reports one evidence body of pre-built items.
 *
 * @param {object} client
 * @param {string} jobId
 * @param {object[]} items evidence items (buildEvidenceItem inputs)
 * @returns {Promise<void>}
 */
async function reportStepEvidence(client, jobId, items) {
  const body = buildEvidenceBody({ jobId, evidenceItems: items });
  assertEvidencePayloadSafe(body);
  await client.reportEvidence(body);
}

/**
 * Handles a single claimed job.
 *
 * Without an execution context (observe-only bootstrap mode, executionContext null or
 * enabled:false): evaluate agent-local policy, then report either a policy
 * rejection (with evidence) or a "blocked" result explaining that execution
 * is not enabled. This branch is byte-for-byte the observe-only bootstrap behavior.
 *
 * With an enabled execution context: run the full trust chain in
 * order -- signature verify -> replay check -> clock window check -> policy
 * evaluateJob -> replay consume -> executeJob. Any { allowed: false }
 * verdict reports policy.checked evidence + a "rejected" result with that
 * rejectionReason. A job missing its signed-dispatch fields is rejected
 * with job_integrity_failed (unsigned jobs must never execute). If no
 * signing key is pinned yet, jobs are "blocked" (never executed) until
 * registration pins one.
 *
 * Never throws for per-job failures; errors are reported through the
 * protocol client and logged.
 *
 * Exported for direct unit testing.
 *
 * @param {object} params
 * @param {object} params.job claimed job payload
 * @param {object} params.policyEngine from createPolicyEngine
 * @param {object} params.client from createProtocolClient
 * @param {object|null} [params.executionContext] from
 *   buildExecutionContext; null preserves observe-only bootstrap behavior
 * @param {(msg: string) => void} [params.log]
 * @returns {Promise<{ status: string, rejectionReason: string|null }>}
 */
async function handleClaimedJob({
  job,
  policyEngine,
  client,
  executionContext = null,
  log = null,
}) {
  const reportableJobId = hasReportableJobId(job?.jobId) ? job.jobId : null;
  const executionEnabled =
    executionContext !== null && executionContext.enabled === true;

  if (executionEnabled) {
    if (!reportableJobId) {
      emitLog(log, "claimed job missing a reportable jobId; skipping");
      return { status: "skipped", rejectionReason: "job_integrity_failed" };
    }
    // Signed dispatch assigns attemptId server-side (mirroring claimId);
    // prefer it, then claimId itself, then a local fallback so result
    // reporting stays schema-valid and idempotency-debuggable.
    const signedAttemptId =
      typeof job.attemptId === "string" && job.attemptId.length > 0
        ? job.attemptId
        : typeof job.claimId === "string" && job.claimId.length > 0
          ? job.claimId
          : localAttemptId(reportableJobId);
    return handleSignedJob({
      job,
      jobId: reportableJobId,
      attemptId: signedAttemptId,
      policyEngine,
      client,
      executionContext,
      log,
    });
  }

  let validated;
  try {
    validated = validateClaimedJob(job);
  } catch (err) {
    emitLog(log, "rejected malformed claimed job before policy evaluation", err);
    if (!reportableJobId) {
      return { status: "skipped", rejectionReason: "job_integrity_failed" };
    }
    try {
      const attemptId = localAttemptId(reportableJobId);
      const evidenceBody = buildPolicyRejectionEvidence({
        rejectionReason: "job_integrity_failed",
        detail: "Claimed job failed agent-side shape and policy-dimension validation.",
        jobId: reportableJobId,
      });
      assertEvidencePayloadSafe(evidenceBody);
      await client.reportEvidence(evidenceBody);
      await client.reportResult({
        jobId: reportableJobId,
        attemptId,
        status: "rejected",
        rejectionReason: "job_integrity_failed",
      });
      return { status: "rejected", rejectionReason: "job_integrity_failed" };
    } catch (reportError) {
      emitLog(log, "failed to report malformed claimed job", reportError);
      return { status: "failed", rejectionReason: "job_integrity_failed" };
    }
  }

  const { job: validatedJob, policyDescriptor } = validated;
  const attemptId = localAttemptId(validatedJob.jobId);
  try {
    const verdict = policyEngine.evaluateJob(policyDescriptor);
    if (!verdict.allowed) {
      emitLog(log, `job ${validatedJob.jobId} rejected by agent-local policy`, {
        rejectionReason: verdict.rejectionReason,
      });
      const evidenceBody = buildPolicyRejectionEvidence({
        rejectionReason: verdict.rejectionReason,
        detail: verdict.detail,
        jobId: validatedJob.jobId,
      });
      assertEvidencePayloadSafe(evidenceBody);
      await client.reportEvidence(evidenceBody);
      await client.reportResult({
        jobId: validatedJob.jobId,
        attemptId,
        status: "rejected",
        rejectionReason: verdict.rejectionReason,
      });
      return { status: "rejected", rejectionReason: verdict.rejectionReason };
    }

    // Execution is not configured on this agent: report "blocked" rather
    // than silently dropping so the control plane sees an explicit
    // terminal state.
    await client.reportResult({
      jobId: validatedJob.jobId,
      attemptId,
      status: "blocked",
      errorMessage: "agent execution is not enabled on this agent",
    });
    return { status: "blocked", rejectionReason: null };
  } catch (err) {
    emitLog(log, `failed while handling claimed job ${validatedJob.jobId}`, err);
    return { status: "failed", rejectionReason: null };
  }
}

/**
 * Trust chain for a claimed job when execution is enabled. Order per
 * ADR-0003 (and tests/integration/agent-protocol.test.js
 * runVerificationChain): signature verify -> replay check -> clock window
 * check -> policy -> replay consume -> execute. The replay nonce is
 * consumed only after every gate passed, so a rejected job does not burn
 * its nonce, but it IS consumed before execution starts, so a crash
 * mid-execution can never allow a replay.
 *
 * @param {object} params see handleClaimedJob
 * @returns {Promise<{ status: string, rejectionReason: string|null }>}
 */
async function handleSignedJob({
  job,
  jobId,
  attemptId,
  policyEngine,
  client,
  executionContext,
  log,
}) {
  const { pinnedSigningKey, replayCache, clockEstimator, execution, outboxDir } =
    executionContext;
  // Server-assigned claim id and single-use dispatch nonce: forwarded on
  // every result so the control plane can re-prove claim ownership and
  // consume the nonce in its replay ledger (ADR-0003).
  const claimId =
    typeof job?.claimId === "string" && job.claimId.length > 0
      ? job.claimId
      : null;
  const nonce =
    typeof job?.nonce === "string" && job.nonce.length > 0 ? job.nonce : null;

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

  // No pinned key => integrity of ANY job cannot be established. Blocked,
  // not rejected: this is an agent-side precondition failure, not a verdict
  // about the job itself.
  if (!pinnedSigningKey) {
    return persistAndTransmitOutcome({
      outboxDir: resolvedOutboxDir,
      client,
      result: {
        jobId,
        attemptId,
        claimId,
        nonce,
        status: "blocked",
        errorMessage:
          "execution is enabled but no control-plane signing key is pinned " +
          "yet (the register response did not carry one); unsigned or " +
          "unverifiable jobs are never executed",
      },
      log,
    });
  }

  // 1. Signature (covers the base-payload fallback: a job without signed
  // fields fails field validation inside verifyJobSignature and is
  // rejected with job_integrity_failed).
  const signatureVerdict = verifyJobSignature({
    job,
    publicKeyPem: pinnedSigningKey.publicKeyPem,
    pinnedSigningKeyId: pinnedSigningKey.signingKeyId,
  });
  if (!signatureVerdict.allowed) {
    return reportJobRejection({ ...rejectionArgs, verdict: signatureVerdict });
  }

  // 2. Replay check (no consume yet).
  const replayVerdict = replayCache.check({
    nonce: job.nonce,
    jobId,
    expiresAt: job.expiresAt,
  });
  if (!replayVerdict.allowed) {
    return reportJobRejection({ ...rejectionArgs, verdict: replayVerdict });
  }

  // 3. Clock window with drift compensation.
  const windowVerdict = checkJobTimeWindow({
    job,
    nowMs: Date.now(),
    clockOffsetMs: clockEstimator.getOffsetMs(),
    toleranceMs: execution.clockDriftToleranceMs,
  });
  if (!windowVerdict.allowed) {
    return reportJobRejection({ ...rejectionArgs, verdict: windowVerdict });
  }

  // 4. Agent-local policy (default deny; ADR-0002 local policy wins).
  const policyVerdict = policyEngine.evaluateJob(buildSignedJobPolicyDescriptor(job));
  if (!policyVerdict.allowed) {
    return reportJobRejection({ ...rejectionArgs, verdict: policyVerdict });
  }

  // 5. Consume the nonce before executing (see function doc comment).
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
  // success as "failed" (B8). Periodic lease heartbeat covers long ACME/DNS
  // stages that can approach the 15-minute lease TTL without stage-boundary
  // renews.
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
    log(`tokentimer-agent: job ${jobId} execution error: ${err.message}`);
    outcome = {
      status: "failed",
      errorMessage: boundErrorMessage(`job execution failed: ${err.message}`),
    };
  } finally {
    stopPeriodicLeaseRenewal(leaseHeartbeat);
  }

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

  if (action === "noop") {
    await reportStepEvidence(client, jobId, [
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
      client,
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
    return executeRenewJob({
      job,
      jobId,
      policyEngine,
      client,
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
      client,
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
    client,
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

  // The ACME client writes to a job-scoped staging path; the deploy module
  // then owns the atomic install (with backup/rollback) to certPath.
  const stagedCertPath = path.join(execution.keysDir, `${jobId}.cert.pem`);

  try {
    // Step 3: ACME renewal via the policy-resolved command profile.
    {
      const leaseGate = await renewJobLeaseOrAbort(leaseOpts || {});
      if (leaseGate && leaseGate.ok === false) {
        discardStagedKey({ keyPath, stagedKeyPath });
        return leaseGate.abort;
      }
    }
    if (typeof onBeforeMutation === "function") onBeforeMutation("acme");
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
      discardStagedKey({ keyPath, stagedKeyPath });
      return {
        status: "rejected",
        rejectionReason: renewal.rejectionReason,
        errorMessage: boundErrorMessage(renewal.detail),
      };
    }
    if (renewal.renewed !== true) {
      discardStagedKey({ keyPath, stagedKeyPath });
      await reportStepEvidence(client, jobId, [
        buildEvidenceItem({
          eventType: "validation.failed",
          observedAt: new Date().toISOString(),
          summary: `ACME renewal step failed for job ${jobId} (exit code ${renewal.exitCode}).`,
          metadata: [{ name: "step", value: "acme" }, { name: "exitCode", value: renewal.exitCode }],
        }),
      ]);
      return {
        status: "failed",
        keyRotated,
        errorMessage: boundErrorMessage(
          `acme step failed with exit code ${renewal.exitCode}: ${renewal.stderrExcerpt || "no stderr"}`,
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
  } finally {
    // The CSR is public material, but it is job-scoped scratch: remove it.
    fs.rmSync(csrPath, { force: true });
  }

  // Steps 4-6 are shared with the deploy action (possibly multi-target).
  let certificatePem;
  try {
    certificatePem = fs.readFileSync(stagedCertPath, "utf8");
  } catch (err) {
    discardStagedKey({ keyPath, stagedKeyPath });
    return {
      status: "failed",
      keyRotated,
      errorMessage: boundErrorMessage(
        `acme step reported success but produced no certificate file: ${err.message}`,
      ),
    };
  } finally {
    fs.rmSync(stagedCertPath, { force: true });
  }
  const tail = await runDeployReloadVerifyForTargets({
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
  if (tail.status !== "succeeded") {
    discardStagedKey({ keyPath, stagedKeyPath });
  }
  return { ...tail, keyRotated };
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

    const probe = await verifyDeployedCertificate({
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
  await reportStepEvidence(client, jobId, [
    buildEvidenceItem({
      eventType: "validation.passed",
      observedAt: new Date().toISOString(),
      fingerprintSha256: fingerprint,
      summary: verifySummary,
      metadata: [{ name: "step", value: "verify" }],
    }),
  ]);

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
  const outcome = await reloadService({
    service: job.reloadService,
    commandProfiles: {
      validateArgv: validateVerdict.argv,
      reloadArgv: reloadVerdict.argv,
    },
  });
  if (outcome.reloaded !== true) {
    log(`tokentimer-agent: reload step failed for job ${jobId}`);
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
 * @returns {Promise<string>} the assigned agentId
 */
async function registerIfNeeded({ client, config, configDir, env = process.env }) {
  // Already-registered paths: an earlier run exchanged the bootstrap token,
  // but systemd may still have re-exported it from a leftover bootstrap.env.
  // Scrub it here too so a registered agent never keeps the (already spent)
  // token in its environment or on disk.
  const scrubBootstrapToken = () => {
    if (env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN !== undefined) {
      delete env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN;
      delete env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID;
    }
    deleteBootstrapEnvFile(configDir);
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
  // (so it can never leak into child processes or diagnostics) and remove
  // the installer-written bootstrap.env file (so systemd stops re-exporting
  // it on every later start).
  delete env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN;
  delete env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID;
  deleteBootstrapEnvFile(configDir);
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
 * stub the ACME child process.
 *
 * @param {object} params
 * @param {object} params.config from loadAgentConfig
 * @param {Function} [params.acmeExecFileImpl] test-only execFile override
 * @returns {{
 *   enabled: true,
 *   execution: object,
 *   outboxDir: string,
 *   replayCache: object,
 *   clockEstimator: object,
 *   pinnedSigningKey: {signingKeyId: string, publicKeyPem: string}|null,
 *   acmeExecFileImpl: Function|undefined,
 * }|null}
 */
function buildExecutionContext({ config, acmeExecFileImpl } = {}) {
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
      const response = await client.heartbeat({
        agentVersion: AGENT_VERSION,
        uptimeSeconds: Math.floor((Date.now() - startedAtMs) / 1000),
        supportedDnsProviders,
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
            const outcome = await handleClaimedJob({
              job,
              policyEngine,
              client,
              executionContext,
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
  executeJob,
  executeDeployJob,
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
};
