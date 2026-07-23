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
 * Job execution is deliberately NOT implemented here. Ed25519 signature
 * verification, the replay cache, and clock-drift handling are runtime
 * runtime work (ADR-0003); until that lands, every policy-allowed job is
 * reported back as "blocked" with an explanatory error message, and every
 * policy-rejected job is reported as "rejected" with evidence. This keeps
 * the full outbound loop (register -> heartbeat -> claim -> result/evidence)
 * exercisable end to end against the fake-agent harness without ever
 * running an unverified job.
 *
 * Execution scope (future): src/keys, src/x509, src/acme, src/deploy, src/reload,
 * src/connectors become load-bearing; today they are placeholders.
 */

const os = require("node:os");

const {
  resolveConfigDir,
  loadAgentConfig,
  readCredential,
  persistRegistration,
  recoverPendingRegistration,
  readCaBundle,
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

const { version: AGENT_VERSION } = require("../package.json");

/**
 * Maps a claimed job payload (packages/contracts/certops/job-payload.
 * schema.json shape) onto the policy engine's jobDescriptor vocabulary.
 *
 * The claimed-job validator checks the full frozen public job shape first.
 * Action-specific policy dimensions are required in public metadata and are
 * never silently omitted. The bootstrap agent still does not execute jobs.
 *
 * @param {object} job claimed job payload
 * @returns {object} policy jobDescriptor
 */
function buildJobPolicyDescriptor(job) {
  return validateClaimedJob(job).policyDescriptor;
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
 * Handles a single claimed job in bootstrap mode: evaluate agent-local
 * policy, then report either a policy rejection (with evidence) or a
 * "blocked" result explaining that execution lands with the signed-dispatch
 * runtime. Never throws for per-job failures; errors are reported through
 * the protocol client and logged.
 *
 * Exported for direct unit testing.
 *
 * @param {object} params
 * @param {object} params.job claimed job payload
 * @param {object} params.policyEngine from createPolicyEngine
 * @param {object} params.client from createProtocolClient
 * @param {(msg: string) => void} [params.log]
 * @returns {Promise<{ status: string, rejectionReason: string|null }>}
 */
async function handleClaimedJob({ job, policyEngine, client, log = null }) {
  const reportableJobId = hasReportableJobId(job?.jobId) ? job.jobId : null;
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

    // Bootstrap deliberately never executes a job. Signed dispatch and every
    // execution mechanism remain out of PR #78 scope.
    await client.reportResult({
      jobId: validatedJob.jobId,
      attemptId,
      status: "blocked",
      errorMessage: "agent runtime does not execute jobs yet",
    });
    return { status: "blocked", rejectionReason: null };
  } catch (err) {
    emitLog(log, `failed while handling claimed job ${validatedJob.jobId}`, err);
    return { status: "failed", rejectionReason: null };
  }
}

/**
 * Runs one observe-only discovery scan over the configured directories and
 * reports parsed certificates as `certificate.observed` evidence. Only
 * public fields ever leave the host: the discovery module never reads key
 * bytes, and metadata here is limited to schema-safe names/values. Evidence
 * bodies are chunked to the schema's 16-item maximum.
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

  const items = [];
  const observedAt = new Date().toISOString();
  for (const cert of certificates) {
    if (!cert.parsed) continue;
    items.push(
      buildEvidenceItem({
        eventType: "certificate.observed",
        observedAt,
        fingerprintSha256: cert.fingerprintSha256,
        summary: `Observed certificate at ${cert.path} (subject: ${cert.subject})`,
        metadata: [
          { name: "validTo", value: cert.validTo },
          { name: "coLocatedKeyDetected", value: cert.coLocatedKeyDetected === true },
        ],
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
 * token is single-use and never persisted by the agent.
 *
 * @param {object} params
 * @param {object} params.client
 * @param {object} params.config from loadAgentConfig
 * @param {string} params.configDir
 * @param {NodeJS.ProcessEnv} [params.env]
 * @returns {Promise<string>} the assigned agentId
 */
async function registerIfNeeded({ client, config, configDir, env = process.env }) {
  const recovered = recoverPendingRegistration(configDir);
  if (recovered !== null) return recovered.agentId;

  const existingCredential = readCredential(configDir);
  if (existingCredential !== null) {
    if (!config.agentId) {
      throw new Error(
        "tokentimer-agent: found a stored credential but no agentId in " +
          "config.json; the config directory is inconsistent. Re-register " +
          "with a fresh bootstrap token or restore config.json.",
      );
    }
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

  const registration = validateRegistrationResponse(await client.register({
    bootstrapToken,
    bootstrapTokenId: env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID || "unknown",
    agentVersion: AGENT_VERSION,
    hostname: os.hostname(),
    platform: process.platform,
    nodeVersion: process.version,
    declaredTargetSelectors: config.declaredTargetSelectors,
    declaredCommandProfileNames: config.declaredCommandProfileNames,
  }), config.protocolVersion);

  persistRegistration(configDir, {
    agentId: registration.agentId,
    credential: registration.credential,
  });
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

  const clientForAgentId = (agentId) =>
    createProtocolClient({
      serverUrl: config.serverUrl,
      agentId,
      protocolVersion: config.protocolVersion,
      getCredential: () => readCredential(configDir),
      signal: controller.signal,
      fetchImpl,
      allowInsecureLocalHttp: config.allowInsecureLocalHttp,
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

  const startedAtMs = Date.now();

  const heartbeatLoop = startPollLoop({
    intervalMs: config.heartbeatIntervalMs,
    signal: controller.signal,
    startImmediately: true,
    onTick: async () => {
      const response = await client.heartbeat({
        agentVersion: AGENT_VERSION,
        uptimeSeconds: Math.floor((Date.now() - startedAtMs) / 1000),
        // ntpSynced / pinnedSigningKeyId / clockOffsetMs are signed-dispatch
        // runtime concerns (drift measurement, key pinning); reported as
        // null until that lands.
      });
      if (response && response.retired === true) {
        defaultAgentLogger.error("control plane retired this agent; exiting cleanly");
        stop();
      }
    },
  });

  const claimLoop = startPollLoop({
    intervalMs: config.pollIntervalMs,
    signal: controller.signal,
    startImmediately: true,
    onTick: async () => {
      const jobs = await client.claim({ maxJobs: 1 });
      for (const job of jobs) {
        if (controller.signal.aborted) break;
        await handleClaimedJob({ job, policyEngine, client });
      }
    },
  });

  // Observe-only discovery loop (filesystem certificate inventory).
  // Only started when config.json opts in with a discovery.directories list;
  // scans run immediately on start, then on the configured interval.
  const loops = [heartbeatLoop, claimLoop];
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
  buildJobPolicyDescriptor,
  runDiscoveryScan,
  registerIfNeeded,
  createCandidateAgentId,
  AGENT_VERSION,
};
