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
 * M4 bootstrap scope (current): this file wires the landed modules together
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
 * verification, the replay cache, and clock-drift handling are Phase 4
 * runtime work (ADR-0003); until that lands, every policy-allowed job is
 * reported back as "blocked" with an explanatory error message, and every
 * policy-rejected job is reported as "rejected" with evidence. This keeps
 * the full outbound loop (register -> heartbeat -> claim -> result/evidence)
 * exercisable end to end against the fake-agent harness without ever
 * running an unverified job.
 *
 * M5 scope (future): src/keys, src/x509, src/acme, src/deploy, src/reload,
 * src/connectors become load-bearing; today they are placeholders.
 */

const os = require("node:os");

const {
  resolveConfigDir,
  loadAgentConfig,
  writeAgentIdentity,
  readCredential,
  writeCredential,
} = require("./config");
const { loadPolicyConfig, createPolicyEngine } = require("./policy");
const {
  createProtocolClient,
  startPollLoop,
} = require("./protocol");
const {
  buildPolicyRejectionEvidence,
  buildEvidenceItem,
  buildEvidenceBody,
  assertEvidencePayloadSafe,
} = require("./evidence");
const { discoverCertificates } = require("./discovery");

const { version: AGENT_VERSION } = require("../package.json");

/**
 * Maps a claimed job payload (packages/contracts/certops/job-payload.
 * schema.json shape) onto the policy engine's jobDescriptor vocabulary.
 *
 * Only fields that are present on the job are forwarded: the policy engine
 * checks each dimension independently, and absent dimensions are simply not
 * checked (checkNoKeyExport always runs). The M2 job payload does not carry
 * commandRef/caEndpoint/dnsZone/dnsProvider yet; those become load-bearing
 * with the Phase 4 signed dispatch payload, and this mapping already passes
 * them through when present so Phase 4 does not need to change call sites.
 *
 * @param {object} job claimed job payload
 * @returns {object} policy jobDescriptor
 */
function buildJobPolicyDescriptor(job) {
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

/**
 * Handles a single claimed job in M4 bootstrap mode: evaluate agent-local
 * policy, then report either a policy rejection (with evidence) or a
 * "blocked" result explaining that execution lands with the Phase 4
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
async function handleClaimedJob({ job, policyEngine, client, log = console.error }) {
  const jobId = job?.jobId;
  if (typeof jobId !== "string" || jobId.length === 0) {
    log("tokentimer-agent: claimed job missing jobId; skipping");
    return { status: "skipped", rejectionReason: null };
  }
  // The M2 payload does not carry attemptId (it is an M4 signed-dispatch
  // addition); until the control plane assigns one, derive a local id so
  // result reporting stays schema-valid and idempotency-debuggable.
  const attemptId =
    typeof job.attemptId === "string" && job.attemptId.length > 0
      ? job.attemptId
      : `local-${jobId}-${Date.now()}`;

  const verdict = policyEngine.evaluateJob(buildJobPolicyDescriptor(job));

  if (!verdict.allowed) {
    log(
      `tokentimer-agent: job ${jobId} rejected by agent-local policy: ${verdict.rejectionReason}`,
    );
    const evidenceBody = buildPolicyRejectionEvidence({
      rejectionReason: verdict.rejectionReason,
      detail: verdict.detail,
      jobId,
    });
    assertEvidencePayloadSafe(evidenceBody);
    await client.reportEvidence(evidenceBody);
    await client.reportResult({
      jobId,
      attemptId,
      status: "rejected",
      rejectionReason: verdict.rejectionReason,
    });
    return { status: "rejected", rejectionReason: verdict.rejectionReason };
  }

  // Policy allows the job, but M4 bootstrap has no execution runtime yet
  // (signature verification / replay cache are Phase 4, ADR-0003). Report
  // "blocked" rather than silently dropping so the control plane sees an
  // explicit terminal state.
  await client.reportResult({
    jobId,
    attemptId,
    status: "blocked",
    errorMessage:
      "agent runtime does not execute jobs yet (M4 bootstrap; execution lands with the Phase 4 runtime)",
  });
  return { status: "blocked", rejectionReason: null };
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
async function runDiscoveryScan({ directories, client, log = console.error }) {
  const { certificates, warnings, truncated } = discoverCertificates(directories, {
    onWarning: (message) => log(`tokentimer-agent: ${message}`),
  });
  if (truncated) {
    log("tokentimer-agent: discovery scan hit a bound and was truncated");
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

  const { agentId } = await client.register({
    bootstrapToken,
    bootstrapTokenId: env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID || "unknown",
    agentVersion: AGENT_VERSION,
    hostname: os.hostname(),
    platform: process.platform,
    nodeVersion: process.version,
    declaredTargetSelectors: config.declaredTargetSelectors,
    declaredCommandProfileNames: config.declaredCommandProfileNames,
  });

  writeAgentIdentity(configDir, { agentId });
  return agentId;
}

/**
 * Runs the agent process: load config, register if needed, then run the
 * heartbeat and claim loops until SIGINT/SIGTERM or until the control plane
 * retires this agent (heartbeat HTTP 410 -> clean exit, no respawn loop,
 * ADR-0002 / plan 7.7 item 11).
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

  // Default deny: with no policy block in config.json every allowlist is
  // empty, so the engine rejects all command/path/CA/DNS dimensions. The
  // agent still runs (heartbeats, claims, reports rejections as evidence)
  // so operators can see policy conflicts instead of silent failures.
  const policyEngine = createPolicyEngine(loadPolicyConfig(config.policy || {}), {
    declaredTargetSelectors: config.declaredTargetSelectors,
  });

  const clientForAgentId = (agentId) =>
    createProtocolClient({
      serverUrl: config.serverUrl,
      agentId,
      protocolVersion: config.protocolVersion,
      getCredential: () => readCredential(configDir),
      onCredentialIssued: (rawCredential) => writeCredential(configDir, rawCredential),
    });

  // For a not-yet-registered agent the envelope needs a client-generated
  // candidate id; the control plane echoes back the assigned id (schema
  // note on agentId). A registered agent uses its stored id.
  const candidateAgentId = config.agentId || `candidate-${os.hostname()}-${process.pid}`;
  const registeredAgentId = await registerIfNeeded({
    client: clientForAgentId(candidateAgentId),
    config,
    configDir,
  });

  const client = clientForAgentId(registeredAgentId);

  const controller = new AbortController();
  const stop = () => controller.abort();
  if (externalSignal) {
    if (externalSignal.aborted) return;
    externalSignal.addEventListener("abort", stop, { once: true });
  }
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);

  const startedAtMs = Date.now();

  const heartbeatLoop = startPollLoop({
    intervalMs: config.heartbeatIntervalMs,
    signal: controller.signal,
    startImmediately: false,
    onTick: async () => {
      const response = await client.heartbeat({
        agentVersion: AGENT_VERSION,
        uptimeSeconds: Math.floor((Date.now() - startedAtMs) / 1000),
        // ntpSynced / pinnedSigningKeyId / clockOffsetMs are Phase 4
        // runtime concerns (drift measurement, key pinning); reported as
        // null until that lands.
      });
      if (response && response.retired === true) {
        console.error(
          "tokentimer-agent: control plane retired this agent; exiting cleanly",
        );
        stop();
      }
    },
  });

  const claimLoop = startPollLoop({
    intervalMs: config.pollIntervalMs,
    signal: controller.signal,
    startImmediately: false,
    onTick: async () => {
      const jobs = await client.claim({ maxJobs: 1 });
      for (const job of jobs) {
        if (controller.signal.aborted) break;
        await handleClaimedJob({ job, policyEngine, client });
      }
    },
  });

  // Observe-only discovery loop (M4: filesystem certificate inventory).
  // Only started when config.json opts in with a discovery.directories list;
  // scans run immediately on start, then on the configured interval.
  const loops = [heartbeatLoop, claimLoop];
  if (config.discovery && config.discovery.directories.length > 0) {
    loops.push(
      startPollLoop({
        intervalMs: config.discovery.intervalMs,
        signal: controller.signal,
        startImmediately: false,
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
  AGENT_VERSION,
};
