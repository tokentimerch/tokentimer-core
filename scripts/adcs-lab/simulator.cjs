"use strict";
// Test-only wire client. No Windows, network targets, CA, keys or installation.
const crypto = require("node:crypto");
const { guard, readState } = require("./common.cjs");
const signing = require("../../packages/agent/src/signing");
const CA = "simulated-ca.example.test\\SIMULATED Developer CA",
  TEMPLATE = "SimulatedWebServer",
  KEY = "ab".repeat(32);
async function machine(
  agent,
  route,
  messageType,
  body,
  credential = agent.credential,
  retry = 0,
) {
  guard();
  const response = await fetch(
    `http://localhost:55471/api/v1/certops/agent/${route}`,
    {
      method: "POST",
      signal: AbortSignal.timeout(30000),
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${credential}`,
      },
      body: JSON.stringify({
        schemaVersion: 1,
        protocolVersion: "1.0.0",
        messageType,
        agentId: agent.agentId,
        sentAt: new Date().toISOString(),
        body,
      }),
    },
  );
  const result = await response.json();
  if (response.status === 429 && retry < 3) {
    const seconds = Number(response.headers.get("retry-after"));
    if (Number.isFinite(seconds) && seconds >= 0 && seconds <= 60) {
      console.log(
        JSON.stringify({
          simulated: true,
          route,
          status: 429,
          retryAfterSeconds: seconds,
        }),
      );
      await new Promise((resolve) => setTimeout(resolve, (seconds + 1) * 1000));
      return machine(agent, route, messageType, body, credential, retry + 1);
    }
  }
  if (!response.ok)
    throw Error(
      `Simulated agent ${route}: ${response.status} ${result.code || result.error}`,
    );
  return result;
}
const capabilities = [
  "adcs-enroll-v1",
  "signed-payload-b64-v1",
  "agent-id-binding-v1",
  "evidence-claim-binding-v1",
];
async function register(request, prefix, name, targets, eligible = true) {
  const bootstrap = await request(`${prefix}/agent-bootstrap-tokens`, "POST", {
    name: `SIMULATED ${name}`,
    expiresAt: new Date(Date.now() + 3600000).toISOString(),
  });
  const agent = { agentId: crypto.randomUUID(), targets, eligible };
  const result = await machine(
    agent,
    "register",
    "register",
    {
      bootstrapTokenId: bootstrap.token.id,
      registrationId: crypto.randomUUID(),
      hostname: `simulated-${name}`,
      platform: "win32",
      agentVersion: "0.19.2-rc.1",
      declaredTargetSelectors: targets,
      declaredCapabilities: eligible ? capabilities : [],
    },
    bootstrap.plaintextToken,
  );
  Object.assign(agent, result);
  await heartbeat(agent);
  return agent;
}
async function heartbeat(agent) {
  return machine(agent, "heartbeat", "heartbeat", {
    agentVersion: "0.19.2-rc.1",
    pinnedSigningKeyId: agent.signingKeyId,
    ntpSynced: true,
    supportedOperations: ["adcs-preflight", "renew", "continue-enrollment"],
    declaredCapabilities: agent.eligible ? capabilities : [],
    declaredTargetSelectors: agent.targets,
  });
}
function preflight(mode) {
  return {
    caConfig: CA,
    template: TEMPLATE,
    templateCheck: {
      verdict: mode === "unsafe" ? "unsafe" : "safe",
      reasons: mode === "unsafe" ? ["eku_not_server_auth_only"] : [],
      schemaVersion: 2,
      templateOid: "1.3.6.1.4.1.311.21.8.123",
      minimalKeySize: 2048,
      enrolleeSuppliesSubject: true,
    },
    caCheck: { verdict: "safe", reasons: [], operatorAttested: false },
    caCertificates: [
      {
        certificateB64: "U0lNVUxBVEVE",
        keySha256: mode === "changed-key" ? "cd".repeat(32) : KEY,
        thumbprintSha1: "a".repeat(40),
        notBefore: new Date(Date.now() - 86400000).toISOString(),
        notAfter: new Date(Date.now() + 365 * 86400000).toISOString(),
      },
    ],
  };
}
async function execute(agent, { mode = "safe", maxJobs = 16 } = {}) {
  await heartbeat(agent);
  const claim = await machine(agent, "jobs/claim", "claim", {
    maxJobs,
    supportedActions: ["adcs-preflight", "renew", "continue-enrollment"],
  });
  const outcomes = [];
  for (const claimed of claim.jobs) {
    const verified = signing.verifyJobEnvelope({
      claimed,
      publicKeyPem: agent.signingPublicKeyPem,
      pinnedSigningKeyId: agent.signingKeyId,
    });
    if (!verified.allowed)
      throw Error("Simulator refused invalid signed envelope");
    const job = verified.job;
    if (
      !signing.checkJobTimeWindow({ job, nowMs: Date.now() }).allowed ||
      job.workspaceId !== readState().workspaceId ||
      job.agentId !== agent.agentId
    )
      throw Error("Simulator refused job identity/time binding");
    if (mode === "timeout") {
      outcomes.push({ jobId: job.jobId, status: "held-for-timeout" });
      continue;
    }
    const body = {
      jobId: job.jobId,
      attemptId: job.attemptId,
      claimId: job.claimId,
      nonce: job.nonce,
      status: "succeeded",
      keyRotated: false,
    };
    if (job.action === "adcs-preflight") {
      if (mode === "unavailable" || mode === "exhausted")
        Object.assign(body, {
          status: "failed",
          errorMessage:
            "ADCS_CA_UNREACHABLE: SIMULATED CA connectivity failure",
        });
      else body.preflightResult = preflight(mode);
    } else if (["renew", "continue-enrollment"].includes(job.action)) {
      // This is an explicitly simulated agent attestation, never a native proof.
      const fingerprint = crypto
        .createHash("sha256")
        .update(`SIMULATED:${job.jobId}`)
        .digest("hex");
      const facts = {
        step: "verify",
        simulated: true,
        validFrom: new Date().toISOString(),
        validTo: new Date(Date.now() + 365 * 86400000).toISOString(),
        serialNumber: job.jobId.replaceAll("-", ""),
        subject: `CN=${job.target.reference}`,
        issuer: "CN=SIMULATED Developer CA",
        subjectAltNames: job.target.reference,
      };
      await machine(agent, "jobs/results", "evidence", {
        jobId: job.jobId,
        claimId: job.claimId,
        evidenceItems: [
          {
            evidenceId: crypto.randomUUID(),
            eventType: "validation.passed",
            observedAt: new Date().toISOString(),
            fingerprintSha256: fingerprint,
            summary:
              "SIMULATED installation and verification; no native CA or TLS execution",
            metadata: Object.entries(facts).map(([name, value]) => ({
              name,
              value,
            })),
          },
        ],
      });
      body.enrollmentResult = {
        enrollmentId: job.enrollment.enrollmentId,
        attempt: job.enrollment.attempt,
        state: "installed",
        requestId: 1,
      };
    } else throw Error("Simulator refuses unsupported action");
    const result = await machine(agent, "jobs/results", "result", body);
    outcomes.push({
      jobId: job.jobId,
      action: job.action,
      status: result.status,
      simulated: true,
    });
  }
  return outcomes;
}
module.exports = {
  CA,
  TEMPLATE,
  KEY,
  register,
  heartbeat,
  execute,
  preflight,
  machine,
};
