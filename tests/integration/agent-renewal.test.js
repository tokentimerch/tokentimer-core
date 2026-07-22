"use strict";

// M5 signed renew job, end to end: the REAL dispatch wiring
// (packages/agent/src/index.js handleClaimedJob -> executeJob) driven
// against the fake control plane (fake-agent.js in signed-dispatch mode).
// No DB. The ACME child process is the ONLY stubbed execution dependency
// (an execFileImpl that fakes certbot by writing a runtime-generated
// certificate PEM to --cert-path); keys and deploy run for real against
// temp directories, reload is skipped (no reloadService on the job), and
// verification uses computeCertificateFingerprint against the deployed
// file (no network probe: the job carries no verifyHost).
//
// Also asserts the custody invariant from agent-protocol.test.js: no
// private-key-shaped content in any protocol message the harness records.

const os = require("node:os");
const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");

const { expect } = require("./setup");
const {
  buildFakeAgentControlPlaneApp,
  createFakeAgent,
} = require("./fake-agent");
const {
  handleClaimedJob,
  buildExecutionContext,
} = require("../../packages/agent/src/index.js");
const {
  loadPolicyConfig,
  createPolicyEngine,
} = require("../../packages/agent/src/policy");
const {
  computeCertificateFingerprint,
} = require("../../packages/agent/src/verify");

// --- custody assertion (reused from agent-protocol.test.js) -----------------

const FORBIDDEN_FIELD_FRAGMENTS = [
  "privatekey",
  "privatekeypem",
  "encryptedprivatekey",
  "keymaterial",
  "pfxblob",
  "jksblob",
  "tlskey",
  "caprivatekey",
  "keystorepassword",
  "privatekeypassword",
  "keypassword",
  "password",
  "secret",
  "rawsecret",
  "rawprivatekey",
  "keypem",
];

const ALLOWED_CREDENTIAL_ADJACENT_NAMES = new Set(["bootstrapTokenId"]);

function normalizeFieldName(name) {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function collectFieldNames(value, names = []) {
  if (Array.isArray(value)) {
    for (const item of value) collectFieldNames(item, names);
    return names;
  }
  if (value === null || typeof value !== "object") return names;
  for (const [key, child] of Object.entries(value)) {
    names.push(key);
    collectFieldNames(child, names);
  }
  return names;
}

function assertNoCustodyShapedContent(payload, label) {
  for (const fieldName of collectFieldNames(payload)) {
    if (ALLOWED_CREDENTIAL_ADJACENT_NAMES.has(fieldName)) continue;
    const normalized = normalizeFieldName(fieldName);
    const hit = FORBIDDEN_FIELD_FRAGMENTS.find((fragment) =>
      normalized.includes(fragment),
    );
    expect(hit, `${label} carries custody-shaped field "${fieldName}"`).to.equal(
      undefined,
    );
  }
  expect(JSON.stringify(payload)).to.not.match(
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  );
}

// --- fixtures ----------------------------------------------------------------

const tempDirs = [];

function makeTempDir(label) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `ttagent-renewal-${label}-`));
  tempDirs.push(dir);
  return dir;
}

// Runtime-generated certificate-shaped PEM. Never a committed fixture: the
// body is a fresh Ed25519 PUBLIC key DER (real, valid base64 DER bytes, no
// key custody risk) wrapped in CERTIFICATE markers. Both the deploy module
// (opaque public payload) and computeCertificateFingerprint (base64 DER
// digest) accept it without parsing X.509 internals.
function generateRuntimeCertificatePem() {
  const { publicKey } = crypto.generateKeyPairSync("ed25519");
  const der = publicKey.export({ type: "spki", format: "der" });
  const body = der.toString("base64").replace(/(.{64})/g, "$1\n").trim();
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
}

// Fake certbot: an execFile-shaped stub that writes `certificatePem` to the
// path following --cert-path in the argv and exits 0. Anything else about
// the argv is recorded for assertions.
function makeFakeCertbotExecFile(certificatePem, recordedInvocations) {
  return (file, args, _options, callback) => {
    recordedInvocations.push({ file, args: [...args] });
    const flagIndex = args.indexOf("--cert-path");
    if (flagIndex === -1 || flagIndex + 1 >= args.length) {
      callback(new Error("fake certbot: no --cert-path in argv"), "", "");
      return;
    }
    fs.writeFileSync(args[flagIndex + 1], certificatePem, "utf8");
    callback(null, "fake certbot: certificate issued\n", "");
  };
}

// Bridges the src/index.js client contract onto the harness fake agent so
// every result/evidence the dispatch layer emits becomes a REAL protocol
// message the harness records (and the custody assertion can inspect).
function makeHarnessBackedClient(agent) {
  return {
    reportResult: async ({ jobId, attemptId, status, rejectionReason, keyRotated, errorMessage }) => {
      const response = await agent.reportResult({
        jobId,
        attemptId,
        status,
        ...(rejectionReason !== undefined && rejectionReason !== null
          ? { rejectionReason }
          : {}),
        ...(keyRotated !== undefined ? { keyRotated } : {}),
        ...(errorMessage !== undefined ? { errorMessage } : {}),
      });
      expect(response.status).to.equal(202);
      return response.body;
    },
    reportEvidence: async (body) => {
      const response = await agent.reportEvidence({
        jobId: body.jobId,
        evidenceItems: body.evidenceItems,
      });
      expect(response.status).to.equal(202);
      return response.body;
    },
  };
}

describe("agent renewal execution (M5 signed dispatch, end to end)", function () {
  this.timeout(30000);

  after(() => {
    while (tempDirs.length > 0) {
      const dir = tempDirs.pop();
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch (_err) {
        // best-effort cleanup
      }
    }
  });

  async function setupRenewalWorld({ dryRun }) {
    const app = buildFakeAgentControlPlaneApp({ signedJobDispatch: true });
    const agent = createFakeAgent({ app });

    const registerResponse = await agent.register({ agentVersion: "1.0.0" });
    expect(registerResponse.status).to.equal(201);
    const pinnedSigningKey = {
      signingKeyId: registerResponse.body.signingKeyId,
      publicKeyPem: registerResponse.body.signingPublicKeyPem,
    };

    const workDir = makeTempDir(dryRun ? "dry" : "real");
    const keysDir = path.join(workDir, "keys");
    const deployDir = path.join(workDir, "deployed");
    fs.mkdirSync(deployDir, { recursive: true });
    const certPath = path.join(deployDir, "cert.pem");

    const caEndpoint = "https://acme.example.test/directory";
    const policyEngine = createPolicyEngine(
      loadPolicyConfig({
        allowedPaths: [workDir],
        allowedCommands: { "certbot-renew": { argv: ["certbot"] } },
        allowedCaEndpoints: [caEndpoint],
      }),
      { declaredTargetSelectors: ["renewal.example.com"] },
    );

    const certificatePem = generateRuntimeCertificatePem();
    const acmeInvocations = [];
    const executionContext = buildExecutionContext({
      config: {
        execution: {
          enabled: true,
          dryRun,
          keysDir,
          replayStorePath: path.join(workDir, "replay-store.json"),
          clockDriftToleranceMs: 30000,
        },
        pinnedSigningKey,
      },
      acmeExecFileImpl: makeFakeCertbotExecFile(certificatePem, acmeInvocations),
    });

    app.dispatchSignedJob({
      action: "renew",
      target: { type: "domain", reference: "renewal.example.com" },
      commandRef: "certbot-renew",
      caEndpoint,
      certPath,
    });

    const claimResponse = await agent.claim({ maxJobs: 1 });
    expect(claimResponse.status).to.equal(200);
    expect(claimResponse.body.jobs).to.have.length(1);
    const job = claimResponse.body.jobs[0];

    return {
      app,
      agent,
      job,
      policyEngine,
      executionContext,
      client: makeHarnessBackedClient(agent),
      certificatePem,
      acmeInvocations,
      keysDir,
      deployDir,
      certPath,
    };
  }

  const silentLog = () => {};

  it("runs a signed renew job through keys -> acme -> deploy -> verify and reports success", async () => {
    const world = await setupRenewalWorld({ dryRun: false });

    const outcome = await handleClaimedJob({
      job: world.job,
      policyEngine: world.policyEngine,
      client: world.client,
      executionContext: world.executionContext,
      log: silentLog,
    });
    expect(outcome.status).to.equal("succeeded");

    // Terminal result: succeeded, keyRotated true (no pre-existing key, so
    // a new one was generated on this first renewal).
    const results = world.app.state.results;
    expect(results).to.have.length(1);
    expect(results[0].body.status).to.equal("succeeded");
    expect(results[0].body.keyRotated).to.equal(true);
    expect(results[0].body.jobId).to.equal(world.job.jobId);

    // Deployed file exists with exactly the PEM the fake certbot issued.
    expect(fs.existsSync(world.certPath)).to.equal(true);
    expect(fs.readFileSync(world.certPath, "utf8")).to.equal(
      world.certificatePem,
    );

    // The private key stayed local, under keysDir, and never left.
    const keyPath = path.join(
      world.keysDir,
      `${world.job.certificateId}.key.pem`,
    );
    expect(fs.existsSync(keyPath)).to.equal(true);

    // The fake certbot ran exactly once, with the allowlisted profile argv
    // head and the policy-approved CA endpoint.
    expect(world.acmeInvocations).to.have.length(1);
    expect(world.acmeInvocations[0].file).to.equal("certbot");
    expect(world.acmeInvocations[0].args).to.include(
      "https://acme.example.test/directory",
    );

    // Per-step evidence: acme pass, deploy update, verify pass (with the
    // deployed certificate's actual fingerprint).
    const evidenceItems = world.app.state.evidence.flatMap(
      (envelope) => envelope.body.evidenceItems,
    );
    const steps = evidenceItems.flatMap((item) =>
      (item.metadata || [])
        .filter((entry) => entry.name === "step")
        .map((entry) => entry.value),
    );
    expect(steps).to.include("acme");
    expect(steps).to.include("deploy");
    expect(steps).to.include("verify");

    const verifyItem = evidenceItems.find((item) =>
      (item.metadata || []).some(
        (entry) => entry.name === "step" && entry.value === "verify",
      ),
    );
    expect(verifyItem.eventType).to.equal("validation.passed");
    expect(verifyItem.fingerprintSha256).to.equal(
      computeCertificateFingerprint(fs.readFileSync(world.certPath, "utf8")),
    );

    const deployItem = evidenceItems.find((item) =>
      (item.metadata || []).some(
        (entry) => entry.name === "step" && entry.value === "deploy",
      ),
    );
    expect(deployItem.eventType).to.equal("deployment.updated");
    // Deploy metrics counters travel as flattened numeric metadata.
    expect(
      deployItem.metadata.some(
        (entry) =>
          entry.name === "deployMetric_attempts" &&
          typeof entry.value === "number",
      ),
    ).to.equal(true);

    // Replay defense: dispatching the SAME signed job again is rejected by
    // the replay cache before any execution.
    const replayOutcome = await handleClaimedJob({
      job: world.job,
      policyEngine: world.policyEngine,
      client: world.client,
      executionContext: world.executionContext,
      log: silentLog,
    });
    expect(replayOutcome.status).to.equal("rejected");
    expect(replayOutcome.rejectionReason).to.equal("job_replay_rejected");
    expect(world.acmeInvocations).to.have.length(1); // still exactly one exec
    const replayResult = world.app.state.results.at(-1);
    expect(replayResult.body.status).to.equal("rejected");
    expect(replayResult.body.rejectionReason).to.equal("job_replay_rejected");

    // Custody invariant: no private-key-shaped content in ANY protocol
    // message the harness recorded during the whole flow.
    const { state } = world.app;
    for (const [label, payloads] of Object.entries({
      heartbeats: state.heartbeats,
      claims: state.claims,
      results: state.results,
      evidence: state.evidence,
    })) {
      for (const payload of payloads) {
        assertNoCustodyShapedContent(payload, `state.${label}`);
      }
    }
  });

  it("dry-run renew reports a plan and succeeds with zero side effects", async () => {
    const world = await setupRenewalWorld({ dryRun: true });

    const outcome = await handleClaimedJob({
      job: world.job,
      policyEngine: world.policyEngine,
      client: world.client,
      executionContext: world.executionContext,
      log: silentLog,
    });
    expect(outcome.status).to.equal("succeeded");

    const results = world.app.state.results;
    expect(results).to.have.length(1);
    expect(results[0].body.status).to.equal("succeeded");
    // No key was generated or rotated in a dry run.
    expect(results[0].body.keyRotated).to.equal(null);

    // Plan evidence only: every item is policy.checked and dry-run-flagged.
    const evidenceItems = world.app.state.evidence.flatMap(
      (envelope) => envelope.body.evidenceItems,
    );
    expect(evidenceItems.length).to.be.greaterThan(0);
    for (const item of evidenceItems) {
      expect(item.eventType).to.equal("policy.checked");
      expect(
        item.metadata.some(
          (entry) => entry.name === "dryRun" && entry.value === true,
        ),
      ).to.equal(true);
    }

    // Zero side effects: no ACME exec, no keysDir, no deployed file.
    expect(world.acmeInvocations).to.have.length(0);
    expect(fs.existsSync(world.keysDir)).to.equal(false);
    expect(fs.existsSync(world.certPath)).to.equal(false);

    // Custody invariant holds in dry-run mode too.
    for (const payload of [
      ...world.app.state.results,
      ...world.app.state.evidence,
    ]) {
      assertNoCustodyShapedContent(payload, "dry-run protocol message");
    }
  });
});
