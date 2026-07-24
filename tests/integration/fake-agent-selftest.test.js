"use strict";

// Self-test for tests/integration/fake-agent.js. Exercises the harness
// end-to-end against its own self-contained mock control-plane app
// (buildFakeAgentControlPlaneApp), proving every method produces a
// schema-shaped, sendable request and gets a sensible response.
//
// Deliberately does NOT require a live Postgres connection: it only uses
// `createFakeAgent` + `buildFakeAgentControlPlaneApp`, never
// `createWorkspacePair`/`cleanupWorkspacePair` (which hit the DB via
// TestUtils.execQuery). tests/integration/setup.js is still required
// (transitively, since fake-agent.js requires it for TestUtils), but merely
// requiring it does not open a DB connection -- only TestUtils.execQuery
// calls do, and this file never calls that.
//
// Also compiles packages/contracts/certops/agent-protocol.schema.json with
// ajv and validates a sample envelope of every messageType produced by the
// harness, to catch drift between the harness and the schema early.

const fs = require("node:fs");
const path = require("node:path");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");

const { expect } = require("./setup");
const {
  AGENT_CLAIM_ROUTE,
  AGENT_EVIDENCE_ROUTE,
  AGENT_HEARTBEAT_ROUTE,
  AGENT_REGISTER_ROUTE,
  AGENT_RESULT_ROUTE,
  buildFakeAgentControlPlaneApp,
  createFakeAgent,
  envelopeFor,
} = require("./fake-agent");

const schema = JSON.parse(
  fs.readFileSync(
    path.resolve(
      __dirname,
      "../../packages/contracts/certops/agent-protocol.schema.json",
    ),
    "utf8",
  ),
);
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const validateEnvelope = ajv.compile(schema);

function expectSchemaValid(envelope) {
  const valid = validateEnvelope(envelope);
  expect(valid, JSON.stringify(validateEnvelope.errors)).to.equal(true);
}

describe("fake-agent harness self-test", function () {
  this.timeout(30000);

  describe("envelopeFor (pure helper)", () => {
    it("builds a schema-valid envelope for every messageType", () => {
      const samples = [
        envelopeFor("register", {
          bootstrapTokenId: "bootstrap-1",
          agentVersion: "1.0.0",
        }),
        envelopeFor("heartbeat", { agentVersion: "1.0.0" }),
        envelopeFor("claim", { maxJobs: 1, supportedActions: ["renew"] }),
        envelopeFor("result", {
          jobId: "job-1",
          attemptId: "attempt-1",
          status: "succeeded",
        }),
        envelopeFor("evidence", {
          evidenceItems: [
            {
              eventType: "certificate.observed",
              observedAt: new Date().toISOString(),
            },
          ],
        }),
      ];

      for (const envelope of samples) {
        expectSchemaValid(envelope);
      }
    });

    it("supports overrides while keeping required envelope fields", () => {
      const envelope = envelopeFor(
        "heartbeat",
        { agentVersion: "2.0.0" },
        { agentId: "agent-explicit", workspaceId: null },
      );
      expect(envelope.agentId).to.equal("agent-explicit");
      expect(envelope.workspaceId).to.equal(null);
      expect(envelope.schemaVersion).to.equal(1);
      expectSchemaValid(envelope);
    });
  });

  describe("createFakeAgent against buildFakeAgentControlPlaneApp", () => {
    it("registers, heartbeats, claims, reports a result, and reports evidence", async () => {
      const app = buildFakeAgentControlPlaneApp();
      const agent = createFakeAgent({ app });

      const registerResponse = await agent.register({
        agentVersion: "1.0.0",
        hostname: "test-host",
        platform: "linux",
        nodeVersion: "22.0.0",
        declaredTargetSelectors: ["kubernetes/default/*"],
        declaredCommandProfileNames: ["certbot-renew"],
      });
      expect(registerResponse.status).to.equal(201);
      expect(registerResponse.body.ok).to.equal(true);
      expect(registerResponse.body.agentId).to.be.a("string").that.is.not
        .empty;
      expect(registerResponse.body.credential)
        .to.be.a("string")
        .that.match(/^ttagent_/);
      expectSchemaValid(agent.lastPayload);
      expect(agent.lastPayload.messageType).to.equal("register");
      expect(agent.credential).to.equal(registerResponse.body.credential);

      const heartbeatResponse = await agent.heartbeat({
        agentVersion: "1.0.0",
        ntpSynced: true,
        uptimeSeconds: 42,
        pinnedSigningKeyId: "key-1",
      });
      expect(heartbeatResponse.status).to.equal(200);
      expect(heartbeatResponse.body.ok).to.equal(true);
      expectSchemaValid(agent.lastPayload);
      expect(agent.lastPayload.messageType).to.equal("heartbeat");
      // Registered credential must be sent as the bearer on subsequent calls.
      expect(heartbeatResponse.request.header.Authorization).to.equal(
        `Bearer ${agent.credential}`,
      );

      const claimResponse = await agent.claim({
        maxJobs: 2,
        supportedActions: ["renew", "deploy"],
      });
      expect(claimResponse.status).to.equal(200);
      expect(claimResponse.body.jobs).to.deep.equal([]);
      expectSchemaValid(agent.lastPayload);
      expect(agent.lastPayload.messageType).to.equal("claim");

      const resultResponse = await agent.reportResult({
        jobId: "job-abc",
        attemptId: "attempt-abc",
        status: "rejected",
        rejectionReason: "target_out_of_scope",
      });
      expect(resultResponse.status).to.equal(202);
      expect(resultResponse.body.ok).to.equal(true);
      expectSchemaValid(agent.lastPayload);
      expect(agent.lastPayload.messageType).to.equal("result");
      expect(agent.lastPayload.body.rejectionReason).to.equal(
        "target_out_of_scope",
      );

      const evidenceResponse = await agent.reportEvidence({
        jobId: "job-abc",
        evidenceItems: [
          {
            eventType: "validation.failed",
            observedAt: new Date().toISOString(),
            summary: "Target out of declared scope",
          },
        ],
      });
      expect(evidenceResponse.status).to.equal(202);
      expect(evidenceResponse.body.ok).to.equal(true);
      expectSchemaValid(agent.lastPayload);
      expect(agent.lastPayload.messageType).to.equal("evidence");

      expect(app.state.registeredAgents.size).to.equal(1);
      expect(app.state.heartbeats).to.have.length(1);
      expect(app.state.claims).to.have.length(1);
      expect(app.state.results).to.have.length(1);
      expect(app.state.evidence).to.have.length(1);
    });

    it("replays the last message verbatim via replayLastMessage", async () => {
      const app = buildFakeAgentControlPlaneApp();
      const agent = createFakeAgent({ app });

      await agent.heartbeat({ agentVersion: "1.0.0" });
      const sentEnvelope = agent.lastPayload;

      const replayResponse = await agent.replayLastMessage();
      expect(replayResponse.status).to.equal(200);
      expect(agent.lastPayload).to.deep.equal(sentEnvelope);
      expect(app.state.heartbeats).to.have.length(2);
      expect(app.state.heartbeats[0]).to.deep.equal(app.state.heartbeats[1]);
    });

    it("throws when replaying before any message has been sent", async () => {
      const app = buildFakeAgentControlPlaneApp();
      const agent = createFakeAgent({ app });

      let thrown = null;
      try {
        await agent.replayLastMessage();
      } catch (error) {
        thrown = error;
      }
      expect(thrown).to.not.equal(null);
      expect(thrown.message).to.match(/nothing to replay/);
    });

    it("allows overriding a handler to simulate agent retirement (410)", async () => {
      const app = buildFakeAgentControlPlaneApp({
        heartbeatHandler: (req, res) => {
          return res.status(410).json({
            error: "Agent retired",
            code: "CERTOPS_AGENT_RETIRED",
          });
        },
      });
      const agent = createFakeAgent({ app, agentId: "agent-retired" });

      const heartbeatResponse = await agent.heartbeat({
        agentVersion: "1.0.0",
      });
      expect(heartbeatResponse.status).to.equal(410);
      expect(heartbeatResponse.body.code).to.equal("CERTOPS_AGENT_RETIRED");
      expectSchemaValid(agent.lastPayload);
    });

    it("sends every message type to its documented route", async () => {
      const seenRoutes = [];
      const app = buildFakeAgentControlPlaneApp({
        registerHandler: (req, res) => {
          seenRoutes.push({ route: AGENT_REGISTER_ROUTE, path: req.path });
          return res
            .status(201)
            .json({ ok: true, agentId: "agent-x", credential: "ttagent_x_y" });
        },
        heartbeatHandler: (req, res) => {
          seenRoutes.push({ route: AGENT_HEARTBEAT_ROUTE, path: req.path });
          return res.status(200).json({ ok: true });
        },
        claimHandler: (req, res) => {
          seenRoutes.push({ route: AGENT_CLAIM_ROUTE, path: req.path });
          return res.status(200).json({ ok: true, jobs: [] });
        },
        resultHandler: (req, res) => {
          seenRoutes.push({ route: AGENT_RESULT_ROUTE, path: req.path });
          return res.status(202).json({ ok: true });
        },
        evidenceHandler: (req, res) => {
          seenRoutes.push({ route: AGENT_EVIDENCE_ROUTE, path: req.path });
          return res.status(202).json({ ok: true });
        },
      });
      const agent = createFakeAgent({ app });

      await agent.register({ agentVersion: "1.0.0" });
      await agent.heartbeat({ agentVersion: "1.0.0" });
      await agent.claim({});
      await agent.reportResult({ status: "succeeded" });
      await agent.reportEvidence({});

      for (const { route, path: seenPath } of seenRoutes) {
        expect(seenPath).to.equal(route);
      }
      expect(seenRoutes).to.have.length(5);
    });

    it("passes workspaceId through to every envelope when provided", async () => {
      const app = buildFakeAgentControlPlaneApp();
      const workspaceId = "11111111-1111-1111-1111-111111111111";
      const agent = createFakeAgent({ app, workspaceId });

      await agent.heartbeat({ agentVersion: "1.0.0" });
      expect(agent.lastPayload.workspaceId).to.equal(workspaceId);
      expectSchemaValid(agent.lastPayload);
    });
  });
});
