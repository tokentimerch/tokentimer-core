"use strict";

// Reusable fake-agent simulator for CertOps M4 integration tests.
//
// Approach taken (documented per the M4 harness spec): this file builds a
// SELF-CONTAINED mock Express control-plane app
// (`buildFakeAgentControlPlaneApp`), not a dependency-injected wrapper around
// a real router. Reasoning:
//
//   - There is no server-side route implementation yet for the M4 agent
//     protocol (no apps/api/routes/certops-agent.js). That is Phase 4 Dev A
//     work and has not started. A `buildFakeAgentApp(router)` helper mirroring
//     fake-executor.js's `buildExecutorApp` would have nothing real to accept
//     as `router` today, and would just push the "what does a route even look
//     like" question into every call site instead of answering it once here.
//   - What IS frozen today is the message envelope/body shapes in
//     packages/contracts/certops/agent-protocol.schema.json and the intent in
//     ADR-0002 (outbound-only, agent-local policy wins) and ADR-0003 (signed
//     jobs, replay protection fields). Building schema-correct requests
//     against a minimal in-memory mock app lets Phase 4 Dev A (and everyone
//     else) start writing protocol-shape tests immediately, without a live
//     Postgres-backed integration DB.
//   - Every default handler on the mock app is overridable per-test
//     (`registerHandler`, `heartbeatHandler`, `claimHandler`, `resultHandler`,
//     `evidenceHandler`), so once the real routes land, tests can either keep
//     using this mock to unit-test the *client* envelope shapes, or swap in
//     the real router the same way fake-executor.js wires
//     `createCertOpsExecutorRouter` -- at that point a thin
//     `buildFakeAgentApp(router)` export can be added alongside this one
//     without touching `createFakeAgent` or `envelopeFor` at all, since those
//     two are already app-shape-agnostic (they only need `{ app }`).
//
// Conventions mirrored from fake-executor.js: factory function returning an
// object with async lifecycle methods, `lastPayload` tracking, a
// `buildXApp` helper, and reuse of `TestUtils` from ./setup for any
// workspace/cleanup helpers a consuming test needs (kept here as thin
// pass-throughs so callers don't need to also require fake-executor.js just
// to stand up a workspace pair).

const crypto = require("crypto");
const { createRequire } = require("module");
const supertest = require("supertest");

const { TestUtils } = require("./setup");

const apiRequire = createRequire(
  require.resolve("../../apps/api/package.json"),
);
const express = apiRequire("express");

// Route paths per the FROZEN namespace in
// packages/contracts/api/certops-route-compat.contract.json ("agent"
// section) -- not invented here. Note that contract only lists one
// ingestion route for agent-originated results
// (`/agent/jobs/results`); the already-landed (but off-limits to import
// from) packages/agent/src/protocol/index.js client sends both `result`
// and `evidence` messageTypes to that same route, letting the envelope's
// `messageType` field disambiguate server-side. This harness mirrors that
// so a fake-agent test exercising evidence hits the same route real agents
// will use, but still exposes a distinct `AGENT_EVIDENCE_ROUTE` constant
// (aliased to the same path) so call sites read clearly and a future route
// split does not require renaming every call site.
const AGENT_REGISTER_ROUTE = "/api/v1/certops/agent/register";
const AGENT_HEARTBEAT_ROUTE = "/api/v1/certops/agent/heartbeat";
const AGENT_CLAIM_ROUTE = "/api/v1/certops/agent/jobs/claim";
const AGENT_RESULT_ROUTE = "/api/v1/certops/agent/jobs/results";
const AGENT_EVIDENCE_ROUTE = AGENT_RESULT_ROUTE;

const DEFAULT_PROTOCOL_VERSION = "1.0.0";
const DEFAULT_SCHEMA_VERSION = 1;

// Pure helper: builds one schema-shaped envelope object for a given
// messageType, without sending anything over HTTP. Useful for tests that
// want to construct malformed envelopes directly (e.g. Phase 4 replay/
// rejection tests) rather than going through createFakeAgent's HTTP methods.
function envelopeFor(messageType, body, overrides = {}) {
  const envelope = {
    schemaVersion: DEFAULT_SCHEMA_VERSION,
    protocolVersion: DEFAULT_PROTOCOL_VERSION,
    messageType,
    agentId: `agent-${crypto.randomUUID()}`,
    sentAt: new Date().toISOString(),
    body: body || null,
    ...overrides,
  };
  if (envelope.workspaceId === undefined) {
    delete envelope.workspaceId;
  }
  return envelope;
}

function issueFakeAgentCredential(agentId) {
  const secret = crypto.randomBytes(16).toString("hex");
  return `ttagent_${agentId}_${secret}`;
}

// Minimal in-memory control-plane state for the default mock handlers. Not
// meant to model real persistence/leasing semantics -- just enough for the
// self-test and for early Phase-4 client-shape tests to get a sensible 200
// instead of a 404 when no test-specific handler is supplied.
function createInMemoryAgentControlPlaneState() {
  return {
    registeredAgents: new Map(),
    heartbeats: [],
    claims: [],
    results: [],
    evidence: [],
  };
}

function defaultRegisterHandler(state) {
  return (req, res) => {
    const envelope = req.body || {};
    const agentId = envelope.agentId || `agent-${crypto.randomUUID()}`;
    const credential = issueFakeAgentCredential(agentId);
    state.registeredAgents.set(agentId, {
      agentId,
      credential,
      registeredAt: new Date().toISOString(),
      body: envelope.body || null,
    });
    return res.status(201).json({
      ok: true,
      agentId,
      credential,
      protocolVersion: envelope.protocolVersion || DEFAULT_PROTOCOL_VERSION,
    });
  };
}

function defaultHeartbeatHandler(state) {
  return (req, res) => {
    const envelope = req.body || {};
    state.heartbeats.push(envelope);
    return res.status(200).json({ ok: true, agentId: envelope.agentId });
  };
}

function defaultClaimHandler(state) {
  return (req, res) => {
    const envelope = req.body || {};
    state.claims.push(envelope);
    return res.status(200).json({ ok: true, jobs: [] });
  };
}

function defaultResultHandler(state) {
  return (req, res) => {
    const envelope = req.body || {};
    state.results.push(envelope);
    return res.status(202).json({ ok: true, jobId: envelope.body?.jobId });
  };
}

function defaultEvidenceHandler(state) {
  return (req, res) => {
    const envelope = req.body || {};
    state.evidence.push(envelope);
    return res.status(202).json({ ok: true });
  };
}

// AGENT_RESULT_ROUTE === AGENT_EVIDENCE_ROUTE (see the route constants
// above), so a single mounted handler on that path dispatches to
// resultHandler/evidenceHandler by the envelope's messageType, the same way
// the real (future) server-side route will need to.
function dispatchResultOrEvidence(state, resultHandler, evidenceHandler) {
  const result = resultHandler || defaultResultHandler(state);
  const evidence = evidenceHandler || defaultEvidenceHandler(state);
  return (req, res, next) => {
    const messageType = req.body?.messageType;
    if (messageType === "evidence") return evidence(req, res, next);
    if (messageType === "result") return result(req, res, next);
    return res.status(400).json({
      error: `Unsupported messageType for ${AGENT_RESULT_ROUTE}: ${messageType}`,
      code: "CERTOPS_AGENT_UNKNOWN_MESSAGE_TYPE",
    });
  };
}

// Self-contained mock Express control-plane app simulating the expected
// register/heartbeat/claim/result/evidence routes per
// agent-protocol.schema.json and ADR-0002/0003, with in-memory state. Every
// handler can be overridden per-test, e.g. a test wants heartbeat to return
// 410 to exercise agent retirement handling once that lands server-side.
function buildFakeAgentControlPlaneApp({
  registerHandler,
  heartbeatHandler,
  claimHandler,
  resultHandler,
  evidenceHandler,
  state: providedState,
} = {}) {
  const state = providedState || createInMemoryAgentControlPlaneState();
  const app = express();
  app.use(express.json());

  app.post(
    AGENT_REGISTER_ROUTE,
    registerHandler || defaultRegisterHandler(state),
  );
  app.post(
    AGENT_HEARTBEAT_ROUTE,
    heartbeatHandler || defaultHeartbeatHandler(state),
  );
  app.post(AGENT_CLAIM_ROUTE, claimHandler || defaultClaimHandler(state));
  app.post(
    AGENT_RESULT_ROUTE,
    dispatchResultOrEvidence(state, resultHandler, evidenceHandler),
  );

  app.use((err, _req, res, next) => {
    if (res.headersSent) return next(err);
    return res.status(500).json({
      error: "Internal test harness error",
      code: err?.code || "INTERNAL_ERROR",
    });
  });

  app.state = state;
  return app;
}

async function createWorkspacePair(label) {
  const ownerEmail = `${label}-${Date.now()}-${crypto.randomUUID()}@example.com`;
  const owner = await TestUtils.execQuery(
    `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
     VALUES ($1, $2, $3, $4, 'local', TRUE)
     RETURNING id`,
    [
      ownerEmail.toLowerCase(),
      ownerEmail,
      label,
      "not-used-in-certops-fake-agent-harness",
    ],
  );
  const ownerId = owner.rows[0].id;
  const workspaceA = crypto.randomUUID();
  const workspaceB = crypto.randomUUID();

  await TestUtils.execQuery(
    `INSERT INTO workspaces (id, name, created_by, plan)
     VALUES ($1, $2, $3, 'oss'), ($4, $5, $3, 'oss')`,
    [workspaceA, `${label} A`, ownerId, workspaceB, `${label} B`],
  );

  return { ownerId, workspaceA, workspaceB };
}

async function cleanupWorkspacePair(ownerId, workspaceIds) {
  await TestUtils.execQuery(
    "DELETE FROM audit_events WHERE workspace_id = ANY($1::uuid[])",
    [workspaceIds],
  );
  await TestUtils.execQuery(
    "DELETE FROM workspaces WHERE id = ANY($1::uuid[])",
    [workspaceIds],
  );
  await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
}

// A fake agent bound to one app (+ optional workspaceId/agentId/credential).
// Before registration succeeds, `agentId` may be a client-generated
// candidate (per schema's agentId description for messageType=register).
// Each lifecycle helper returns the supertest response; the sent envelope is
// kept on `lastPayload` so callers can replay it verbatim (mirrors
// fake-executor.js's `replayLastEvent`).
function createFakeAgent({
  app,
  agentId,
  credential,
  workspaceId,
  protocolVersion = DEFAULT_PROTOCOL_VERSION,
} = {}) {
  const agent = {
    app,
    agentId: agentId || `agent-${crypto.randomUUID()}`,
    credential: credential || null,
    workspaceId: workspaceId || undefined,
    protocolVersion,
    lastPayload: null,

    buildEnvelope(messageType, body, overrides = {}) {
      return envelopeFor(messageType, body, {
        agentId: agent.agentId,
        protocolVersion: agent.protocolVersion,
        workspaceId: agent.workspaceId,
        ...overrides,
      });
    },

    async postEnvelope(route, envelope) {
      agent.lastPayload = envelope;
      const req = supertest(agent.app).post(route);
      if (agent.credential) {
        req.set("Authorization", `Bearer ${agent.credential}`);
      }
      return req.send(envelope);
    },

    async register({
      bootstrapTokenId,
      agentVersion,
      hostname,
      platform,
      nodeVersion,
      declaredTargetSelectors,
      declaredCommandProfileNames,
      ...overrides
    } = {}) {
      const body = {
        bootstrapTokenId:
          bootstrapTokenId || `bootstrap-${crypto.randomUUID()}`,
        agentVersion: agentVersion || "1.0.0",
      };
      if (hostname !== undefined) body.hostname = hostname;
      if (platform !== undefined) body.platform = platform;
      if (nodeVersion !== undefined) body.nodeVersion = nodeVersion;
      if (declaredTargetSelectors !== undefined) {
        body.declaredTargetSelectors = declaredTargetSelectors;
      }
      if (declaredCommandProfileNames !== undefined) {
        body.declaredCommandProfileNames = declaredCommandProfileNames;
      }
      const envelope = agent.buildEnvelope("register", body, overrides);
      const response = await agent.postEnvelope(
        AGENT_REGISTER_ROUTE,
        envelope,
      );
      if (response.body?.agentId) {
        agent.agentId = response.body.agentId;
      }
      if (response.body?.credential) {
        agent.credential = response.body.credential;
      }
      return response;
    },

    async heartbeat({
      agentVersion,
      ntpSynced,
      uptimeSeconds,
      pinnedSigningKeyId,
      ...overrides
    } = {}) {
      const body = {
        agentVersion: agentVersion || "1.0.0",
      };
      if (ntpSynced !== undefined) body.ntpSynced = ntpSynced;
      if (uptimeSeconds !== undefined) body.uptimeSeconds = uptimeSeconds;
      if (pinnedSigningKeyId !== undefined) {
        body.pinnedSigningKeyId = pinnedSigningKeyId;
      }
      const envelope = agent.buildEnvelope("heartbeat", body, overrides);
      return agent.postEnvelope(AGENT_HEARTBEAT_ROUTE, envelope);
    },

    async claim({ maxJobs, supportedActions, ...overrides } = {}) {
      const body = {};
      if (maxJobs !== undefined) body.maxJobs = maxJobs;
      if (supportedActions !== undefined) {
        body.supportedActions = supportedActions;
      }
      const envelope = agent.buildEnvelope("claim", body, overrides);
      return agent.postEnvelope(AGENT_CLAIM_ROUTE, envelope);
    },

    async reportResult({
      jobId,
      attemptId,
      status,
      rejectionReason,
      keyRotated,
      errorMessage,
      ...overrides
    } = {}) {
      const body = {
        jobId: jobId || `job-${crypto.randomUUID()}`,
        attemptId: attemptId || `attempt-${crypto.randomUUID()}`,
        status: status || "succeeded",
      };
      if (rejectionReason !== undefined) {
        body.rejectionReason = rejectionReason;
      }
      if (keyRotated !== undefined) body.keyRotated = keyRotated;
      if (errorMessage !== undefined) body.errorMessage = errorMessage;
      const envelope = agent.buildEnvelope("result", body, overrides);
      return agent.postEnvelope(AGENT_RESULT_ROUTE, envelope);
    },

    async reportEvidence({ jobId, evidenceItems, ...overrides } = {}) {
      const body = {
        evidenceItems: evidenceItems || [
          {
            eventType: "certificate.observed",
            observedAt: new Date().toISOString(),
          },
        ],
      };
      if (jobId !== undefined) body.jobId = jobId;
      const envelope = agent.buildEnvelope("evidence", body, overrides);
      return agent.postEnvelope(AGENT_EVIDENCE_ROUTE, envelope);
    },

    // Re-sends the exact same envelope verbatim, to exercise replay-rejection
    // behavior once Phase 4 server-side replay defense (ADR-0003) ships.
    async replayLastMessage() {
      if (!agent.lastPayload) {
        throw new Error("No message sent yet; nothing to replay");
      }
      const routeByMessageType = {
        register: AGENT_REGISTER_ROUTE,
        heartbeat: AGENT_HEARTBEAT_ROUTE,
        claim: AGENT_CLAIM_ROUTE,
        result: AGENT_RESULT_ROUTE,
        evidence: AGENT_EVIDENCE_ROUTE,
      };
      const route = routeByMessageType[agent.lastPayload.messageType];
      if (!route) {
        throw new Error(
          `Cannot replay unknown messageType: ${agent.lastPayload.messageType}`,
        );
      }
      const req = supertest(agent.app).post(route);
      if (agent.credential) {
        req.set("Authorization", `Bearer ${agent.credential}`);
      }
      return req.send(agent.lastPayload);
    },
  };

  return agent;
}

module.exports = {
  AGENT_CLAIM_ROUTE,
  AGENT_EVIDENCE_ROUTE,
  AGENT_HEARTBEAT_ROUTE,
  AGENT_REGISTER_ROUTE,
  AGENT_RESULT_ROUTE,
  buildFakeAgentControlPlaneApp,
  cleanupWorkspacePair,
  createFakeAgent,
  createInMemoryAgentControlPlaneState,
  createWorkspacePair,
  envelopeFor,
  issueFakeAgentCredential,
};
