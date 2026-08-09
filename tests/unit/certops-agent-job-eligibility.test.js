"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const service = (name) =>
  path.resolve(__dirname, "../../apps/api/services/certops", name);
const {
  evaluateAgentJobEligibility,
  resolveAgentJobRoutingRequirements,
} = require(service("agentJobEligibility.js"));
const { computeAgentCompatibility } = require(service("agentRegistry.js"));
const dispatch = require(service("agentDispatch.js"));
const {
  RENEWAL_PATH_STATES,
  _test: { resolveRenewalPathForRow },
} = require(service("renewalPathHealth.js"));
const {
  executionFieldsFromRenewalProfile,
  validateRenewalProfile,
} = require(service("renewalProfile.js"));

const NOW = Date.parse("2026-08-09T12:00:00.000Z");

function profile() {
  return {
    schemaVersion: 1,
    profileId: "profile-1",
    profileName: "web",
    sanPolicy: { mode: "exact", sans: ["app.example.com"], allowWildcards: false },
    keyAlgorithm: "rsa",
    keySize: 2048,
    keyRotationPolicy: { rotateOnRenew: true },
    preferredChain: null,
    ca: { endpoint: "https://acme.example.test/directory", accountRef: null, eabRef: null },
    acme: { kind: "certbot", commandRef: "renew.web" },
    dns: { provider: "cloudflare", zone: "example.com" },
    deploymentTargets: [{ type: "endpoint", reference: "host/web", certPath: "/etc/ssl/app.pem" }],
    target: { type: "endpoint", reference: "host/web", certPath: "/etc/ssl/app.pem" },
    verification: { host: null, port: null, requireMatch: false },
  };
}

function agent(overrides = {}) {
  return {
    id: "agent-1",
    agentId: "agent-one",
    name: "agent-one",
    hostname: "host-one",
    platform: "linux",
    status: "active",
    lastSeenAt: new Date(NOW - 30_000).toISOString(),
    createdAt: new Date(NOW - 86_400_000).toISOString(),
    agentVersion: "0.1.0",
    protocolVersion: "1.0.0",
    clockOffsetMs: 0,
    supportedOperations: ["renew"],
    targetSelectors: ["host/web"],
    dnsProviders: ["cloudflare"],
    commandProfiles: ["renew.web"],
    declaredCapabilities: [],
    capabilitiesUpdatedAt: new Date(NOW).toISOString(),
    agentKind: "normal",
    ...overrides,
  };
}

function indexFor(candidate) {
  return {
    byRowId: new Map([[candidate.id, candidate]]),
    byAgentIdString: new Map([[candidate.agentId, candidate]]),
    retiredRowIds: new Set(),
    retiredAgentIdStrings: new Set(),
    all: [candidate],
  };
}

function indexForMany(candidates) {
  return {
    byRowId: new Map(candidates.map((candidate) => [candidate.id, candidate])),
    byAgentIdString: new Map(
      candidates.map((candidate) => [candidate.agentId, candidate]),
    ),
    retiredRowIds: new Set(),
    retiredAgentIdStrings: new Set(),
    all: candidates,
  };
}

function certificateRow() {
  return {
    id: "cert-1",
    status: "active",
    key_mode: "agent-local",
    source: "manual",
    profile_id: "profile-1",
    profile_status: "active",
    deployed_agent_id: null,
    discovery_agent_id: null,
    profile_public_metadata: { renewalProfile: profile() },
  };
}

describe("shared agent-job eligibility", () => {
  it("is the exact predicate exported by the real dispatch implementation", () => {
    assert.strictEqual(
      dispatch._test.evaluateAgentJobEligibility,
      evaluateAgentJobEligibility,
    );
  });

  it("keeps renewal-path health in parity across persisted claim requirements", () => {
    const validated = validateRenewalProfile(profile());
    const job = {
      operation: "renew",
      ...resolveAgentJobRoutingRequirements({
        executorKind: "agent",
        payload: executionFieldsFromRenewalProfile(validated),
      }),
      subjectIsProvisioning: false,
    };
    const cases = [
      ["eligible", {}, true],
      ["operation", { supportedOperations: ["deploy"] }, false],
      ["selector", { targetSelectors: ["host/other"] }, false],
      ["dns", { dnsProviders: ["route53"] }, false],
      ["command", { commandProfiles: ["renew.other"] }, false],
      ["diagnostic kind", { agentKind: "diagnostic" }, false],
      ["blocked version", { protocolVersion: "999.0.0" }, false],
    ];

    for (const [label, overrides, expected] of cases) {
      const candidate = agent(overrides);
      const predicate = evaluateAgentJobEligibility({
        agent: candidate,
        job,
        compatibility: computeAgentCompatibility(candidate, {}),
        env: {},
        now: NOW,
      });
      assert.equal(predicate.eligible, expected, `${label}: predicate`);

      const projection = resolveRenewalPathForRow({
        certificateRow: certificateRow(),
        agentIndex: indexFor(candidate),
        env: {},
        now: NOW,
      });
      assert.equal(
        projection.renewalPathState === RENEWAL_PATH_STATES.HEALTHY,
        expected,
        `${label}: health projection`,
      );
    }
  });

  it("requires fresh claim-binding capability for provisioning renewals", () => {
    const candidate = agent({
      declaredCapabilities: ["evidence-claim-binding-v1"],
      capabilitiesUpdatedAt: new Date(NOW - 60 * 60 * 1000).toISOString(),
    });
    const outcome = evaluateAgentJobEligibility({
      agent: candidate,
      job: {
        operation: "renew",
        executorKind: "agent",
        subjectIsProvisioning: true,
      },
      compatibility: computeAgentCompatibility(candidate, {}),
      env: { CERTOPS_AGENT_OFFLINE_AFTER_MS: "600000" },
      now: NOW,
    });
    assert.equal(outcome.eligible, false);
    assert.equal(outcome.reason, "claim_bound_evidence_unavailable");
  });

  it("counts only truly eligible agents as redundant renewal paths", () => {
    const eligible = agent({ id: "agent-1", agentId: "eligible" });
    const selectorOnly = agent({
      id: "agent-2",
      agentId: "selector-only",
      lastSeenAt: new Date(NOW - 60 * 60 * 1000).toISOString(),
      dnsProviders: ["route53"],
    });
    const projection = resolveRenewalPathForRow({
      certificateRow: certificateRow(),
      agentIndex: indexForMany([eligible, selectorOnly]),
      env: {},
      now: NOW,
    });

    assert.equal(projection.renewalPathState, RENEWAL_PATH_STATES.HEALTHY);
    assert.deepEqual(
      projection.dependencies.map((dependency) => dependency.agentRowId),
      ["agent-1"],
    );
  });

  it("applies the same assigned-agent restriction to health and dispatch", () => {
    const assigned = agent({ id: "agent-1", agentId: "assigned" });
    const other = agent({ id: "agent-2", agentId: "other" });
    const row = certificateRow();
    row.source = "agent_filesystem";
    row.discovery_agent_id = "assigned";
    const projection = resolveRenewalPathForRow({
      certificateRow: row,
      agentIndex: indexForMany([assigned, other]),
      env: {},
      now: NOW,
    });
    const requirements = {
      operation: "renew",
      ...resolveAgentJobRoutingRequirements({
        executorKind: "agent",
        assignedAgentId: "agent-1",
        payload: executionFieldsFromRenewalProfile(
          validateRenewalProfile(profile()),
        ),
      }),
    };

    assert.deepEqual(
      projection.dependencies.map((dependency) => dependency.agentRowId),
      ["agent-1"],
    );
    assert.equal(
      evaluateAgentJobEligibility({
        agent: other,
        job: requirements,
        compatibility: computeAgentCompatibility(other, {}),
        env: {},
        now: NOW,
      }).reason,
      "assigned_agent_mismatch",
    );
  });

  it("reports Unknown when persisted eligibility facts are malformed", () => {
    const malformed = agent({ targetSelectors: { unexpected: true } });
    const projection = resolveRenewalPathForRow({
      certificateRow: certificateRow(),
      agentIndex: indexFor(malformed),
      env: {},
      now: NOW,
    });
    assert.equal(projection.renewalPathState, RENEWAL_PATH_STATES.UNKNOWN);
  });

  it("reports Unknown when only a live candidate has malformed required facts", () => {
    const knownOffline = agent({
      id: "agent-1",
      agentId: "known-offline",
      lastSeenAt: new Date(NOW - 60 * 60 * 1000).toISOString(),
    });
    const malformedLive = agent({
      id: "agent-2",
      agentId: "malformed-live",
      dnsProviders: { unexpected: true },
    });
    const projection = resolveRenewalPathForRow({
      certificateRow: certificateRow(),
      agentIndex: indexForMany([knownOffline, malformedLive]),
      env: {},
      now: NOW,
    });
    assert.equal(projection.renewalPathState, RENEWAL_PATH_STATES.UNKNOWN);
  });

  it("ignores malformed capability facts on an agent excluded by a hard pin", () => {
    const assigned = agent({
      id: "agent-1",
      agentId: "assigned",
      lastSeenAt: new Date(NOW - 60 * 60 * 1000).toISOString(),
    });
    const unrelated = agent({
      id: "agent-2",
      agentId: "unrelated",
      supportedOperations: { unexpected: true },
      dnsProviders: { unexpected: true },
    });
    const row = certificateRow();
    row.source = "agent_filesystem";
    row.discovery_agent_id = "assigned";
    const projection = resolveRenewalPathForRow({
      certificateRow: row,
      agentIndex: indexForMany([assigned, unrelated]),
      env: {},
      now: NOW,
    });
    assert.equal(projection.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
  });
});
