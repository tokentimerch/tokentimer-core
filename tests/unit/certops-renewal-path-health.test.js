"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  RENEWAL_PATH_STATES,
  RENEWAL_PATH_REASONS,
  resolveRenewalPathForCertificate,
  resolveRenewalPathsForWorkspace,
  resolveRenewalPathsForCertificateIds,
  listCertificatesDependentOnAgent,
  _test: {
    resolveRenewalPathForRow,
    resolveRequiredExecutors,
    classifyExecutors,
    targetReferenceFromProfile,
    adcsPreflightKey,
    NO_CAPABILITY_DECLARED_SUMMARY,
  },
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/renewalPathHealth.js",
  ),
);
const { TRUST_JOB_INELIGIBLE_MESSAGE_BY_REASON } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/trustAnchors.js"),
);

const NOW = new Date("2026-08-07T12:00:00.000Z").getTime();
const OFFLINE_AFTER_MS = 10 * 60 * 1000;

function agentRow({
  id,
  agentId = id,
  status = "active",
  lastSeenAt,
  createdAt = "2026-01-01T00:00:00.000Z",
  targetSelectors = ["host/web"],
  supportedOperations = ["renew"],
  dnsProviders = ["cloudflare"],
  commandProfiles = ["renew.web"],
  protocolVersion = "1.0.0",
}) {
  return {
    id,
    agent_id: agentId,
    name: `agent-${id}`,
    hostname: `host-${id}`,
    platform: "linux",
    status,
    last_seen_at: lastSeenAt,
    created_at: createdAt,
    declared_target_selectors: targetSelectors,
    supported_operations: supportedOperations,
    supported_dns_providers: dnsProviders,
    declared_command_profile_names: commandProfiles,
    declared_capabilities: [],
    capabilities_updated_at: new Date(NOW).toISOString(),
    agent_kind: "normal",
    agent_version: "0.1.0",
    protocol_version: protocolVersion,
    clock_offset_ms: 0,
  };
}

function buildAgentIndex(rows) {
  const byRowId = new Map();
  const byAgentIdString = new Map();
  for (const row of rows) {
    const agent = {
      id: String(row.id),
      agentId: row.agent_id,
      name: row.name || null,
      hostname: row.hostname || null,
      platform: row.platform || null,
      status: row.status,
      lastSeenAt: row.last_seen_at,
      createdAt: row.created_at,
      targetSelectors: Array.isArray(row.declared_target_selectors)
        ? row.declared_target_selectors
        : [],
      supportedOperations: row.supported_operations,
      dnsProviders: row.supported_dns_providers,
      commandProfiles: row.declared_command_profile_names,
      declaredCapabilities: row.declared_capabilities,
      capabilitiesUpdatedAt: row.capabilities_updated_at,
      agentKind: row.agent_kind,
      agentVersion: row.agent_version,
      protocolVersion: row.protocol_version,
      clockOffsetMs: row.clock_offset_ms,
    };
    byRowId.set(agent.id, agent);
    if (agent.agentId) byAgentIdString.set(agent.agentId, agent);
  }
  return {
    byRowId,
    byAgentIdString,
    retiredRowIds: new Set(),
    retiredAgentIdStrings: new Set(),
    all: [...byRowId.values()],
  };
}

function executableRenewalProfile() {
  return {
    schemaVersion: 1,
    profileId: "profile-1",
    profileName: "web-tls",
    sanPolicy: { mode: "exact", sans: ["app.example.com"], allowWildcards: false },
    keyAlgorithm: "rsa",
    keySize: 2048,
    keyRotationPolicy: { rotateOnRenew: true },
    preferredChain: null,
    ca: { endpoint: "https://acme.example.test/directory", accountRef: null, eabRef: null },
    acme: { kind: "certbot", commandRef: "renew.web" },
    dns: { provider: "cloudflare", zone: "example.com" },
    deploymentTargets: [
      { type: "endpoint", reference: "host/web", certPath: "/etc/ssl/app.pem" },
    ],
    target: { type: "endpoint", reference: "host/web", certPath: "/etc/ssl/app.pem" },
    verification: { host: null, port: null, requireMatch: false },
  };
}

function onlineAgentRow(overrides = {}) {
  return agentRow({
    id: "agent-a",
    lastSeenAt: new Date(NOW - 60 * 1000).toISOString(),
    ...overrides,
  });
}

function offlineAgentRow(overrides = {}) {
  return agentRow({
    id: "agent-a",
    lastSeenAt: new Date(NOW - 60 * 60 * 1000).toISOString(),
    ...overrides,
  });
}

function certRow(overrides = {}) {
  return {
    id: "cert-1",
    workspace_id: "ws-1",
    status: "active",
    key_mode: "agent-local",
    source: "agent_filesystem",
    profile_id: "profile-1",
    deployed_agent_id: null,
    discovery_agent_id: null,
    profile_status: "active",
    profile_issuer_id: "issuer-1",
    profile_public_metadata: {
      renewalProfile: executableRenewalProfile(),
    },
    ...overrides,
  };
}

describe("renewalPathHealth: targetReferenceFromProfile", () => {
  it("reads target.reference when present", () => {
    const ref = targetReferenceFromProfile({
      renewalProfile: { target: { reference: "host/web" } },
    });
    assert.equal(ref, "host/web");
  });

  it("falls back to deploymentTargets[0].reference", () => {
    const ref = targetReferenceFromProfile({
      renewalProfile: { deploymentTargets: [{ reference: "host/other" }] },
    });
    assert.equal(ref, "host/other");
  });

  it("returns null when no reference is present", () => {
    assert.equal(targetReferenceFromProfile({}), null);
    assert.equal(targetReferenceFromProfile(null), null);
  });
});

describe("renewalPathHealth: resolveRequiredExecutors", () => {
  it("CASE A: agent_filesystem legacy discovery-agent string resolves to exactly one required executor", () => {
    const agentIndex = buildAgentIndex([
      onlineAgentRow({ id: "row-1", agentId: "agent-a" }),
    ]);
    const { pinned, pinnedButRetired, agents } = resolveRequiredExecutors({
      certificateRow: certRow({
        source: "agent_filesystem",
        deployed_agent_id: null,
        discovery_agent_id: "agent-a",
      }),
      profileMetadata: { renewalProfile: {} },
      agentIndex,
      offlineAfterMs: OFFLINE_AFTER_MS,
      now: NOW,
    });
    assert.equal(pinned, true);
    assert.equal(pinnedButRetired, false);
    assert.equal(agents.length, 1);
    assert.equal(agents[0].required, true);
    assert.equal(agents[0].online, true);
  });

  it("deployed_agent_id alone (non-agent_filesystem source) is NOT a pin: falls to open-claim", () => {
    // resolveManagedCertificateJobDefaults (jobs.js) never reads
    // deployed_agent_id, and only auto-pins agent_filesystem-sourced
    // certificates. An adopted certificate (source "manual"/"api"/etc.)
    // with deployed_agent_id set must still resolve via the declared
    // target selector, matching what the real scheduler will actually do
    // for every renewal after the one-time setup job.
    const agentIndex = buildAgentIndex([
      onlineAgentRow({ id: "agent-a", targetSelectors: ["host/web"] }),
      offlineAgentRow({ id: "agent-b", targetSelectors: ["host/web"] }),
    ]);
    const { pinned, pinnedButRetired, agents, targetReference } = resolveRequiredExecutors({
      certificateRow: certRow({
        source: "manual",
        deployed_agent_id: "agent-a",
        discovery_agent_id: null,
      }),
      profileMetadata: {
        renewalProfile: { target: { reference: "host/web" } },
      },
      agentIndex,
      offlineAfterMs: OFFLINE_AFTER_MS,
      now: NOW,
    });
    assert.equal(pinned, false);
    assert.equal(pinnedButRetired, false);
    assert.equal(targetReference, "host/web");
    assert.equal(agents.length, 2);
    assert.ok(agents.every((a) => a.required === false));
  });

  it("pinned agent_filesystem discovery agent that has since retired: pinnedButRetired, no open-claim fallback", () => {
    // The retired agent is excluded from agentIndex (retireAgent-style),
    // but a live agent-b happens to also declare the same target selector.
    // Real dispatch would never let agent-b claim this job (assigned_agent_id
    // still hard-pins to the retired row), so this must not resolve as
    // Degraded/Healthy via agent-b.
    const agentIndex = buildAgentIndex([
      onlineAgentRow({ id: "agent-b", targetSelectors: ["host/web"] }),
    ]);
    agentIndex.retiredAgentIdStrings.add("agent-a");
    const { pinned, pinnedButRetired, agents } = resolveRequiredExecutors({
      certificateRow: certRow({
        source: "agent_filesystem",
        deployed_agent_id: null,
        discovery_agent_id: "agent-a",
      }),
      profileMetadata: {
        renewalProfile: { target: { reference: "host/web" } },
      },
      agentIndex,
      offlineAfterMs: OFFLINE_AFTER_MS,
      now: NOW,
    });
    assert.equal(pinned, true);
    assert.equal(pinnedButRetired, true);
    assert.deepEqual(agents, []);
  });

  it("open-claim: single agent declaring the target selector is required", () => {
    const agentIndex = buildAgentIndex([
      onlineAgentRow({ id: "agent-a", targetSelectors: ["host/web"] }),
    ]);
    const { pinned, agents, targetReference } = resolveRequiredExecutors({
      certificateRow: certRow(),
      profileMetadata: {
        renewalProfile: { target: { reference: "host/web" } },
      },
      agentIndex,
      offlineAfterMs: OFFLINE_AFTER_MS,
      now: NOW,
    });
    assert.equal(pinned, false);
    assert.equal(targetReference, "host/web");
    assert.equal(agents.length, 1);
    assert.equal(agents[0].required, true);
  });

  it("CASE B: two agents declaring the same selector are redundant, not required", () => {
    const agentIndex = buildAgentIndex([
      onlineAgentRow({ id: "agent-a", targetSelectors: ["host/web"] }),
      offlineAgentRow({ id: "agent-b", targetSelectors: ["host/web"] }),
    ]);
    const { agents } = resolveRequiredExecutors({
      certificateRow: certRow(),
      profileMetadata: {
        renewalProfile: { target: { reference: "host/web" } },
      },
      agentIndex,
      offlineAfterMs: OFFLINE_AFTER_MS,
      now: NOW,
    });
    assert.equal(agents.length, 2);
    assert.ok(agents.every((a) => a.required === false));
  });

  it("no pin and no target reference resolves to an empty (topology-unknown) set", () => {
    const agentIndex = buildAgentIndex([]);
    const { agents, targetReference } = resolveRequiredExecutors({
      certificateRow: certRow(),
      profileMetadata: {},
      agentIndex,
      offlineAfterMs: OFFLINE_AFTER_MS,
      now: NOW,
    });
    assert.equal(agents.length, 0);
    assert.equal(targetReference, null);
  });

  it("pinned agent_filesystem discovery agent that is compatibility-blocked: pinnedAgentIneligibleReason set, no open-claim fallback even with a live redundant-looking agent", () => {
    // Real dispatch would never let agent-b claim this job (assigned_agent_id
    // still hard-pins to agent-a), so a live decoy declaring the same
    // selector must not resolve this as Degraded/Healthy via agent-b.
    const agentIndex = buildAgentIndex([
      onlineAgentRow({ id: "agent-a", protocolVersion: "999.0.0" }),
      onlineAgentRow({ id: "agent-b", targetSelectors: ["host/web"] }),
    ]);
    const jobRequirements = {
      operation: "renew",
      executorKind: "agent",
      requiredTargetSelector: "host/web",
    };
    const { pinned, pinnedButRetired, pinnedAgentIneligibleReason, agents } =
      resolveRequiredExecutors({
        certificateRow: certRow({
          source: "agent_filesystem",
          deployed_agent_id: null,
          discovery_agent_id: "agent-a",
        }),
        profileMetadata: {
          renewalProfile: { target: { reference: "host/web" } },
        },
        agentIndex,
        offlineAfterMs: OFFLINE_AFTER_MS,
        now: NOW,
        jobRequirements,
      });
    assert.equal(pinned, true);
    assert.equal(pinnedButRetired, false);
    assert.equal(pinnedAgentIneligibleReason, "compatibility_blocked");
    assert.equal(agents.length, 0);
  });

  it("pinned agent that has never declared any supported operation (fresh/never-polled agent): pinnedAgentIneligibleReason 'operation_unsupported', no declared operations", () => {
    const agentIndex = buildAgentIndex([
      onlineAgentRow({ id: "agent-a", supportedOperations: [] }),
    ]);
    const jobRequirements = {
      operation: "renew",
      executorKind: "agent",
      requiredTargetSelector: "host/web",
    };
    const {
      pinned,
      pinnedAgentIneligibleReason,
      pinnedAgentDeclaredOperations,
      agents,
    } = resolveRequiredExecutors({
      certificateRow: certRow({
        source: "agent_filesystem",
        deployed_agent_id: null,
        discovery_agent_id: "agent-a",
      }),
      profileMetadata: {
        renewalProfile: { target: { reference: "host/web" } },
      },
      agentIndex,
      offlineAfterMs: OFFLINE_AFTER_MS,
      now: NOW,
      jobRequirements,
    });
    assert.equal(pinned, true);
    assert.equal(pinnedAgentIneligibleReason, "operation_unsupported");
    assert.deepEqual(pinnedAgentDeclaredOperations, []);
    assert.equal(agents.length, 0);
  });

  it("pinned agent that declared other operations but not renew (partial capability, not never-polled): pinnedAgentDeclaredOperations names what it DID declare", () => {
    const agentIndex = buildAgentIndex([
      onlineAgentRow({
        id: "agent-a",
        supportedOperations: ["issue", "deploy"],
      }),
    ]);
    const jobRequirements = {
      operation: "renew",
      executorKind: "agent",
      requiredTargetSelector: "host/web",
    };
    const {
      pinned,
      pinnedAgentIneligibleReason,
      pinnedAgentDeclaredOperations,
      agents,
    } = resolveRequiredExecutors({
      certificateRow: certRow({
        source: "agent_filesystem",
        deployed_agent_id: null,
        discovery_agent_id: "agent-a",
      }),
      profileMetadata: {
        renewalProfile: { target: { reference: "host/web" } },
      },
      agentIndex,
      offlineAfterMs: OFFLINE_AFTER_MS,
      now: NOW,
      jobRequirements,
    });
    assert.equal(pinned, true);
    assert.equal(pinnedAgentIneligibleReason, "operation_unsupported");
    assert.deepEqual(pinnedAgentDeclaredOperations, ["issue", "deploy"]);
    assert.equal(agents.length, 0);
  });
});

describe("renewalPathHealth: classifyExecutors", () => {
  it("CASE A: one required agent online -> Healthy", () => {
    const result = classifyExecutors({
      agents: [{ agentRowId: "a", required: true, online: true }],
      targetReference: null,
      hasResolvableTopology: true,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.HEALTHY);
    assert.equal(result.renewalPathReason, RENEWAL_PATH_REASONS.ALL_PATHS_AVAILABLE);
  });

  it("CASE A: only required agent offline -> Renewal path unavailable", () => {
    const result = classifyExecutors({
      agents: [{ agentRowId: "a", required: true, online: false }],
      targetReference: null,
      hasResolvableTopology: true,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(result.renewalPathReason, RENEWAL_PATH_REASONS.AGENT_OFFLINE);
  });

  it("CASE B: redundant A+B, one offline -> Degraded", () => {
    const result = classifyExecutors({
      agents: [
        { agentRowId: "a", required: false, online: true },
        { agentRowId: "b", required: false, online: false },
      ],
      targetReference: "host/web",
      hasResolvableTopology: true,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.DEGRADED);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.PARTIAL_LOCATION_OUTAGE,
    );
  });

  it("CASE C: redundant A+B, both offline -> Renewal path unavailable", () => {
    const result = classifyExecutors({
      agents: [
        { agentRowId: "a", required: false, online: false },
        { agentRowId: "b", required: false, online: false },
      ],
      targetReference: "host/web",
      hasResolvableTopology: true,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.ALL_EXECUTORS_OFFLINE,
    );
  });

  it("pinnedAgentIneligibleReason 'compatibility_blocked' -> Renewal path unavailable, assigned_agent_ineligible, summary reused from TRUST_JOB_INELIGIBLE_MESSAGE_BY_REASON", () => {
    const result = classifyExecutors({
      agents: [],
      targetReference: null,
      hasResolvableTopology: true,
      pinnedAgentIneligibleReason: "compatibility_blocked",
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.ASSIGNED_AGENT_INELIGIBLE,
    );
    assert.equal(
      result.renewalPathSummary,
      TRUST_JOB_INELIGIBLE_MESSAGE_BY_REASON.compatibility_blocked,
    );
  });

  it("pinnedAgentIneligibleReason 'operation_unsupported' -> Renewal path unavailable, assigned_agent_ineligible, operation-agnostic summary (not the trust-specific one)", () => {
    const result = classifyExecutors({
      agents: [],
      targetReference: null,
      hasResolvableTopology: true,
      pinnedAgentIneligibleReason: "operation_unsupported",
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.ASSIGNED_AGENT_INELIGIBLE,
    );
    assert.equal(result.renewalPathSummary, NO_CAPABILITY_DECLARED_SUMMARY);
    assert.notEqual(
      result.renewalPathSummary,
      TRUST_JOB_INELIGIBLE_MESSAGE_BY_REASON.operation_unsupported,
    );
  });

  it("pinnedAgentIneligibleReason 'operation_unsupported' WITH declared operations -> distinct partial-capability summary, not the 'declared nothing' wording", () => {
    const result = classifyExecutors({
      agents: [],
      targetReference: null,
      hasResolvableTopology: true,
      pinnedAgentIneligibleReason: "operation_unsupported",
      pinnedAgentDeclaredOperations: ["issue", "deploy"],
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.ASSIGNED_AGENT_INELIGIBLE,
    );
    assert.notEqual(result.renewalPathSummary, NO_CAPABILITY_DECLARED_SUMMARY);
    assert.match(result.renewalPathSummary, /issue, deploy/);
    assert.match(result.renewalPathSummary, /not for renew/);
  });

  it("no execution target resolved -> Renewal path unavailable", () => {
    const result = classifyExecutors({
      agents: [],
      targetReference: "host/web",
      hasResolvableTopology: true,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.NO_EXECUTION_TARGET,
    );
  });

  it("topology insufficient -> Unknown", () => {
    const result = classifyExecutors({
      agents: [],
      targetReference: null,
      hasResolvableTopology: false,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNKNOWN);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.TOPOLOGY_UNKNOWN,
    );
  });
});

describe("renewalPathHealth: resolveRenewalPathForRow (end to end classification)", () => {
  it("auto-renew disabled profile does not report a misleading failure state", () => {
    const agentIndex = buildAgentIndex([offlineAgentRow({ id: "agent-a" })]);
    const result = resolveRenewalPathForRow({
      certificateRow: certRow({
        deployed_agent_id: "agent-a",
        profile_status: "disabled",
      }),
      agentIndex,
      now: NOW,
    });
    assert.equal(result.renewalPathState, null);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.AUTO_RENEW_DISABLED,
    );
    assert.deepEqual(result.dependencies, []);
  });

  it("certificate with no profile reports no_profile, not unknown", () => {
    const agentIndex = buildAgentIndex([]);
    const result = resolveRenewalPathForRow({
      certificateRow: certRow({ profile_id: null }),
      agentIndex,
      now: NOW,
    });
    assert.equal(result.renewalPathState, null);
    assert.equal(result.renewalPathReason, RENEWAL_PATH_REASONS.NO_PROFILE);
  });

  it("unprofiled certificate with a deployed-agent pin that declared issue/deploy but not renew reports assigned_agent_ineligible", () => {
    const agentIndex = buildAgentIndex([
      onlineAgentRow({
        id: "agent-a",
        supportedOperations: ["issue", "deploy"],
      }),
    ]);
    const result = resolveRenewalPathForRow({
      certificateRow: certRow({
        profile_id: null,
        source: "manual",
        deployed_agent_id: "agent-a",
        discovery_agent_id: null,
      }),
      agentIndex,
      now: NOW,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.ASSIGNED_AGENT_INELIGIBLE,
    );
    assert.match(result.renewalPathSummary, /issue, deploy/);
    assert.match(result.renewalPathSummary, /not for renew/);
    assert.doesNotMatch(result.renewalPathSummary, /has not declared any/);
  });

  it("unprofiled certificate with a capable deployed-agent pin still reports no_profile (not a healthy auto-renew path)", () => {
    const agentIndex = buildAgentIndex([
      onlineAgentRow({ id: "agent-a", supportedOperations: ["renew"] }),
    ]);
    const result = resolveRenewalPathForRow({
      certificateRow: certRow({
        profile_id: null,
        source: "manual",
        deployed_agent_id: "agent-a",
        discovery_agent_id: null,
      }),
      agentIndex,
      now: NOW,
    });
    assert.equal(result.renewalPathState, null);
    assert.equal(result.renewalPathReason, RENEWAL_PATH_REASONS.NO_PROFILE);
  });

  it("observation-only certificate (no agent-deployable key custody) is not_agent_deployable", () => {
    const agentIndex = buildAgentIndex([]);
    const result = resolveRenewalPathForRow({
      certificateRow: certRow({ key_mode: null }),
      agentIndex,
      now: NOW,
    });
    assert.equal(result.renewalPathState, null);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.NOT_AGENT_DEPLOYABLE,
    );
  });

  it("decommissioned certificate is not applicable", () => {
    const agentIndex = buildAgentIndex([]);
    const result = resolveRenewalPathForRow({
      certificateRow: certRow({ status: "decommissioned" }),
      agentIndex,
      now: NOW,
    });
    assert.equal(result.renewalPathState, null);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.CERTIFICATE_RETIRED,
    );
  });

  it("pinned online agent -> Healthy with one dependency", () => {
    const agentIndex = buildAgentIndex([onlineAgentRow({ id: "agent-a" })]);
    const result = resolveRenewalPathForRow({
      certificateRow: certRow({ discovery_agent_id: "agent-a" }),
      agentIndex,
      now: NOW,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.HEALTHY);
    assert.equal(result.dependencies.length, 1);
    assert.equal(result.dependencies[0].agentRowId, "agent-a");
  });

  it("pinned offline agent -> Renewal path unavailable", () => {
    const agentIndex = buildAgentIndex([offlineAgentRow({ id: "agent-a" })]);
    const result = resolveRenewalPathForRow({
      certificateRow: certRow({ discovery_agent_id: "agent-a" }),
      agentIndex,
      now: NOW,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(result.renewalPathReason, RENEWAL_PATH_REASONS.AGENT_OFFLINE);
  });

  it("pinned agent that has since retired -> Renewal path unavailable (assigned_agent_retired), even with a live redundant-looking agent", () => {
    const agentIndex = buildAgentIndex([
      onlineAgentRow({ id: "agent-b", targetSelectors: ["host/web"] }),
    ]);
    agentIndex.retiredAgentIdStrings.add("agent-a");
    const result = resolveRenewalPathForRow({
      certificateRow: certRow({ discovery_agent_id: "agent-a" }),
      agentIndex,
      now: NOW,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.ASSIGNED_AGENT_RETIRED,
    );
    assert.deepEqual(result.dependencies, []);
  });

  it("pinned agent that is compatibility-blocked -> Renewal path unavailable (assigned_agent_ineligible), not no_execution_target, even with a live redundant-looking agent", () => {
    const agentIndex = buildAgentIndex([
      onlineAgentRow({ id: "agent-a", protocolVersion: "999.0.0" }),
      onlineAgentRow({ id: "agent-b", targetSelectors: ["host/web"] }),
    ]);
    const result = resolveRenewalPathForRow({
      certificateRow: certRow({ discovery_agent_id: "agent-a" }),
      agentIndex,
      now: NOW,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.ASSIGNED_AGENT_INELIGIBLE,
    );
    assert.notEqual(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.NO_EXECUTION_TARGET,
    );
    assert.deepEqual(result.dependencies, []);
  });

  it("pinned agent that has never declared any supported operation -> Renewal path unavailable (assigned_agent_ineligible), not no_execution_target, 'has not declared any executable action' wording", () => {
    const agentIndex = buildAgentIndex([
      onlineAgentRow({ id: "agent-a", supportedOperations: [] }),
    ]);
    const result = resolveRenewalPathForRow({
      certificateRow: certRow({ discovery_agent_id: "agent-a" }),
      agentIndex,
      now: NOW,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.ASSIGNED_AGENT_INELIGIBLE,
    );
    assert.notEqual(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.NO_EXECUTION_TARGET,
    );
    assert.match(result.renewalPathSummary, /has not declared any/);
    assert.deepEqual(result.dependencies, []);
  });

  it("pinned agent that declared other operations but not renew -> Renewal path unavailable (assigned_agent_ineligible), summary names what it DID declare instead of claiming it declared nothing", () => {
    const agentIndex = buildAgentIndex([
      onlineAgentRow({
        id: "agent-a",
        supportedOperations: ["issue", "deploy"],
      }),
    ]);
    const result = resolveRenewalPathForRow({
      certificateRow: certRow({ discovery_agent_id: "agent-a" }),
      agentIndex,
      now: NOW,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.ASSIGNED_AGENT_INELIGIBLE,
    );
    assert.doesNotMatch(result.renewalPathSummary, /has not declared any/);
    assert.match(result.renewalPathSummary, /issue, deploy/);
    assert.deepEqual(result.dependencies, []);
  });
});

// A profile as the AD CS create path stores it: no ACME schemaVersion, a
// Windows/IIS target, and DNS names only.
function nativeAdcsProfile(overrides = {}) {
  return {
    target: {
      type: "windows-iis",
      reference: "app.example.com",
      store: "My",
      binding: { site: "Default Web Site", port: 443 },
    },
    sanPolicy: { sans: ["app.example.com"] },
    keyAlgorithm: "rsa",
    keySize: 2048,
    ...overrides,
  };
}

function nativeAdcsIndex({ declaredCapabilities = [], updatedAtMs = NOW } = {}) {
  const agentIndex = buildAgentIndex([
    onlineAgentRow({ id: "agent-a", targetSelectors: ["app.example.com"] }),
  ]);
  const candidate = agentIndex.byRowId.get("agent-a");
  candidate.declaredCapabilities = declaredCapabilities;
  candidate.capabilitiesUpdatedAt = new Date(updatedAtMs).toISOString();
  return agentIndex;
}

// The index loadAdcsPreflightIndex builds: agents holding a fresh, safe
// adcs-preflight for issuer-1 against the native profile's target.
function freshPreflightIndex(agentRowIds = ["agent-a"]) {
  return new Map([
    [adcsPreflightKey("issuer-1", "app.example.com"), new Set(agentRowIds)],
  ]);
}

describe("renewalPathHealth: native AD CS profiles", () => {
  const nativeRow = (overrides = {}) =>
    certRow({
      profile_issuer_kind: "adcs",
      profile_public_metadata: { renewalProfile: nativeAdcsProfile() },
      ...overrides,
    });

  it("valid native profile with a fresh adcs-enroll-v1 declaration reports its normal state, not unknown", () => {
    const result = resolveRenewalPathForRow({
      certificateRow: nativeRow(),
      agentIndex: nativeAdcsIndex({
        declaredCapabilities: ["adcs-enroll-v1"],
        updatedAtMs: NOW - 30_000,
      }),
      now: NOW,
      adcsPreflightIndex: freshPreflightIndex(),
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.HEALTHY);
    assert.equal(result.renewalPathReason, RENEWAL_PATH_REASONS.ALL_PATHS_AVAILABLE);
  });

  it("valid native profile without adcs-enroll-v1 reports unavailable naming the capability", () => {
    const result = resolveRenewalPathForRow({
      certificateRow: nativeRow(),
      agentIndex: nativeAdcsIndex({ declaredCapabilities: [] }),
      now: NOW,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.ADCS_ENROLL_CAPABILITY_UNAVAILABLE,
    );
  });

  it("native profile missing its IIS binding is unknown, judged by AD CS rules rather than ACME fields", () => {
    const result = resolveRenewalPathForRow({
      certificateRow: certRow({
        profile_issuer_kind: "adcs",
        profile_public_metadata: {
          renewalProfile: nativeAdcsProfile({
            target: { type: "windows-iis", reference: "app.example.com", store: "My" },
          }),
        },
      }),
      agentIndex: nativeAdcsIndex({
        declaredCapabilities: ["adcs-enroll-v1"],
        updatedAtMs: NOW - 30_000,
      }),
      now: NOW,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNKNOWN);
    assert.equal(result.renewalPathReason, RENEWAL_PATH_REASONS.TOPOLOGY_UNKNOWN);
  });

  it("ACME profile with no adcs-enroll-v1 declaration is unchanged (healthy)", () => {
    const result = resolveRenewalPathForRow({
      certificateRow: certRow({ profile_issuer_kind: "acme" }),
      agentIndex: buildAgentIndex([onlineAgentRow({ id: "agent-a" })]),
      now: NOW,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.HEALTHY);
    assert.equal(result.renewalPathReason, RENEWAL_PATH_REASONS.ALL_PATHS_AVAILABLE);
  });
});

describe("renewalPathHealth: AD CS renewals gated on adcs-enroll-v1", () => {
  // An ACME-shaped profile moved onto an AD CS issuer: it keeps schemaVersion
  // and the ACME fields, and gains the Windows/IIS target AD CS requires.
  const switchedAdcsProfile = () => ({
    ...executableRenewalProfile(),
    target: {
      type: "windows-iis",
      reference: "app.example.com",
      store: "My",
      binding: { site: "Default Web Site", port: 443 },
    },
    deploymentTargets: [
      {
        type: "windows-iis",
        reference: "app.example.com",
        store: "My",
        binding: { site: "Default Web Site", port: 443 },
      },
    ],
    sanPolicy: { mode: "exact", sans: ["app.example.com"], allowWildcards: false },
  });
  const switchedRow = (overrides = {}) =>
    certRow({
      profile_issuer_kind: "adcs",
      profile_public_metadata: { renewalProfile: switchedAdcsProfile() },
      ...overrides,
    });

  function adcsIndex({ id = "agent-a", declaredCapabilities = [], updatedAtMs = NOW } = {}) {
    const agentIndex = buildAgentIndex([
      onlineAgentRow({ id, targetSelectors: ["app.example.com"] }),
    ]);
    const candidate = agentIndex.byRowId.get(id);
    candidate.declaredCapabilities = declaredCapabilities;
    candidate.capabilitiesUpdatedAt = new Date(updatedAtMs).toISOString();
    return agentIndex;
  }

  it("missing declaration -> Renewal path unavailable naming adcs-enroll-v1, not healthy", () => {
    const result = resolveRenewalPathForRow({
      certificateRow: switchedRow(),
      agentIndex: adcsIndex({ declaredCapabilities: [] }),
      now: NOW,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.ADCS_ENROLL_CAPABILITY_UNAVAILABLE,
    );
    assert.match(result.renewalPathSummary, /adcs-enroll-v1/);
    assert.deepEqual(result.dependencies, []);
  });

  it("stale declaration past the capability epoch -> blocked with the same reason", () => {
    const result = resolveRenewalPathForRow({
      certificateRow: switchedRow(),
      agentIndex: adcsIndex({
        declaredCapabilities: ["adcs-enroll-v1"],
        updatedAtMs: NOW - 60 * 60 * 1000,
      }),
      now: NOW,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.ADCS_ENROLL_CAPABILITY_UNAVAILABLE,
    );
  });

  it("fresh declaration -> Healthy with the declaring agent as the dependency", () => {
    const result = resolveRenewalPathForRow({
      certificateRow: switchedRow(),
      agentIndex: adcsIndex({
        declaredCapabilities: ["adcs-enroll-v1"],
        updatedAtMs: NOW - 30_000,
      }),
      now: NOW,
      adcsPreflightIndex: freshPreflightIndex(),
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.HEALTHY);
    assert.equal(result.dependencies.length, 1);
    assert.equal(result.dependencies[0].agentRowId, "agent-a");
  });

  it("an undeclared agent does not count as a redundant AD CS path", () => {
    const agentIndex = buildAgentIndex([
      onlineAgentRow({ id: "agent-a", targetSelectors: ["app.example.com"] }),
      onlineAgentRow({ id: "agent-b", targetSelectors: ["app.example.com"] }),
    ]);
    const declaring = agentIndex.byRowId.get("agent-b");
    declaring.declaredCapabilities = ["adcs-enroll-v1"];
    declaring.capabilitiesUpdatedAt = new Date(NOW - 30_000).toISOString();
    const result = resolveRenewalPathForRow({
      certificateRow: switchedRow(),
      agentIndex,
      now: NOW,
      adcsPreflightIndex: freshPreflightIndex(["agent-b"]),
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.HEALTHY);
    assert.deepEqual(
      result.dependencies.map((dependency) => dependency.agentRowId),
      ["agent-b"],
    );
  });

  it("ACME renewal without any adcs-enroll-v1 declaration is unchanged (healthy)", () => {
    const result = resolveRenewalPathForRow({
      certificateRow: certRow({ profile_issuer_kind: "acme" }),
      agentIndex: buildAgentIndex([onlineAgentRow({ id: "agent-a" })]),
      now: NOW,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.HEALTHY);
    assert.equal(result.renewalPathReason, RENEWAL_PATH_REASONS.ALL_PATHS_AVAILABLE);
  });

  it("pinned AD CS renewal without declaration names the capability", () => {
    const result = resolveRenewalPathForRow({
      certificateRow: switchedRow({ discovery_agent_id: "agent-a" }),
      agentIndex: adcsIndex({ declaredCapabilities: [] }),
      now: NOW,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.ADCS_ENROLL_CAPABILITY_UNAVAILABLE,
    );
  });

  it("a second blocker on the pinned agent is reported instead of the missing declaration", () => {
    const agentIndex = adcsIndex({ declaredCapabilities: [] });
    agentIndex.byRowId.get("agent-a").supportedOperations = ["issue"];
    const result = resolveRenewalPathForRow({
      certificateRow: switchedRow({ discovery_agent_id: "agent-a" }),
      agentIndex,
      now: NOW,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.ASSIGNED_AGENT_INELIGIBLE,
    );
  });
});

describe("renewalPathHealth: switched profiles follow the AD CS rules", () => {
  const switchedProfile = () => ({
    ...executableRenewalProfile(),
    target: {
      type: "windows-iis",
      reference: "app.example.com",
      store: "My",
      binding: { site: "Default Web Site", port: 443 },
    },
    sanPolicy: { mode: "exact", sans: ["app.example.com"], allowWildcards: false },
  });
  const indexWith = (declaredCapabilities, updatedAtMs) => {
    const agentIndex = buildAgentIndex([
      onlineAgentRow({ id: "agent-a", targetSelectors: ["app.example.com"] }),
    ]);
    const candidate = agentIndex.byRowId.get("agent-a");
    candidate.declaredCapabilities = declaredCapabilities;
    candidate.capabilitiesUpdatedAt = new Date(updatedAtMs).toISOString();
    return agentIndex;
  };

  it("ACME-shaped profile switched to AD CS with no adcs-enroll-v1 is unavailable, not healthy", () => {
    const result = resolveRenewalPathForRow({
      certificateRow: certRow({
        profile_issuer_kind: "adcs",
        profile_public_metadata: { renewalProfile: switchedProfile() },
      }),
      agentIndex: indexWith([], NOW),
      now: NOW,
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.ADCS_ENROLL_CAPABILITY_UNAVAILABLE,
    );
  });

  it("ACME-shaped profile switched to AD CS with a fresh adcs-enroll-v1 reports its normal state", () => {
    const result = resolveRenewalPathForRow({
      certificateRow: certRow({
        profile_issuer_kind: "adcs",
        profile_public_metadata: { renewalProfile: switchedProfile() },
      }),
      agentIndex: indexWith(["adcs-enroll-v1"], NOW - 30_000),
      now: NOW,
      adcsPreflightIndex: freshPreflightIndex(),
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.HEALTHY);
    assert.equal(result.renewalPathReason, RENEWAL_PATH_REASONS.ALL_PATHS_AVAILABLE);
  });
});

describe("renewalPathHealth: resolveRenewalPathForCertificate (DB-facing)", () => {
  function fakeDb({ certRows, agentRows }) {
    return {
      queries: [],
      async query(sql, params) {
        const normalized = String(sql).replace(/\s+/g, " ").trim();
        this.queries.push({ sql: normalized, params });
        if (normalized.startsWith("SELECT mc.id")) {
          return { rows: certRows };
        }
        if (normalized.startsWith("SELECT id, agent_id, name, hostname")) {
          return { rows: agentRows };
        }
        return { rows: [] };
      },
    };
  }

  it("returns null when the certificate does not exist in the workspace", async () => {
    const db = fakeDb({ certRows: [], agentRows: [] });
    const result = await resolveRenewalPathForCertificate({
      db,
      workspaceId: "ws-1",
      certificateId: "missing",
    });
    assert.equal(result, null);
  });

  it("resolves Healthy end to end against a fake db", async () => {
    const db = fakeDb({
      certRows: [
        {
          id: "cert-1",
          workspace_id: "ws-1",
          status: "active",
          key_mode: "agent-local",
          source: "agent_filesystem",
          profile_id: "profile-1",
          deployed_agent_id: null,
          discovery_agent_id: "agent-a",
          profile_status: "active",
          profile_public_metadata: { renewalProfile: executableRenewalProfile() },
        },
      ],
      // resolveRenewalPathForCertificate has no injectable `now` (unlike the
      // pure resolveRenewalPathForRow unit tests above): it always classifies
      // liveness against the real Date.now(), so this fixture's lastSeenAt
      // must be relative to actual wall-clock time, not the fixed NOW anchor
      // used by the pure-function tests, or this test silently rots into a
      // false "offline" failure once real time passes that fixed instant.
      agentRows: [onlineAgentRow({ id: "agent-a", lastSeenAt: new Date(Date.now() - 60 * 1000).toISOString() })],
    });
    const result = await resolveRenewalPathForCertificate({
      db,
      workspaceId: "ws-1",
      certificateId: "cert-1",
    });
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.HEALTHY);
  });
});

describe("renewalPathHealth: AD CS preflight freshness", () => {
  const DAY_MS = 24 * 60 * 60 * 1000;
  const CA = "ca01.corp.example.com\\Corp Issuing CA 01";
  const KEY = "a".repeat(64);
  const TEMPLATE = "TokenTimerWebServer";

  const issuerVersion = () => ({
    ca_config: CA,
    template: TEMPLATE,
    ca_key_sha256: KEY,
    confirmed_at: new Date(Date.now() - 7 * DAY_MS),
  });

  // The latest adcs-preflight an agent holds, as the gate loads it.
  const preflightRow = (createdAgoMs) => ({
    id: "agent-a",
    last_seen_at: new Date(Date.now() - 60 * 1000).toISOString(),
    status: "succeeded",
    result_metadata: {
      preflightVerdict: {
        templateCheck: "safe",
        caCheck: "safe",
        caConfig: CA,
        template: TEMPLATE,
        caKeySha256s: [KEY],
      },
    },
    created_at: new Date(Date.now() - createdAgoMs),
  });

  // Answers only the SQL the batch loads. The freshness decision runs on the
  // evidence rows, through the same gate the scheduler uses.
  function dbWithEvidence(evidenceRows) {
    const agent = {
      ...onlineAgentRow({
        id: "agent-a",
        targetSelectors: ["app.example.com"],
        lastSeenAt: new Date(Date.now() - 60 * 1000).toISOString(),
      }),
      declared_capabilities: ["adcs-enroll-v1"],
      capabilities_updated_at: new Date(Date.now() - 30 * 1000).toISOString(),
    };
    const certificate = certRow({
      profile_issuer_kind: "adcs",
      profile_public_metadata: { renewalProfile: nativeAdcsProfile() },
    });
    return {
      async query(sql) {
        const normalized = String(sql).replace(/\s+/g, " ").trim();
        if (normalized.startsWith("SELECT mc.id")) return { rows: [certificate] };
        if (normalized.startsWith("SELECT id, agent_id, name, hostname")) {
          return { rows: [agent] };
        }
        if (normalized.includes("FROM certificate_issuers i")) {
          return { rows: [issuerVersion()] };
        }
        if (normalized.includes("LEFT JOIN LATERAL")) return { rows: evidenceRows };
        return { rows: [] };
      },
    };
  }

  async function healthWithEvidence(evidenceRows) {
    const result = await resolveRenewalPathsForCertificateIds({
      db: dbWithEvidence(evidenceRows),
      workspaceId: "ws-1",
      certificateIds: ["cert-1"],
    });
    return result.get("cert-1");
  }

  it("waits when no agent has run adcs-preflight for the CA", async () => {
    const result = await healthWithEvidence([]);
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.WAITING_FOR_FRESH_PREFLIGHT,
    );
    assert.match(result.renewalPathSummary, /fresh CA check/);
  });

  it("reports the normal state once an agent holds a fresh, safe preflight", async () => {
    const result = await healthWithEvidence([preflightRow(60 * 60 * 1000)]);
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.HEALTHY);
    assert.equal(result.renewalPathReason, RENEWAL_PATH_REASONS.ALL_PATHS_AVAILABLE);
  });

  it("waits when the only preflight is older than the freshness bound", async () => {
    const result = await healthWithEvidence([preflightRow(25 * 60 * 60 * 1000)]);
    assert.equal(result.renewalPathState, RENEWAL_PATH_STATES.UNAVAILABLE);
    assert.equal(
      result.renewalPathReason,
      RENEWAL_PATH_REASONS.WAITING_FOR_FRESH_PREFLIGHT,
    );
    assert.match(result.renewalPathSummary, /last 24 hours/);
  });
});

describe("renewalPathHealth: listCertificatesDependentOnAgent", () => {
  function fakeWorkspaceDb({ certRows, agentRows }) {
    return {
      async query(sql) {
        const normalized = String(sql).replace(/\s+/g, " ").trim();
        if (normalized.startsWith("SELECT mc.id")) return { rows: certRows };
        if (normalized.startsWith("SELECT id, agent_id, name, hostname")) {
          return { rows: agentRows };
        }
        return { rows: [] };
      },
    };
  }

  it("includes only auto-renew certificates actually dependent on the agent", async () => {
    const agentRows = [
      onlineAgentRow({ id: "agent-a" }),
      onlineAgentRow({ id: "agent-b" }),
    ];
    const certRows = [
      {
        id: "cert-dependent",
        workspace_id: "ws-1",
        status: "active",
        key_mode: "agent-local",
        source: "agent_filesystem",
        profile_id: "profile-1",
        deployed_agent_id: null,
        discovery_agent_id: "agent-a",
        profile_status: "active",
        profile_public_metadata: { renewalProfile: executableRenewalProfile() },
      },
      {
        id: "cert-unrelated",
        workspace_id: "ws-1",
        status: "active",
        key_mode: "agent-local",
        source: "agent_filesystem",
        profile_id: "profile-2",
        deployed_agent_id: null,
        discovery_agent_id: "agent-b",
        profile_status: "active",
        profile_public_metadata: { renewalProfile: executableRenewalProfile() },
      },
      {
        // Observed by agent-a but not a renewal dependency: no profile at all.
        id: "cert-observed-only",
        workspace_id: "ws-1",
        status: "discovered",
        key_mode: null,
        source: "agent_filesystem",
        profile_id: null,
        deployed_agent_id: null,
        discovery_agent_id: "agent-a",
        profile_status: null,
        profile_public_metadata: {},
      },
    ];
    const db = fakeWorkspaceDb({ certRows, agentRows });
    const dependent = await listCertificatesDependentOnAgent({
      db,
      workspaceId: "ws-1",
      agentRowId: "agent-a",
    });
    assert.equal(dependent.length, 1);
    assert.equal(dependent[0].certificateId, "cert-dependent");
  });
});

describe("renewalPathHealth: resolveRenewalPathsForWorkspace", () => {
  it("resolves a projection for every non-retired certificate in the workspace", async () => {
    const db = {
      async query(sql) {
        const normalized = String(sql).replace(/\s+/g, " ").trim();
        if (normalized.startsWith("SELECT mc.id")) {
          return {
            rows: [
              certRow({ id: "cert-1", discovery_agent_id: "agent-a" }),
              certRow({ id: "cert-2", discovery_agent_id: "agent-a" }),
            ],
          };
        }
        if (normalized.startsWith("SELECT id, agent_id, name, hostname")) {
          // Same real-Date.now() caveat as the resolveRenewalPathForCertificate
          // test above: resolveRenewalPathsForWorkspace computes `now` from
          // the real clock, not an injectable fixture anchor.
          return {
            rows: [onlineAgentRow({ id: "agent-a", lastSeenAt: new Date(Date.now() - 60 * 1000).toISOString() })],
          };
        }
        return { rows: [] };
      },
    };
    const results = await resolveRenewalPathsForWorkspace({
      db,
      workspaceId: "ws-1",
    });
    assert.equal(results.length, 2);
    assert.ok(results.every((r) => r.renewalPathState === RENEWAL_PATH_STATES.HEALTHY));
  });
});
