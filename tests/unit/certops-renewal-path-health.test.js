"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  RENEWAL_PATH_STATES,
  RENEWAL_PATH_REASONS,
  resolveRenewalPathForCertificate,
  resolveRenewalPathsForWorkspace,
  listCertificatesDependentOnAgent,
  _test: {
    resolveRenewalPathForRow,
    resolveRequiredExecutors,
    classifyExecutors,
    targetReferenceFromProfile,
  },
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/renewalPathHealth.js",
  ),
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
    protocol_version: "1.0.0",
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
