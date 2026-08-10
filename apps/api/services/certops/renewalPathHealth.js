"use strict";

/**
 * Derived, read-only health for a certificate's automatic-renewal execution
 * path. Certificate lifecycle and observed-location connectivity remain
 * separate axes: this projection answers only whether a live agent could
 * claim the renewal job that the current profile would create.
 *
 * Job requirements are derived through renewalProfile.js/jobs.js semantics,
 * then evaluated with the same pure predicate used by real dispatch. Filesystem
 * discoveries pin through their legacy discovery-agent identity; Windows IIS
 * discoveries pin through deployed_agent_id because the store and binding are
 * host-local. Other paths remain open to every genuinely eligible agent.
 * Unknown or malformed persisted eligibility facts fail closed to Unknown,
 * never Healthy.
 *
 * Zero custody is unchanged: only routing, capability, compatibility, and
 * liveness metadata is read here; no certificate private-key material exists
 * in this projection.
 */

const { pool } = require("../../db/database");
const { isAgentDeployableKeyMode } = require("./jobs");
const {
  AUTO_RENEW_DISABLED_PROFILE_STATUSES,
  executionFieldsFromRenewalProfile,
  validateRenewalProfile,
} = require("./renewalProfile");
const { computeAgentCompatibility } = require("./agentRegistry");
const {
  evaluateAgentJobEligibility,
  resolveAgentJobRoutingRequirements,
} = require("./agentJobEligibility");
const {
  resolveAgentOfflineAfterMs,
  classifyAgentLiveness,
} = require("./agentLiveness");

const RENEWAL_PATH_STATES = Object.freeze({
  HEALTHY: "healthy",
  DEGRADED: "degraded",
  UNAVAILABLE: "unavailable",
  UNKNOWN: "unknown",
});

const RENEWAL_PATH_REASONS = Object.freeze({
  ALL_PATHS_AVAILABLE: "all_paths_available",
  PARTIAL_LOCATION_OUTAGE: "partial_location_outage",
  AGENT_OFFLINE: "agent_offline",
  ALL_EXECUTORS_OFFLINE: "all_executors_offline",
  NO_EXECUTION_TARGET: "no_execution_target",
  TOPOLOGY_UNKNOWN: "topology_unknown",
  // The certificate's pinned executor (agent_filesystem discovery-agent
  // string) resolves to a real agent that has since been retired. Retirement
  // never re-derives a fresh assignment, so this pin is permanent and
  // distinct from "no execution target was ever configured" -- surfaced
  // separately so an operator knows re-homing (not just waiting for a
  // liveness recovery) is required.
  ASSIGNED_AGENT_RETIRED: "assigned_agent_retired",
  // Not in the product spec's suggested list, but needed so a certificate
  // that is not currently expected to auto-renew never gets shown next to
  // "Renewal path unavailable" -- rule: "auto-renew disabled should not
  // misleadingly show an active renewal dependency failure."
  AUTO_RENEW_DISABLED: "auto_renew_disabled",
  NOT_AGENT_DEPLOYABLE: "not_agent_deployable",
  NO_PROFILE: "no_profile",
  CERTIFICATE_RETIRED: "certificate_retired",
});

// Certificate lifecycle statuses for which "will this renew automatically"
// is a meaningless question -- mirrors the statuses NOT eligible for renewal
// scheduling (see renewalScheduler.js NON_RENEWABLE_CERTIFICATE_STATUSES,
// duplicated narrowly here rather than imported to avoid a require cycle
// between renewalScheduler.js and this module).
const RENEWAL_PATH_NOT_APPLICABLE_CERT_STATUSES = new Set([
  "revoked",
  "decommissioned",
]);

function parseMetadata(value) {
  if (value == null) return {};
  if (typeof value === "object" && !Array.isArray(value)) return value;
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return parsed && typeof parsed === "object" && !Array.isArray(parsed)
        ? parsed
        : {};
    } catch (_err) {
      return {};
    }
  }
  return {};
}

function targetReferenceFromProfile(profileMetadata) {
  const renewalProfile = profileMetadata?.renewalProfile;
  if (!renewalProfile || typeof renewalProfile !== "object") return null;
  const primary = renewalProfile.target?.reference;
  if (typeof primary === "string" && primary.trim()) return primary.trim();
  const first = Array.isArray(renewalProfile.deploymentTargets)
    ? renewalProfile.deploymentTargets[0]?.reference
    : null;
  return typeof first === "string" && first.trim() ? first.trim() : null;
}

/**
 * Build a lookup of a workspace's agents, keyed both by row id and by
 * agent_id string, plus a helper to find agents declaring a given target
 * selector. Fetched once per workspace call so resolving N certificates
 * costs one query, not N.
 *
 * Retired agents are excluded from `byRowId`/`byAgentIdString`/`all` (a
 * retired agent can never be a live open-claim candidate or a live pinned
 * executor), but their agent_id strings are still tracked in
 * `retiredAgentIdStrings` so resolveRequiredExecutors can distinguish "this
 * certificate's pin target is a real agent that has since retired" (a
 * permanent, distinctly-reported Unavailable) from "no pin was ever
 * configured" (which legitimately falls through to open-claim matching).
 */
async function loadWorkspaceAgentIndex({ db, workspaceId }) {
  const result = await db.query(
    `SELECT id, agent_id, name, hostname, platform, status, last_seen_at,
            created_at, agent_version, protocol_version, clock_offset_ms,
            supported_operations, declared_target_selectors,
            supported_dns_providers, declared_command_profile_names,
            declared_capabilities, capabilities_updated_at, agent_kind
       FROM certops_agents
      WHERE workspace_id = $1`,
    [workspaceId],
  );
  const byRowId = new Map();
  const byAgentIdString = new Map();
  const retiredRowIds = new Set();
  const retiredAgentIdStrings = new Set();
  for (const row of result.rows) {
    if (row.status === "retired") {
      retiredRowIds.add(String(row.id));
      if (row.agent_id) retiredAgentIdStrings.add(row.agent_id);
      continue;
    }
    const agent = {
      id: String(row.id),
      agentId: row.agent_id,
      name: row.name || null,
      hostname: row.hostname || null,
      platform: row.platform || null,
      status: row.status,
      lastSeenAt: row.last_seen_at,
      createdAt: row.created_at,
      agentVersion: row.agent_version,
      protocolVersion: row.protocol_version,
      clockOffsetMs: row.clock_offset_ms,
      supportedOperations: row.supported_operations,
      targetSelectors: row.declared_target_selectors,
      dnsProviders: row.supported_dns_providers,
      commandProfiles: row.declared_command_profile_names,
      declaredCapabilities: row.declared_capabilities,
      capabilitiesUpdatedAt: row.capabilities_updated_at,
      agentKind: row.agent_kind,
    };
    byRowId.set(agent.id, agent);
    if (agent.agentId) byAgentIdString.set(agent.agentId, agent);
  }
  return {
    byRowId,
    byAgentIdString,
    retiredRowIds,
    retiredAgentIdStrings,
    all: [...byRowId.values()],
  };
}

function isAgentOnline(agent, { offlineAfterMs, now }) {
  return (
    classifyAgentLiveness({
      lastSeenAt: agent.lastSeenAt,
      createdAt: agent.createdAt,
      now,
      offlineAfterMs,
    }) === "live"
  );
}

function agentDependencyView(agent, { required, offlineAfterMs, now }) {
  return {
    agentRowId: agent.id,
    agentId: agent.agentId,
    agentName: agent.name,
    hostname: agent.hostname,
    platform: agent.platform,
    required,
    online: isAgentOnline(agent, { offlineAfterMs, now }),
  };
}

/**
 * Resolve the required-executor set for one certificate row against a
 * pre-loaded agent index. Pure function of (certificate row, profile
 * metadata, agent index) so it is trivially unit-testable without a DB.
 *
 * @returns {{ pinned: boolean, pinnedButRetired: boolean, agents: object[] }}
 *   agents is the full candidate list (dependencies view), already
 *   liveness-annotated. pinnedButRetired is true only when a pin target was
 *   configured but resolves to a now-retired agent (see module doc comment).
 */
function resolveRequiredExecutors({
  certificateRow,
  profileMetadata,
  agentIndex,
  offlineAfterMs,
  now,
  env = process.env,
  jobRequirements = null,
}) {
  let assignedAgentId = null;
  if (certificateRow.source === "agent_filesystem") {
    const legacyAgentIdString = certificateRow.discovery_agent_id || null;
    if (legacyAgentIdString) {
      const pinnedAgent = agentIndex.byAgentIdString.get(legacyAgentIdString);
      if (pinnedAgent) {
        assignedAgentId = pinnedAgent.id;
      }
      if (!pinnedAgent && agentIndex.retiredAgentIdStrings.has(legacyAgentIdString)) {
        return {
          pinned: true,
          pinnedButRetired: true,
          targetReference: null,
          agents: [],
        };
      }
    }
  } else if (certificateRow.source === "agent_windows" && certificateRow.deployed_agent_id) {
    const candidateId = String(certificateRow.deployed_agent_id);
    if (agentIndex.byRowId.has(candidateId)) assignedAgentId = candidateId;
    if (agentIndex.retiredRowIds?.has(candidateId)) {
      return {
        pinned: true,
        pinnedButRetired: true,
        targetReference: null,
        agents: [],
      };
    }
  }

  const targetReference = targetReferenceFromProfile(profileMetadata);
  if (!targetReference && !assignedAgentId) {
    return { pinned: false, pinnedButRetired: false, targetReference: null, agents: [] };
  }

  // Direct unit callers may omit a full executable profile. The real health
  // path always supplies validated jobRequirements and therefore always uses
  // the shared dispatch predicate below.
  let eligibilityIndeterminate = false;
  let liveEligibilityIndeterminate = false;
  const matching = jobRequirements
    ? agentIndex.all.filter((agent) => {
        const evaluation = evaluateAgentJobEligibility({
          agent,
          job: {
            ...jobRequirements,
            assignedAgentId,
          },
          compatibility: computeAgentCompatibility(agent, env),
          env,
          now,
        });
        if (!evaluation.determinate) {
          eligibilityIndeterminate = true;
          if (isAgentOnline(agent, { offlineAfterMs, now })) {
            liveEligibilityIndeterminate = true;
          }
        }
        return evaluation.eligible;
      })
    : agentIndex.all.filter((agent) =>
        assignedAgentId
          ? agent.id === assignedAgentId
          : Array.isArray(agent.targetSelectors) &&
            agent.targetSelectors.includes(targetReference),
      );
  return {
    pinned: Boolean(assignedAgentId),
    pinnedButRetired: false,
    targetReference,
    eligibilityIndeterminate,
    liveEligibilityIndeterminate,
    agents: matching.map((agent) =>
      agentDependencyView(agent, {
        required: Boolean(assignedAgentId) || matching.length === 1,
        offlineAfterMs,
        now,
      }),
    ),
  };
}

/**
 * Classify a resolved executor set into a renewalPathState projection.
 */
function classifyExecutors({
  agents,
  targetReference,
  hasResolvableTopology,
  pinnedButRetired = false,
}) {
  if (pinnedButRetired) {
    return {
      renewalPathState: RENEWAL_PATH_STATES.UNAVAILABLE,
      renewalPathReason: RENEWAL_PATH_REASONS.ASSIGNED_AGENT_RETIRED,
      renewalPathSummary:
        "The agent assigned to renew this certificate has been retired. Re-assign this certificate to an active agent.",
    };
  }
  if (!hasResolvableTopology) {
    return {
      renewalPathState: RENEWAL_PATH_STATES.UNKNOWN,
      renewalPathReason: RENEWAL_PATH_REASONS.TOPOLOGY_UNKNOWN,
      renewalPathSummary:
        "TokenTimer does not have enough deployment topology information to determine renewal-path health.",
    };
  }
  const total = agents.length;
  const onlineCount = agents.filter((a) => a.online).length;

  if (total === 0) {
    return {
      renewalPathState: RENEWAL_PATH_STATES.UNAVAILABLE,
      renewalPathReason: RENEWAL_PATH_REASONS.NO_EXECUTION_TARGET,
      renewalPathSummary: targetReference
        ? `No registered agent currently declares support for deployment target "${targetReference}".`
        : "No agent is currently associated with this certificate's renewal.",
    };
  }
  if (onlineCount === total) {
    return {
      renewalPathState: RENEWAL_PATH_STATES.HEALTHY,
      renewalPathReason: RENEWAL_PATH_REASONS.ALL_PATHS_AVAILABLE,
      renewalPathSummary:
        total === 1
          ? "The agent responsible for this certificate's renewal is online."
          : `All ${total} renewal execution agents are online.`,
    };
  }
  if (onlineCount === 0) {
    return {
      renewalPathState: RENEWAL_PATH_STATES.UNAVAILABLE,
      renewalPathReason:
        total === 1
          ? RENEWAL_PATH_REASONS.AGENT_OFFLINE
          : RENEWAL_PATH_REASONS.ALL_EXECUTORS_OFFLINE,
      renewalPathSummary:
        total === 1
          ? "The only agent able to renew this certificate is offline."
          : `All ${total} renewal execution agents are currently offline.`,
    };
  }
  return {
    renewalPathState: RENEWAL_PATH_STATES.DEGRADED,
    renewalPathReason: RENEWAL_PATH_REASONS.PARTIAL_LOCATION_OUTAGE,
    renewalPathSummary: `${onlineCount} of ${total} renewal execution agents are online; a redundant path is still available.`,
  };
}

/**
 * Full renewal-path projection for one certificate row (as returned by the
 * SELECT in loadCertificateRowsForRenewalPath).
 */
function resolveRenewalPathForRow({ certificateRow, agentIndex, env = process.env, now = Date.now() }) {
  const offlineAfterMs = resolveAgentOfflineAfterMs(env);

  if (
    RENEWAL_PATH_NOT_APPLICABLE_CERT_STATUSES.has(
      String(certificateRow.status || "").toLowerCase(),
    )
  ) {
    return {
      renewalPathState: null,
      renewalPathReason: RENEWAL_PATH_REASONS.CERTIFICATE_RETIRED,
      renewalPathSummary: null,
      dependencies: [],
    };
  }
  if (!isAgentDeployableKeyMode(certificateRow)) {
    return {
      renewalPathState: null,
      renewalPathReason: RENEWAL_PATH_REASONS.NOT_AGENT_DEPLOYABLE,
      renewalPathSummary: null,
      dependencies: [],
    };
  }
  if (!certificateRow.profile_id) {
    return {
      renewalPathState: null,
      renewalPathReason: RENEWAL_PATH_REASONS.NO_PROFILE,
      renewalPathSummary: null,
      dependencies: [],
    };
  }
  if (
    AUTO_RENEW_DISABLED_PROFILE_STATUSES.includes(
      String(certificateRow.profile_status || "").toLowerCase(),
    )
  ) {
    return {
      renewalPathState: null,
      renewalPathReason: RENEWAL_PATH_REASONS.AUTO_RENEW_DISABLED,
      renewalPathSummary: null,
      dependencies: [],
    };
  }

  const profileMetadata = parseMetadata(certificateRow.profile_public_metadata);
  let jobRequirements;
  try {
    const profile = validateRenewalProfile(profileMetadata.renewalProfile);
    const payload = executionFieldsFromRenewalProfile(profile);
    jobRequirements = {
      operation: "renew",
      ...resolveAgentJobRoutingRequirements({
        executorKind: "agent",
        payload,
      }),
      subjectIsProvisioning: certificateRow.status === "provisioning",
    };
  } catch (_error) {
    return {
      renewalPathState: RENEWAL_PATH_STATES.UNKNOWN,
      renewalPathReason: RENEWAL_PATH_REASONS.TOPOLOGY_UNKNOWN,
      renewalPathSummary:
        "TokenTimer cannot resolve a complete executable renewal profile for this certificate.",
      dependencies: [],
    };
  }

  const {
    agents,
    targetReference,
    pinned,
    pinnedButRetired,
    eligibilityIndeterminate,
    liveEligibilityIndeterminate,
  } = resolveRequiredExecutors({
    certificateRow,
    profileMetadata,
    agentIndex,
    offlineAfterMs,
    now,
    env,
    jobRequirements,
  });
  if (
    eligibilityIndeterminate &&
    liveEligibilityIndeterminate &&
    !agents.some((agent) => agent.online)
  ) {
    return {
      renewalPathState: RENEWAL_PATH_STATES.UNKNOWN,
      renewalPathReason: RENEWAL_PATH_REASONS.TOPOLOGY_UNKNOWN,
      renewalPathSummary:
        "TokenTimer cannot determine agent eligibility from the persisted capability facts.",
      dependencies: [],
    };
  }
  const hasResolvableTopology =
    agents.length > 0 || Boolean(targetReference) || pinned || pinnedButRetired;

  const classification = classifyExecutors({
    agents,
    targetReference,
    hasResolvableTopology,
    pinnedButRetired,
  });

  return {
    ...classification,
    dependencies: agents,
  };
}

const CERTIFICATE_ROW_SELECT = `
  SELECT mc.id,
         mc.workspace_id,
         mc.status,
         mc.key_mode,
         mc.source,
         mc.common_name,
         mc.profile_id,
         mc.deployed_agent_id,
         mc.public_metadata->'controllerObservation'->>'agentId' AS discovery_agent_id,
         mc.public_metadata AS certificate_public_metadata,
         cp.status AS profile_status,
         cp.public_metadata AS profile_public_metadata
    FROM managed_certificates mc
    LEFT JOIN certificate_profiles cp
      ON cp.workspace_id = mc.workspace_id AND cp.id = mc.profile_id
`;

async function resolveRenewalPathForCertificate({
  db = pool,
  workspaceId,
  certificateId,
  env = process.env,
} = {}) {
  const [certResult, agentIndex] = await Promise.all([
    db.query(`${CERTIFICATE_ROW_SELECT} WHERE mc.workspace_id = $1 AND mc.id = $2::uuid`, [
      workspaceId,
      certificateId,
    ]),
    loadWorkspaceAgentIndex({ db, workspaceId }),
  ]);
  const certificateRow = certResult.rows[0];
  if (!certificateRow) return null;
  return resolveRenewalPathForRow({ certificateRow, agentIndex, env });
}

/**
 * Batch projection for every non-retired certificate in a workspace. Used by
 * the Agent Fleet "N auto-renew certificates affected" count and by the
 * agent-down alert enrichment -- both need "which certificates
 * depend on agent X", which is cheapest to answer by resolving every
 * certificate once and filtering, rather than re-querying per agent.
 */
async function resolveRenewalPathsForWorkspace({
  db = pool,
  workspaceId,
  env = process.env,
} = {}) {
  const [certResult, agentIndex] = await Promise.all([
    db.query(
      `${CERTIFICATE_ROW_SELECT}
        WHERE mc.workspace_id = $1
          AND mc.status NOT IN ('revoked', 'decommissioned')`,
      [workspaceId],
    ),
    loadWorkspaceAgentIndex({ db, workspaceId }),
  ]);
  const now = Date.now();
  return certResult.rows.map((certificateRow) => ({
    certificateId: String(certificateRow.id),
    commonName: certificateRow.common_name || null,
    ...resolveRenewalPathForRow({ certificateRow, agentIndex, env, now }),
  }));
}

/**
 * Batch projection for a specific set of certificate ids (certificate list/
 * detail routes via withRenewalState in routes/certops.js). Costs the same
 * two queries as resolveRenewalPathsForWorkspace but scoped to the page
 * actually being rendered, rather than every certificate in the workspace.
 *
 * @returns {Map<string, object>} certificateId -> renewal-path projection
 */
async function resolveRenewalPathsForCertificateIds({
  db = pool,
  workspaceId,
  certificateIds,
  env = process.env,
} = {}) {
  const ids = Array.isArray(certificateIds)
    ? [...new Set(certificateIds.map(String))]
    : [];
  if (ids.length === 0) return new Map();

  const [certResult, agentIndex] = await Promise.all([
    db.query(
      `${CERTIFICATE_ROW_SELECT}
        WHERE mc.workspace_id = $1
          AND mc.id = ANY($2::uuid[])`,
      [workspaceId, ids],
    ),
    loadWorkspaceAgentIndex({ db, workspaceId }),
  ]);
  const now = Date.now();
  const result = new Map();
  for (const certificateRow of certResult.rows) {
    result.set(
      String(certificateRow.id),
      resolveRenewalPathForRow({ certificateRow, agentIndex, env, now }),
    );
  }
  return result;
}

/**
 * Auto-renew certificates whose renewal path currently depends on a given
 * agent (Agent Fleet impact count + agent-down alert enrichment). "Depends
 * on" means the agent appears in the resolved dependency set at all --
 * including a redundant (non-required) dependency, because losing a
 * redundant executor is exactly what turns a Healthy path Degraded, which is
 * itself worth surfacing.
 */
async function listCertificatesDependentOnAgent({
  db = pool,
  workspaceId,
  agentRowId,
  env = process.env,
} = {}) {
  const targetAgentRowId = String(agentRowId);
  const all = await resolveRenewalPathsForWorkspace({ db, workspaceId, env });
  return all.filter(
    (entry) =>
      entry.renewalPathState != null &&
      entry.dependencies.some((dep) => dep.agentRowId === targetAgentRowId),
  );
}

/**
 * Agent Fleet impact counts: for every agent in the workspace, how many
 * auto-renew certificates currently depend on it (as either the required
 * executor or a redundant one). One workspace-wide resolve, not one query
 * per agent, so rendering the whole fleet table costs the same two queries
 * as resolving a single certificate.
 *
 * @returns {Map<string, number>} agentRowId -> dependent certificate count
 */
async function countCertificatesDependentPerAgent({
  db = pool,
  workspaceId,
  env = process.env,
} = {}) {
  const all = await resolveRenewalPathsForWorkspace({ db, workspaceId, env });
  const counts = new Map();
  for (const entry of all) {
    if (entry.renewalPathState == null) continue;
    const seenAgentIds = new Set(entry.dependencies.map((dep) => dep.agentRowId));
    for (const agentRowId of seenAgentIds) {
      counts.set(agentRowId, (counts.get(agentRowId) || 0) + 1);
    }
  }
  return counts;
}

module.exports = {
  RENEWAL_PATH_STATES,
  RENEWAL_PATH_REASONS,
  resolveRenewalPathForCertificate,
  resolveRenewalPathsForWorkspace,
  resolveRenewalPathsForCertificateIds,
  listCertificatesDependentOnAgent,
  countCertificatesDependentPerAgent,
  // Exported for unit testing without a DB.
  _test: {
    resolveRenewalPathForRow,
    resolveRequiredExecutors,
    classifyExecutors,
    targetReferenceFromProfile,
    loadWorkspaceAgentIndex,
  },
};
