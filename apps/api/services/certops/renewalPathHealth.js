"use strict";

/**
 * Renewal-path health: a derived, read-only projection of whether the
 * automatic-renewal execution path for a managed certificate currently has a
 * live agent able to run it.
 *
 * This is a SEPARATE axis from managed_certificates.status (the certificate
 * lifecycle: active/renewing/expired/...) and from certificate_instances'
 * observed-location connectivity. A certificate can be lifecycle ACTIVE while
 * its renewal path is unavailable (the agent that would renew it is offline),
 * and an observed location can show "agent offline" for a certificate whose
 * renewal path is perfectly healthy (a different agent owns renewal).
 *
 * Topology model (deliberately built around what this codebase actually
 * represents, not an idealized multi-target-AND graph -- see the note on
 * "Case D" below):
 *
 *   managed_certificate --profile_id--> certificate_profile
 *     .public_metadata.renewalProfile.target.reference  (single selector)
 *
 * A renew job for a certificate is claimable by exactly one agent, chosen one
 * of two ways. This MUST mirror jobs.js resolveManagedCertificateJobDefaults /
 * agentDispatch.js claimJobs exactly rather than approximate it, because
 * `managed_certificates.deployed_agent_id` -- despite the name -- is NOT the
 * scheduler's assignment source: renewalScheduler.js's ongoing sweep creates
 * every renewal job via `createCertificateJob` with no `assignedAgentId` in
 * either its call options or its payload (see buildRenewalJobPayload /
 * executionFieldsFromRenewalProfile), so `resolveExecutorKindAndRouting`
 * falls through to `autoAssignedAgentId` alone. `resolveManagedCertificateJobDefaults`
 * only ever produces a non-null `autoAssignedAgentId` when
 * `certificateRow.source === "agent_filesystem"`, resolved from the legacy
 * `public_metadata.controllerObservation.agentId` string -- it never reads
 * `deployed_agent_id`. Treating `deployed_agent_id` as an unconditional pin
 * here (an earlier version of this module did) would misreport a genuinely
 * open-claim, redundancy-eligible path (e.g. any adopted certificate whose
 * source is "manual"/"api"/"agent_windows"/etc., or an "agent_filesystem" row
 * whose `deployed_agent_id` has drifted from its `discovery_agent_id` string)
 * as a hard single point of failure with no possible fallback, in either
 * direction: it can fabricate an "Unavailable" when a redundant agent would
 * really claim the next job, or fabricate a "Healthy"/"Degraded" pin on an
 * agent the real dispatcher would never actually route to.
 *
 *   1. PINNED: `certificateRow.source === "agent_filesystem"` AND its legacy
 *      `public_metadata.controllerObservation.agentId` string resolves to a
 *      real agent row (live or retired -- see case below). Exactly one
 *      required executor; no redundancy is possible because the job's
 *      `assigned_agent_id` pins it, bypassing target-selector matching
 *      entirely (agentDispatch.js claimJobs: `assigned_agent_id IS NULL OR
 *      assigned_agent_id = $agent`, no fallback to any other agent, ever,
 *      regardless of what that other agent declares).
 *
 *      If the string resolves to an agent that has since been retired (never
 *      cleared by retireAgent -- a retired row is a frozen historical fact,
 *      not deleted), that pin is permanent and un-claimable by design: no
 *      code path re-derives a fresh assignment for an already-configured
 *      renewal profile mid-lifecycle, so this reports Unavailable with a
 *      distinct reason rather than silently falling through to open-claim
 *      matching as if no pin had ever existed.
 *
 *   2. OPEN-CLAIM: source is not "agent_filesystem", or no legacy agent-id
 *      string resolves. The job carries requiredTargetSelector =
 *      renewalProfile.target.reference, and any agent that declares that
 *      selector in declared_target_selectors may claim it (agentDispatch.js).
 *      If more than one agent in the workspace declares the same selector,
 *      that is genuine redundancy: either can execute the renewal.
 *
 * Case D from the product spec ("deployment requires BOTH target A and
 * target B, each a distinct required dependency") has no representation here:
 * a certificate's renewalProfile has exactly one target/selector.
 * `deploymentTargets` is a same-agent multi-DESTINATION list (one agent
 * writes the renewed cert to several local paths), not multiple independent
 * required executors -- see renewalProfile.js executionFieldsFromRenewalProfile
 * and jobs.js's MAX_ISSUE_DEPLOYMENT_TARGETS comment. Modeling Case D would
 * require inventing a topology concept the rest of CertOps does not have, so
 * it is intentionally not implemented; only Cases A/B/C (single required
 * executor, redundant executors, all executors down) are real states this
 * resolver can honestly report.
 *
 * Zero-custody: every field read here (deployed_agent_id, target.reference,
 * declared_target_selectors, agent name/hostname/platform/status) is already
 * public/non-secret elsewhere in CertOps. This module never reads key
 * material and never introduces a new secret-bearing column.
 */

const { pool } = require("../../db/database");
const { isAgentDeployableKeyMode } = require("./jobs");
const { AUTO_RENEW_DISABLED_PROFILE_STATUSES } = require("./renewalProfile");
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
            created_at, declared_target_selectors
       FROM certops_agents
      WHERE workspace_id = $1`,
    [workspaceId],
  );
  const byRowId = new Map();
  const byAgentIdString = new Map();
  const retiredAgentIdStrings = new Set();
  for (const row of result.rows) {
    if (row.status === "retired") {
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
      targetSelectors: Array.isArray(row.declared_target_selectors)
        ? row.declared_target_selectors.filter((v) => typeof v === "string")
        : [],
    };
    byRowId.set(agent.id, agent);
    if (agent.agentId) byAgentIdString.set(agent.agentId, agent);
  }
  return {
    byRowId,
    byAgentIdString,
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
}) {
  // Mirrors resolveManagedCertificateJobDefaults (jobs.js) exactly: the
  // ongoing renewal scheduler only ever auto-pins a job's assigned_agent_id
  // for agent_filesystem-sourced certificates, via this legacy string. Every
  // other source (adopted certs, agent_windows, imports, ...) is open-claim
  // for every renewal after any one-time setup job, regardless of
  // deployed_agent_id -- see the module doc comment for why deployed_agent_id
  // itself must not be treated as a pin here.
  if (certificateRow.source === "agent_filesystem") {
    const legacyAgentIdString = certificateRow.discovery_agent_id || null;
    if (legacyAgentIdString) {
      const pinnedAgent = agentIndex.byAgentIdString.get(legacyAgentIdString);
      if (pinnedAgent) {
        return {
          pinned: true,
          pinnedButRetired: false,
          targetReference: null,
          agents: [
            agentDependencyView(pinnedAgent, {
              required: true,
              offlineAfterMs,
              now,
            }),
          ],
        };
      }
      if (agentIndex.retiredAgentIdStrings.has(legacyAgentIdString)) {
        // The pin target is a real agent that has since retired. Retirement
        // never re-derives a fresh assignment for an already-configured
        // renewal profile, so this is a permanent Unavailable, not "no pin
        // was ever configured" -- must not fall through to open-claim
        // matching against some unrelated agent's declared selector.
        return {
          pinned: true,
          pinnedButRetired: true,
          targetReference: null,
          agents: [],
        };
      }
      // The string does not resolve to any known agent (live or retired) --
      // e.g. stale/malformed metadata. Falls through to open-claim below
      // rather than being treated as a hard pin to nothing.
    }
  }

  const targetReference = targetReferenceFromProfile(profileMetadata);
  if (!targetReference) {
    return { pinned: false, pinnedButRetired: false, targetReference: null, agents: [] };
  }

  const matching = agentIndex.all.filter((agent) =>
    agent.targetSelectors.includes(targetReference),
  );
  return {
    pinned: false,
    pinnedButRetired: false,
    targetReference,
    agents: matching.map((agent) =>
      agentDependencyView(agent, {
        required: matching.length === 1,
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
  const { agents, targetReference, pinned, pinnedButRetired } = resolveRequiredExecutors({
    certificateRow,
    profileMetadata,
    agentIndex,
    offlineAfterMs,
    now,
  });
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
 * agent-down alert enrichment (Phase F) -- both need "which certificates
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
