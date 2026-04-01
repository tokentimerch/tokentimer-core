/**
 * tokentimer-core: No paid plans. All users have the same level of access.
 * Access is role-based only (viewer / workspace_manager / admin).
 * All limits are unlimited; plan parameters are ignored.
 */
const { pool } = require("../db/database");

function parseLimits(raw, fallback) {
  try {
    if (!raw || typeof raw !== "string") return { ...fallback };
    const map = {};
    for (const part of raw.split(",")) {
      const [k, v] = part.split(":").map((s) => String(s || "").trim());
      if (!k) continue;
      const num = Number(v);
      if (Number.isFinite(num)) map[k] = num;
    }
    return { ...fallback, ...map };
  } catch (_) {
    return { ...fallback };
  }
}

// Integration scan limits per month per workspace
// Core: all integrations available, no scan limits
const DEFAULT_INTEGRATION_SCAN_LIMITS = {
  oss: null,
};

const INTEGRATION_SCAN_LIMITS = parseLimits(
  process.env.INTEGRATION_SCAN_LIMITS,
  DEFAULT_INTEGRATION_SCAN_LIMITS,
);

/**
 * Get integration scan usage for a workspace for the current month.
 * Uses the workspace_integration_usage table with automatic month rollover.
 * @param {number} workspaceId - The workspace ID
 * @returns {Promise<{used: number, monthStart: string}>}
 */
async function getWorkspaceIntegrationUsage(workspaceId) {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM get_integration_usage($1)`,
      [workspaceId],
    );
    return {
      used: rows[0]?.used || 0,
      monthStart: rows[0]?.month_start || new Date().toISOString().slice(0, 10),
    };
  } catch (_e) {
    // Fallback to audit_events if function doesn't exist (pre-migration)
    const { rows } = await pool.query(
      `SELECT COUNT(*)::int AS c
       FROM audit_events
       WHERE workspace_id = $1
         AND action = 'INTEGRATION_SCAN'
         AND date_trunc('month', (occurred_at AT TIME ZONE 'UTC')) = date_trunc('month', (NOW() AT TIME ZONE 'UTC'))`,
      [workspaceId],
    );
    return {
      used: rows[0]?.c || 0,
      monthStart: new Date().toISOString().slice(0, 7) + "-01",
    };
  }
}

/**
 * Atomically check if workspace can perform scan and increment counter.
 * Core: no plan limits; always allow (integrations are stubbed in core).
 * @param {number} workspaceId - The workspace ID
 * @param {string} [_workspacePlan] - Ignored in core
 */
async function checkAndIncrementIntegrationUsage(workspaceId, _workspacePlan) {
  // Core: no plan-based limits
  const limit = INTEGRATION_SCAN_LIMITS.oss;
  if (limit === null || !Number.isFinite(limit)) {
    return { allowed: true, used: 0, limit: null, remaining: null };
  }

  try {
    const { rows } = await pool.query(
      `SELECT check_and_increment_integration_usage($1, $2) AS result`,
      [workspaceId, limit],
    );

    const result = rows[0]?.result;

    if (result === 0) {
      // Success - get updated usage
      const usage = await getWorkspaceIntegrationUsage(workspaceId);
      return {
        allowed: true,
        used: usage.used,
        limit,
        remaining: Math.max(0, limit - usage.used),
      };
    } else if (result === 1) {
      // Limit reached
      const usage = await getWorkspaceIntegrationUsage(workspaceId);
      return {
        allowed: false,
        used: usage.used,
        limit,
        remaining: 0,
        error: "QUOTA_EXCEEDED",
      };
    } else {
      // Error
      return {
        allowed: false,
        used: 0,
        limit,
        remaining: 0,
        error: "INTERNAL_ERROR",
      };
    }
  } catch (_e) {
    // Fallback for pre-migration: use simple check (not atomic, but functional)
    const usage = await getWorkspaceIntegrationUsage(workspaceId);
    if (usage.used >= limit) {
      return {
        allowed: false,
        used: usage.used,
        limit,
        remaining: 0,
        error: "QUOTA_EXCEEDED",
      };
    }
    return {
      allowed: true,
      used: usage.used,
      limit,
      remaining: Math.max(0, limit - usage.used - 1), // -1 because we're about to use one
    };
  }
}

/**
 * Get integration quota info for a workspace without incrementing.
 * Core: no plan limits; always unlimited.
 * @param {number} workspaceId - The workspace ID
 * @param {string} [_workspacePlan] - Ignored in core
 */
async function getWorkspaceIntegrationQuota(workspaceId, _workspacePlan) {
  const limit = INTEGRATION_SCAN_LIMITS.oss;
  if (limit === null || !Number.isFinite(limit)) {
    return { used: 0, limit: null, remaining: null };
  }

  const usage = await getWorkspaceIntegrationUsage(workspaceId);
  return {
    used: usage.used,
    limit,
    remaining: Math.max(0, limit - usage.used),
  };
}

// Max contact groups per workspace
// Note: tokentimer-core provides unlimited contact groups
const DEFAULT_CONTACT_GROUP_LIMITS = {
  oss: Number.POSITIVE_INFINITY,
};

const CONTACT_GROUP_LIMITS = parseLimits(
  process.env.CONTACT_GROUP_LIMITS,
  DEFAULT_CONTACT_GROUP_LIMITS,
);

// Max email recipients per contact group
// Note: tokentimer-core provides unlimited members per group
const DEFAULT_CONTACT_GROUP_MEMBER_LIMITS = {
  oss: Number.POSITIVE_INFINITY,
};

const CONTACT_GROUP_MEMBER_LIMITS = parseLimits(
  process.env.CONTACT_GROUP_MEMBER_LIMITS,
  DEFAULT_CONTACT_GROUP_MEMBER_LIMITS,
);

// Workspace limits per user
// Note: tokentimer-core provides unlimited workspaces
const DEFAULT_LIMITS = {
  oss: Number.POSITIVE_INFINITY,
};

const WORKSPACE_LIMITS = parseLimits(
  process.env.WORKSPACE_PLAN_LIMITS,
  DEFAULT_LIMITS,
);

// Members per workspace limits
// Note: tokentimer-core provides unlimited members per workspace
const DEFAULT_MEMBER_LIMITS = {
  oss: Number.POSITIVE_INFINITY,
};

const MEMBER_LIMITS = parseLimits(
  process.env.MEMBER_PLAN_LIMITS,
  DEFAULT_MEMBER_LIMITS,
);

/**
 * Count the number of workspaces a user is eligible for (member of any role)
 * @param {number|string} userId - The user ID
 * @returns {Promise<number>} Number of workspaces the user is a member of
 */
async function countUserEligibleWorkspaces(userId) {
  // Eligible: member (any role). Adjust if needed to owner/admin-only by changing WHERE.
  const { rows } = await pool.query(
    `SELECT COUNT(DISTINCT wm.workspace_id) AS cnt
     FROM workspace_memberships wm
     WHERE wm.user_id = $1`,
    [userId],
  );
  return Number(rows[0]?.cnt || 0);
}

/**
 * Check if a user can create another workspace
 * Core: no plan limits; always allow creating another workspace
 * @param {number|string} _userId - The user ID (unused in core)
 * @param {string} _userPlan - The user's plan (unused in core)
 * @returns {boolean} Always returns true in core
 */
function canCreateAnotherWorkspace(_userId, _userPlan) {
  return true;
}

module.exports = {
  WORKSPACE_LIMITS,
  MEMBER_LIMITS,
  CONTACT_GROUP_LIMITS,
  CONTACT_GROUP_MEMBER_LIMITS,
  INTEGRATION_SCAN_LIMITS,
  canCreateAnotherWorkspace,
  countUserEligibleWorkspaces,
  // Per-workspace integration quota functions
  getWorkspaceIntegrationUsage,
  getWorkspaceIntegrationQuota,
  checkAndIncrementIntegrationUsage,
  parseLimits,
};
