"use strict";

const { validateSessionWrite } = require("./sessionSchema");

class RevisionConflictError extends Error {
  constructor(current) {
    super("Onboarding session was changed elsewhere");
    this.name = "RevisionConflictError";
    this.code = "REVISION_CONFLICT";
    this.current = current;
  }
}

const COLUMNS = `id, flow, schema_version, planner_version, status, intent,
  progress, operation_refs, revision, created_at, updated_at, completed_at`;

function mapRow(row) {
  return {
    exists: true,
    flow: row.flow,
    schemaVersion: row.schema_version,
    plannerVersion: row.planner_version,
    status: row.status,
    intent: row.intent || {},
    progress: row.progress || {},
    operationRefs: row.operation_refs || {},
    revision: row.revision,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    completedAt: row.completed_at,
  };
}

function emptySession(flow) {
  return {
    exists: false,
    flow,
    schemaVersion: 1,
    plannerVersion: 1,
    status: "in_progress",
    intent: {},
    progress: {},
    operationRefs: {},
    revision: 0,
    createdAt: null,
    updatedAt: null,
    completedAt: null,
  };
}

async function getSession(pool, { userId, workspaceId, flow }) {
  const { rows } = await pool.query(
    `SELECT ${COLUMNS} FROM onboarding_sessions
      WHERE user_id = $1 AND workspace_id = $2 AND flow = $3`,
    [userId, workspaceId, flow],
  );
  return rows[0] ? mapRow(rows[0]) : emptySession(flow);
}

/**
 * Optimistic write. Revision 0 means "no row yet": the insert loses to a
 * concurrent first write instead of overwriting it.
 */
async function writeSession(
  pool,
  { userId, workspaceId, flow, expectedRevision, patch },
) {
  // Keep the persistence boundary safe for every caller, including callers
  // that do not pass through the HTTP route. Validate before serializing or
  // issuing either INSERT or UPDATE, using the same bounded secret checks.
  ({ patch } = validateSessionWrite({ ...patch, expectedRevision }));
  const status = patch.status || "in_progress";
  const intent = JSON.stringify(patch.intent || {});
  const progress = JSON.stringify(patch.progress || {});
  const refs = JSON.stringify(patch.operation_refs || {});
  const plannerVersion = patch.plannerVersion || 1;

  let rows;
  if (expectedRevision === 0) {
    ({ rows } = await pool.query(
      `INSERT INTO onboarding_sessions
         (user_id, workspace_id, flow, planner_version, status, intent,
          progress, operation_refs, completed_at)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb,
               CASE WHEN $5 = 'completed' THEN NOW() ELSE NULL END)
       ON CONFLICT (user_id, workspace_id, flow) DO NOTHING
       RETURNING ${COLUMNS}`,
      [userId, workspaceId, flow, plannerVersion, status, intent, progress, refs],
    ));
  } else {
    ({ rows } = await pool.query(
      `UPDATE onboarding_sessions SET
         planner_version = COALESCE($5, planner_version),
         status = COALESCE($6, status),
         intent = COALESCE($7::jsonb, intent),
         progress = COALESCE($8::jsonb, progress),
         operation_refs = COALESCE($9::jsonb, operation_refs),
         completed_at = CASE
           WHEN COALESCE($6, status) = 'completed'
             THEN COALESCE(completed_at, NOW())
           ELSE NULL END,
         revision = revision + 1,
         updated_at = NOW()
       WHERE user_id = $1 AND workspace_id = $2 AND flow = $3
         AND revision = $4
       RETURNING ${COLUMNS}`,
      [
        userId,
        workspaceId,
        flow,
        expectedRevision,
        patch.plannerVersion || null,
        patch.status || null,
        patch.intent ? intent : null,
        patch.progress ? progress : null,
        patch.operation_refs ? refs : null,
      ],
    ));
  }

  if (!rows[0]) {
    throw new RevisionConflictError(
      await getSession(pool, { userId, workspaceId, flow }),
    );
  }
  return mapRow(rows[0]);
}

async function resetSession(pool, { userId, workspaceId, flow }) {
  const { rowCount } = await pool.query(
    `DELETE FROM onboarding_sessions
      WHERE user_id = $1 AND workspace_id = $2 AND flow = $3`,
    [userId, workspaceId, flow],
  );
  return rowCount > 0;
}

module.exports = {
  RevisionConflictError,
  emptySession,
  getSession,
  writeSession,
  resetSession,
};
