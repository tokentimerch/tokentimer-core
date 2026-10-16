/**
 * One genuine production maintenance invocation in an owned child process.
 * Only the selected log sweep is enabled; all other current production sweeps
 * are disabled using their exported configuration. The exclusive disposable
 * stack and workspace fence are mandatory because purge has global scope.
 * IPC returns bounded counters; raw worker logs/credentials are never artifacts.
 */
import assert from "node:assert/strict";

assert.equal(process.env.CERTOPS_LOG_MAINTENANCE_EXCLUSIVE_STACK, "1");
assert.equal(process.env.CERTOPS_CSR_DISPOSABLE_STACK, "1");
const operation = process.env.CERTOPS_LOG_MAINTENANCE_OPERATION;
assert.ok(["abandon", "purge"].includes(operation));
const workspaceId = process.env.CERTOPS_LOG_MAINTENANCE_WORKSPACE_ID;
assert.match(workspaceId || "", /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
for (const name of ["DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD"]) assert.ok(process.env[name]);
const { pool } = await import("../../../apps/worker/src/db.js");
try {
  const foreign = await pool.query(`SELECT EXISTS (
    SELECT 1 FROM certops_agent_log_stream WHERE workspace_id<>$1 UNION ALL
    SELECT 1 FROM certops_agent_job_log WHERE workspace_id<>$1 UNION ALL
    SELECT 1 FROM certops_agent_log_daily_quota WHERE workspace_id<>$1
  ) AS present`, [workspaceId]);
  assert.equal(foreign.rows[0].present, false, "Refuse global maintenance with foreign fixture log data");
  const { CERTOPS_SWEEP_CONFIG, runCertOpsMaintenance } = await import("../../../apps/worker/src/certops-worker.js");
  const env = { ...process.env, CERTOPS_AGENT_LOG_RETENTION_DAYS: operation === "purge" ? "0" : "30" };
  for (const config of Object.values(CERTOPS_SWEEP_CONFIG)) env[config.enableEnv] = "false";
  env[CERTOPS_SWEEP_CONFIG[`agent-log-${operation}`].enableEnv] = "true";
  const results = await runCertOpsMaintenance({ env });
  const selectedKey = operation === "abandon" ? "agentLogAbandon" : "agentLogPurge";
  assert.equal(results[selectedKey].status, "success");
  for (const [key, value] of Object.entries(results)) if (key !== selectedKey) assert.equal(value.status, "skipped", "Every unselected sweep must be disabled");
  process.send({ kind: "certops-log-maintenance", operation, pid: process.pid, result: results[selectedKey].result, onlySelectedSweep: true });
} finally {
  await pool.end();
  process.disconnect?.();
}
