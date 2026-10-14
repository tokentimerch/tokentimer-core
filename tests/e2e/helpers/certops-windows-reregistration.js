"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

async function qualifyWindowsReregistration({ baseUrl, workspaceId, oldAgentId, pool, createBootstrap, packageRoot, workDir }) {
  assert.equal(process.platform, "win32");
  const oldAgent = (await pool.query("SELECT id,status,credential_hash FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [workspaceId, oldAgentId])).rows[0];
  assert.equal(oldAgent?.status, "retired", "re-registration fixture requires an actually retired predecessor");
  const oldJobs = async () => (await pool.query("SELECT id,status,attempt_count,claim_id FROM certificate_jobs WHERE workspace_id=$1 AND assigned_agent_id=$2 ORDER BY id", [workspaceId, oldAgent.id])).rows;
  const beforeJobs = await oldJobs();
  const state = path.join(workDir, "fresh-registration-state");
  assert.equal(fs.existsSync(state), false); fs.mkdirSync(state);
  const platform = require(path.join(packageRoot, "src/platform"));
  platform.applyRestrictivePermissions(state, { kind: "directory" });
  const configFile = path.join(state, "config.json");
  const config = { serverUrl: baseUrl, agentId: oldAgentId, allowInsecureLocalHttp: true, heartbeatIntervalMs: 500, pollIntervalMs: 500, discovery: null, windowsDiscovery: { enabled: false }, execution: { enabled: false, dryRun: false }, declaredTargetSelectors: ["registration.example.test"], declaredCommandProfileNames: [] };
  const save = () => { fs.writeFileSync(configFile, JSON.stringify(config)); platform.applyRestrictivePermissions(configFile, { kind: "file" }); };
  save();
  const entry = path.join(packageRoot, "bin/tokentimer-agent.js");
  const environment = bootstrap => ({ PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR, COMSPEC: process.env.COMSPEC, TEMP: process.env.TEMP, TMP: process.env.TMP, TOKENTIMER_AGENT_CONFIG_DIR: state, TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: bootstrap.plaintextToken, TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID: String(bootstrap.token.id) });
  const conflictBootstrap = await createBootstrap();
  const refused = spawnSync(process.execPath, [entry], { env: environment(conflictBootstrap), stdio: ["ignore", "ignore", "pipe"], timeout: 30000 });
  const nativeAssertion = (String(refused.stderr).match(/^Assertion failed:.*$/m) || [""])[0].slice(0, 200);
  assert.ifError(refused.error); assert.equal(refused.status, 1, `retired identity reuse must fail before a new credential is written ${nativeAssertion}`);
  assert.match(String(refused.stderr), /agent registration failed with HTTP 409/, "native refusal must identify actual HTTP registration failure");
  assert.equal(String(refused.stderr).includes(conflictBootstrap.plaintextToken), false, "bootstrap credential must not appear in failure logs");
  const conflictResponse = await fetch(new URL("/api/v1/certops/agent/register", baseUrl), {
    method: "POST", signal: AbortSignal.timeout(15000),
    headers: { "content-type": "application/json", authorization: `Bearer ${conflictBootstrap.plaintextToken}` },
    body: JSON.stringify({ schemaVersion: 1, protocolVersion: "1.0.0", messageType: "register", agentId: oldAgentId, sentAt: new Date().toISOString(), body: {
      bootstrapTokenId: conflictBootstrap.token.id, registrationId: crypto.randomUUID(), hostname: "owned-registration-conflict", platform: "win32", agentVersion: JSON.parse(fs.readFileSync(path.join(packageRoot, "package.json"), "utf8")).version, declaredCapabilities: [],
    } }),
  });
  assert.equal(conflictResponse.status, 409);
  assert.equal((await conflictResponse.json()).code, "CERTOPS_AGENT_REGISTRATION_CONFLICT", "independent public protocol check must confirm identity conflict classification");
  assert.equal(fs.existsSync(path.join(state, "credential")), false);
  assert.equal(JSON.parse(fs.readFileSync(configFile, "utf8")).agentId, oldAgentId);
  assert.equal((await pool.query("SELECT status FROM certops_agent_bootstrap_tokens WHERE workspace_id=$1 AND id=$2", [workspaceId, conflictBootstrap.token.id])).rows[0].status, "active", "conflict transaction must not consume bootstrap authorization");
  config.agentId = `replacement-${crypto.randomUUID()}`; save();
  const replacementBootstrap = await createBootstrap();
  const replacement = spawn(process.execPath, [entry], { env: environment(replacementBootstrap), stdio: "ignore" });
  const closed = new Promise((resolve, reject) => { replacement.once("error", reject); replacement.once("close", resolve); });
  closed.catch(() => {});
  let registrationResult;
  try {
    const deadline = Date.now() + 45000;
    let registered;
    do {
      assert.equal(replacement.exitCode, null); assert.equal(replacement.signalCode, null);
      registered = (await pool.query("SELECT id,status,platform,created_at,last_seen_at,declared_target_selectors FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [workspaceId, config.agentId])).rows[0];
      if (registered && Date.parse(registered.last_seen_at) > Date.parse(registered.created_at)) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    } while (Date.now() < deadline);
    assert.ok(registered && Date.parse(registered.last_seen_at) > Date.parse(registered.created_at), "replacement must register and subsequently heartbeat using its real persisted credential");
    assert.equal(registered.status, "active"); assert.equal(registered.platform, "win32"); assert.notEqual(registered.id, oldAgent.id);
    assert.deepEqual(registered.declared_target_selectors, config.declaredTargetSelectors);
    assert.ok(fs.statSync(path.join(state, "credential")).size > 0);
    assert.equal(JSON.parse(fs.readFileSync(configFile, "utf8")).agentId, config.agentId);
    assert.equal((await pool.query("SELECT status FROM certops_agent_bootstrap_tokens WHERE workspace_id=$1 AND id=$2", [workspaceId, replacementBootstrap.token.id])).rows[0].status, "used");
    const unchanged = (await pool.query("SELECT status,credential_hash FROM certops_agents WHERE workspace_id=$1 AND id=$2", [workspaceId, oldAgent.id])).rows[0];
    assert.equal(unchanged.status, "retired"); assert.ok(unchanged.credential_hash === oldAgent.credential_hash, "Predecessor credential changed during replacement registration");
    assert.deepEqual(await oldJobs(), beforeJobs, "replacement identity must not inherit or replay predecessor jobs");
    registrationResult = { identityConflictRefused: true, conflictTokenPreserved: true, replacementRegisteredAndHeartbeating: true, predecessorPreserved: true };
  } finally {
    if (replacement.exitCode === null && replacement.signalCode === null) replacement.kill("SIGKILL");
    await closed;
  }
  const refreshed = await require("./certops-windows-capability-refresh").qualifyWindowsCapabilityRefresh({
    pool, workspaceId, agentId: config.agentId, state, packageRoot,
  });
  return { ...registrationResult, ...refreshed };
}
module.exports = { qualifyWindowsReregistration };
