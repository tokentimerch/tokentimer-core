/**
 * Observe lease-loss cancellation of a genuine owned ACME command in the native journey.
 * The parent arms a transparent command barrier, triggers public retirement, and proves
 * actual process-tree exit plus unchanged certificate/key/TLS/DNS state. This fixture
 * must run only under its owning disposable ACME harness and exact PID identity checks. */
"use strict";
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const attachment = require("./certops-acme-lease-attachment");
const active = new Set();
function measureOwnedProcess(proof, { token, agent, barrierDirectory }) {
  assert.equal(proof.token, token);
  assert.ok(Number.isInteger(proof.pid) && proof.pid > 0);
  assert.equal(proof.parentPid, agent.pid);
  const raw = fs.readFileSync(`/proc/${proof.pid}/stat`, "utf8"),
    fields = raw
      .slice(raw.lastIndexOf(")") + 2)
      .trim()
      .split(/\s+/);
  assert.equal(Number(fields[1]), agent.pid);
  assert.equal(Number(fields[2]), proof.pid);
  assert.equal(proof.processGroup, proof.pid);
  assert.equal(fields[19], proof.startTicks);
  const argv = fs
    .readFileSync(`/proc/${proof.pid}/cmdline`, "utf8")
    .split("\0");
  assert.ok(
    argv.includes(path.join(__dirname, "certops-acme-command-barrier.js")),
  );
  assert.ok(argv.includes(barrierDirectory));
  assert.equal(
    fs.realpathSync(`/proc/${proof.pid}/exe`),
    fs.realpathSync(process.execPath),
  );
  return proof;
}
module.exports = async function qualifyLeaseLoss({
  pool,
  workspaceId,
  agentId,
  agent,
  publicSession,
  certificateId,
  certPath,
  keyPath,
  barrierDirectory,
  ownedJobIds,
  ownedLeaseResources,
  waitUntil,
  verifyDnsCleanup,
  servedFingerprint,
}) {
  assert.equal(process.platform, "linux");
  const beforeCert = fs.readFileSync(certPath),
    beforeKey = fs.readFileSync(keyPath),
    fingerprint = new crypto.X509Certificate(beforeCert).fingerprint256;
  const arm = path.join(barrierDirectory, "armed.json"),
    receipt = path.join(barrierDirectory, "process.json"),
    token = crypto.randomUUID();
  assert.equal(fs.lstatSync(arm, { throwIfNoEntry: false }), undefined);
  assert.equal(fs.lstatSync(receipt, { throwIfNoEntry: false }), undefined);
  assert.ok(Array.isArray(ownedLeaseResources));
  active.add(path.resolve(barrierDirectory));
  fs.writeFileSync(arm, JSON.stringify({ token }), { flag: "wx", mode: 0o600 });
  let proof, primary, owner;
  try {
    const created = await publicSession.request(
      `/api/v1/workspaces/${workspaceId}/certops/jobs`,
      "POST",
      {
        operation: "renew",
        subjectId: certificateId,
        subjectType: "managed_certificate",
        idempotencyKey: crypto.randomUUID(),
      },
    );
    assert.equal(created.status, 201);
    const jobId = created.body.job.id;
    ownedJobIds.push(jobId);
    await waitUntil(() => fs.existsSync(receipt), 60000);
    proof = measureOwnedProcess(JSON.parse(fs.readFileSync(receipt, "utf8")), {
      token,
      agent,
      barrierDirectory,
    });
    owner = attachment.attach({
      proof,
      token,
      agent,
      barrierDirectory,
      ownedResources: ownedLeaseResources,
      waitUntil,
    });
    await owner.ready;
    assert.equal(agent.exitCode, null);
    assert.equal(agent.signalCode, null);
    const active = (
      await pool.query(
        "SELECT status,claim_id,claimed_by_agent_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
        [workspaceId, jobId],
      )
    ).rows[0];
    assert.ok(["claimed", "running"].includes(active.status));
    assert.ok(active.claim_id);
    await verifyDnsCleanup();
    assert.ok(fs.readFileSync(certPath).equals(beforeCert));
    assert.ok(fs.readFileSync(keyPath).equals(beforeKey));
    assert.equal(await servedFingerprint(), fingerprint);
    const actualAgent = (
      await pool.query(
        "SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
        [workspaceId, agentId],
      )
    ).rows[0];
    assert.ok(actualAgent);
    assert.equal(active.claimed_by_agent_id, actualAgent.id);
    const retired = await publicSession.request(
      `/api/v1/workspaces/${workspaceId}/certops/agents/${actualAgent.id}/retire`,
      "POST",
      { force: true, reason: "Qualification native mutation-time lease loss" },
    );
    assert.equal(retired.status, 200);
    await owner.waitForNativeExit();
    // The arm remains present throughout: only native lease-abort cancellation,
    // not a fixture release, can terminate this genuine executing command.
    assert.equal(JSON.parse(fs.readFileSync(arm, "utf8")).token, token);
    await verifyDnsCleanup();
    assert.ok(fs.readFileSync(certPath).equals(beforeCert));
    assert.ok(fs.readFileSync(keyPath).equals(beforeKey));
    assert.equal(await servedFingerprint(), fingerprint);
    assert.equal(
      (
        await pool.query(
          "SELECT status FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
          [workspaceId, jobId],
        )
      ).rows[0].status,
      "cancelled",
    );
  } catch (error) {
    primary = error;
  } finally {
    const failures = [];
    try {
      assert.ok(
        owner,
        "Unconfirmed command attachment; preserve ownership and fixture state",
      );
      await owner.stopAndDrain();
      owner.removeOwnedBarriersAndRelease();
      active.delete(path.resolve(barrierDirectory));
    } catch (error) {
      failures.push(error);
    }
    if (failures.length)
      throw new AggregateError(
        [...(primary ? [primary] : []), ...failures],
        "Native lease barrier ownership or cleanup failed",
      );
  }
  if (primary) throw primary;
};
module.exports.assertCleanupSafe = function assertCleanupSafe(root) {
  assert.equal(
    active.has(path.resolve(root)),
    false,
    "Preserve unresolved lease-loss fixture",
  );
  attachment.assertCleanupSafe(root);
};
module.exports.REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-acme-lease-loss.js",
  "tests/e2e/helpers/certops-acme-command-barrier.js",
  "tests/e2e/helpers/certops-acme-lease-attachment.js",
  "tests/e2e/helpers/certops-acme-lease-pidfd.py",
]);
