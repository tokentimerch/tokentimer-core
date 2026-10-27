"use strict";
const calendar = require("../../../../packages/contracts/certops/activation-calendar.cjs");
const material = require("./materialDistribution");
const { assertSafePublicValue } = require("./jobs");
const { assertDistributionPolicy } = require("./distributionPolicy");
const { writeAudit } = require("../audit");
function fail(code, statusCode = 409) {
  const e = new Error(code);
  e.code = code;
  e.statusCode = statusCode;
  throw e;
}
async function putConsumerPolicy({
  workspaceId,
  groupId,
  bindingId,
  policy,
  expectedAuthorizationRevision,
  actorUserId,
  emergency = false,
  dbPool,
}) {
  workspaceId = material.normalizeDistributionId(workspaceId);
  groupId = material.normalizeDistributionId(groupId);
  bindingId = material.normalizeDistributionId(bindingId);
  assertSafePublicValue(policy);
  calendar.validateActivationPolicy(policy);
  if (
    policy.emergency &&
    (!emergency ||
      !policy.requiresApproval ||
      Date.parse(policy.emergency.end) <= Date.now() ||
      Date.parse(policy.emergency.start) > Date.now() + 3600000)
  )
    fail("CERTOPS_EMERGENCY_AUTHORIZATION_REQUIRED", 403);
  return require("./distributionOperations").transaction(async (client) => {
    await assertDistributionPolicy({ client, workspaceId });
    await material.lockGroup(client, workspaceId, groupId);
    const binding = (
      await client.query(
        `SELECT * FROM certops_consumer_bindings WHERE workspace_id=$1 AND group_id=$2 AND id=$3 FOR UPDATE`,
        [workspaceId, groupId, bindingId],
      )
    ).rows[0];
    if (!binding) fail("CERTOPS_BINDING_NOT_FOUND", 404);
    if (binding.authorization_revision !== expectedAuthorizationRevision)
      fail("CERTOPS_CONSUMER_AUTHORIZATION_REVISION_CHANGED");
    const old = (
      await client.query(
        `SELECT policy FROM certops_consumer_lifecycle WHERE workspace_id=$1 AND binding_id=$2`,
        [workspaceId, bindingId],
      )
    ).rows[0];
    if (old && material.hashIntent(old.policy) === material.hashIntent(policy))
      return { authorizationRevision: binding.authorization_revision, policy };
    await client.query(
      `INSERT INTO certops_consumer_lifecycle(workspace_id,group_id,binding_id,policy) VALUES($1,$2,$3,$4)
      ON CONFLICT(workspace_id,binding_id) DO UPDATE SET policy=EXCLUDED.policy,updated_at=clock_timestamp()`,
      [workspaceId, groupId, bindingId, policy],
    );
    const row = (
      await client.query(
        `UPDATE certops_consumer_bindings SET authorization_revision=authorization_revision+1
      WHERE workspace_id=$1 AND id=$2 RETURNING authorization_revision`,
        [workspaceId, bindingId],
      )
    ).rows[0];
    await writeAudit({
      client,
      workspaceId,
      actorUserId,
      action: emergency
        ? "CERTOPS_EMERGENCY_ACTIVATION_REQUESTED"
        : "CERTOPS_CONSUMER_ACTIVATION_POLICY_CHANGED",
      targetType: "certops_consumer_binding",
      targetId: bindingId,
      metadata: {
        groupId,
        authorizationRevision: row.authorization_revision,
        method: policy.method,
        disruptive: policy.disruptive,
        requiresApproval: policy.requiresApproval,
        emergency: policy.emergency,
      },
    });
    return { authorizationRevision: row.authorization_revision, policy };
  }, dbPool);
}
function supportedActivation(policy, verificationPolicy) {
  if (!policy) return true;
  return verificationPolicy === "installed"
    ? policy.method === "none"
    : policy.method === "reload";
}
function activationDeadline(desiredExpiry,deployedExpiry){
  const desired=new Date(desiredExpiry).getTime(),deployed=deployedExpiry?new Date(deployedExpiry).getTime():Infinity;
  const deadline=Math.min(desired,deployed);
  return Number.isFinite(deadline)?new Date(deadline).toISOString():null;
}
function activationPlanner(now=Date.now()){
  const results=new Map();
  return (policy,expiry)=>{
    const key=material.hashIntent({policy:policy || null,expiry:expiry || null});
    if(!results.has(key))results.set(key,calendar.nextActivation(policy,expiry,now));
    return results.get(key);
  };
}
module.exports = { ...calendar, putConsumerPolicy, supportedActivation,activationDeadline,activationPlanner };
