"use strict";

// Public evidence fixture only. This does not qualify native CA execution.
async function prepareAdcsAgent({ db,workspaceId,issuerId,agentId,reference }) {
  await db.query(`UPDATE certops_agents SET platform='win32',agent_version='0.18.0',
    supported_operations='["adcs-preflight","renew","continue-enrollment"]'::jsonb,
    declared_target_selectors=$2::jsonb,
    declared_capabilities='["adcs-enroll-v1","evidence-claim-binding-v1","signed-payload-b64-v1","iis-explicit-ip-v1"]'::jsonb,
    capabilities_updated_at=NOW() WHERE workspace_id=$3 AND id=$1`,[agentId,JSON.stringify([reference]),workspaceId]);
  const version=(await db.query(`SELECT v.* FROM certificate_issuer_versions v JOIN certificate_issuers i
    ON i.workspace_id=v.workspace_id AND i.id=v.issuer_id AND i.current_version=v.version
    WHERE v.workspace_id=$1 AND v.issuer_id=$2`,[workspaceId,issuerId])).rows[0];
  const job=await require("../../../apps/api/services/certops/certificateEnrollments").dispatchPreflight({client:db,
    workspaceId,issuerId,agentId,caConfig:version.ca_config,template:version.template});
  await db.query(`UPDATE certificate_jobs SET status='succeeded',completed_at=NOW(),
    result_metadata=result_metadata || $2::jsonb WHERE id=$1`,[job.id,JSON.stringify({preflightVerdict:{
      caConfig:version.ca_config,template:version.template,caKeySha256s:[version.ca_key_sha256],templateCheck:"safe",caCheck:"safe",
    }})]);
  return job.id;
}
module.exports={ prepareAdcsAgent };
