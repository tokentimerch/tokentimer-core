"use strict";

// An old site:port identity cannot distinguish a wildcard from a specific IP.
// If the agent observes the specific binding but no longer observes the old
// wildcard, keep queued renewals from creating a different HTTP.sys binding.
// This predicate is used before LIMIT so a blocked job cannot starve others.
const legacyIisClaimGuard = `NOT (cj.operation = 'renew' AND cj.subject_type = 'managed_certificate' AND EXISTS (
  SELECT 1 FROM managed_certificates old
  JOIN certops_agents owner ON owner.workspace_id=old.workspace_id AND owner.id=old.deployed_agent_id
  JOIN certificate_targets target ON target.workspace_id=old.workspace_id
    AND target.location_kind='iis_binding' AND target.public_metadata->>'agentId'=owner.agent_id
  JOIN certificate_instances observed ON observed.workspace_id=target.workspace_id AND observed.target_id=target.id
    AND observed.presence_state='confirmed_present'
    AND observed.captured_at BETWEEN clock_timestamp()-interval '24 hours' AND clock_timestamp()
  WHERE old.workspace_id=cj.workspace_id AND old.id::text=cj.subject_id AND old.source='agent_windows'
    AND old.source_ref LIKE '%/iis_binding/%'
    AND right(old.source_ref,length('/iis_binding/' || target.windows_site || ':' || target.windows_port::text))
      = '/iis_binding/' || target.windows_site || ':' || target.windows_port::text
    AND COALESCE(target.windows_sni_host,'')=''
    AND COALESCE(target.public_metadata->>'boundAddress','') NOT IN ('','*','0.0.0.0','::')
    AND NOT EXISTS (
      SELECT 1 FROM certificate_instances prior
      JOIN certificate_targets prior_target ON prior_target.workspace_id=prior.workspace_id AND prior_target.id=prior.target_id
      WHERE prior.workspace_id=old.workspace_id AND prior.managed_certificate_id=old.id
        AND prior.presence_state='confirmed_present'
        AND prior.captured_at BETWEEN clock_timestamp()-interval '24 hours' AND clock_timestamp()
        AND prior_target.public_metadata->>'agentId'=owner.agent_id
        AND prior_target.public_metadata->>'boundAddress'='0.0.0.0'
    )
))`;

module.exports = { legacyIisClaimGuard };
