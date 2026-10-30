"use strict";
// Actual independent PR ledger orders, before integration. These are executed
// as historical SQL in PostgreSQL; tests never fabricate applied ledger rows.
const base=["certops_installed_file_distribution","auto_sync_provider_stats","auto_sync_run_metrics"];
const lifecycle=["certops_distribution_lifecycle","certops_distribution_incident_delivery","certops_stable_consumer_discovery","certops_material_cleanup","certops_consumer_verification_failures"];
module.exports={
  "main-81":[...base,"auto_sync_metric_labels"],
  "lifecycle-81-85":[...base,...lifecycle],
  "providers-78":["certops_material_providers",base[0],...base.slice(1)],
  "providers-79":[base[0],"certops_material_providers",...base.slice(1)],
  "providers-81":[...base,"certops_material_providers"],
  "recipient-81-digest-82":[...base,"recipient_channel_verification","weekly_digest_recipient_claim_token"],
  "pagerduty-81":[...base,"pagerduty_incident_lifecycle"],
  "pagerduty-preview-79":[base[0],"pagerduty_incident_lifecycle"],
  "combined-previews":[...base,"certops_material_providers","recipient_channel_verification","weekly_digest_recipient_claim_token","pagerduty_incident_lifecycle",...lifecycle],
};
