-- Remove the unpublished optional REST lookup without changing applied history.
-- Events routing keys and the incident action/audit ledgers are unaffected.
DROP TABLE IF EXISTS pagerduty_lookup_credentials;
ALTER TABLE pagerduty_incidents
  DROP COLUMN IF EXISTS remote_incident_id,
  DROP COLUMN IF EXISTS remote_incident_url,
  DROP COLUMN IF EXISTS remote_status,
  DROP COLUMN IF EXISTS lookup_at,
  DROP COLUMN IF EXISTS lookup_error;
