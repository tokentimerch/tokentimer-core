ALTER TABLE pagerduty_incidents ADD COLUMN IF NOT EXISTS resolution_reason TEXT
  CHECK (resolution_reason IN ('expiration_extended', 'certificate_revoked', 'certificate_decommissioned'));
