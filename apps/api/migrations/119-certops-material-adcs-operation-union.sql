-- The AD CS proof and material reconciliation migrations each predate the
-- other. Keep both historical migrations unchanged and restore their union.
ALTER TABLE certificate_jobs DROP CONSTRAINT certificate_jobs_operation_check;
ALTER TABLE certificate_jobs ADD CONSTRAINT certificate_jobs_operation_check CHECK (operation IN
  ('issue','renew','deploy','deploy-from-store','cleanup-from-store','reconcile-from-store','reload','revoke','noop','protocol_smoke','distribute-trust','revoke-trust','continue-enrollment','adcs-preflight','adcs-installation-proof'));
