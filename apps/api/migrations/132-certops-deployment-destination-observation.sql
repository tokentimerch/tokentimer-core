ALTER TABLE certificate_jobs DROP CONSTRAINT certificate_jobs_operation_check;
ALTER TABLE certificate_jobs ADD CONSTRAINT certificate_jobs_operation_check CHECK (operation IN
  ('issue','renew','deploy','deploy-from-store','cleanup-from-store','reconcile-from-store','reload','revoke','noop','protocol_smoke','distribute-trust','revoke-trust','continue-enrollment','adcs-preflight','adcs-installation-proof','validate-deployment-destination','execute-deployment-destination','observe-deployment-destination'));
