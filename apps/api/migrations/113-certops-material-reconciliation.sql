-- Fresh reviewed inspections may settle only their original material obligation.
ALTER TABLE certificate_jobs DROP CONSTRAINT certificate_jobs_operation_check;
ALTER TABLE certificate_jobs ADD CONSTRAINT certificate_jobs_operation_check CHECK (operation IN
 ('issue','renew','deploy','deploy-from-store','cleanup-from-store','reconcile-from-store','reload','revoke','noop','protocol_smoke','distribute-trust','revoke-trust','continue-enrollment','adcs-preflight'));
CREATE UNIQUE INDEX certops_one_live_material_reconciliation
  ON certificate_jobs(workspace_id, ((payload->'materialReconciliation')->>'originalJobId'))
  WHERE operation='reconcile-from-store' AND status IN ('pending_approval','pending','claimed','running');
