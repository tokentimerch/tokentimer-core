-- Issuance is separately enabled and separately delegated from renewal.
ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS operator_issuance_enabled BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE operator_action_plans DROP CONSTRAINT IF EXISTS operator_action_plans_operation_check;
ALTER TABLE operator_action_plans ADD CONSTRAINT operator_action_plans_operation_check CHECK (operation IN ('renew', 'issue'));
ALTER TABLE operator_action_plans ALTER COLUMN identity_id DROP NOT NULL;
ALTER TABLE operator_action_plans ALTER COLUMN subject_id DROP NOT NULL;
ALTER TABLE operator_action_plans ADD CONSTRAINT operator_action_plans_subject_check CHECK (
  (operation = 'renew' AND identity_id IS NOT NULL AND subject_id IS NOT NULL) OR
  (operation = 'issue' AND identity_id IS NULL AND subject_id IS NULL)
);

ALTER TABLE operator_action_requests DROP CONSTRAINT IF EXISTS operator_action_requests_operation_check;
ALTER TABLE operator_action_requests ADD CONSTRAINT operator_action_requests_operation_check CHECK (operation IN ('renew', 'issue'));
ALTER TABLE operator_action_requests ALTER COLUMN identity_id DROP NOT NULL;
ALTER TABLE operator_action_requests ADD CONSTRAINT operator_action_requests_identity_check CHECK (
  (operation = 'renew' AND identity_id IS NOT NULL) OR (operation = 'issue' AND identity_id IS NULL)
);
