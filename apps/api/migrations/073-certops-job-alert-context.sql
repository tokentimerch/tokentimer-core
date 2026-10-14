-- Historical job-time token links cannot be proved from a mutable source.
-- Leave existing jobs NULL; only subsequent inserts capture the association.
ALTER TABLE certificate_jobs ADD COLUMN IF NOT EXISTS certificate_token_id INTEGER;

CREATE OR REPLACE FUNCTION certops_capture_job_alert_token()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE source_token INTEGER;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.certificate_token_id IS DISTINCT FROM OLD.certificate_token_id THEN
      RAISE EXCEPTION 'CertOps job alert token attribution is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.subject_type = 'managed_certificate' AND NEW.subject_id ~
    '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' THEN
    SELECT mc.token_id INTO source_token FROM managed_certificates mc
      JOIN tokens t ON t.id = mc.token_id AND t.workspace_id = mc.workspace_id
      WHERE mc.workspace_id = NEW.workspace_id AND mc.id = NEW.subject_id::uuid
      FOR SHARE OF mc;
  END IF;
  IF NEW.certificate_token_id IS NOT NULL AND NEW.certificate_token_id IS DISTINCT FROM source_token THEN
    RAISE EXCEPTION 'CertOps job alert token attribution is invalid' USING ERRCODE = '23514';
  END IF;
  NEW.certificate_token_id := source_token;
  RETURN NEW;
END $$;

-- Capture the source before the management-period lock, matching rotation.
DROP TRIGGER IF EXISTS trg_certops_0_capture_job_alert_token ON certificate_jobs;
CREATE TRIGGER trg_certops_0_capture_job_alert_token BEFORE INSERT OR UPDATE ON certificate_jobs
  FOR EACH ROW EXECUTE FUNCTION certops_capture_job_alert_token();

-- Payload assertions do not prove what an agent will install or restore.
-- An accepted replacement first acquires its own active fingerprint identity.
CREATE OR REPLACE FUNCTION certops_guard_job_identity_start()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE period_row RECORD; lifecycle TEXT;
BEGIN
  IF NEW.subject_type IS DISTINCT FROM 'managed_certificate' OR NEW.management_period_id IS NULL
    OR NEW.operation NOT IN ('renew','deploy','reload') OR NEW.status NOT IN ('claimed','running') THEN
    RETURN NEW;
  END IF;
  IF TG_OP='UPDATE' AND OLD.status IN ('claimed','running') THEN RETURN NEW; END IF;
  SELECT * INTO period_row FROM certops_management_periods
    WHERE id=NEW.management_period_id AND workspace_id=NEW.workspace_id FOR SHARE;
  -- The existing management-period guard owns closure and reconciliation.
  IF NOT FOUND OR period_row.ended_at IS NOT NULL THEN RETURN NEW; END IF;
  SELECT lifecycle_status INTO lifecycle FROM certops_certificate_identities
    WHERE workspace_id=NEW.workspace_id AND id=NEW.certificate_identity_id FOR SHARE;
  IF lifecycle IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION 'CertOps certificate lifecycle blocks this operation' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
-- A separate guard survives replay of older migration definitions. It follows
-- immutable attribution and precedes the original management-period guard.
DROP TRIGGER IF EXISTS trg_certops_b_guard_job_identity_start ON certificate_jobs;
CREATE TRIGGER trg_certops_b_guard_job_identity_start BEFORE INSERT OR UPDATE ON certificate_jobs
  FOR EACH ROW EXECUTE FUNCTION certops_guard_job_identity_start();

-- Existing unstarted work with an unknown or retired identity cannot safely
-- execute. Preserve the records; started work requires operator reconciliation.
UPDATE certificate_jobs cj SET status='cancelled', canceled_at=COALESCE(canceled_at,NOW()),
  claim_id=NULL, claimed_by_agent_id=NULL, claimed_by_controller_cluster_id=NULL,
  lease_expires_at=NULL, lease_renewed_at=NULL, updated_at=NOW()
  WHERE cj.subject_type='managed_certificate' AND cj.management_period_id IS NOT NULL
    AND cj.operation IN ('renew','deploy','reload')
    AND cj.status IN ('pending','pending_approval','approved')
    AND (cj.certificate_identity_id IS NULL OR EXISTS (
      SELECT 1 FROM certops_certificate_identities i WHERE i.workspace_id=cj.workspace_id
        AND i.id=cj.certificate_identity_id AND i.lifecycle_status IN ('revoked','decommissioned')));
UPDATE certificate_jobs cj SET needs_operator_reconciliation=TRUE,
  reconciliation_reason=COALESCE(reconciliation_reason,'certificate_identity_unknown_or_retired'), updated_at=NOW()
  WHERE cj.subject_type='managed_certificate' AND cj.management_period_id IS NOT NULL
    AND cj.operation IN ('renew','deploy','reload') AND cj.status IN ('claimed','running')
    AND (needs_operator_reconciliation IS DISTINCT FROM TRUE OR reconciliation_reason IS NULL)
    AND (cj.certificate_identity_id IS NULL OR EXISTS (
      SELECT 1 FROM certops_certificate_identities i WHERE i.workspace_id=cj.workspace_id
        AND i.id=cj.certificate_identity_id AND i.lifecycle_status IN ('revoked','decommissioned')));

-- Do not deliver historical renewal failures using a source's current token.
-- Sent evidence remains untouched; undelivered records remain as discarded.
WITH discarded AS (
  UPDATE alert_queue aq SET status='sent',
    error_message='Discarded: original certificate alert context unknown',
    next_attempt_at=NULL, delivery_claim_id=NULL, updated_at=NOW()
    FROM certificate_jobs cj
    WHERE aq.alert_key='cert_renewal_failed:' || cj.id::text
      AND cj.subject_type='managed_certificate'
      AND (cj.certificate_identity_id IS NULL OR cj.certificate_token_id IS NULL)
      AND aq.status IN ('pending','failed','blocked','limit_exceeded','partial')
    RETURNING aq.id,cj.workspace_id
)
UPDATE operational_notifications n SET resolved_at=NOW(),updated_at=NOW()
  FROM discarded d WHERE n.workspace_id=d.workspace_id AND n.category='delivery'
    AND n.resolved_at IS NULL AND n.metadata->>'alert_queue_id'=d.id::text;
