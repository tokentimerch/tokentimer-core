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
-- Initial issuance has no fingerprint yet. Only server-owned provisioning
-- sources with no previous fingerprint association or observation qualify.
CREATE OR REPLACE FUNCTION certops_is_initial_provisioning(
  workspace UUID, source_id UUID, operation TEXT, executor TEXT, job_source TEXT
) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1 FROM managed_certificates mc
      JOIN certops_management_periods p ON p.workspace_id=mc.workspace_id
        AND p.managed_certificate_id=mc.id AND p.ended_at IS NULL
    WHERE mc.workspace_id=workspace AND mc.id=source_id
      AND certops_normalize_fingerprint(mc.fingerprint_sha256) IS NULL
      AND p.current_identity_id IS NULL
      AND ((mc.status='provisioning' AND mc.source='agent_issuance' AND executor='agent' AND operation='renew')
        OR (mc.status IN ('discovered','provisioning') AND mc.source='cert_manager'
          AND mc.key_mode='cert-manager-managed' AND mc.public_metadata ? 'controllerProvisioning'
          AND executor='controller' AND operation='deploy' AND job_source='controller_provisioning'))
      AND NOT EXISTS (SELECT 1 FROM certops_management_periods history
        JOIN certops_management_associations a ON a.period_id=history.id
        WHERE history.workspace_id=mc.workspace_id AND history.managed_certificate_id=mc.id)
      AND NOT EXISTS (SELECT 1 FROM certificate_instances observation
        WHERE observation.workspace_id=mc.workspace_id AND observation.managed_certificate_id=mc.id
          AND certops_normalize_fingerprint(observation.observed_fingerprint_sha256) IS NOT NULL)
  );
$$;

CREATE OR REPLACE FUNCTION certops_guard_job_identity_start()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE period_row RECORD; identity_row RECORD; lifecycle TEXT;
BEGIN
  IF NEW.subject_type IS DISTINCT FROM 'managed_certificate'
    OR NEW.operation NOT IN ('renew','deploy','reload') THEN
    RETURN NEW;
  END IF;
  IF TG_OP='UPDATE' AND OLD.status IN ('claimed','running') THEN
    IF OLD.mode IS DISTINCT FROM 'dry_run' THEN
      IF NEW.certificate_identity_id IS NOT NULL THEN
        -- Completion may own a token/source row that retirement needs. Never
        -- wait on an identity row in the reverse order. A busy retirement fence
        -- is itself a reconciliation conflict; otherwise keep retirement from
        -- starting until this short result transaction commits.
        IF NOT pg_try_advisory_xact_lock_shared(hashtextextended(
          'certops-identity-retirement:' || NEW.certificate_identity_id::text, 0)) THEN
          lifecycle := 'revoked';
        ELSE
          SELECT lifecycle_status INTO lifecycle FROM certops_certificate_identities
            WHERE workspace_id=NEW.workspace_id AND id=NEW.certificate_identity_id;
        END IF;
      ELSE
        -- Historical NULL attribution cannot prove which association was
        -- installed. Any retired association in this job's period is a conflict.
        -- First provisioning with no fingerprint history remains unaffected.
        FOR identity_row IN SELECT DISTINCT i.id FROM certops_certificate_identities i
          JOIN certops_management_associations a ON a.identity_id=i.id AND a.workspace_id=i.workspace_id
          WHERE a.workspace_id=NEW.workspace_id AND a.period_id=NEW.management_period_id
          ORDER BY i.id LOOP
          IF NOT pg_try_advisory_xact_lock_shared(hashtextextended(
            'certops-identity-retirement:' || identity_row.id::text, 0)) THEN
            lifecycle := 'revoked';
          ELSE
            SELECT lifecycle_status INTO lifecycle FROM certops_certificate_identities
              WHERE workspace_id=NEW.workspace_id AND id=identity_row.id;
          END IF;
          EXIT WHEN lifecycle IN ('revoked','decommissioned');
        END LOOP;
      END IF;
      IF lifecycle IN ('revoked','decommissioned') THEN
        NEW.needs_operator_reconciliation := TRUE;
        NEW.reconciliation_reason := COALESCE(NEW.reconciliation_reason, 'certificate_retirement_overlapped_execution');
      END IF;
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.management_period_id IS NULL OR NEW.status NOT IN ('claimed','running') THEN RETURN NEW; END IF;
  SELECT * INTO period_row FROM certops_management_periods
    WHERE id=NEW.management_period_id AND workspace_id=NEW.workspace_id FOR SHARE;
  -- The existing management-period guard owns closure and reconciliation.
  IF NOT FOUND OR period_row.ended_at IS NOT NULL THEN RETURN NEW; END IF;
  SELECT lifecycle_status INTO lifecycle FROM certops_certificate_identities
    WHERE workspace_id=NEW.workspace_id AND id=NEW.certificate_identity_id FOR SHARE;
  IF NEW.certificate_identity_id IS NULL AND certops_is_initial_provisioning(
    NEW.workspace_id,period_row.managed_certificate_id,NEW.operation,NEW.executor_kind,NEW.source
  ) THEN RETURN NEW; END IF;
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
    AND ((cj.certificate_identity_id IS NULL AND NOT certops_is_initial_provisioning(
      cj.workspace_id,cj.subject_id::uuid,cj.operation,cj.executor_kind,cj.source)) OR EXISTS (
      SELECT 1 FROM certops_certificate_identities i WHERE i.workspace_id=cj.workspace_id
        AND i.id=cj.certificate_identity_id AND i.lifecycle_status IN ('revoked','decommissioned')));
UPDATE certificate_jobs cj SET needs_operator_reconciliation=TRUE,
  reconciliation_reason=COALESCE(reconciliation_reason,'certificate_identity_unknown_or_retired'), updated_at=NOW()
  WHERE cj.subject_type='managed_certificate' AND cj.management_period_id IS NOT NULL
    AND cj.operation IN ('renew','deploy','reload') AND cj.status IN ('claimed','running')
    AND (needs_operator_reconciliation IS DISTINCT FROM TRUE OR reconciliation_reason IS NULL)
    AND ((cj.certificate_identity_id IS NULL AND NOT certops_is_initial_provisioning(
      cj.workspace_id,cj.subject_id::uuid,cj.operation,cj.executor_kind,cj.source)) OR EXISTS (
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
