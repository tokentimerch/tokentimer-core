-- Replayed after job-alert context on canonical and immutable preview histories.
-- Existing mainline migration 73 and applied ledger rows remain unchanged.
CREATE OR REPLACE FUNCTION certops_tag_management_job()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE period_row RECORD; pinned_identity UUID;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
      AND current_setting('certops.workspace_transfer', TRUE) = OLD.workspace_id::text || ':' || NEW.workspace_id::text THEN
      RETURN NEW;
    END IF;
    IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.subject_type IS DISTINCT FROM OLD.subject_type
      OR NEW.subject_id IS DISTINCT FROM OLD.subject_id OR NEW.management_period_id IS DISTINCT FROM OLD.management_period_id
      OR NEW.certificate_identity_id IS DISTINCT FROM OLD.certificate_identity_id THEN
      RAISE EXCEPTION 'CertOps job management attribution is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.subject_type = 'managed_certificate' AND NEW.subject_id ~
    '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' THEN
    SELECT * INTO period_row FROM certops_management_periods WHERE workspace_id = NEW.workspace_id
      AND managed_certificate_id = NEW.subject_id::uuid AND ended_at IS NULL FOR SHARE;
    IF NOT FOUND THEN
      -- Generic legacy jobs can reference an absent inventory record. They do
      -- not acquire management, and cannot supply invented period attribution.
      IF NEW.management_period_id IS NOT NULL OR NEW.certificate_identity_id IS NOT NULL
        OR EXISTS (SELECT 1 FROM managed_certificates WHERE workspace_id = NEW.workspace_id AND id = NEW.subject_id::uuid) THEN
        RAISE EXCEPTION 'CertOps management source is stopped' USING ERRCODE = '55000';
      END IF;
      RETURN NEW;
    END IF;
    pinned_identity := period_row.current_identity_id;
    IF NEW.operation='deploy-from-store' THEN
      SELECT v.certificate_identity_id INTO pinned_identity FROM certops_material_versions v
        WHERE v.workspace_id=NEW.workspace_id AND v.management_period_id=period_row.id
        AND v.group_id=(NEW.payload->'materialDeployment'->>'groupId')::uuid
        AND v.id=(NEW.payload->'materialDeployment'->>'materialVersionId')::uuid
        AND v.fingerprint_sha256=NEW.payload->'materialDeployment'->>'fingerprintSha256'
        AND v.state='published';
      IF pinned_identity IS NULL THEN
        RAISE EXCEPTION 'CertOps deployment identity is not published' USING ERRCODE='23514';
      END IF;
    END IF;
    IF (NEW.management_period_id IS NOT NULL AND NEW.management_period_id <> period_row.id)
      OR (NEW.certificate_identity_id IS NOT NULL AND NEW.certificate_identity_id IS DISTINCT FROM pinned_identity) THEN
      RAISE EXCEPTION 'CertOps job management attribution is invalid' USING ERRCODE = '23514';
    END IF;
    NEW.management_period_id := period_row.id;
    NEW.certificate_identity_id := pinned_identity;
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION certops_guard_job_identity_start()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE period_row RECORD; identity_row RECORD; lifecycle TEXT;
BEGIN
  IF NEW.subject_type IS DISTINCT FROM 'managed_certificate'
    OR NEW.operation NOT IN ('renew','deploy','deploy-from-store','reload') THEN
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
    AND cj.operation IN ('renew','deploy','deploy-from-store','reload')
    AND cj.status IN ('pending','pending_approval','approved')
    AND ((cj.certificate_identity_id IS NULL AND NOT certops_is_initial_provisioning(
      cj.workspace_id,cj.subject_id::uuid,cj.operation,cj.executor_kind,cj.source)) OR EXISTS (
      SELECT 1 FROM certops_certificate_identities i WHERE i.workspace_id=cj.workspace_id
        AND i.id=cj.certificate_identity_id AND i.lifecycle_status IN ('revoked','decommissioned')));
UPDATE certificate_jobs cj SET needs_operator_reconciliation=TRUE,
  reconciliation_reason=COALESCE(reconciliation_reason,'certificate_identity_unknown_or_retired'), updated_at=NOW()
  WHERE cj.subject_type='managed_certificate' AND cj.management_period_id IS NOT NULL
    AND cj.operation IN ('renew','deploy','deploy-from-store','reload') AND cj.status IN ('claimed','running')
    AND (needs_operator_reconciliation IS DISTINCT FROM TRUE OR reconciliation_reason IS NULL)
    AND ((cj.certificate_identity_id IS NULL AND NOT certops_is_initial_provisioning(
      cj.workspace_id,cj.subject_id::uuid,cj.operation,cj.executor_kind,cj.source)) OR EXISTS (
      SELECT 1 FROM certops_certificate_identities i WHERE i.workspace_id=cj.workspace_id
        AND i.id=cj.certificate_identity_id AND i.lifecycle_status IN ('revoked','decommissioned')));
