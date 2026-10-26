-- A continuation becomes key cleanup only for its bound terminal enrollment.
-- Insertion precedes updating current_job_id; claims and existing-work cleanup
-- require that pointer too. These checks never authorize a new installation.
CREATE OR REPLACE FUNCTION certops_is_bound_enrollment_continuation(
  candidate certificate_jobs, terminal_only BOOLEAN DEFAULT TRUE,
  current_only BOOLEAN DEFAULT TRUE
) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
  SELECT COALESCE(candidate.operation = 'continue-enrollment'
    AND candidate.subject_type = 'managed_certificate'
    AND EXISTS (SELECT 1 FROM certificate_enrollments e
      WHERE e.workspace_id = candidate.workspace_id AND e.id = candidate.enrollment_id
        AND e.certificate_id::text = lower(candidate.subject_id)
        AND e.agent_id = candidate.assigned_agent_id
        AND (NOT terminal_only OR e.state IN ('cancelled','expired','abandoned'))
        AND (NOT current_only OR e.current_job_id = candidate.id)), FALSE)
$$;

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
  -- Terminal cleanup is enrollment-owned and does not reopen source management.
  IF certops_is_bound_enrollment_continuation(NEW, TRUE, FALSE) THEN
    IF NEW.management_period_id IS NOT NULL OR NEW.certificate_identity_id IS NOT NULL THEN
      RAISE EXCEPTION 'Cleanup cannot invent management attribution' USING ERRCODE='23514';
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
  install_continuation BOOLEAN := FALSE;
BEGIN
  IF NEW.subject_type IS DISTINCT FROM 'managed_certificate' THEN
    RETURN NEW;
  END IF;
  -- Installation retries are new installs. Any continuation that can retrieve
  -- and install a leaf is fenced. Key cleanup stays claimable after retirement;
  -- a missing identity is not retirement.
  IF NEW.operation = 'continue-enrollment' THEN
    IF NEW.enrollment_id IS NULL OR NOT EXISTS (
      SELECT 1 FROM certificate_enrollments continuation
       WHERE continuation.workspace_id = NEW.workspace_id
         AND continuation.id = NEW.enrollment_id
         AND continuation.state NOT IN ('cancelled', 'expired', 'abandoned')
    ) THEN
      RETURN NEW;
    END IF;
    install_continuation := TRUE;
  ELSIF NEW.operation NOT IN ('renew','deploy','deploy-from-store','reload') THEN
    RETURN NEW;
  END IF;
  IF TG_OP='UPDATE' AND OLD.status IN ('claimed','running') THEN
    IF install_continuation THEN
      RETURN NEW;
    END IF;
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
  IF install_continuation THEN
    IF lifecycle IN ('revoked','decommissioned') THEN
      RAISE EXCEPTION 'CertOps certificate lifecycle blocks this operation' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
  END IF;
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
    AND cj.mode IS DISTINCT FROM 'dry_run'
    AND (needs_operator_reconciliation IS DISTINCT FROM TRUE OR reconciliation_reason IS NULL)
    AND ((cj.certificate_identity_id IS NULL AND NOT certops_is_initial_provisioning(
      cj.workspace_id,cj.subject_id::uuid,cj.operation,cj.executor_kind,cj.source)) OR EXISTS (
      SELECT 1 FROM certops_certificate_identities i WHERE i.workspace_id=cj.workspace_id
        AND i.id=cj.certificate_identity_id AND i.lifecycle_status IN ('revoked','decommissioned')));

-- Replayed on every startup, after older management guard definitions.
CREATE OR REPLACE FUNCTION certops_close_management_work()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.ended_at IS NULL AND NEW.ended_at IS NOT NULL THEN
    UPDATE certops_management_associations SET superseded_at = NEW.ended_at
      WHERE period_id = NEW.id AND superseded_at IS NULL;
    UPDATE certificate_jobs j SET status = 'cancelled', canceled_at = COALESCE(j.canceled_at, NEW.ended_at), updated_at = NOW()
      WHERE j.id IN (SELECT id FROM certificate_jobs WHERE workspace_id = NEW.workspace_id
        AND management_period_id = NEW.id AND status IN ('pending', 'approved', 'pending_approval')
        AND NOT certops_is_bound_enrollment_continuation(certificate_jobs, FALSE, TRUE)
        FOR UPDATE SKIP LOCKED);
    UPDATE certificate_jobs j SET needs_operator_reconciliation = TRUE,
      reconciliation_reason = COALESCE(j.reconciliation_reason, 'management_period_closed'), updated_at = NOW()
      WHERE j.id IN (SELECT id FROM certificate_jobs WHERE workspace_id = NEW.workspace_id
        AND management_period_id = NEW.id AND status IN ('claimed', 'running')
        AND (COALESCE(NEW.ended_reason, '') NOT IN ('certificate_revoked','certificate_decommissioned')
          OR (mode IS DISTINCT FROM 'dry_run'
            AND operation IN ('renew','deploy','deploy-from-store','reload','continue-enrollment')))
        AND NOT certops_is_bound_enrollment_continuation(certificate_jobs) FOR UPDATE SKIP LOCKED);
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION certops_guard_management_job_claim()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE period_row RECORD; lifecycle TEXT; fingerprint TEXT; already_started BOOLEAN := FALSE;
BEGIN
  IF NEW.subject_type IS DISTINCT FROM 'managed_certificate' OR NEW.management_period_id IS NULL THEN RETURN NEW; END IF;
  IF NEW.status NOT IN ('pending', 'pending_approval', 'approved', 'claimed', 'running') THEN RETURN NEW; END IF;
  IF TG_OP = 'UPDATE' THEN already_started := OLD.status IN ('claimed', 'running'); END IF;
  IF certops_is_bound_enrollment_continuation(NEW) THEN RETURN NEW; END IF;
  SELECT * INTO period_row FROM certops_management_periods WHERE id = NEW.management_period_id
    AND workspace_id = NEW.workspace_id FOR SHARE;
  IF FOUND AND already_started AND period_row.ended_reason IN ('certificate_revoked','certificate_decommissioned') THEN
    IF OLD.mode = 'dry_run' OR (OLD.operation NOT IN ('renew','deploy','deploy-from-store','reload','continue-enrollment')
      AND NEW.operation NOT IN ('renew','deploy','deploy-from-store','reload','continue-enrollment')) THEN RETURN NEW; END IF;
  END IF;
  IF NOT FOUND OR period_row.ended_at IS NOT NULL THEN
    IF already_started AND NEW.status IN ('claimed', 'running') THEN
      NEW.needs_operator_reconciliation := TRUE;
      NEW.reconciliation_reason := COALESCE(NEW.reconciliation_reason, 'management_period_closed');
    ELSE
      NEW.status := 'cancelled'; NEW.canceled_at := COALESCE(NEW.canceled_at, NOW());
      NEW.claim_id := NULL; NEW.claimed_by_agent_id := NULL; NEW.claimed_by_controller_cluster_id := NULL;
      NEW.lease_expires_at := NULL; NEW.lease_renewed_at := NULL;
      IF TG_OP = 'UPDATE' THEN NEW.started_at := OLD.started_at; NEW.attempt_count := OLD.attempt_count; END IF;
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status NOT IN ('claimed', 'running') OR already_started THEN RETURN NEW; END IF;
  SELECT lifecycle_status, fingerprint_sha256 INTO lifecycle, fingerprint FROM certops_certificate_identities
    WHERE workspace_id = NEW.workspace_id AND id = COALESCE(NEW.certificate_identity_id, period_row.current_identity_id) FOR SHARE;
  IF lifecycle IN ('revoked', 'decommissioned') AND NEW.operation IN ('renew', 'deploy', 'reload')
    AND NOT (certops_normalize_fingerprint(NEW.payload->>'targetFingerprintSha256') IS NOT NULL
      AND certops_normalize_fingerprint(NEW.payload->>'targetFingerprintSha256') <> fingerprint
      AND NEW.payload->>'canRestoreOriginal' = 'false') THEN
    RAISE EXCEPTION 'CertOps certificate lifecycle blocks this operation' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END $$;
