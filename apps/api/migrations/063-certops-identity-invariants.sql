-- Additive repair for both fresh v61 -> v62 -> v63 and already-applied v62.
-- Core remains unlimited unless an installation supplies a workspace limit.
ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS certops_managed_identity_limit INTEGER
  CHECK (certops_managed_identity_limit IS NULL OR certops_managed_identity_limit >= 0);
ALTER TABLE managed_certificates ADD COLUMN IF NOT EXISTS identity_observed_at TIMESTAMPTZ;
-- Observation facts outlive the management source that first recorded them.
ALTER TABLE certificate_instances ALTER COLUMN managed_certificate_id DROP NOT NULL;
DROP TRIGGER IF EXISTS trg_certops_guard_management_period ON certops_management_periods;
ALTER TABLE certops_management_periods ADD COLUMN IF NOT EXISTS source TEXT;
ALTER TABLE certops_management_periods ADD COLUMN IF NOT EXISTS source_ref TEXT;
UPDATE certops_management_periods p SET source = mc.source, source_ref = mc.source_ref
  FROM managed_certificates mc WHERE mc.id = p.managed_certificate_id AND p.source IS NULL;
-- Closed provenance survives source deletion and workspace transfer. Open
-- source ownership is enforced with a row lock by the period trigger below.
ALTER TABLE certops_management_periods DROP CONSTRAINT IF EXISTS certops_management_periods_workspace_id_managed_certificat_fkey;
ALTER TABLE certops_management_periods DROP CONSTRAINT IF EXISTS fk_certops_period_source;
ALTER TABLE certops_management_periods DROP CONSTRAINT IF EXISTS fk_certops_period_workspace;
ALTER TABLE certops_management_periods ADD CONSTRAINT fk_certops_period_workspace
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE;
ALTER TABLE certops_management_periods ALTER CONSTRAINT certops_management_periods_workspace_id_current_identity_i_fkey DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE certops_management_associations ALTER CONSTRAINT certops_management_associations_workspace_id_identity_id_fkey DEFERRABLE INITIALLY DEFERRED;

CREATE OR REPLACE FUNCTION certops_normalize_fingerprint(value TEXT)
RETURNS TEXT LANGUAGE sql IMMUTABLE PARALLEL SAFE COST 1 AS $$
  SELECT CASE WHEN lower(replace(btrim(value), ':', '')) ~ '^[a-f0-9]{64}$'
    THEN lower(replace(btrim(value), ':', '')) ELSE NULL END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_certops_period_workspace_id
  ON certops_management_periods(workspace_id, id);
ALTER TABLE certops_management_associations DROP CONSTRAINT IF EXISTS fk_certops_association_workspace_period;
ALTER TABLE certops_management_associations ADD CONSTRAINT fk_certops_association_workspace_period
  FOREIGN KEY (workspace_id, period_id) REFERENCES certops_management_periods(workspace_id, id) ON DELETE CASCADE;
ALTER TABLE certificate_jobs DROP CONSTRAINT IF EXISTS fk_certops_job_workspace_period;
ALTER TABLE certificate_jobs ADD CONSTRAINT fk_certops_job_workspace_period
  FOREIGN KEY (workspace_id, management_period_id) REFERENCES certops_management_periods(workspace_id, id);
ALTER TABLE certificate_jobs DROP CONSTRAINT IF EXISTS fk_certops_job_workspace_identity;
ALTER TABLE certificate_jobs ADD CONSTRAINT fk_certops_job_workspace_identity
  FOREIGN KEY (workspace_id, certificate_identity_id) REFERENCES certops_certificate_identities(workspace_id, id);
ALTER TABLE certops_management_periods DROP CONSTRAINT IF EXISTS fk_certops_period_workspace_profile;
ALTER TABLE certops_management_periods ADD CONSTRAINT fk_certops_period_workspace_profile
  FOREIGN KEY (workspace_id, renewal_profile_id) REFERENCES certificate_profiles(workspace_id, id);

CREATE INDEX IF NOT EXISTS idx_certops_period_source_history
  ON certops_management_periods(workspace_id, managed_certificate_id, started_at DESC, id);
CREATE INDEX IF NOT EXISTS idx_certops_jobs_period_status
  ON certificate_jobs(workspace_id, management_period_id, status);
CREATE INDEX IF NOT EXISTS idx_certops_source_normalized_fingerprint
  ON managed_certificates(workspace_id, certops_normalize_fingerprint(fingerprint_sha256));
CREATE INDEX IF NOT EXISTS idx_certops_observation_normalized_fingerprint
  ON certificate_instances(workspace_id, certops_normalize_fingerprint(observed_fingerprint_sha256), captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_certops_identity_workspace_expiry
  ON certops_certificate_identities(workspace_id, not_after, id);

-- Lifecycle is owned only by the identity. Observers cannot reset it, including
-- a revoked -> decommissioned downgrade or a source moving to another workspace.
CREATE OR REPLACE FUNCTION certops_keep_certificate_identity_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.fingerprint_sha256 := certops_normalize_fingerprint(NEW.fingerprint_sha256);
  ELSE
    IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
      OR NEW.fingerprint_sha256 IS DISTINCT FROM OLD.fingerprint_sha256 THEN
      RAISE EXCEPTION 'CertOps certificate identity is immutable' USING ERRCODE = '23514';
    END IF;
    IF (OLD.lifecycle_status IN ('revoked', 'decommissioned') AND NEW.lifecycle_status = 'active')
      OR (OLD.lifecycle_status = 'revoked' AND NEW.lifecycle_status = 'decommissioned') THEN
      RAISE EXCEPTION 'CertOps retired lifecycle is terminal' USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_certops_keep_certificate_identity_immutable ON certops_certificate_identities;
CREATE TRIGGER trg_certops_keep_certificate_identity_immutable BEFORE INSERT OR UPDATE
  ON certops_certificate_identities FOR EACH ROW EXECUTE FUNCTION certops_keep_certificate_identity_immutable();

-- Admission is at the period boundary, including INSERTs performed by triggers
-- and identity changes during rotation. The lock key is the existing Core/Cloud
-- import-quota key. Counting excludes the period being rotated: replacing its
-- last A association with B uses one unit; leaving another A source open adds B.
CREATE OR REPLACE FUNCTION certops_admit_management(workspace UUID, identity UUID, excluded_period UUID DEFAULT NULL)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE quota_limit INTEGER; used INTEGER;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('certops_managed_cert_quota_' || workspace::text));
  SELECT certops_managed_identity_limit INTO quota_limit FROM workspaces WHERE id = workspace;
  IF quota_limit IS NULL THEN RETURN; END IF;
  IF identity IS NOT NULL AND EXISTS (SELECT 1 FROM certops_management_periods p
    WHERE p.workspace_id = workspace AND p.ended_at IS NULL AND p.current_identity_id = identity
      AND p.id IS DISTINCT FROM excluded_period) THEN RETURN; END IF;
  SELECT (COUNT(DISTINCT p.current_identity_id) + COUNT(*) FILTER (WHERE p.current_identity_id IS NULL))::int
    INTO used FROM certops_management_periods p
    WHERE p.workspace_id = workspace AND p.ended_at IS NULL AND p.id IS DISTINCT FROM excluded_period;
  IF used + 1 > quota_limit THEN
    RAISE EXCEPTION 'CertOps managed certificate quota exceeded' USING ERRCODE = 'P0001',
      DETAIL = 'CERTOPS_MANAGED_CERT_LIMIT', HINT = format('limit=%s used=%s', quota_limit, used);
  END IF;
END $$;

-- No closed row can be reopened, reconfigured, reassigned or have its dates
-- rewritten. A new period always means a new INSERT and fresh admission.
CREATE OR REPLACE FUNCTION certops_guard_management_period()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE source_row RECORD;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT source, source_ref INTO source_row FROM managed_certificates
      WHERE workspace_id = NEW.workspace_id AND id = NEW.managed_certificate_id FOR KEY SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'CertOps management source workspace mismatch' USING ERRCODE = '23503'; END IF;
    NEW.source := source_row.source; NEW.source_ref := source_row.source_ref;
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF OLD.ended_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
      RAISE EXCEPTION 'CertOps closed management period is immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
      OR NEW.managed_certificate_id IS DISTINCT FROM OLD.managed_certificate_id
      OR NEW.started_at IS DISTINCT FROM OLD.started_at OR NEW.source IS DISTINCT FROM OLD.source
      OR NEW.source_ref IS DISTINCT FROM OLD.source_ref THEN
      RAISE EXCEPTION 'CertOps management period ownership is immutable' USING ERRCODE = '23514';
    END IF;
  END IF;
  IF NEW.ended_at IS NOT NULL AND NEW.ended_at < NEW.started_at THEN
    RAISE EXCEPTION 'CertOps management period ends before it starts' USING ERRCODE = '23514';
  END IF;
  IF NEW.ended_at IS NULL AND (TG_OP = 'INSERT' OR NEW.current_identity_id IS DISTINCT FROM OLD.current_identity_id) THEN
    SELECT mc.source, mc.source_ref, i.id AS identity_id INTO source_row FROM managed_certificates mc
      LEFT JOIN certops_certificate_identities i ON i.workspace_id = mc.workspace_id
        AND i.fingerprint_sha256 = certops_normalize_fingerprint(mc.fingerprint_sha256)
      WHERE mc.workspace_id = NEW.workspace_id AND mc.id = NEW.managed_certificate_id;
    IF NEW.current_identity_id IS NULL THEN NEW.current_identity_id := source_row.identity_id; END IF;
    IF NEW.current_identity_id IS DISTINCT FROM source_row.identity_id THEN
      RAISE EXCEPTION 'CertOps management identity does not match its source' USING ERRCODE = '23514';
    END IF;
    IF source_row.source = 'endpoint_monitor' THEN
      PERFORM 1 FROM domain_monitors WHERE workspace_id = NEW.workspace_id
        AND id::text = source_row.source_ref FOR KEY SHARE;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'CertOps endpoint management source is unavailable' USING ERRCODE = '23514';
      END IF;
    END IF;
    PERFORM certops_admit_management(NEW.workspace_id, NEW.current_identity_id,
      CASE WHEN TG_OP = 'UPDATE' THEN OLD.id ELSE NULL END);
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_certops_guard_management_period ON certops_management_periods;
CREATE TRIGGER trg_certops_guard_management_period BEFORE INSERT OR UPDATE ON certops_management_periods
  FOR EACH ROW EXECUTE FUNCTION certops_guard_management_period();

CREATE OR REPLACE FUNCTION certops_track_management_association()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' AND NEW.ended_at IS NOT NULL THEN RETURN NEW; END IF;
  IF TG_OP = 'UPDATE' THEN
    IF NEW.current_identity_id IS NOT DISTINCT FROM OLD.current_identity_id THEN RETURN NEW; END IF;
    UPDATE certops_management_associations SET superseded_at = clock_timestamp()
      WHERE period_id = NEW.id AND superseded_at IS NULL;
  END IF;
  IF NEW.current_identity_id IS NOT NULL THEN
    INSERT INTO certops_management_associations(workspace_id, period_id, identity_id, associated_at, superseded_at)
      VALUES (NEW.workspace_id, NEW.id, NEW.current_identity_id,
        CASE WHEN TG_OP = 'INSERT' THEN NEW.started_at ELSE clock_timestamp() END, NEW.ended_at);
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_certops_track_management_association ON certops_management_periods;
CREATE TRIGGER trg_certops_track_management_association AFTER INSERT OR UPDATE OF current_identity_id
  ON certops_management_periods FOR EACH ROW EXECUTE FUNCTION certops_track_management_association();

-- Do not wait on a job row held by a claimant that is waiting for this period.
-- A racing claimant is cancelled by the job boundary below after the close
-- commits. Claims that acquired the period SHARE lock first remain auditable.
CREATE OR REPLACE FUNCTION certops_close_management_work()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.ended_at IS NULL AND NEW.ended_at IS NOT NULL THEN
    UPDATE certops_management_associations SET superseded_at = NEW.ended_at
      WHERE period_id = NEW.id AND superseded_at IS NULL;
    UPDATE certificate_jobs j SET status = 'cancelled', canceled_at = COALESCE(j.canceled_at, NEW.ended_at), updated_at = NOW()
      WHERE j.id IN (SELECT id FROM certificate_jobs WHERE workspace_id = NEW.workspace_id
        AND management_period_id = NEW.id AND status IN ('pending', 'approved', 'pending_approval')
        FOR UPDATE SKIP LOCKED);
    UPDATE certificate_jobs j SET needs_operator_reconciliation = TRUE,
      reconciliation_reason = COALESCE(j.reconciliation_reason, 'management_period_closed'), updated_at = NOW()
      WHERE j.id IN (SELECT id FROM certificate_jobs WHERE workspace_id = NEW.workspace_id
        AND management_period_id = NEW.id AND status IN ('claimed', 'running') FOR UPDATE SKIP LOCKED);
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_certops_close_management_work ON certops_management_periods;
CREATE TRIGGER trg_certops_close_management_work AFTER UPDATE OF ended_at ON certops_management_periods
  FOR EACH ROW EXECUTE FUNCTION certops_close_management_work();

CREATE OR REPLACE FUNCTION certops_close_endpoint_management()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE certops_management_periods p SET ended_at = GREATEST(NOW(), p.started_at), ended_reason = 'endpoint_monitor_deleted'
    FROM managed_certificates mc WHERE p.workspace_id = OLD.workspace_id AND p.ended_at IS NULL
      AND p.managed_certificate_id = mc.id AND mc.workspace_id = OLD.workspace_id
      AND mc.source IN ('endpoint_monitor', 'domain_checker')
      AND (mc.source_ref = OLD.id::text OR EXISTS (SELECT 1 FROM certificate_instances i
        WHERE i.workspace_id = OLD.workspace_id AND i.managed_certificate_id = mc.id AND i.domain_monitor_id = OLD.id)
        OR EXISTS (SELECT 1 FROM certificate_targets t WHERE t.workspace_id = OLD.workspace_id
          AND t.domain_monitor_id = OLD.id AND t.source = mc.source AND t.source_ref = mc.source_ref));
  RETURN OLD;
END $$;
DROP TRIGGER IF EXISTS trg_certops_close_endpoint_management ON domain_monitors;
CREATE TRIGGER trg_certops_close_endpoint_management BEFORE DELETE ON domain_monitors
  FOR EACH ROW EXECUTE FUNCTION certops_close_endpoint_management();

CREATE OR REPLACE FUNCTION certops_close_deleted_management_source()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- Workspace/account erasure is allowed to erase its own history. Ordinary
  -- source removal keeps period snapshots, identities and observation facts.
  IF NOT EXISTS (SELECT 1 FROM workspaces WHERE id = OLD.workspace_id) THEN RETURN OLD; END IF;
  UPDATE certops_management_periods SET ended_at = GREATEST(NOW(),started_at), ended_reason = 'management_source_deleted'
    WHERE workspace_id = OLD.workspace_id AND managed_certificate_id = OLD.id AND ended_at IS NULL;
  UPDATE certificate_instances SET managed_certificate_id = NULL
    WHERE workspace_id = OLD.workspace_id AND managed_certificate_id = OLD.id;
  RETURN OLD;
END $$;
DROP TRIGGER IF EXISTS trg_certops_close_deleted_management_source ON managed_certificates;
CREATE TRIGGER trg_certops_close_deleted_management_source BEFORE DELETE ON managed_certificates
  FOR EACH ROW EXECUTE FUNCTION certops_close_deleted_management_source();

CREATE OR REPLACE FUNCTION certops_tag_management_job()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE period_row RECORD;
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
    IF (NEW.management_period_id IS NOT NULL AND NEW.management_period_id <> period_row.id)
      OR (NEW.certificate_identity_id IS NOT NULL AND NEW.certificate_identity_id IS DISTINCT FROM period_row.current_identity_id) THEN
      RAISE EXCEPTION 'CertOps job management attribution is invalid' USING ERRCODE = '23514';
    END IF;
    NEW.management_period_id := period_row.id;
    NEW.certificate_identity_id := period_row.current_identity_id;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_certops_tag_management_job ON certificate_jobs;
DROP TRIGGER IF EXISTS trg_certops_a_tag_management_job ON certificate_jobs;
-- Alphabetical order: attribution runs before the status/lease guard.
CREATE TRIGGER trg_certops_a_tag_management_job BEFORE INSERT OR UPDATE ON certificate_jobs
  FOR EACH ROW EXECUTE FUNCTION certops_tag_management_job();

CREATE OR REPLACE FUNCTION certops_guard_management_job_claim()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE period_row RECORD; lifecycle TEXT; fingerprint TEXT; already_started BOOLEAN := FALSE;
BEGIN
  IF NEW.subject_type IS DISTINCT FROM 'managed_certificate' OR NEW.management_period_id IS NULL THEN RETURN NEW; END IF;
  IF NEW.status NOT IN ('pending', 'pending_approval', 'approved', 'claimed', 'running') THEN RETURN NEW; END IF;
  IF TG_OP = 'UPDATE' THEN already_started := OLD.status IN ('claimed', 'running'); END IF;
  SELECT * INTO period_row FROM certops_management_periods WHERE id = NEW.management_period_id
    AND workspace_id = NEW.workspace_id FOR SHARE;
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
DROP TRIGGER IF EXISTS trg_certops_guard_management_job_claim ON certificate_jobs;
CREATE TRIGGER trg_certops_guard_management_job_claim BEFORE INSERT OR UPDATE ON certificate_jobs
  FOR EACH ROW EXECUTE FUNCTION certops_guard_management_job_claim();

-- Keep the existing prepare function's lifecycle rules, but cover every write,
-- normalize whitespace, and reject a backwards source observation watermark.
CREATE OR REPLACE FUNCTION certops_prepare_managed_identity()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE fingerprint TEXT; lifecycle TEXT; observation_time TIMESTAMPTZ;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('certops_managed_cert_quota_' || NEW.workspace_id::text));
  IF TG_OP = 'UPDATE' AND NEW.workspace_id IS DISTINCT FROM OLD.workspace_id THEN
    IF current_setting('certops.workspace_transfer', TRUE) IS DISTINCT FROM OLD.workspace_id::text || ':' || NEW.workspace_id::text THEN
      RAISE EXCEPTION 'CertOps management source workspace is immutable' USING ERRCODE = '23514';
    END IF;
  END IF;
  observation_time := NEW.identity_observed_at;
  IF observation_time > clock_timestamp() + INTERVAL '5 minutes' THEN
    RAISE EXCEPTION 'CertOps observation timestamp is in the future' USING ERRCODE = '23514';
  END IF;
  IF TG_OP = 'UPDATE' AND NEW.workspace_id = OLD.workspace_id AND observation_time IS NOT NULL AND OLD.identity_observed_at IS NOT NULL
    AND certops_normalize_fingerprint(OLD.fingerprint_sha256) IS NOT NULL
    AND observation_time <= OLD.identity_observed_at
    AND (observation_time < OLD.identity_observed_at
      OR CASE WHEN NEW.source = 'cert_manager'
          AND NEW.public_metadata#>>'{controllerObservation,resourceVersion}' ~ '^[0-9]+$'
          AND OLD.public_metadata#>>'{controllerObservation,resourceVersion}' ~ '^[0-9]+$'
          THEN (NEW.public_metadata#>>'{controllerObservation,resourceVersion}')::numeric <
            (OLD.public_metadata#>>'{controllerObservation,resourceVersion}')::numeric ELSE FALSE END
      OR (certops_normalize_fingerprint(NEW.fingerprint_sha256) IS DISTINCT FROM certops_normalize_fingerprint(OLD.fingerprint_sha256)
        AND NOT CASE WHEN NEW.source = 'cert_manager'
          AND NEW.public_metadata#>>'{controllerObservation,resourceVersion}' ~ '^[0-9]+$'
          AND OLD.public_metadata#>>'{controllerObservation,resourceVersion}' ~ '^[0-9]+$'
          THEN (NEW.public_metadata#>>'{controllerObservation,resourceVersion}')::numeric >
            (OLD.public_metadata#>>'{controllerObservation,resourceVersion}')::numeric ELSE FALSE END)) THEN
    -- The instance/evidence write still records this observation separately.
    RETURN OLD;
  END IF;
  fingerprint := certops_normalize_fingerprint(NEW.fingerprint_sha256);
  IF fingerprint IS NULL THEN RETURN NEW; END IF;
  NEW.fingerprint_sha256 := fingerprint;
  IF TG_OP = 'INSERT' OR NEW.fingerprint_sha256 IS DISTINCT FROM OLD.fingerprint_sha256 THEN
    NEW.identity_observed_at := COALESCE(observation_time, clock_timestamp());
  END IF;
  INSERT INTO certops_certificate_identities(workspace_id, fingerprint_sha256, common_name, issuer, not_after)
    VALUES (NEW.workspace_id, fingerprint, NEW.common_name, NEW.issuer, NEW.not_after)
    ON CONFLICT (workspace_id, fingerprint_sha256) DO UPDATE SET
      common_name = COALESCE(certops_certificate_identities.common_name, EXCLUDED.common_name),
      issuer = COALESCE(certops_certificate_identities.issuer, EXCLUDED.issuer),
      not_after = COALESCE(certops_certificate_identities.not_after, EXCLUDED.not_after);
  SELECT lifecycle_status INTO lifecycle FROM certops_certificate_identities
    WHERE workspace_id = NEW.workspace_id AND fingerprint_sha256 = fingerprint;
  IF lifecycle IN ('revoked', 'decommissioned') THEN NEW.status := lifecycle;
  ELSIF TG_OP = 'UPDATE' AND certops_normalize_fingerprint(OLD.fingerprint_sha256) IS DISTINCT FROM fingerprint
    AND OLD.status IN ('revoked', 'decommissioned') THEN
    NEW.status := CASE WHEN NEW.source = 'agent_issuance' THEN 'active' ELSE 'discovered' END;
  END IF;
  RETURN NEW;
END $$;

-- Called only by the existing authorized token-transfer transaction. Identities
-- never move: destination identities are independently deduplicated; the old
-- workspace keeps closed period history. In-flight mutations must reconcile
-- before transfer, and destination management always passes admission.
CREATE OR REPLACE FUNCTION certops_transfer_management_sources(from_workspace UUID, to_workspace UUID, source_ids UUID[])
RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE historic_period RECORD; association RECORD; new_period UUID; new_identity UUID; mc RECORD; moved INTEGER; open_source_ids UUID[];
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('certops_managed_cert_quota_' || id::text))
    FROM (SELECT from_workspace id UNION SELECT to_workspace id) workspaces ORDER BY id;
  IF EXISTS (SELECT 1 FROM certificate_jobs WHERE workspace_id = from_workspace
    AND subject_type = 'managed_certificate' AND subject_id = ANY(SELECT unnest(source_ids)::text)
    AND status IN ('claimed', 'running')) THEN
    RAISE EXCEPTION 'CertOps in-flight work must reconcile before workspace transfer' USING ERRCODE = '55000';
  END IF;
  -- Seed all historically associated fingerprints without reactivating any
  -- existing retired destination identity or mutating the original identity.
  INSERT INTO certops_certificate_identities(workspace_id,fingerprint_sha256,lifecycle_status,lifecycle_reason,retired_at,common_name,issuer,not_after)
    SELECT DISTINCT to_workspace,i.fingerprint_sha256,i.lifecycle_status,i.lifecycle_reason,i.retired_at,i.common_name,i.issuer,i.not_after
      FROM certops_certificate_identities i JOIN certops_management_associations a ON a.identity_id = i.id
      JOIN certops_management_periods p ON p.id = a.period_id
      WHERE p.workspace_id = from_workspace AND p.managed_certificate_id = ANY(source_ids)
    ON CONFLICT (workspace_id,fingerprint_sha256) DO UPDATE SET lifecycle_status = CASE
      WHEN certops_certificate_identities.lifecycle_status = 'revoked' OR EXCLUDED.lifecycle_status = 'revoked' THEN 'revoked'
      WHEN certops_certificate_identities.lifecycle_status = 'decommissioned' THEN 'decommissioned'
      ELSE EXCLUDED.lifecycle_status END;
  PERFORM set_config('certops.workspace_transfer', from_workspace::text || ':' || to_workspace::text, TRUE);
  SELECT array_agg(managed_certificate_id) INTO open_source_ids FROM certops_management_periods
    WHERE workspace_id = from_workspace AND managed_certificate_id = ANY(source_ids) AND ended_at IS NULL;
  UPDATE certops_management_periods SET ended_at = GREATEST(NOW(),started_at), ended_reason = 'workspace_transfer'
    WHERE workspace_id = from_workspace AND managed_certificate_id = ANY(source_ids) AND ended_at IS NULL;
  UPDATE managed_certificates SET workspace_id = to_workspace, profile_id = NULL, updated_at = NOW()
    WHERE workspace_id = from_workspace AND id = ANY(source_ids);
  GET DIAGNOSTICS moved = ROW_COUNT;
  FOR historic_period IN SELECT * FROM certops_management_periods WHERE workspace_id = from_workspace
    AND managed_certificate_id = ANY(source_ids) LOOP
    SELECT destination.id INTO new_identity FROM certops_certificate_identities original
      JOIN certops_certificate_identities destination ON destination.workspace_id = to_workspace
        AND destination.fingerprint_sha256 = original.fingerprint_sha256 WHERE original.id = historic_period.current_identity_id;
    INSERT INTO certops_management_periods(workspace_id,managed_certificate_id,current_identity_id,started_at,ended_at,ended_reason,automation_enabled,created_by)
      VALUES(to_workspace,historic_period.managed_certificate_id,new_identity,historic_period.started_at,historic_period.ended_at,historic_period.ended_reason,historic_period.automation_enabled,historic_period.created_by)
      RETURNING id INTO new_period;
    FOR association IN SELECT a.*,i.fingerprint_sha256 FROM certops_management_associations a
      JOIN certops_certificate_identities i ON i.id = a.identity_id WHERE a.period_id = historic_period.id LOOP
      INSERT INTO certops_management_associations(workspace_id,period_id,identity_id,associated_at,superseded_at)
        SELECT to_workspace,new_period,id,association.associated_at,association.superseded_at FROM certops_certificate_identities
          WHERE workspace_id = to_workspace AND fingerprint_sha256 = association.fingerprint_sha256;
    END LOOP;
    UPDATE certificate_jobs j SET workspace_id = to_workspace,management_period_id = new_period,
      certificate_identity_id = (SELECT destination.id FROM certops_certificate_identities original
        JOIN certops_certificate_identities destination ON destination.workspace_id = to_workspace
          AND destination.fingerprint_sha256 = original.fingerprint_sha256 WHERE original.id = j.certificate_identity_id),
      requested_by_api_token_id = NULL WHERE j.workspace_id = from_workspace AND j.management_period_id = historic_period.id;
  END LOOP;
  FOR mc IN SELECT * FROM managed_certificates WHERE workspace_id = to_workspace AND id = ANY(open_source_ids) LOOP
    INSERT INTO certops_management_periods(workspace_id,managed_certificate_id,current_identity_id,automation_enabled)
      SELECT to_workspace,mc.id,i.id,FALSE FROM (SELECT 1) singleton LEFT JOIN certops_certificate_identities i
        ON i.workspace_id = to_workspace AND i.fingerprint_sha256 = certops_normalize_fingerprint(mc.fingerprint_sha256);
  END LOOP;
  PERFORM set_config('certops.workspace_transfer','',TRUE);
  RETURN moved;
END $$;
DROP TRIGGER IF EXISTS trg_certops_prepare_managed_identity ON managed_certificates;
CREATE TRIGGER trg_certops_prepare_managed_identity BEFORE INSERT OR UPDATE ON managed_certificates
  FOR EACH ROW EXECUTE FUNCTION certops_prepare_managed_identity();

CREATE OR REPLACE FUNCTION certops_track_management_period()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE identity_uuid UUID; period_uuid UUID; previous_uuid UUID;
BEGIN
  SELECT id INTO identity_uuid FROM certops_certificate_identities WHERE workspace_id = NEW.workspace_id
    AND fingerprint_sha256 = certops_normalize_fingerprint(NEW.fingerprint_sha256);
  IF TG_OP = 'INSERT' THEN
    INSERT INTO certops_management_periods(workspace_id, managed_certificate_id, current_identity_id,
      renewal_profile_id, automation_enabled, created_by)
      VALUES (NEW.workspace_id, NEW.id, identity_uuid, NEW.profile_id, NEW.profile_id IS NOT NULL, NEW.created_by)
      RETURNING id INTO period_uuid;
  ELSE
    SELECT id, current_identity_id INTO period_uuid, previous_uuid FROM certops_management_periods
      WHERE workspace_id = NEW.workspace_id AND managed_certificate_id = NEW.id AND ended_at IS NULL FOR UPDATE;
    IF period_uuid IS NULL OR previous_uuid IS NOT DISTINCT FROM identity_uuid THEN RETURN NEW; END IF;
    UPDATE certops_management_periods SET current_identity_id = identity_uuid WHERE id = period_uuid;
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION certops_record_positive_observation()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE fingerprint TEXT;
BEGIN
  fingerprint := certops_normalize_fingerprint(NEW.observed_fingerprint_sha256);
  IF fingerprint IS NULL THEN RETURN NEW; END IF;
  NEW.observed_fingerprint_sha256 := fingerprint;
  INSERT INTO certops_certificate_identities(workspace_id, fingerprint_sha256, common_name, issuer, not_after)
    VALUES (NEW.workspace_id, fingerprint, NEW.observed_subject, NEW.observed_issuer, NEW.observed_not_after)
    ON CONFLICT (workspace_id, fingerprint_sha256) DO UPDATE SET
      common_name = COALESCE(certops_certificate_identities.common_name, EXCLUDED.common_name),
      issuer = COALESCE(certops_certificate_identities.issuer, EXCLUDED.issuer),
      not_after = COALESCE(certops_certificate_identities.not_after, EXCLUDED.not_after);
  IF TG_OP = 'UPDATE' AND OLD.captured_at IS NOT NULL
    AND (NEW.observed_at IS NULL OR NEW.observed_at <= OLD.captured_at) THEN
    NEW.observed_at := OLD.observed_at; NEW.captured_at := OLD.captured_at;
    NEW.presence_state := OLD.presence_state; NEW.evidence_kind := OLD.evidence_kind;
  ELSIF NEW.observed_at IS NOT NULL AND NEW.observed_at <= clock_timestamp() + INTERVAL '5 minutes' THEN
    NEW.captured_at := NEW.observed_at; NEW.presence_state := 'confirmed_present';
    NEW.evidence_kind := CASE WHEN NEW.source IN ('endpoint_monitor', 'domain_checker')
      OR NEW.location_kind IN ('iis_binding', 'http_sys') THEN 'service_binding'
      WHEN NEW.location_kind IS NOT NULL THEN 'stored_copy' ELSE 'unknown' END;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_certops_record_positive_observation ON certificate_instances;
CREATE TRIGGER trg_certops_record_positive_observation BEFORE INSERT OR UPDATE OF observed_at, observed_fingerprint_sha256
  ON certificate_instances FOR EACH ROW EXECUTE FUNCTION certops_record_positive_observation();

CREATE OR REPLACE FUNCTION certops_record_slot_observation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.source = 'agent_filesystem' AND NEW.observed_fingerprint_sha256 ~ '^[a-f0-9]{64}$'
    AND NEW.observed_at IS NOT NULL AND NEW.observed_at <= clock_timestamp() + INTERVAL '5 minutes' THEN
    INSERT INTO certops_slot_observations(workspace_id, target_id, fingerprint_sha256,
      location_ref, source_ref, captured_at)
      VALUES (NEW.workspace_id, NEW.target_id, NEW.observed_fingerprint_sha256,
        COALESCE(NULLIF(NEW.deployment_reference, ''), NEW.source_ref, NEW.id::text), NEW.source_ref, NEW.observed_at)
      ON CONFLICT DO NOTHING;
    UPDATE certops_slot_observations SET captured_at = NEW.observed_at
      WHERE workspace_id = NEW.workspace_id AND target_id IS NOT DISTINCT FROM NEW.target_id
        AND fingerprint_sha256 = NEW.observed_fingerprint_sha256
        AND source_ref IS NOT DISTINCT FROM NEW.source_ref AND captured_at < NEW.observed_at;
  END IF;
  RETURN NEW;
END $$;

-- Repair identities missed by v62's whitespace normalization and choose one
-- deterministic public-metadata source. Never infer lifecycle from mc.status.
INSERT INTO certops_certificate_identities(workspace_id, fingerprint_sha256)
  SELECT workspace_id, certops_normalize_fingerprint(fingerprint_sha256) FROM managed_certificates
    WHERE certops_normalize_fingerprint(fingerprint_sha256) IS NOT NULL
  UNION SELECT workspace_id, certops_normalize_fingerprint(observed_fingerprint_sha256) FROM certificate_instances
    WHERE certops_normalize_fingerprint(observed_fingerprint_sha256) IS NOT NULL
  UNION SELECT workspace_id, certops_normalize_fingerprint(metadata->>'fingerprintSha256') FROM audit_events
    WHERE workspace_id IS NOT NULL AND action = 'CERTOPS_CERTIFICATE_RETIRED'
      AND certops_normalize_fingerprint(metadata->>'fingerprintSha256') IS NOT NULL
  ON CONFLICT (workspace_id, fingerprint_sha256) DO NOTHING;
WITH chosen AS (
  SELECT DISTINCT ON (workspace_id, certops_normalize_fingerprint(fingerprint_sha256))
    workspace_id, certops_normalize_fingerprint(fingerprint_sha256) AS fingerprint, common_name, issuer, not_after
    FROM managed_certificates WHERE certops_normalize_fingerprint(fingerprint_sha256) IS NOT NULL
    ORDER BY workspace_id, certops_normalize_fingerprint(fingerprint_sha256), updated_at DESC, created_at DESC, id DESC
)
UPDATE certops_certificate_identities i SET common_name = c.common_name, issuer = c.issuer, not_after = c.not_after
  FROM chosen c WHERE i.workspace_id = c.workspace_id AND i.fingerprint_sha256 = c.fingerprint
    AND EXISTS (SELECT 1 FROM managed_certificates mc WHERE mc.workspace_id = i.workspace_id
      AND certops_normalize_fingerprint(mc.fingerprint_sha256) = i.fingerprint_sha256 AND mc.identity_observed_at IS NULL);
WITH verified AS (
  SELECT DISTINCT ON (workspace_id, certops_normalize_fingerprint(metadata->>'fingerprintSha256'))
    workspace_id, certops_normalize_fingerprint(metadata->>'fingerprintSha256') fingerprint,
    metadata->>'status' status, metadata->>'reason' reason, occurred_at
    FROM audit_events WHERE workspace_id IS NOT NULL AND action = 'CERTOPS_CERTIFICATE_RETIRED'
      AND certops_normalize_fingerprint(metadata->>'fingerprintSha256') IS NOT NULL
      AND metadata->>'status' IN ('revoked', 'decommissioned')
    ORDER BY workspace_id, certops_normalize_fingerprint(metadata->>'fingerprintSha256'),
      (metadata->>'status' = 'revoked') DESC, occurred_at DESC, id DESC
)
UPDATE certops_certificate_identities i SET lifecycle_status = v.status, lifecycle_reason = v.reason, retired_at = v.occurred_at
  FROM verified v WHERE i.workspace_id = v.workspace_id AND i.fingerprint_sha256 = v.fingerprint
    AND (i.lifecycle_status = 'active' OR (i.lifecycle_status = 'decommissioned' AND v.status = 'revoked'));

INSERT INTO certops_identity_backfill_issues(managed_certificate_id, workspace_id, issue)
  SELECT mc.id, mc.workspace_id, 'historical_rotation_or_retirement_attribution_unknown'
    FROM managed_certificates mc WHERE mc.identity_observed_at IS NULL AND (
      (mc.status IN ('revoked', 'decommissioned') AND NOT EXISTS (SELECT 1 FROM audit_events ae
        WHERE ae.workspace_id = mc.workspace_id AND ae.action = 'CERTOPS_CERTIFICATE_RETIRED'
          AND ae.metadata->>'managedCertificateId' = mc.id::text
          AND ae.metadata->>'status' IN ('revoked', 'decommissioned')
          AND certops_normalize_fingerprint(ae.metadata->>'fingerprintSha256') IS NOT NULL))
      OR EXISTS (SELECT 1 FROM certificate_instances ci WHERE ci.workspace_id = mc.workspace_id
        AND ci.managed_certificate_id = mc.id AND certops_normalize_fingerprint(ci.observed_fingerprint_sha256)
          IS DISTINCT FROM certops_normalize_fingerprint(mc.fingerprint_sha256)))
  ON CONFLICT (managed_certificate_id) DO NOTHING;

-- v62 pinned historic jobs to a mutable source's current fingerprint. Clear
-- those guesses if rotation evidence exists. NULL means explicitly unknown,
-- and the source issue above remains accessible to operators.
ALTER TABLE certificate_jobs DISABLE TRIGGER trg_certops_a_tag_management_job;
UPDATE certificate_jobs j SET certificate_identity_id = NULL FROM managed_certificates mc
  WHERE mc.identity_observed_at IS NULL AND j.workspace_id = mc.workspace_id
    AND j.subject_type = 'managed_certificate' AND j.subject_id = mc.id::text
    AND EXISTS (SELECT 1 FROM certificate_instances ci WHERE ci.workspace_id = mc.workspace_id
      AND ci.managed_certificate_id = mc.id AND certops_normalize_fingerprint(ci.observed_fingerprint_sha256)
        IS DISTINCT FROM certops_normalize_fingerprint(mc.fingerprint_sha256));

ALTER TABLE certificate_jobs ENABLE TRIGGER trg_certops_a_tag_management_job;

UPDATE certops_management_periods p SET current_identity_id = i.id
  FROM managed_certificates mc JOIN certops_certificate_identities i
    ON i.workspace_id = mc.workspace_id AND i.fingerprint_sha256 = certops_normalize_fingerprint(mc.fingerprint_sha256)
  WHERE mc.identity_observed_at IS NULL AND p.workspace_id = mc.workspace_id
    AND p.managed_certificate_id = mc.id AND p.current_identity_id IS NULL AND p.ended_at IS NULL;
INSERT INTO certops_management_associations(workspace_id, period_id, identity_id, associated_at, superseded_at)
  SELECT p.workspace_id, p.id, i.id, p.started_at, p.ended_at
    FROM certops_management_periods p JOIN managed_certificates mc ON mc.id = p.managed_certificate_id
    JOIN certops_certificate_identities i ON i.workspace_id = p.workspace_id
      AND i.fingerprint_sha256 = certops_normalize_fingerprint(mc.fingerprint_sha256)
    WHERE mc.identity_observed_at IS NULL AND NOT EXISTS (
      SELECT 1 FROM certops_management_associations a WHERE a.period_id = p.id);

UPDATE certops_management_periods p SET ended_at = GREATEST(NOW(), p.started_at), ended_reason = 'endpoint_monitor_deleted'
  FROM managed_certificates mc WHERE p.ended_at IS NULL AND p.managed_certificate_id = mc.id
    AND mc.source = 'domain_checker' AND mc.public_metadata->>'domainMonitorId' IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM domain_monitors dm WHERE dm.workspace_id = mc.workspace_id
      AND dm.id::text = mc.public_metadata->>'domainMonitorId');

-- A source's latest known observation is its watermark, not migration time.
-- Disable the prepare trigger solely for historical normalization collisions:
-- multiple raw source rows can legitimately normalize to the same identity.
ALTER TABLE managed_certificates DISABLE TRIGGER trg_certops_prepare_managed_identity;
UPDATE managed_certificates mc SET identity_observed_at = COALESCE((
  SELECT MAX(ci.observed_at) FROM certificate_instances ci WHERE ci.workspace_id = mc.workspace_id
    AND ci.managed_certificate_id = mc.id AND ci.observed_at <= NOW() + INTERVAL '5 minutes'
), mc.updated_at)
  WHERE mc.identity_observed_at IS NULL;
ALTER TABLE managed_certificates ENABLE TRIGGER trg_certops_prepare_managed_identity;

CREATE OR REPLACE FUNCTION certops_sync_token_identity_lifecycle()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE token INTEGER; workspace UUID; next_status TEXT;
BEGIN
  token := NEW.token_id; workspace := NEW.workspace_id;
  IF token IS NULL THEN RETURN NEW; END IF;
  SELECT CASE
    WHEN bool_or(i.lifecycle_status = 'active' OR (i.id IS NULL AND mc.status NOT IN ('revoked', 'decommissioned'))) THEN 'active'
    WHEN bool_or(i.lifecycle_status = 'revoked') THEN 'revoked'
    WHEN bool_or(i.lifecycle_status = 'decommissioned') THEN 'decommissioned' ELSE NULL END
    INTO next_status FROM managed_certificates mc LEFT JOIN certops_certificate_identities i
      ON i.workspace_id = mc.workspace_id AND i.fingerprint_sha256 = certops_normalize_fingerprint(mc.fingerprint_sha256)
    WHERE mc.workspace_id = workspace AND mc.token_id = token;
  UPDATE tokens SET cert_lifecycle_status = next_status, updated_at = NOW()
    WHERE id = token AND workspace_id = workspace AND cert_lifecycle_status IS DISTINCT FROM next_status;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trg_certops_sync_token_identity_lifecycle ON managed_certificates;
CREATE TRIGGER trg_certops_sync_token_identity_lifecycle AFTER INSERT OR UPDATE ON managed_certificates
  FOR EACH ROW EXECUTE FUNCTION certops_sync_token_identity_lifecycle();

-- Endpoint and Windows binding rotation prove the older fingerprint absent at
-- this service slot. A delayed observation cannot contradict newer evidence.
CREATE OR REPLACE FUNCTION certops_replace_service_binding()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.presence_state = 'confirmed_present' AND NEW.evidence_kind = 'service_binding' THEN
    UPDATE certificate_instances previous SET presence_state = 'confirmed_absent', captured_at = NEW.captured_at
      WHERE previous.workspace_id = NEW.workspace_id AND previous.target_id IS NOT DISTINCT FROM NEW.target_id
        AND previous.source = NEW.source AND previous.source_ref IS NOT DISTINCT FROM NEW.source_ref
        AND previous.id <> NEW.id
        AND previous.observed_fingerprint_sha256 IS DISTINCT FROM NEW.observed_fingerprint_sha256
        AND (previous.captured_at IS NULL OR previous.captured_at <= NEW.captured_at);
    IF EXISTS (SELECT 1 FROM certificate_instances newer WHERE newer.workspace_id = NEW.workspace_id
      AND newer.target_id IS NOT DISTINCT FROM NEW.target_id AND newer.source = NEW.source
      AND newer.source_ref IS NOT DISTINCT FROM NEW.source_ref AND newer.id <> NEW.id
      AND newer.observed_fingerprint_sha256 IS DISTINCT FROM NEW.observed_fingerprint_sha256
      AND newer.captured_at > NEW.captured_at AND newer.presence_state = 'confirmed_present') THEN
      UPDATE certificate_instances SET presence_state = 'confirmed_absent' WHERE id = NEW.id;
    END IF;
  END IF;
  RETURN NEW;
END $$;
