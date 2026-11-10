-- Preserve closed provenance while permitting creator foreign-key nullification.
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
      -- A deleted creator is detached by the users foreign key. Preserve all
      -- period facts and reject direct edits, even to created_by alone.
      IF NOT (pg_trigger_depth() > 1
        AND OLD.created_by IS NOT NULL AND NEW.created_by IS NULL
        AND NOT EXISTS (SELECT 1 FROM users WHERE id = OLD.created_by)
        AND (to_jsonb(NEW) - 'created_by') = (to_jsonb(OLD) - 'created_by')) THEN
        RAISE EXCEPTION 'CertOps closed management period is immutable' USING ERRCODE = '23514';
      END IF;
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
