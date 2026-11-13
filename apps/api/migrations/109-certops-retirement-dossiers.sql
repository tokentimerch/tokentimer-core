-- Human-reviewed references do not prove physical fencing or clear an obligation.
CREATE TABLE IF NOT EXISTS certops_material_retirement_dossiers (
  id UUID PRIMARY KEY, workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE, original_job_id UUID NOT NULL,
  scope JSONB NOT NULL, evidence JSONB NOT NULL, dossier_hash TEXT NOT NULL,
  requested_by BIGINT NOT NULL, reviewed_by BIGINT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending_review','reviewed_history_unknown')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), reviewed_at TIMESTAMPTZ NULL,
  CHECK ((status='pending_review' AND reviewed_by IS NULL AND reviewed_at IS NULL) OR
         (status='reviewed_history_unknown' AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL AND reviewed_by<>requested_by))
);
CREATE OR REPLACE FUNCTION certops_retirement_dossier_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    IF EXISTS (SELECT 1 FROM workspaces WHERE id=OLD.workspace_id) THEN
      RAISE EXCEPTION 'retirement dossier cannot be deleted independently' USING ERRCODE='55000';
    END IF;
    RETURN OLD;
  END IF;
  IF OLD.status<>'pending_review' OR NEW.status<>'reviewed_history_unknown'
     OR (NEW.id,NEW.workspace_id,NEW.original_job_id,NEW.scope,NEW.evidence,NEW.dossier_hash,NEW.requested_by,NEW.created_at)
        IS DISTINCT FROM
        (OLD.id,OLD.workspace_id,OLD.original_job_id,OLD.scope,OLD.evidence,OLD.dossier_hash,OLD.requested_by,OLD.created_at)
  THEN RAISE EXCEPTION 'retirement dossier is immutable' USING ERRCODE='55000'; END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS certops_retirement_dossier_immutable ON certops_material_retirement_dossiers;
CREATE TRIGGER certops_retirement_dossier_immutable BEFORE UPDATE OR DELETE ON certops_material_retirement_dossiers
  FOR EACH ROW EXECUTE FUNCTION certops_retirement_dossier_immutable();
