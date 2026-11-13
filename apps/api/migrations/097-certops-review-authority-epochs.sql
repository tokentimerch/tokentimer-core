-- Membership removal/re-addition must not revive an earlier review. Append to
-- the existing authorization epoch; preserve all original migration SQL/rows.
CREATE OR REPLACE FUNCTION certops_distribution_workspace_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.certops_require_approval_always,NEW.certops_paused,NEW.created_by) IS DISTINCT FROM
     (OLD.certops_require_approval_always,OLD.certops_paused,OLD.created_by) THEN
    NEW.certops_distribution_authorization_revision := OLD.certops_distribution_authorization_revision + 1;
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION certops_distribution_reviewer_revision() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE affected UUID[];
BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.role NOT IN ('admin','workspace_manager') THEN RETURN NEW; END IF;
    affected:=ARRAY[NEW.workspace_id];
  ELSIF TG_OP='DELETE' THEN
    IF OLD.role NOT IN ('admin','workspace_manager') THEN RETURN OLD; END IF;
    affected:=ARRAY[OLD.workspace_id];
  ELSE
    IF (NEW.workspace_id,NEW.user_id,NEW.role) IS NOT DISTINCT FROM (OLD.workspace_id,OLD.user_id,OLD.role) OR
       (NEW.role NOT IN ('admin','workspace_manager') AND OLD.role NOT IN ('admin','workspace_manager')) THEN RETURN NEW; END IF;
    affected:=ARRAY[OLD.workspace_id,NEW.workspace_id];
  END IF;
  -- Stable order also covers an explicit membership move between workspaces.
  PERFORM id FROM workspaces WHERE id=ANY(affected) ORDER BY id FOR UPDATE;
  UPDATE workspaces SET certops_distribution_authorization_revision=certops_distribution_authorization_revision+1
    WHERE id=ANY(affected);
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_certops_distribution_reviewer_revision AFTER INSERT OR UPDATE OR DELETE ON workspace_memberships
  FOR EACH ROW EXECUTE FUNCTION certops_distribution_reviewer_revision();

-- Existing grants predate durable membership epochs and require fresh review.
-- Stored intents, approvals, material versions and permanent fences are intact.
UPDATE workspaces SET certops_distribution_authorization_revision=certops_distribution_authorization_revision+1;
