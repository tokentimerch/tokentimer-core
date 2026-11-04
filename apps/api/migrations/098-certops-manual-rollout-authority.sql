-- Any change to human authority or workspace execution policy invalidates
-- previously frozen rollout intents, even if the old setting is restored.
ALTER TABLE workspaces ADD COLUMN certops_manual_rollout_revision BIGINT NOT NULL DEFAULT 1;

CREATE FUNCTION certops_manual_rollout_workspace_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.created_by, NEW.certops_paused, NEW.certops_require_approval_always) IS DISTINCT FROM
     (OLD.created_by, OLD.certops_paused, OLD.certops_require_approval_always) THEN
    NEW.certops_manual_rollout_revision := OLD.certops_manual_rollout_revision + 1;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_certops_manual_rollout_workspace_revision BEFORE UPDATE ON workspaces
  FOR EACH ROW EXECUTE FUNCTION certops_manual_rollout_workspace_revision();

CREATE FUNCTION certops_manual_rollout_membership_revision() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE affected UUID[];
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.role NOT IN ('admin', 'workspace_manager') THEN RETURN NEW; END IF;
    affected := ARRAY[NEW.workspace_id];
  ELSIF TG_OP = 'DELETE' THEN
    IF OLD.role NOT IN ('admin', 'workspace_manager') THEN RETURN OLD; END IF;
    affected := ARRAY[OLD.workspace_id];
  ELSE
    IF (NEW.workspace_id, NEW.user_id, NEW.role) IS NOT DISTINCT FROM
       (OLD.workspace_id, OLD.user_id, OLD.role) OR
       (NEW.role NOT IN ('admin', 'workspace_manager') AND OLD.role NOT IN ('admin', 'workspace_manager')) THEN
      RETURN NEW;
    END IF;
    affected := ARRAY[OLD.workspace_id, NEW.workspace_id];
  END IF;
  PERFORM id FROM workspaces WHERE id = ANY(affected) ORDER BY id FOR UPDATE;
  UPDATE workspaces SET certops_manual_rollout_revision = certops_manual_rollout_revision + 1
    WHERE id = ANY(affected);
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_certops_manual_rollout_membership_revision AFTER INSERT OR UPDATE OR DELETE ON workspace_memberships
  FOR EACH ROW EXECUTE FUNCTION certops_manual_rollout_membership_revision();
