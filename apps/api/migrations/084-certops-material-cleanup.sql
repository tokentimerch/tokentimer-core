-- Exact-object customer-side cleanup. Public lifecycle rows are never deleted.
ALTER TABLE certificate_jobs DROP CONSTRAINT certificate_jobs_operation_check;
ALTER TABLE certificate_jobs ADD CONSTRAINT certificate_jobs_operation_check CHECK(operation IN
 ('issue','renew','deploy','deploy-from-store','cleanup-from-store','reload','revoke','noop','protocol_smoke','distribute-trust','revoke-trust','continue-enrollment','adcs-preflight'));
CREATE TABLE certops_material_cleanups (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id UUID NOT NULL, group_id UUID NOT NULL,
 material_version_id UUID NOT NULL, job_id UUID NULL, policy_revision INTEGER NOT NULL,
 scope_hash TEXT NOT NULL CHECK(scope_hash ~ '^[a-f0-9]{64}$'),
 state TEXT NOT NULL DEFAULT 'planned' CHECK(state IN ('planned','fenced','soft_deleted')),
 created_by_user_id INTEGER NOT NULL REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 fenced_at TIMESTAMPTZ NULL, completed_at TIMESTAMPTZ NULL, receipt JSONB NULL,
 UNIQUE(workspace_id,id), UNIQUE(workspace_id,group_id,material_version_id),
 FOREIGN KEY(workspace_id,group_id,material_version_id) REFERENCES certops_material_versions(workspace_id,group_id,id),
 FOREIGN KEY(workspace_id,job_id) REFERENCES certificate_jobs(workspace_id,id)
);
-- A lease timeout, failed receipt or cancelled job cannot release a deletion
-- fence. Only explicit whole-workspace deletion removes this public history.
CREATE FUNCTION certops_material_cleanup_fence_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.state IN ('fenced','soft_deleted') AND
   (NEW.state='planned' OR NEW.workspace_id<>OLD.workspace_id OR NEW.group_id<>OLD.group_id OR
    NEW.material_version_id<>OLD.material_version_id OR
    OLD.state='soft_deleted' AND (NEW.job_id IS DISTINCT FROM OLD.job_id OR NEW.scope_hash<>OLD.scope_hash OR NEW.policy_revision<>OLD.policy_revision) OR
    OLD.state='soft_deleted' AND NEW.state<>'soft_deleted') THEN
   RAISE EXCEPTION 'material cleanup fence is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER trg_certops_material_cleanup_fence_immutable BEFORE UPDATE ON certops_material_cleanups
 FOR EACH ROW EXECUTE FUNCTION certops_material_cleanup_fence_immutable();

CREATE FUNCTION certops_material_cleanup_reference_fence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE versions UUID[]; intent JSONB; group_ref UUID;
BEGIN
 IF TG_TABLE_NAME='certificate_jobs' THEN
   IF NEW.status NOT IN ('pending_approval','approved','pending','claimed','running') THEN RETURN NEW; END IF;
   intent:=COALESCE(NEW.payload->'materialDeployment',NEW.payload->'distributionRollout',NEW.payload->'publication');
   IF intent IS NULL THEN RETURN NEW; END IF;
   versions:=ARRAY[(intent->>'materialVersionId')::uuid]; group_ref:=(intent->>'groupId')::uuid;
 ELSIF TG_TABLE_NAME='certops_distribution_rollouts' THEN
   versions:=ARRAY[NEW.material_version_id];group_ref:=NEW.group_id;
 ELSE
   versions:=ARRAY[NEW.desired_material_version_id,NEW.observed_material_version_id];group_ref:=NEW.group_id;
 END IF;
 PERFORM id FROM certops_distribution_groups WHERE workspace_id=NEW.workspace_id AND id=group_ref FOR UPDATE;
 IF EXISTS(SELECT 1 FROM certops_material_cleanups c WHERE c.workspace_id=NEW.workspace_id AND c.group_id=group_ref
    AND c.material_version_id=ANY(versions) AND c.state IN ('fenced','soft_deleted')) THEN
   RAISE EXCEPTION 'material version is fenced for cleanup' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER trg_certops_cleanup_job_reference BEFORE INSERT OR UPDATE OF payload,status ON certificate_jobs
 FOR EACH ROW EXECUTE FUNCTION certops_material_cleanup_reference_fence();
CREATE TRIGGER trg_certops_cleanup_rollout_reference BEFORE INSERT OR UPDATE OF material_version_id ON certops_distribution_rollouts
 FOR EACH ROW EXECUTE FUNCTION certops_material_cleanup_reference_fence();
CREATE TRIGGER trg_certops_cleanup_consumer_reference BEFORE INSERT OR UPDATE OF desired_material_version_id,observed_material_version_id ON certops_consumer_current_state
 FOR EACH ROW EXECUTE FUNCTION certops_material_cleanup_reference_fence();
