-- Additive public metadata. Existing installations remain manual/report-only.
ALTER TABLE workspaces ADD COLUMN certops_distribution_authorization_revision BIGINT NOT NULL DEFAULT 1;
CREATE FUNCTION certops_distribution_workspace_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.certops_require_approval_always,NEW.certops_paused) IS DISTINCT FROM
     (OLD.certops_require_approval_always,OLD.certops_paused) THEN
    NEW.certops_distribution_authorization_revision := OLD.certops_distribution_authorization_revision + 1;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_certops_distribution_workspace_revision BEFORE UPDATE ON workspaces
  FOR EACH ROW EXECUTE FUNCTION certops_distribution_workspace_revision();

CREATE TABLE certops_distribution_policies (
  workspace_id UUID NOT NULL,
  group_id UUID NOT NULL,
  revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
  policy JSONB NOT NULL CHECK(jsonb_typeof(policy)='object'),
  scope_hash TEXT NOT NULL CHECK(scope_hash ~ '^[a-f0-9]{64}$'),
  approval_job_id UUID NULL,
  configured_by_user_id INTEGER NOT NULL REFERENCES users(id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(workspace_id,group_id),
  FOREIGN KEY(workspace_id,group_id) REFERENCES certops_distribution_groups(workspace_id,id),
  FOREIGN KEY(workspace_id,approval_job_id) REFERENCES certificate_jobs(workspace_id,id)
);
CREATE TABLE certops_consumer_lifecycle (
  workspace_id UUID NOT NULL,
  group_id UUID NOT NULL,
  binding_id UUID NOT NULL,
  policy JSONB NOT NULL CHECK(jsonb_typeof(policy)='object'),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(workspace_id,binding_id),
  FOREIGN KEY(workspace_id,group_id,binding_id) REFERENCES certops_consumer_bindings(workspace_id,group_id,id)
);
ALTER TABLE certops_consumer_deployments ADD COLUMN activation_policy JSONB;

CREATE TABLE certops_distribution_automations (
  workspace_id UUID NOT NULL,
  group_id UUID NOT NULL,
  material_version_id UUID NOT NULL,
  policy_revision INTEGER NOT NULL,
  outcome TEXT NOT NULL CHECK(outcome IN ('manual','approval_requested','authorized','authorization_stale','policy_changed','no_consumers')),
  job_id UUID NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(workspace_id,group_id,material_version_id),
  FOREIGN KEY(workspace_id,group_id,material_version_id) REFERENCES certops_material_versions(workspace_id,group_id,id),
  FOREIGN KEY(workspace_id,job_id) REFERENCES certificate_jobs(workspace_id,id)
);
CREATE TABLE certops_distribution_schedules (
  workspace_id UUID NOT NULL,
  group_id UUID NOT NULL,
  sequence BIGINT NOT NULL DEFAULT 0,
  failures INTEGER NOT NULL DEFAULT 0,
  next_run_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  last_job_id UUID NULL,
  last_outcome TEXT NULL,
  PRIMARY KEY(workspace_id,group_id),
  FOREIGN KEY(workspace_id,group_id) REFERENCES certops_distribution_groups(workspace_id,id),
  FOREIGN KEY(workspace_id,last_job_id) REFERENCES certificate_jobs(workspace_id,id)
);
CREATE INDEX idx_certops_distribution_schedule_due ON certops_distribution_schedules(next_run_at,workspace_id);

CREATE TABLE certops_distribution_incidents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL,
  group_id UUID NOT NULL,
  binding_id UUID NULL,
  code TEXT NOT NULL CHECK(code ~ '^[a-z_]{1,64}$'),
  dedupe_key TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('warning','critical')),
  evidence JSONB NOT NULL DEFAULT '{}',
  revision INTEGER NOT NULL DEFAULT 1,
  opened_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  last_notified_at TIMESTAMPTZ NULL,
  resolved_at TIMESTAMPTZ NULL,
  FOREIGN KEY(workspace_id,group_id) REFERENCES certops_distribution_groups(workspace_id,id),
  FOREIGN KEY(workspace_id,group_id,binding_id) REFERENCES certops_consumer_bindings(workspace_id,group_id,id)
);
CREATE UNIQUE INDEX uq_certops_distribution_incident_open ON certops_distribution_incidents(workspace_id,dedupe_key) WHERE resolved_at IS NULL;
CREATE INDEX idx_certops_distribution_incident_group ON certops_distribution_incidents(workspace_id,group_id,updated_at DESC);
