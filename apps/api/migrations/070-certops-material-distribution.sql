-- Public metadata only. No key-bearing bundle, credential or Vault response.
ALTER TABLE certificate_jobs DROP CONSTRAINT certificate_jobs_operation_check;
ALTER TABLE certificate_jobs ADD CONSTRAINT certificate_jobs_operation_check CHECK (operation IN
  ('issue','renew','deploy','deploy-from-store','reload','revoke','noop','protocol_smoke','distribute-trust','revoke-trust','continue-enrollment'));
ALTER TABLE certops_management_periods ADD CONSTRAINT uq_certops_period_scope
  UNIQUE (workspace_id, managed_certificate_id, id);
ALTER TABLE certops_agents ADD CONSTRAINT uq_certops_agent_scope UNIQUE (workspace_id, id);
ALTER TABLE certificate_jobs ADD CONSTRAINT uq_certops_job_scope UNIQUE (workspace_id, id);
ALTER TABLE certops_outbox DROP CONSTRAINT certops_outbox_event_type_check;
ALTER TABLE certops_outbox ADD CONSTRAINT certops_outbox_event_type_check CHECK(event_type IN
  ('renewal_alert_requested','profile_derivation_requested','material_published','distribution_approval_granted','distribution_rollout_requested'));

CREATE TABLE certops_distribution_groups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  managed_certificate_id UUID NOT NULL,
  management_period_id UUID NOT NULL,
  issuer_agent_id UUID NOT NULL,
  material_store_ref TEXT NOT NULL CHECK (material_store_ref ~ '^[A-Za-z0-9_-]{1,64}$'),
  issuance_profile_ref TEXT NOT NULL CHECK (issuance_profile_ref ~ '^[A-Za-z0-9_-]{1,64}$'),
  profile_revision INTEGER NOT NULL CHECK (profile_revision > 0),
  state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active','disabled','retired')),
  generation BIGINT NOT NULL DEFAULT 0 CHECK (generation BETWEEN 0 AND 9007199254740991),
  latest_material_version_id UUID NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, id, management_period_id),
  UNIQUE (workspace_id, managed_certificate_id, management_period_id),
  FOREIGN KEY (workspace_id, managed_certificate_id, management_period_id)
    REFERENCES certops_management_periods(workspace_id, managed_certificate_id, id),
  FOREIGN KEY (workspace_id, issuer_agent_id) REFERENCES certops_agents(workspace_id, id)
);

CREATE TABLE certops_material_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL,
  group_id UUID NOT NULL,
  management_period_id UUID NOT NULL,
  publishing_job_id UUID NOT NULL,
  publishing_claim_id TEXT NULL,
  profile_revision INTEGER NOT NULL CHECK (profile_revision > 0),
  state TEXT NOT NULL DEFAULT 'allocated'
    CHECK (state IN ('allocated','staged','published','orphaned_unknown_effect','failed')),
  certificate_identity_id UUID NULL,
  provider_version INTEGER NULL CHECK (provider_version > 0),
  fingerprint_sha256 TEXT NULL CHECK (fingerprint_sha256 ~ '^[a-f0-9]{64}$'),
  valid_to TIMESTAMPTZ NULL,
  published_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (workspace_id, group_id, id),
  UNIQUE (workspace_id, publishing_job_id),
  FOREIGN KEY (workspace_id, group_id) REFERENCES certops_distribution_groups(workspace_id, id),
  FOREIGN KEY (workspace_id, group_id, management_period_id) REFERENCES certops_distribution_groups(workspace_id, id, management_period_id),
  FOREIGN KEY (workspace_id, publishing_job_id) REFERENCES certificate_jobs(workspace_id, id),
  FOREIGN KEY (workspace_id, certificate_identity_id) REFERENCES certops_certificate_identities(workspace_id, id),
  CHECK (state <> 'published' OR (certificate_identity_id IS NOT NULL AND
    provider_version IS NOT NULL AND fingerprint_sha256 IS NOT NULL AND
    valid_to IS NOT NULL AND publishing_claim_id IS NOT NULL AND published_at IS NOT NULL))
);
ALTER TABLE certops_distribution_groups ADD CONSTRAINT fk_certops_group_latest_version
  FOREIGN KEY (workspace_id, id, latest_material_version_id)
  REFERENCES certops_material_versions(workspace_id, group_id, id);

CREATE TABLE certops_consumer_bindings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL,
  group_id UUID NOT NULL,
  assigned_agent_id UUID NOT NULL,
  deployment_profile_ref TEXT NOT NULL CHECK (deployment_profile_ref ~ '^[A-Za-z0-9_-]{1,64}$'),
  profile_revision INTEGER NOT NULL CHECK (profile_revision > 0),
  authorization_revision INTEGER NOT NULL DEFAULT 1 CHECK (authorization_revision > 0),
  required BOOLEAN NOT NULL DEFAULT TRUE,
  wave INTEGER NOT NULL DEFAULT 0 CHECK (wave BETWEEN 0 AND 1000),
  verification_policy TEXT NOT NULL CHECK (verification_policy IN ('served','trust')),
  freshness_seconds INTEGER NOT NULL DEFAULT 3600 CHECK (freshness_seconds BETWEEN 60 AND 604800),
  state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active','removed')),
  UNIQUE (workspace_id, group_id, id),
  UNIQUE (workspace_id, assigned_agent_id, deployment_profile_ref),
  FOREIGN KEY (workspace_id, group_id) REFERENCES certops_distribution_groups(workspace_id, id),
  FOREIGN KEY (workspace_id, assigned_agent_id) REFERENCES certops_agents(workspace_id, id)
);

CREATE TABLE certops_distribution_rollouts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL,
  group_id UUID NOT NULL,
  material_version_id UUID NOT NULL,
  generation BIGINT NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  approved_intent_hash TEXT NOT NULL CHECK (approved_intent_hash ~ '^[a-f0-9]{64}$'),
  approval_job_id UUID NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','deploying','verified','degraded','paused','retired')),
  verification_only BOOLEAN NOT NULL DEFAULT false,
  max_parallel INTEGER NOT NULL DEFAULT 1 CHECK (max_parallel BETWEEN 1 AND 16),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (workspace_id, group_id, id),
  UNIQUE (workspace_id, group_id, generation),
  UNIQUE (workspace_id, approval_job_id),
  FOREIGN KEY (workspace_id, group_id, material_version_id)
    REFERENCES certops_material_versions(workspace_id, group_id, id),
  FOREIGN KEY (workspace_id, approval_job_id) REFERENCES certificate_jobs(workspace_id, id)
);

CREATE TABLE certops_consumer_deployments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL,
  group_id UUID NOT NULL,
  rollout_id UUID NOT NULL,
  binding_id UUID NOT NULL,
  assigned_agent_id UUID NOT NULL,
  deployment_profile_ref TEXT NOT NULL CHECK (deployment_profile_ref ~ '^[A-Za-z0-9_-]{1,64}$'),
  profile_revision INTEGER NOT NULL CHECK (profile_revision > 0),
  authorization_revision INTEGER NOT NULL CHECK (authorization_revision > 0),
  required BOOLEAN NOT NULL,
  wave INTEGER NOT NULL CHECK (wave BETWEEN 0 AND 1000),
  verification_policy TEXT NOT NULL CHECK (verification_policy IN ('served','trust')),
  freshness_seconds INTEGER NOT NULL CHECK (freshness_seconds BETWEEN 60 AND 604800),
  job_id UUID NULL,
  stage TEXT NOT NULL DEFAULT 'pending'
    CHECK (stage IN ('pending','fetched','installed','bound','served_verified','trust_validated','failed','orphaned_unknown_effect')),
  observed_fingerprint_sha256 TEXT NULL CHECK (observed_fingerprint_sha256 ~ '^[a-f0-9]{64}$'),
  observed_valid_to TIMESTAMPTZ NULL,
  observed_at TIMESTAMPTZ NULL,
  failure_code TEXT NULL CHECK (failure_code ~ '^[a-z0-9_]{1,64}$'),
  UNIQUE (workspace_id, rollout_id, binding_id),
  FOREIGN KEY (workspace_id, group_id, rollout_id) REFERENCES certops_distribution_rollouts(workspace_id, group_id, id),
  FOREIGN KEY (workspace_id, group_id, binding_id) REFERENCES certops_consumer_bindings(workspace_id, group_id, id),
  FOREIGN KEY (workspace_id, assigned_agent_id) REFERENCES certops_agents(workspace_id, id),
  FOREIGN KEY (workspace_id, job_id) REFERENCES certificate_jobs(workspace_id, id)
);

CREATE TABLE certops_consumer_current_state (
  workspace_id UUID NOT NULL,
  group_id UUID NOT NULL,
  binding_id UUID NOT NULL,
  desired_material_version_id UUID NOT NULL,
  desired_generation BIGINT NOT NULL CHECK (desired_generation BETWEEN 1 AND 9007199254740991),
  accepted_generation BIGINT NOT NULL DEFAULT 0 CHECK (accepted_generation BETWEEN 0 AND desired_generation),
  observed_material_version_id UUID NULL,
  observed_fingerprint_sha256 TEXT NULL CHECK (observed_fingerprint_sha256 ~ '^[a-f0-9]{64}$'),
  observed_valid_to TIMESTAMPTZ NULL,
  verification_method TEXT NULL CHECK (verification_method IN ('served','trust')),
  observed_at TIMESTAMPTZ NULL,
  PRIMARY KEY (workspace_id, binding_id),
  FOREIGN KEY (workspace_id, group_id, binding_id) REFERENCES certops_consumer_bindings(workspace_id, group_id, id),
  FOREIGN KEY (workspace_id, group_id, desired_material_version_id) REFERENCES certops_material_versions(workspace_id, group_id, id),
  FOREIGN KEY (workspace_id, group_id, observed_material_version_id) REFERENCES certops_material_versions(workspace_id, group_id, id)
);

CREATE FUNCTION certops_material_version_immutable() RETURNS trigger AS $$
BEGIN
  IF OLD.state = 'published' AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'Published material versions are immutable';
  END IF;
  IF (NEW.workspace_id, NEW.group_id, NEW.id, NEW.management_period_id,
      NEW.publishing_job_id, NEW.profile_revision) IS DISTINCT FROM
     (OLD.workspace_id, OLD.group_id, OLD.id, OLD.management_period_id,
      OLD.publishing_job_id, OLD.profile_revision) THEN
    RAISE EXCEPTION 'Material publication intent is immutable';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_certops_material_version_immutable BEFORE UPDATE ON certops_material_versions
  FOR EACH ROW EXECUTE FUNCTION certops_material_version_immutable();

CREATE FUNCTION certops_rollout_snapshot_immutable() RETURNS trigger AS $$
BEGIN
  IF (to_jsonb(NEW) - ARRAY['stage','observed_fingerprint_sha256','observed_valid_to','observed_at','failure_code','job_id'])
     IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['stage','observed_fingerprint_sha256','observed_valid_to','observed_at','failure_code','job_id']) THEN
    RAISE EXCEPTION 'Consumer rollout snapshot is immutable';
  END IF;
  IF OLD.job_id IS NOT NULL AND NEW.job_id IS DISTINCT FROM OLD.job_id THEN
    RAISE EXCEPTION 'Consumer child job is immutable';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_certops_rollout_snapshot_immutable BEFORE UPDATE ON certops_consumer_deployments
  FOR EACH ROW EXECUTE FUNCTION certops_rollout_snapshot_immutable();

CREATE INDEX idx_certops_consumer_wave ON certops_consumer_deployments(workspace_id, rollout_id, wave, stage);

CREATE FUNCTION certops_rollout_intent_immutable() RETURNS trigger AS $$
BEGIN
  IF (to_jsonb(NEW) - 'state') IS DISTINCT FROM (to_jsonb(OLD) - 'state') THEN
    RAISE EXCEPTION 'Rollout intent is immutable';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_certops_rollout_intent_immutable BEFORE UPDATE ON certops_distribution_rollouts
  FOR EACH ROW EXECUTE FUNCTION certops_rollout_intent_immutable();

CREATE FUNCTION certops_group_authority_immutable() RETURNS trigger AS $$
BEGIN
  IF (to_jsonb(NEW) - ARRAY['state','generation','latest_material_version_id']) IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['state','generation','latest_material_version_id']) THEN
    RAISE EXCEPTION 'Distribution source authority is immutable';
  END IF;
  IF NEW.generation < OLD.generation THEN RAISE EXCEPTION 'Generation cannot decrease'; END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_certops_group_authority_immutable BEFORE UPDATE ON certops_distribution_groups
  FOR EACH ROW EXECUTE FUNCTION certops_group_authority_immutable();
