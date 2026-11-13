-- Additive preparation history. Preparation never advances installed/served proof.
ALTER TABLE certops_consumer_deployments
  ADD COLUMN staging_job_id UUID NULL,
  ADD COLUMN staging_receipt JSONB NULL,
  ADD CONSTRAINT fk_certops_consumer_staging_job FOREIGN KEY(workspace_id,staging_job_id)
    REFERENCES certificate_jobs(workspace_id,id),
  ADD CONSTRAINT ck_certops_consumer_staging_receipt CHECK(staging_receipt IS NULL OR jsonb_typeof(staging_receipt)='object');

ALTER TABLE certops_consumer_deployments DROP CONSTRAINT certops_consumer_deployments_stage_check;
ALTER TABLE certops_consumer_deployments ADD CONSTRAINT certops_consumer_deployments_stage_check
  CHECK(stage IN ('pending','staged','fetched','installed','bound','served_verified','trust_validated','failed','orphaned_unknown_effect'));

CREATE OR REPLACE FUNCTION certops_rollout_snapshot_immutable() RETURNS trigger AS $$
BEGIN
  IF (to_jsonb(NEW) - ARRAY['stage','observed_fingerprint_sha256','observed_valid_to','observed_at','failure_code','job_id','staging_job_id','staging_receipt'])
     IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['stage','observed_fingerprint_sha256','observed_valid_to','observed_at','failure_code','job_id','staging_job_id','staging_receipt']) THEN
    RAISE EXCEPTION 'Consumer rollout snapshot is immutable';
  END IF;
  IF OLD.job_id IS NOT NULL AND NEW.job_id IS DISTINCT FROM OLD.job_id THEN
    RAISE EXCEPTION 'Consumer child job is immutable';
  END IF;
  IF OLD.staging_job_id IS NOT NULL AND NEW.staging_job_id IS DISTINCT FROM OLD.staging_job_id THEN
    RAISE EXCEPTION 'Consumer staging job is immutable';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
