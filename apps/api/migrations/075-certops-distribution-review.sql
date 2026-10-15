-- Terminal intent is not evidence of execution. Release only allocations whose
-- job has never been claimed/started; ambiguous and failed jobs stay fenced.
ALTER TABLE certops_material_versions ADD COLUMN allocation_released_at TIMESTAMPTZ;
ALTER TABLE certops_material_versions ADD COLUMN allocation_release_reason TEXT
  CHECK (allocation_release_reason IN ('rejected_before_execution','cancelled_before_execution'));

CREATE FUNCTION certops_release_unexecuted_publication() RETURNS trigger AS $$
BEGIN
  IF NEW.status IN ('rejected','cancelled') AND NEW.attempt_count = 0
     AND NEW.claim_id IS NULL AND NEW.claimed_by_agent_id IS NULL
     AND NEW.started_at IS NULL AND NEW.lease_expires_at IS NULL
     AND NEW.lease_renewed_at IS NULL THEN
    UPDATE certops_material_versions SET state='failed',
      allocation_released_at=clock_timestamp(),
      allocation_release_reason=NEW.status || '_before_execution'
    WHERE workspace_id=NEW.workspace_id AND publishing_job_id=NEW.id
      AND state='allocated' AND publishing_claim_id IS NULL;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_certops_release_unexecuted_publication
  AFTER UPDATE OF status ON certificate_jobs FOR EACH ROW
  EXECUTE FUNCTION certops_release_unexecuted_publication();

-- Repair already-stranded terminal jobs with exactly the same proof. Keep both
-- the job/approval history and the allocated version identity for audit.
UPDATE certops_material_versions v SET state='failed',
  allocation_released_at=clock_timestamp(),
  allocation_release_reason=j.status || '_before_execution'
FROM certificate_jobs j WHERE j.workspace_id=v.workspace_id AND j.id=v.publishing_job_id
  AND v.state='allocated' AND v.publishing_claim_id IS NULL
  AND j.status IN ('rejected','cancelled') AND j.attempt_count=0
  AND j.claim_id IS NULL AND j.claimed_by_agent_id IS NULL AND j.started_at IS NULL
  AND j.lease_expires_at IS NULL AND j.lease_renewed_at IS NULL;

-- Stable client request identity is independent of the fully approved frozen
-- execution intent. Older approval jobs can derive this from their payload.
ALTER TABLE certificate_jobs ADD COLUMN distribution_request_hash TEXT
  CHECK (distribution_request_hash ~ '^[a-f0-9]{64}$');
CREATE FUNCTION certops_distribution_request_immutable() RETURNS trigger AS $$
BEGIN
  IF OLD.distribution_request_hash IS NOT NULL AND
     NEW.distribution_request_hash IS DISTINCT FROM OLD.distribution_request_hash THEN
    RAISE EXCEPTION 'Distribution request identity is immutable';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_certops_distribution_request_immutable
  BEFORE UPDATE OF distribution_request_hash ON certificate_jobs FOR EACH ROW
  EXECUTE FUNCTION certops_distribution_request_immutable();
