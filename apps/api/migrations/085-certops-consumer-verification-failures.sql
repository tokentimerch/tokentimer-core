-- Derived verification outcomes. Original jobs, receipts and audit rows remain
-- authoritative and unchanged. One row represents one binding/rollout, not one
-- execution attempt. Monitoring reads the per-binding summary, never history.
ALTER TABLE certops_consumer_current_state
  ADD COLUMN verification_failure_count BIGINT NOT NULL DEFAULT 0 CHECK (verification_failure_count BETWEEN 0 AND 9007199254740991),
  ADD COLUMN verification_failure_revision INTEGER NULL,
  ADD COLUMN verification_outcome_generation BIGINT NOT NULL DEFAULT 0 CHECK (verification_outcome_generation BETWEEN 0 AND 9007199254740991);

CREATE TABLE certops_consumer_verification_outcomes (
  workspace_id UUID NOT NULL,
  rollout_id UUID NOT NULL,
  binding_id UUID NOT NULL,
  authorization_revision INTEGER NOT NULL CHECK (authorization_revision>0),
  generation BIGINT NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  outcome TEXT NOT NULL CHECK (outcome IN ('failed','succeeded','uncertain')),
  PRIMARY KEY (workspace_id,rollout_id,binding_id),
  FOREIGN KEY (workspace_id,rollout_id,binding_id)
    REFERENCES certops_consumer_deployments(workspace_id,rollout_id,binding_id) ON DELETE CASCADE
);
CREATE INDEX idx_certops_consumer_verification_streak
  ON certops_consumer_verification_outcomes(workspace_id,binding_id,authorization_revision,generation DESC)
  INCLUDE (outcome);
CREATE INDEX idx_certops_consumer_verification_success
  ON certops_consumer_verification_outcomes(workspace_id,binding_id,authorization_revision,generation DESC)
  WHERE outcome='succeeded';

-- A successful proof resets a streak only if it met the snapshot's assurance
-- and was fresh when the job completed. It must not stop being a reset merely
-- because that historical proof later expires. A verified real deployment can
-- reset a streak; its failures are not read-only verification-cycle failures.
CREATE VIEW certops_consumer_verification_outcome_candidates AS
SELECT d.workspace_id,d.group_id,d.rollout_id,d.binding_id,d.job_id,d.authorization_revision,r.generation,
  CASE
    WHEN j.needs_operator_reconciliation OR j.status='orphaned_unknown_effect' OR d.stage='orphaned_unknown_effect'
    THEN 'uncertain'
    WHEN j.status='succeeded'
      AND d.observed_fingerprint_sha256=v.fingerprint_sha256
      AND d.observed_valid_to=date_trunc('milliseconds',v.valid_to)
      AND d.observed_valid_to>COALESCE(j.completed_at,j.updated_at)
      AND d.observed_at>=COALESCE(j.started_at,j.created_at)-interval '30 seconds'
      AND d.observed_at>=COALESCE(j.completed_at,j.updated_at)-d.freshness_seconds*interval '1 second'
      AND d.observed_at<=COALESCE(j.completed_at,j.updated_at)+interval '30 seconds'
      AND ((d.verification_policy='installed' AND d.stage='installed')
        OR (d.verification_policy='served' AND d.stage IN ('served_verified','trust_validated'))
        OR (d.verification_policy='trust' AND d.stage='trust_validated'))
    THEN 'succeeded'
    WHEN r.verification_only
      AND j.payload->'materialDeployment'->>'verificationOnly'='true'
      AND (j.status IN ('failed','blocked','rejected','cancelled') OR EXISTS (
        SELECT 1 FROM certificate_job_log log
        WHERE log.workspace_id=j.workspace_id AND log.job_id=j.id
          AND log.event_type IN ('job.failed','job.rejected','approval.rejected','job.cancelled')
          AND log.status IN ('failed','blocked','rejected','cancelled')))
    THEN 'failed'
    ELSE NULL
  END AS outcome
FROM certops_consumer_deployments d
JOIN certops_distribution_rollouts r ON r.workspace_id=d.workspace_id AND r.id=d.rollout_id
JOIN certops_material_versions v ON v.workspace_id=r.workspace_id AND v.id=r.material_version_id
JOIN certificate_jobs j ON j.workspace_id=d.workspace_id AND j.id=d.job_id
WHERE j.operation='deploy-from-store' AND j.mode='real';

CREATE FUNCTION certops_record_consumer_verification_outcome() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE candidate RECORD; changed INTEGER;
BEGIN
  IF NEW.operation<>'deploy-from-store' OR NEW.payload->'materialDeployment' IS NULL
    OR (NEW.status NOT IN ('succeeded','failed','blocked','rejected','cancelled','orphaned_unknown_effect') AND NOT NEW.needs_operator_reconciliation)
    OR NEW.mode<>'real' THEN
    RETURN NEW;
  END IF;
  -- Serialize only this binding's summaries, using the state row already
  -- locked by receipt ingestion. Do not introduce a job -> group lock upgrade
  -- for bulk cancellations or rejected jobs. Different consumers stay independent.
  PERFORM binding_id FROM certops_consumer_current_state
    WHERE workspace_id=NEW.workspace_id AND binding_id=(NEW.payload->'materialDeployment'->>'bindingId')::uuid FOR UPDATE;
  IF NOT FOUND THEN RETURN NEW; END IF;
  SELECT * INTO candidate FROM certops_consumer_verification_outcome_candidates
    WHERE workspace_id=NEW.workspace_id
      AND group_id=(NEW.payload->'materialDeployment'->>'groupId')::uuid AND job_id=NEW.id
      AND rollout_id=(NEW.payload->'materialDeployment'->>'rolloutId')::uuid
      AND binding_id=(NEW.payload->'materialDeployment'->>'bindingId')::uuid;
  IF NOT FOUND OR candidate.outcome IS NULL THEN RETURN NEW; END IF;

  INSERT INTO certops_consumer_verification_outcomes
    (workspace_id,rollout_id,binding_id,authorization_revision,generation,outcome)
    VALUES(candidate.workspace_id,candidate.rollout_id,candidate.binding_id,
      candidate.authorization_revision,candidate.generation,candidate.outcome)
    ON CONFLICT(workspace_id,rollout_id,binding_id) DO UPDATE SET outcome=EXCLUDED.outcome
      WHERE certops_consumer_verification_outcomes.outcome<>'succeeded'
        AND certops_consumer_verification_outcomes.outcome IS DISTINCT FROM EXCLUDED.outcome;
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed=0 THEN RETURN NEW; END IF;

  WITH boundary AS (
    SELECT (SELECT generation FROM certops_consumer_verification_outcomes
      WHERE workspace_id=candidate.workspace_id AND binding_id=candidate.binding_id
        AND authorization_revision=candidate.authorization_revision AND outcome='succeeded'
      ORDER BY generation DESC LIMIT 1) AS success_generation,
      (SELECT generation FROM certops_consumer_verification_outcomes
        WHERE workspace_id=candidate.workspace_id AND binding_id=candidate.binding_id
          AND authorization_revision=candidate.authorization_revision
        ORDER BY generation DESC LIMIT 1) AS latest_generation
  ), streak AS (
    SELECT count(*) AS failures FROM certops_consumer_verification_outcomes o,boundary b
    WHERE o.workspace_id=candidate.workspace_id AND o.binding_id=candidate.binding_id
      AND o.authorization_revision=candidate.authorization_revision AND o.outcome='failed'
      AND o.generation>COALESCE(b.success_generation,0)
  )
  UPDATE certops_consumer_current_state s SET verification_failure_count=streak.failures,
    verification_failure_revision=candidate.authorization_revision,
    verification_outcome_generation=boundary.latest_generation
  FROM streak,boundary,certops_consumer_bindings binding
  WHERE s.workspace_id=candidate.workspace_id AND s.binding_id=candidate.binding_id
    AND binding.workspace_id=s.workspace_id AND binding.id=s.binding_id
    AND binding.authorization_revision=candidate.authorization_revision;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_certops_consumer_verification_outcome
  AFTER UPDATE OF status,needs_operator_reconciliation ON certificate_jobs
  FOR EACH ROW EXECUTE FUNCTION certops_record_consumer_verification_outcome();

-- One-time backfill. Regular monitoring never repeats this history scan.
INSERT INTO certops_consumer_verification_outcomes
  (workspace_id,rollout_id,binding_id,authorization_revision,generation,outcome)
SELECT workspace_id,rollout_id,binding_id,authorization_revision,generation,outcome
FROM certops_consumer_verification_outcome_candidates WHERE outcome IS NOT NULL;
WITH boundaries AS (
  SELECT workspace_id,binding_id,authorization_revision,
    max(generation) FILTER (WHERE outcome='succeeded') AS success_generation,
    max(generation) AS latest_generation
  FROM certops_consumer_verification_outcomes GROUP BY workspace_id,binding_id,authorization_revision
), streaks AS (
  SELECT b.workspace_id,b.binding_id,b.authorization_revision,b.latest_generation,
    count(*) FILTER (WHERE o.outcome='failed' AND o.generation>COALESCE(b.success_generation,0)) AS failures
  FROM boundaries b JOIN certops_consumer_verification_outcomes o
    ON o.workspace_id=b.workspace_id AND o.binding_id=b.binding_id AND o.authorization_revision=b.authorization_revision
  GROUP BY b.workspace_id,b.binding_id,b.authorization_revision,b.latest_generation
)
UPDATE certops_consumer_current_state s SET verification_failure_count=streaks.failures,
  verification_failure_revision=streaks.authorization_revision,
  verification_outcome_generation=streaks.latest_generation
FROM streaks,certops_consumer_bindings binding
WHERE s.workspace_id=streaks.workspace_id AND s.binding_id=streaks.binding_id
  AND binding.workspace_id=s.workspace_id AND binding.id=s.binding_id
  AND binding.authorization_revision=streaks.authorization_revision;
