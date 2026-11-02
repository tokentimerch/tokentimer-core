-- Add an explicit file-install assurance policy. Existing served/trust rows
-- keep their meaning; no historical deployment is promoted or backfilled.
ALTER TABLE certops_consumer_bindings
  DROP CONSTRAINT certops_consumer_bindings_verification_policy_check;
ALTER TABLE certops_consumer_bindings
  ADD CONSTRAINT certops_consumer_bindings_verification_policy_check
  CHECK (verification_policy IN ('installed', 'served', 'trust'));

ALTER TABLE certops_consumer_deployments
  DROP CONSTRAINT certops_consumer_deployments_verification_policy_check;
ALTER TABLE certops_consumer_deployments
  ADD CONSTRAINT certops_consumer_deployments_verification_policy_check
  CHECK (verification_policy IN ('installed', 'served', 'trust'));

ALTER TABLE certops_consumer_current_state
  DROP CONSTRAINT certops_consumer_current_state_verification_method_check;
ALTER TABLE certops_consumer_current_state
  ADD CONSTRAINT certops_consumer_current_state_verification_method_check
  CHECK (verification_method IN ('installed', 'served', 'trust'));

ALTER TABLE certops_distribution_rollouts
  DROP CONSTRAINT certops_distribution_rollouts_state_check;
ALTER TABLE certops_distribution_rollouts
  ADD CONSTRAINT certops_distribution_rollouts_state_check
  CHECK (state IN ('pending', 'deploying', 'installed', 'verified', 'degraded', 'paused', 'retired'));
