ALTER TABLE certops_agent_credential_rotations
  DROP CONSTRAINT IF EXISTS certops_agent_credential_rotations_state_check;
ALTER TABLE certops_agent_credential_rotations
  ADD CONSTRAINT certops_agent_credential_rotations_state_check
  CHECK (state IN ('pending', 'committed', 'acknowledged'));
