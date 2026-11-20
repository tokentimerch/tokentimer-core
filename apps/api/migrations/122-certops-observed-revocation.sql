ALTER TABLE certops_slot_observations
  ADD COLUMN IF NOT EXISTS observed_revocation jsonb;
