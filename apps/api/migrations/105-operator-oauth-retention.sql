-- Token storage is bounded by retention and a per-grant row budget rather
-- than a lifetime counter, so long-lived connections can keep refreshing.
ALTER TABLE operator_oauth_grants DROP CONSTRAINT operator_oauth_grants_generation_count_check;
ALTER TABLE operator_oauth_grants ADD CONSTRAINT operator_oauth_grants_generation_count_check
  CHECK (generation_count >= 0);
