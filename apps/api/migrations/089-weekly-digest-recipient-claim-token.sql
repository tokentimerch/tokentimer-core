ALTER TABLE weekly_digest_recipient_log ADD COLUMN IF NOT EXISTS claim_token TEXT;
ALTER TABLE weekly_digest_recipient_log ADD COLUMN IF NOT EXISTS provider_accepted_at TIMESTAMPTZ;
ALTER TABLE weekly_digest_recipient_log ADD COLUMN IF NOT EXISTS delivery_state TEXT;
ALTER TABLE weekly_digest_recipient_log ADD COLUMN IF NOT EXISTS retry_after TIMESTAMPTZ;
ALTER TABLE weekly_digest_recipient_log DROP CONSTRAINT IF EXISTS weekly_digest_recipient_delivery_state_check;
ALTER TABLE weekly_digest_recipient_log ADD CONSTRAINT weekly_digest_recipient_delivery_state_check
  CHECK (delivery_state IS NULL OR delivery_state IN ('in_progress','accepted','rejected','uncertain'));
