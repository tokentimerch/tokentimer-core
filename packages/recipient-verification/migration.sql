-- Recipient ownership verification is separate from contact existence,
-- contact-group membership, and historical contact_opt_ins rows.
CREATE TABLE IF NOT EXISTS contact_channel_verifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  contact_id UUID NOT NULL REFERENCES workspace_contacts(id) ON DELETE CASCADE,
  channel TEXT NOT NULL CHECK (channel IN ('email', 'whatsapp')),
  destination_normalized TEXT NOT NULL,
  destination_fingerprint TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'verified', 'revoked', 'opted_out')),
  verified_at TIMESTAMPTZ NULL,
  consent_at TIMESTAMPTZ NULL,
  consent_method TEXT NULL,
  consent_policy_version TEXT NULL,
  revoked_at TIMESTAMPTZ NULL,
  opted_out_at TIMESTAMPTZ NULL,
  opt_out_method TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, contact_id, channel)
);

CREATE INDEX IF NOT EXISTS idx_contact_channel_verifications_destination
  ON contact_channel_verifications (workspace_id, channel, destination_fingerprint);

CREATE TABLE IF NOT EXISTS contact_verification_challenges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  contact_id UUID NOT NULL REFERENCES workspace_contacts(id) ON DELETE CASCADE,
  channel TEXT NOT NULL CHECK (channel IN ('email', 'whatsapp')),
  destination_normalized TEXT NOT NULL,
  destination_fingerprint TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  code_hash TEXT NULL,
  code_ciphertext TEXT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'consumed', 'declined', 'superseded')),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ NULL,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_contact_verification_one_pending
  ON contact_verification_challenges (workspace_id, contact_id, channel)
  WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_contact_verification_code_hash
  ON contact_verification_challenges (code_hash)
  WHERE code_hash IS NOT NULL AND status = 'pending';

CREATE TABLE IF NOT EXISTS notification_suppressions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  channel TEXT NOT NULL CHECK (channel IN ('email', 'whatsapp')),
  destination_fingerprint TEXT NOT NULL,
  scope TEXT NOT NULL CHECK (scope IN ('global', 'workspace')),
  workspace_id UUID NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  reason TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NULL,
  CHECK (
    (scope = 'global' AND workspace_id IS NULL)
    OR (scope = 'workspace' AND workspace_id IS NOT NULL)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_notification_suppressions_global
  ON notification_suppressions (channel, destination_fingerprint, reason)
  WHERE scope = 'global';

CREATE UNIQUE INDEX IF NOT EXISTS uq_notification_suppressions_workspace
  ON notification_suppressions (channel, destination_fingerprint, workspace_id, reason)
  WHERE scope = 'workspace';

CREATE TABLE IF NOT EXISTS recipient_verification_events (
  id BIGSERIAL PRIMARY KEY,
  bucket_key TEXT NOT NULL,
  workspace_id UUID NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_recipient_verification_events_bucket
  ON recipient_verification_events (bucket_key, created_at);

CREATE TABLE IF NOT EXISTS twilio_inbound_messages (
  message_sid TEXT PRIMARY KEY,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Legacy contacts stay unverified. contact_opt_ins rows with method
-- contact_created are historical only and are not copied forward.
