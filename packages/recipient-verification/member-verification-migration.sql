ALTER TABLE users ADD COLUMN IF NOT EXISTS recipient_verified_email TEXT;

CREATE OR REPLACE FUNCTION recipient_member_clear_email_proof()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.recipient_verified_email := NULL;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS recipient_member_clear_email_proof ON users;
CREATE TRIGGER recipient_member_clear_email_proof
  BEFORE UPDATE OF email, email_original ON users
  FOR EACH ROW EXECUTE FUNCTION recipient_member_clear_email_proof();

-- Preserve refusals across duplicate contacts, edits and contact deletion.
CREATE OR REPLACE FUNCTION recipient_member_verification_preserve_revocation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status = 'opted_out'
     AND (TG_OP = 'INSERT' OR OLD.status IS DISTINCT FROM NEW.status
       OR OLD.channel IS DISTINCT FROM NEW.channel
       OR OLD.destination_fingerprint IS DISTINCT FROM NEW.destination_fingerprint
       OR OLD.workspace_id IS DISTINCT FROM NEW.workspace_id) THEN
    INSERT INTO notification_suppressions
      (channel, destination_fingerprint, scope, workspace_id, reason)
    SELECT NEW.channel, NEW.destination_fingerprint, 'workspace', NEW.workspace_id,
           'recipient_declined'
     WHERE EXISTS (SELECT 1 FROM workspaces WHERE id = NEW.workspace_id)
    ON CONFLICT (channel, destination_fingerprint, workspace_id, reason)
      WHERE scope = 'workspace'
    DO UPDATE SET expires_at = NULL;
  ELSIF NEW.channel = 'email' AND NEW.status = 'revoked'
     AND (TG_OP = 'INSERT' OR OLD.status IS DISTINCT FROM NEW.status
       OR OLD.channel IS DISTINCT FROM NEW.channel
       OR OLD.destination_fingerprint IS DISTINCT FROM NEW.destination_fingerprint
       OR OLD.workspace_id IS DISTINCT FROM NEW.workspace_id
       OR OLD.revoked_at IS DISTINCT FROM NEW.revoked_at) THEN
    INSERT INTO notification_suppressions
      (channel, destination_fingerprint, scope, workspace_id, reason)
    SELECT 'email', NEW.destination_fingerprint, 'workspace', NEW.workspace_id,
           'member_verification_revoked'
     WHERE EXISTS (SELECT 1 FROM workspaces WHERE id = NEW.workspace_id)
    ON CONFLICT (channel, destination_fingerprint, workspace_id, reason)
      WHERE scope = 'workspace'
    DO UPDATE SET expires_at = NULL;
  ELSIF NEW.channel = 'email' AND NEW.status = 'verified' AND NEW.consent_at IS NOT NULL
     AND (TG_OP = 'INSERT' OR OLD.status IS DISTINCT FROM NEW.status
       OR OLD.channel IS DISTINCT FROM NEW.channel
       OR OLD.destination_fingerprint IS DISTINCT FROM NEW.destination_fingerprint
       OR OLD.workspace_id IS DISTINCT FROM NEW.workspace_id
       OR OLD.consent_at IS DISTINCT FROM NEW.consent_at) THEN
    INSERT INTO notification_suppressions
      (channel, destination_fingerprint, scope, workspace_id, reason, expires_at)
    SELECT 'email', NEW.destination_fingerprint, 'workspace', NEW.workspace_id,
           'member_verification_revoked', '-infinity'::timestamptz
     WHERE EXISTS (SELECT 1 FROM workspaces WHERE id = NEW.workspace_id)
    ON CONFLICT (channel, destination_fingerprint, workspace_id, reason)
      WHERE scope = 'workspace'
    DO UPDATE SET expires_at = '-infinity'::timestamptz;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS recipient_member_verification_preserve_revocation
  ON contact_channel_verifications;
CREATE TRIGGER recipient_member_verification_preserve_revocation
  AFTER INSERT OR UPDATE OF status, channel, destination_fingerprint, workspace_id, revoked_at, consent_at
  ON contact_channel_verifications
  FOR EACH ROW EXECUTE FUNCTION recipient_member_verification_preserve_revocation();

-- Preserve historical reconfirmation before replaying older duplicate refusals.
INSERT INTO notification_suppressions
  (channel, destination_fingerprint, scope, workspace_id, reason, expires_at)
SELECT v.channel, v.destination_fingerprint, 'workspace', v.workspace_id,
       'member_verification_revoked', '-infinity'::timestamptz
  FROM contact_channel_verifications v
  JOIN workspaces w ON w.id = v.workspace_id
 WHERE v.channel = 'email'
 GROUP BY v.channel, v.destination_fingerprint, v.workspace_id
HAVING MAX(v.consent_at) FILTER (WHERE v.status = 'verified') >
       MAX(COALESCE(CASE WHEN v.status = 'revoked' THEN v.revoked_at ELSE v.opted_out_at END,
                    v.updated_at, v.created_at))
         FILTER (WHERE v.status IN ('revoked', 'opted_out'))
ON CONFLICT (channel, destination_fingerprint, workspace_id, reason)
  WHERE scope = 'workspace'
DO NOTHING;

INSERT INTO notification_suppressions
  (channel, destination_fingerprint, scope, workspace_id, reason)
SELECT DISTINCT v.channel, v.destination_fingerprint, 'workspace', v.workspace_id,
       'member_verification_revoked'
  FROM contact_channel_verifications v
  JOIN workspaces w ON w.id = v.workspace_id
 WHERE v.channel = 'email' AND v.status = 'revoked'
ON CONFLICT (channel, destination_fingerprint, workspace_id, reason)
  WHERE scope = 'workspace'
DO NOTHING;

INSERT INTO notification_suppressions
  (channel, destination_fingerprint, scope, workspace_id, reason)
SELECT DISTINCT v.channel, v.destination_fingerprint, 'workspace', v.workspace_id,
       'recipient_declined'
  FROM contact_channel_verifications v
  JOIN workspaces w ON w.id = v.workspace_id
 WHERE v.channel = 'email' AND v.status = 'opted_out'
   AND NOT EXISTS (
     SELECT 1 FROM notification_suppressions s
      WHERE s.channel = v.channel AND s.destination_fingerprint = v.destination_fingerprint
        AND s.scope = 'workspace' AND s.workspace_id = v.workspace_id
        AND s.reason = 'member_verification_revoked' AND s.expires_at = '-infinity'::timestamptz
   )
ON CONFLICT (channel, destination_fingerprint, workspace_id, reason)
  WHERE scope = 'workspace'
DO NOTHING;
