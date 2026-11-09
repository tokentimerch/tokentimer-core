-- Empty on upgrade: legacy delivery is enabled only by an operator-reviewed
-- snapshot and RECIPIENT_VERIFICATION_LEGACY_GRACE=1. This is not consent.
CREATE TABLE IF NOT EXISTS recipient_legacy_grace_snapshots (
  id UUID PRIMARY KEY,
  snapshot_sha256 TEXT NOT NULL CHECK (snapshot_sha256 ~ '^[a-f0-9]{64}$'),
  cutoff_at TIMESTAMPTZ NOT NULL,
  captured_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  activated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  activated_by TEXT NOT NULL CHECK (length(btrim(activated_by)) BETWEEN 1 AND 200),
  recipient_count INTEGER NOT NULL CHECK (recipient_count > 0),
  revoked_at TIMESTAMPTZ NULL,
  CHECK (cutoff_at <= captured_at),
  CHECK (expires_at > captured_at AND expires_at <= captured_at + INTERVAL '30 days'),
  CHECK (activated_at >= captured_at AND activated_at < expires_at)
);

CREATE TABLE IF NOT EXISTS contact_channel_legacy_grants (
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  contact_id UUID NOT NULL REFERENCES workspace_contacts(id) ON DELETE CASCADE,
  channel TEXT NOT NULL CHECK (channel IN ('email', 'whatsapp')),
  snapshot_id UUID NOT NULL REFERENCES recipient_legacy_grace_snapshots(id),
  destination_normalized TEXT NOT NULL,
  destination_fingerprint TEXT NOT NULL,
  source_version TEXT NOT NULL,
  revoked_at TIMESTAMPTZ NULL,
  -- A contact/channel can receive grace only once. A later snapshot cannot
  -- renew an expired grant or restore one invalidated by a destination edit.
  PRIMARY KEY (workspace_id, contact_id, channel)
);

CREATE INDEX IF NOT EXISTS idx_contact_channel_legacy_grants_snapshot
  ON contact_channel_legacy_grants (snapshot_id);

CREATE OR REPLACE FUNCTION recipient_legacy_grace_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (to_jsonb(NEW) - 'revoked_at') IS DISTINCT FROM (to_jsonb(OLD) - 'revoked_at')
     OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN
    RAISE EXCEPTION 'Legacy recipient grace is immutable; revoke it instead of extending or replacing it';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS recipient_legacy_grace_snapshot_immutable ON recipient_legacy_grace_snapshots;
CREATE TRIGGER recipient_legacy_grace_snapshot_immutable
  BEFORE UPDATE ON recipient_legacy_grace_snapshots
  FOR EACH ROW EXECUTE FUNCTION recipient_legacy_grace_immutable();

DROP TRIGGER IF EXISTS recipient_legacy_grace_grant_immutable ON contact_channel_legacy_grants;
CREATE TRIGGER recipient_legacy_grace_grant_immutable
  BEFORE UPDATE ON contact_channel_legacy_grants
  FOR EACH ROW EXECUTE FUNCTION recipient_legacy_grace_immutable();

-- Every writer is covered, including older API replicas and direct imports.
-- Returning an edited address/number to its previous value never restores grace.
CREATE OR REPLACE FUNCTION recipient_legacy_grace_destination_changed()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id THEN
    UPDATE contact_channel_legacy_grants
       SET revoked_at = COALESCE(revoked_at, clock_timestamp())
     WHERE contact_id = OLD.id;
    RETURN NEW;
  END IF;
  IF lower(btrim(COALESCE(NEW.details->>'email', '')))
       IS DISTINCT FROM lower(btrim(COALESCE(OLD.details->>'email', ''))) THEN
    UPDATE contact_channel_legacy_grants
       SET revoked_at = COALESCE(revoked_at, clock_timestamp())
     WHERE workspace_id = OLD.workspace_id AND contact_id = OLD.id AND channel = 'email';
  END IF;
  IF btrim(COALESCE(NEW.phone_e164, '')) IS DISTINCT FROM btrim(COALESCE(OLD.phone_e164, '')) THEN
    UPDATE contact_channel_legacy_grants
       SET revoked_at = COALESCE(revoked_at, clock_timestamp())
     WHERE workspace_id = OLD.workspace_id AND contact_id = OLD.id AND channel = 'whatsapp';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS recipient_legacy_grace_destination_changed ON workspace_contacts;
CREATE TRIGGER recipient_legacy_grace_destination_changed
  AFTER UPDATE OF workspace_id, details, phone_e164 ON workspace_contacts
  FOR EACH ROW EXECUTE FUNCTION recipient_legacy_grace_destination_changed();

-- A later invitation/resubscribe can set consent back to pending. It must not
-- reopen grace after a manager revoked delivery or the recipient declined.
CREATE OR REPLACE FUNCTION recipient_legacy_grace_consent_revoked()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status IN ('revoked', 'opted_out') THEN
    -- Activation locks this same parent row before inspecting consent and
    -- inserting grants. A concurrent direct consent UPDATE must invalidate
    -- any grant activated before it commits, even if none existed at start.
    PERFORM 1 FROM workspace_contacts
      WHERE workspace_id = NEW.workspace_id AND id = NEW.contact_id FOR UPDATE;
    UPDATE contact_channel_legacy_grants
       SET revoked_at = COALESCE(revoked_at, clock_timestamp())
     WHERE workspace_id = NEW.workspace_id AND contact_id = NEW.contact_id AND channel = NEW.channel;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS recipient_legacy_grace_consent_revoked ON contact_channel_verifications;
CREATE TRIGGER recipient_legacy_grace_consent_revoked
  AFTER INSERT OR UPDATE OF status ON contact_channel_verifications
  FOR EACH ROW EXECUTE FUNCTION recipient_legacy_grace_consent_revoked();
