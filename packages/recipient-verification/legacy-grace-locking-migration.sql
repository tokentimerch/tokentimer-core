-- Replace the preview triggers atomically, including when upgrading a preview.
LOCK TABLE workspace_contacts, contact_channel_verifications, contact_channel_legacy_grants IN SHARE ROW EXCLUSIVE MODE;

-- No contact foreign key: a refusal must not wait on the contact lock.
CREATE TABLE IF NOT EXISTS recipient_legacy_grace_refusals (
  workspace_id UUID NOT NULL,
  contact_id UUID NOT NULL,
  channel TEXT NOT NULL CHECK (channel IN ('email', 'whatsapp')),
  refused BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (workspace_id, contact_id, channel)
);

CREATE OR REPLACE FUNCTION recipient_legacy_grace_lock_verifications()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM 1 FROM contact_channel_verifications
   WHERE workspace_id = OLD.workspace_id AND contact_id = OLD.id
   ORDER BY channel FOR UPDATE;
  RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS recipient_legacy_grace_before_contact_delete ON workspace_contacts;
CREATE TRIGGER recipient_legacy_grace_before_contact_delete
  BEFORE DELETE ON workspace_contacts
  FOR EACH ROW EXECUTE FUNCTION recipient_legacy_grace_lock_verifications();

CREATE OR REPLACE FUNCTION recipient_legacy_grace_destination_changed()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
     OR lower(btrim(COALESCE(NEW.details->>'email', ''))) IS DISTINCT FROM lower(btrim(COALESCE(OLD.details->>'email', '')))
     OR btrim(COALESCE(NEW.phone_e164, '')) IS DISTINCT FROM btrim(COALESCE(OLD.phone_e164, '')) THEN
    PERFORM 1 FROM contact_channel_verifications
     WHERE workspace_id = OLD.workspace_id AND contact_id = OLD.id
     ORDER BY channel FOR UPDATE;
  END IF;
  IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id THEN
    UPDATE contact_channel_legacy_grants SET revoked_at = COALESCE(revoked_at, clock_timestamp())
     WHERE contact_id = OLD.id;
    RETURN NEW;
  END IF;
  IF lower(btrim(COALESCE(NEW.details->>'email', ''))) IS DISTINCT FROM lower(btrim(COALESCE(OLD.details->>'email', ''))) THEN
    UPDATE contact_channel_legacy_grants SET revoked_at = COALESCE(revoked_at, clock_timestamp())
     WHERE workspace_id = OLD.workspace_id AND contact_id = OLD.id AND channel = 'email';
  END IF;
  IF btrim(COALESCE(NEW.phone_e164, '')) IS DISTINCT FROM btrim(COALESCE(OLD.phone_e164, '')) THEN
    UPDATE contact_channel_legacy_grants SET revoked_at = COALESCE(revoked_at, clock_timestamp())
     WHERE workspace_id = OLD.workspace_id AND contact_id = OLD.id AND channel = 'whatsapp';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION recipient_legacy_grace_consent_revoked()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status IN ('revoked', 'opted_out') THEN
    INSERT INTO recipient_legacy_grace_refusals (workspace_id, contact_id, channel, refused)
    VALUES (NEW.workspace_id, NEW.contact_id, NEW.channel, TRUE)
    ON CONFLICT (workspace_id, contact_id, channel) DO UPDATE SET refused = TRUE;
    UPDATE contact_channel_legacy_grants SET revoked_at = COALESCE(revoked_at, clock_timestamp())
     WHERE workspace_id = NEW.workspace_id AND contact_id = NEW.contact_id AND channel = NEW.channel;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION recipient_legacy_grace_guard_insert()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE refused BOOLEAN;
BEGIN
  INSERT INTO recipient_legacy_grace_refusals AS r (workspace_id, contact_id, channel)
  VALUES (NEW.workspace_id, NEW.contact_id, NEW.channel)
  ON CONFLICT (workspace_id, contact_id, channel) DO UPDATE SET channel = EXCLUDED.channel
  RETURNING r.refused INTO refused;
  IF refused THEN
    RAISE EXCEPTION 'A snapshotted recipient is no longer eligible';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS recipient_legacy_grace_guard_insert ON contact_channel_legacy_grants;
CREATE TRIGGER recipient_legacy_grace_guard_insert
  BEFORE INSERT ON contact_channel_legacy_grants
  FOR EACH ROW EXECUTE FUNCTION recipient_legacy_grace_guard_insert();

CREATE OR REPLACE FUNCTION recipient_legacy_grace_forget_contact()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM recipient_legacy_grace_refusals WHERE contact_id = OLD.id;
  RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS recipient_legacy_grace_forget_contact ON workspace_contacts;
CREATE TRIGGER recipient_legacy_grace_forget_contact
  AFTER DELETE ON workspace_contacts
  FOR EACH ROW EXECUTE FUNCTION recipient_legacy_grace_forget_contact();

INSERT INTO recipient_legacy_grace_refusals (workspace_id, contact_id, channel, refused)
SELECT workspace_id, contact_id, channel, TRUE FROM contact_channel_verifications
 WHERE status IN ('revoked', 'opted_out')
ON CONFLICT (workspace_id, contact_id, channel) DO UPDATE SET refused = TRUE;
