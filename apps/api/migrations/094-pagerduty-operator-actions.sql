ALTER TABLE pagerduty_incidents DROP CONSTRAINT IF EXISTS pagerduty_incidents_resolution_reason_check;
ALTER TABLE pagerduty_incidents ADD CONSTRAINT pagerduty_incidents_resolution_reason_check
  CHECK (resolution_reason IN ('expiration_extended','certificate_revoked','certificate_decommissioned','manual_resolve'));
ALTER TABLE pagerduty_incidents
  ADD COLUMN operator_reason TEXT CHECK (char_length(operator_reason) BETWEEN 5 AND 1000),
  ADD COLUMN manual_suppression_active BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN requested_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN acknowledged_at TIMESTAMPTZ,
  ADD COLUMN remote_incident_id TEXT,
  ADD COLUMN remote_incident_url TEXT,
  ADD COLUMN remote_status TEXT CHECK (remote_status IN ('triggered','acknowledged','resolved')),
  ADD COLUMN lookup_at TIMESTAMPTZ,
  ADD COLUMN lookup_error TEXT;
CREATE TABLE pagerduty_ack_requests (
  incident_id UUID PRIMARY KEY REFERENCES pagerduty_incidents(id) ON DELETE CASCADE,
  requested_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  accepted_at TIMESTAMPTZ,
  cancelled_at TIMESTAMPTZ,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_error TEXT,
  exhausted BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX idx_pagerduty_ack_due ON pagerduty_ack_requests(next_attempt_at)
  WHERE accepted_at IS NULL AND cancelled_at IS NULL AND NOT exhausted;
CREATE TABLE pagerduty_lookup_credentials (
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  destination_id TEXT NOT NULL,
  token_encrypted TEXT NOT NULL,
  region TEXT NOT NULL CHECK (region IN ('us','eu')),
  PRIMARY KEY(workspace_id,destination_id)
);
-- Keep manual closure independent of queue retention. Every expiry writer,
-- including a direct SQL monitor update, rearms it only on a genuine change.
CREATE FUNCTION rearm_manually_closed_pagerduty_incidents() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  UPDATE pagerduty_incidents SET manual_suppression_active=FALSE
    WHERE token_id_snapshot=NEW.id AND manual_suppression_active;
  RETURN NEW;
END;
$$;
CREATE TRIGGER trg_rearm_manually_closed_pagerduty_incidents AFTER UPDATE OF expiration ON tokens
  FOR EACH ROW WHEN (OLD.expiration IS DISTINCT FROM NEW.expiration)
  EXECUTE FUNCTION rearm_manually_closed_pagerduty_incidents();
