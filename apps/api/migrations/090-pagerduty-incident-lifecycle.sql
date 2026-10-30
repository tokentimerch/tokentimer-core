-- This is both the incident ledger and the durable Events v2 outbox. Credentials
-- remain in the existing workspace configuration, never in this table.
CREATE TABLE IF NOT EXISTS pagerduty_incidents (
  id UUID PRIMARY KEY,
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  token_id INTEGER NULL,
  token_id_snapshot INTEGER NOT NULL,
  destination_id TEXT NOT NULL CHECK (destination_id ~ '^[a-f0-9]{64}$'),
  dedup_key TEXT NOT NULL UNIQUE CHECK (char_length(dedup_key) BETWEEN 1 AND 255),
  original_expiration DATE NOT NULL,
  expiry_authority TEXT NOT NULL CHECK (expiry_authority IN ('manual','provider','certificate','monitor')),
  original_source_observed_at TIMESTAMPTZ NULL,
  risk_threshold_days INTEGER NOT NULL,
  recovery_expiration DATE NULL,
  state TEXT NOT NULL DEFAULT 'trigger_pending'
    CHECK (state IN ('trigger_pending', 'open', 'resolve_pending', 'resolved', 'cancelled')),
  trigger_alert_queue_id INTEGER NULL REFERENCES alert_queue(id) ON DELETE SET NULL,
  trigger_attempts INTEGER NOT NULL DEFAULT 0 CHECK (trigger_attempts >= 0),
  resolve_attempts INTEGER NOT NULL DEFAULT 0 CHECK (resolve_attempts >= 0),
  action_attempts INTEGER NOT NULL DEFAULT 0 CHECK (action_attempts >= 0),
  trigger_accepted_at TIMESTAMPTZ NULL,
  trigger_delivery_uncertain BOOLEAN NOT NULL DEFAULT FALSE,
  resolve_requested_at TIMESTAMPTZ NULL,
  resolved_at TIMESTAMPTZ NULL,
  last_attempt_at TIMESTAMPTZ NULL,
  last_error TEXT NULL CHECK (last_error IS NULL OR char_length(last_error) <= 128),
  retry_exhausted BOOLEAN NOT NULL DEFAULT FALSE,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  claim_id UUID NULL,
  claimed_until TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (workspace_id, token_id) REFERENCES tokens(workspace_id, id)
    ON DELETE SET NULL (token_id),
  CHECK (token_id IS NULL OR token_id = token_id_snapshot),
  CHECK (state NOT IN ('open', 'resolve_pending', 'resolved') OR trigger_accepted_at IS NOT NULL),
  CHECK (state NOT IN ('resolve_pending', 'resolved') OR
    (resolve_requested_at IS NOT NULL AND recovery_expiration IS NOT NULL)),
  CHECK (state <> 'resolved' OR resolved_at IS NOT NULL)
);
-- An older episode may still be resolving while a new episode is at risk.
CREATE UNIQUE INDEX IF NOT EXISTS uq_pagerduty_active_destination
  ON pagerduty_incidents(workspace_id, token_id_snapshot, destination_id)
  WHERE state IN ('trigger_pending', 'open');
CREATE INDEX IF NOT EXISTS idx_pagerduty_incidents_due
  ON pagerduty_incidents(next_attempt_at, id)
  WHERE state IN ('trigger_pending', 'open', 'resolve_pending');
CREATE INDEX IF NOT EXISTS idx_pagerduty_incidents_asset
  ON pagerduty_incidents(workspace_id, token_id_snapshot);

-- Freeze the date the queue row describes. No incident ledger is backfilled:
-- historic PagerDuty sends have no recoverable Events v2 correlation key.
ALTER TABLE alert_queue ADD COLUMN IF NOT EXISTS expiration_snapshot DATE NULL;
UPDATE alert_queue aq SET expiration_snapshot = t.expiration
  FROM tokens t WHERE t.id = aq.token_id AND aq.alert_key LIKE 'token_expiry:%'
    AND aq.alert_key NOT LIKE '%:previous_expiration:%'
    AND aq.status IN ('pending','failed','partial') AND aq.expiration_snapshot IS NULL;
CREATE OR REPLACE FUNCTION snapshot_expiry_alert_date()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.alert_key LIKE 'token_expiry:%' THEN
    SELECT expiration INTO NEW.expiration_snapshot FROM tokens WHERE id = NEW.token_id;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER trg_snapshot_expiry_alert_date BEFORE INSERT ON alert_queue
  FOR EACH ROW EXECUTE FUNCTION snapshot_expiry_alert_date();

-- Extend CertOps' existing archival convention to ALL expiration writers,
-- including imports, Token.update and the direct endpoint-monitor SQL path.
-- Keep the rows and their delivery logs; revoke in-flight queue claims.
CREATE OR REPLACE FUNCTION archive_changed_token_expiry_alerts()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  WITH archived AS (
    UPDATE alert_queue SET
      alert_key = alert_key || ':previous_expiration:' || OLD.expiration::text || ':' || id::text,
      error_message = CASE WHEN status IN ('pending','failed','partial','blocked','limit_exceeded')
        THEN 'Discarded: asset expiry changed' ELSE error_message END,
      status = CASE WHEN status IN ('pending','failed','partial','blocked','limit_exceeded')
        THEN 'sent' ELSE status END,
      next_attempt_at = NULL, delivery_claim_id = NULL, updated_at = NOW()
    WHERE token_id = NEW.id AND alert_key LIKE 'token_expiry:%'
      AND alert_key NOT LIKE '%:previous_expiration:%'
    RETURNING id
  )
  UPDATE operational_notifications SET resolved_at = NOW(), updated_at = NOW()
    WHERE workspace_id = NEW.workspace_id AND category = 'delivery' AND resolved_at IS NULL
      AND metadata->>'alert_queue_id' IN (SELECT id::text FROM archived);

  -- Wake the reconciler; deciding recovery still requires verified facts and
  -- the destination's risk window. A changed value alone is not recovery.
  UPDATE pagerduty_incidents SET next_attempt_at = LEAST(next_attempt_at, NOW())
    WHERE workspace_id = NEW.workspace_id AND token_id = NEW.id
      AND state IN ('trigger_pending','open');
  RETURN NEW;
END;
$$;
CREATE TRIGGER trg_archive_changed_token_expiry_alerts AFTER UPDATE OF expiration ON tokens
  FOR EACH ROW WHEN (OLD.expiration IS DISTINCT FROM NEW.expiration)
  EXECUTE FUNCTION archive_changed_token_expiry_alerts();
