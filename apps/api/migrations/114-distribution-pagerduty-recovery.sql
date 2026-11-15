-- Preserve only destination fingerprints; credentials remain in workspace settings.
CREATE UNIQUE INDEX IF NOT EXISTS uq_certops_distribution_incidents_workspace_id
  ON certops_distribution_incidents(workspace_id,id);
CREATE TABLE certops_distribution_pagerduty (
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  incident_id UUID NOT NULL,
  destination_id TEXT NOT NULL CHECK (destination_id ~ '^[a-f0-9]{64}$'),
  trigger_accepted_at TIMESTAMPTZ,
  trigger_delivery_uncertain BOOLEAN NOT NULL DEFAULT FALSE,
  resolved_at TIMESTAMPTZ,
  resolve_attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_error TEXT,
  PRIMARY KEY (workspace_id, incident_id, destination_id),
  FOREIGN KEY (workspace_id,incident_id) REFERENCES certops_distribution_incidents(workspace_id,id) ON DELETE CASCADE
);
CREATE INDEX certops_distribution_pagerduty_due ON certops_distribution_pagerduty(next_attempt_at)
  WHERE resolved_at IS NULL AND trigger_accepted_at IS NOT NULL;

-- Existing distribution events already used a stable incident deduplication key.
-- Backfill only exact, destination-specific successful trigger evidence.
INSERT INTO certops_distribution_pagerduty(workspace_id,incident_id,destination_id,trigger_accepted_at)
SELECT dl.workspace_id,i.id,dl.metadata->>'destination_id',MIN(dl.sent_at)
FROM alert_delivery_log dl
JOIN alert_queue aq ON aq.id=dl.alert_queue_id
JOIN certops_distribution_incidents i ON i.workspace_id=dl.workspace_id AND i.id::text=aq.metadata->>'incidentId'
WHERE dl.channel='webhooks' AND dl.status='success' AND dl.metadata->>'kind'='pagerduty'
  AND dl.metadata->>'destination_id' ~ '^[a-f0-9]{64}$'
  AND aq.alert_key LIKE 'cert_distribution:%' AND aq.metadata->>'transition' IN ('opened','updated')
GROUP BY dl.workspace_id,i.id,dl.metadata->>'destination_id'
ON CONFLICT DO NOTHING;
