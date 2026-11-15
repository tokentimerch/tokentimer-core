-- Preserve only destination fingerprints; credentials remain in workspace settings.
CREATE UNIQUE INDEX IF NOT EXISTS uq_certops_distribution_incidents_workspace_id
  ON certops_distribution_incidents(workspace_id,id);
CREATE TABLE certops_distribution_pagerduty (
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  incident_id UUID NOT NULL,
  destination_id TEXT NOT NULL CHECK (destination_id ~ '^[a-f0-9]{64}$'),
  trigger_accepted_at TIMESTAMPTZ,
  historical_resolution_at TIMESTAMPTZ,
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

-- Older logs may contain only a urlHash. Preserve those candidates without
-- treating them as an exact integration until the worker matches a current
-- tenant/URL/routing-key fingerprint.
INSERT INTO certops_distribution_pagerduty(workspace_id,incident_id,destination_id,trigger_accepted_at,trigger_delivery_uncertain,last_error)
SELECT dl.workspace_id,i.id,COALESCE(dl.metadata->>'destination_id',dl.metadata->>'urlHash'),MIN(dl.sent_at),
  NOT BOOL_OR(COALESCE(dl.metadata->>'destination_id' ~ '^[a-f0-9]{64}$',FALSE)),
  CASE WHEN BOOL_OR(COALESCE(dl.metadata->>'destination_id' ~ '^[a-f0-9]{64}$',FALSE)) THEN NULL ELSE 'historical_destination_unverified' END
FROM alert_delivery_log dl
JOIN alert_queue aq ON aq.id=dl.alert_queue_id
JOIN certops_distribution_incidents i ON i.workspace_id=dl.workspace_id AND i.id::text=aq.metadata->>'incidentId'
WHERE dl.channel='webhooks' AND dl.status='success' AND dl.metadata->>'kind'='pagerduty'
  AND COALESCE(dl.metadata->>'destination_id',dl.metadata->>'urlHash') ~ '^[a-f0-9]{64}$'
  AND aq.alert_key LIKE 'cert_distribution:%' AND aq.metadata->>'transition' IN ('opened','updated')
GROUP BY dl.workspace_id,i.id,COALESCE(dl.metadata->>'destination_id',dl.metadata->>'urlHash')
ON CONFLICT DO NOTHING;

-- Preserve later successful resolves for the same historical destination.
-- An unverified hash stays parked until its exact routing-key fingerprint is proven.
WITH delivery_evidence AS (
  SELECT dl.workspace_id,aq.metadata->>'incidentId' AS incident_id,
    COALESCE(dl.metadata->>'destination_id',dl.metadata->>'urlHash') AS destination_id,
    aq.metadata->>'transition' AS transition,dl.sent_at,dl.id AS delivery_id
  FROM alert_delivery_log dl
  JOIN alert_queue aq ON aq.id=dl.alert_queue_id
  JOIN certops_agents a ON a.id=aq.certops_agent_id AND a.workspace_id=dl.workspace_id
  WHERE dl.channel='webhooks' AND dl.status='success' AND dl.metadata->>'kind'='pagerduty'
    AND aq.alert_key LIKE 'cert_distribution:%'
    AND aq.metadata->>'transition' IN ('opened','updated','resolved')
), last_trigger AS (
  SELECT DISTINCT ON (workspace_id,incident_id,destination_id)
    workspace_id,incident_id,destination_id,sent_at,delivery_id
  FROM delivery_evidence WHERE transition IN ('opened','updated')
  ORDER BY workspace_id,incident_id,destination_id,sent_at DESC,delivery_id DESC
), resolved AS (
  SELECT p.workspace_id,p.incident_id,p.destination_id,MIN(r.sent_at) AS resolved_at
  FROM certops_distribution_pagerduty p
  JOIN delivery_evidence r ON r.workspace_id=p.workspace_id AND r.incident_id=p.incident_id::text
    AND r.destination_id=p.destination_id AND r.transition='resolved'
  JOIN last_trigger t ON t.workspace_id=p.workspace_id AND t.incident_id=p.incident_id::text
    AND t.destination_id=p.destination_id
  WHERE (r.sent_at,r.delivery_id) >= (t.sent_at,t.delivery_id)
  GROUP BY p.workspace_id,p.incident_id,p.destination_id
)
UPDATE certops_distribution_pagerduty p SET historical_resolution_at=r.resolved_at,
  resolved_at=CASE WHEN p.trigger_delivery_uncertain THEN NULL ELSE r.resolved_at END
FROM resolved r WHERE p.workspace_id=r.workspace_id AND p.incident_id=r.incident_id AND p.destination_id=r.destination_id;
