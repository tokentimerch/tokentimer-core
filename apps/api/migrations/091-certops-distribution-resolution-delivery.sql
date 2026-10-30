-- Resolving health and delivering recovery are separate durable obligations.
ALTER TABLE certops_distribution_incidents
  ADD COLUMN resolution_delivery_pending BOOLEAN NOT NULL DEFAULT false,
  ADD CONSTRAINT certops_resolution_pending_requires_resolution
    CHECK (NOT resolution_delivery_pending OR resolved_at IS NOT NULL);
UPDATE certops_distribution_incidents i SET resolution_delivery_pending=true
  WHERE i.resolved_at IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM alert_queue q
    WHERE q.alert_key LIKE 'cert_distribution:%'
      AND q.alert_key='cert_distribution:' || i.id::text || ':' || i.revision::text || ':resolved');
CREATE INDEX idx_certops_distribution_resolution_pending
  ON certops_distribution_incidents(workspace_id,group_id,resolved_at,id)
  WHERE resolution_delivery_pending;
