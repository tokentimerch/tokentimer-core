ALTER TABLE operational_notifications DROP CONSTRAINT operational_notifications_category_check;
ALTER TABLE operational_notifications ADD CONSTRAINT operational_notifications_category_check
  CHECK(category IN ('delivery','auto_sync','certops'));
-- The existing durable channel pipeline uses a real customer agent as its
-- workspace anchor, just as agent-health alerts do. No token is manufactured.
CREATE UNIQUE INDEX uq_certops_distribution_alert_key ON alert_queue(alert_key)
  WHERE alert_key LIKE 'cert_distribution:%';
ALTER TABLE certops_distribution_policies ADD COLUMN next_monitor_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();
