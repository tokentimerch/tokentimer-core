ALTER TABLE operational_notifications DROP CONSTRAINT operational_notifications_category_check;
ALTER TABLE operational_notifications ADD CONSTRAINT operational_notifications_category_check
  CHECK(category IN ('delivery','auto_sync','certops'));
-- The existing durable channel pipeline uses a real customer agent as its
-- workspace anchor, just as agent-health alerts do. No token is manufactured.
CREATE UNIQUE INDEX uq_certops_distribution_alert_key ON alert_queue(alert_key)
  WHERE alert_key LIKE 'cert_distribution:%';
ALTER TABLE certops_distribution_policies ADD COLUMN next_monitor_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();

CREATE FUNCTION certops_close_distribution_approval_notice() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status='pending_approval' AND NEW.status<>'pending_approval' THEN
    UPDATE operational_notifications SET resolved_at=clock_timestamp(),updated_at=clock_timestamp()
      WHERE workspace_id=NEW.workspace_id AND dedupe_key='distribution_approval:' || NEW.id::text AND resolved_at IS NULL;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_certops_close_distribution_approval_notice AFTER UPDATE OF status ON certificate_jobs
  FOR EACH ROW EXECUTE FUNCTION certops_close_distribution_approval_notice();
