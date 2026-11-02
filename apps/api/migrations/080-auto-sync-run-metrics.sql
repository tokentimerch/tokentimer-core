-- Installation-wide telemetry survives run/configuration/workspace retention.
-- Existing run history is deliberately not backfilled.
CREATE TABLE auto_sync_run_outcome_stats (
  provider TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('success', 'partial', 'failed', 'superseded')),
  runs_total BIGINT NOT NULL DEFAULT 0 CHECK (runs_total >= 0),
  PRIMARY KEY (provider, status)
);

CREATE TABLE auto_sync_run_freshness (
  provider TEXT PRIMARY KEY,
  last_attempt_at TIMESTAMPTZ,
  last_success_at TIMESTAMPTZ
);

CREATE FUNCTION record_auto_sync_run_metrics() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  -- Both worker completion and API supersession pass through this boundary.
  -- Only a first terminal transition counts; retries and metadata edits do not.
  IF TG_OP = 'UPDATE' THEN
    IF OLD.status <> 'running' OR NEW.status = 'running' THEN
      RETURN NEW;
    END IF;
  END IF;

  INSERT INTO auto_sync_run_freshness (provider, last_attempt_at, last_success_at)
  VALUES (NEW.provider, NEW.started_at,
    CASE WHEN NEW.status = 'success' THEN COALESCE(NEW.finished_at, NOW()) END)
  ON CONFLICT (provider) DO UPDATE SET
    last_attempt_at = GREATEST(auto_sync_run_freshness.last_attempt_at, EXCLUDED.last_attempt_at),
    last_success_at = GREATEST(auto_sync_run_freshness.last_success_at, EXCLUDED.last_success_at);

  IF NEW.status <> 'running' THEN
    INSERT INTO auto_sync_run_outcome_stats (provider, status, runs_total)
    VALUES (NEW.provider, NEW.status, 1)
    ON CONFLICT (provider, status) DO UPDATE SET
      runs_total = auto_sync_run_outcome_stats.runs_total + 1;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER auto_sync_run_metrics
AFTER INSERT OR UPDATE OF status ON auto_sync_runs
FOR EACH ROW EXECUTE FUNCTION record_auto_sync_run_metrics();
