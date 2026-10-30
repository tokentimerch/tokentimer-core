ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS auto_sync_metrics JSONB NOT NULL DEFAULT '{}'::jsonb;
-- Preserve explicit opt-ins; other connections inherit future system defaults.
UPDATE auto_sync_configs SET metrics_settings = metrics_settings || jsonb_build_object(
  'inherit_system', COALESCE((metrics_settings->>'enabled')::boolean, FALSE) = FALSE)
WHERE NOT (metrics_settings ? 'inherit_system');
ALTER TABLE auto_sync_configs ALTER COLUMN metrics_settings SET DEFAULT
  '{"enabled":false,"labels":[],"monitoring_group":"","inherit_system":true}'::jsonb;
