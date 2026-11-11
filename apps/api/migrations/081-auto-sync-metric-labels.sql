-- Aggregate history is preserved independently of configuration deletion.
ALTER TABLE auto_sync_configs ADD COLUMN IF NOT EXISTS metrics_settings JSONB NOT NULL
  DEFAULT '{"enabled":false,"labels":[],"monitoring_group":""}'::jsonb;
CREATE TABLE IF NOT EXISTS auto_sync_kind_stats (
  provider TEXT NOT NULL, kind TEXT NOT NULL,
  items_created_total BIGINT NOT NULL CHECK (items_created_total >= 0),
  PRIMARY KEY (provider, kind)
);
-- High-cardinality values are retained here only when explicitly selected.
-- Per-configuration metadata is removed with its configuration; global totals survive.
CREATE TABLE IF NOT EXISTS auto_sync_creation_stats (
  config_id UUID NOT NULL REFERENCES auto_sync_configs(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, asset_name TEXT NOT NULL DEFAULT '',
  project TEXT NOT NULL DEFAULT '', group_name TEXT NOT NULL DEFAULT '',
  dimension_key TEXT NOT NULL CHECK (dimension_key ~ '^[0-9a-f]{64}$'),
  items_created_total BIGINT NOT NULL CHECK (items_created_total >= 0),
  last_created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (config_id, dimension_key)
);
