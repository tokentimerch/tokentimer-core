-- Historical creation totals belong to the installation, not to inventory or
-- configuration rows. No foreign keys: cleanup and workspace deletion must
-- never decrease this counter. Start at rollout rather than backfilling from
-- run summaries, which cannot account for imports committed before a crash.
CREATE TABLE IF NOT EXISTS auto_sync_provider_stats (
  provider TEXT PRIMARY KEY,
  items_created_total BIGINT NOT NULL DEFAULT 0
    CHECK (items_created_total >= 0)
);

INSERT INTO auto_sync_provider_stats (provider)
VALUES ('github'), ('gitlab')
ON CONFLICT (provider) DO NOTHING;
