-- Empty owners retain their existing dimension keys, counters and timestamps.
ALTER TABLE auto_sync_creation_stats
  ADD COLUMN IF NOT EXISTS owner_username TEXT NOT NULL DEFAULT '';
