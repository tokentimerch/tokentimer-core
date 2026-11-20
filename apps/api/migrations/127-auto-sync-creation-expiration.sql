-- Optional expiry metadata for newly committed auto-sync creations.
ALTER TABLE auto_sync_creation_stats
  ADD COLUMN IF NOT EXISTS expiration TEXT NOT NULL DEFAULT '';
