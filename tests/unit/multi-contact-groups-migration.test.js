"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { migrations } = require(
  path.resolve(__dirname, "../../apps/api/migrations/migrate.js"),
);

describe("migration 52 multi contact groups per asset", () => {
  const migration = migrations.find((entry) => entry.version === 52);

  it("exists with the expected name", () => {
    assert.ok(migration, "migration 52 expected");
    assert.equal(migration.name, "multi_contact_groups_per_asset");
  });

  it("adds a helper unique on tokens so composite FKs can target (workspace_id, id)", () => {
    assert.match(
      migration.sql,
      /ADD CONSTRAINT uq_tokens_workspace_id UNIQUE \(workspace_id, id\)/,
    );
    assert.match(
      migration.sql,
      /SELECT 1 FROM pg_constraint WHERE conname = 'uq_tokens_workspace_id'/,
    );
  });

  it("creates both join tables with workspace-bound composite FKs", () => {
    assert.match(
      migration.sql,
      /CREATE TABLE IF NOT EXISTS token_contact_groups/,
    );
    assert.match(
      migration.sql,
      /FOREIGN KEY \(workspace_id, token_id\) REFERENCES tokens\(workspace_id, id\) ON DELETE CASCADE/,
    );
    assert.match(
      migration.sql,
      /CREATE TABLE IF NOT EXISTS certops_agent_contact_groups/,
    );
    assert.match(
      migration.sql,
      /FOREIGN KEY \(workspace_id, agent_id\) REFERENCES certops_agents\(workspace_id, id\) ON DELETE CASCADE/,
    );
    assert.match(
      migration.sql,
      /FOREIGN KEY \(workspace_id\) REFERENCES workspaces\(id\) ON DELETE CASCADE/,
    );
  });

  it("indexes both join tables for reverse lookup by workspace and group", () => {
    assert.match(
      migration.sql,
      /CREATE INDEX IF NOT EXISTS idx_token_contact_groups_workspace_group\s+ON token_contact_groups\(workspace_id, contact_group_id, token_id\)/,
    );
    assert.match(
      migration.sql,
      /CREATE INDEX IF NOT EXISTS idx_certops_agent_contact_groups_workspace_group\s+ON certops_agent_contact_groups\(workspace_id, contact_group_id, agent_id\)/,
    );
  });

  it("backfills join rows from non-empty singular contact_group_id values", () => {
    assert.match(
      migration.sql,
      /INSERT INTO token_contact_groups \(token_id, workspace_id, contact_group_id\)\s+SELECT id, workspace_id, contact_group_id\s+FROM tokens\s+WHERE contact_group_id IS NOT NULL\s+AND btrim\(contact_group_id\) <> ''\s+ON CONFLICT DO NOTHING/,
    );
    assert.match(
      migration.sql,
      /INSERT INTO certops_agent_contact_groups \(agent_id, workspace_id, contact_group_id\)\s+SELECT id, workspace_id, contact_group_id\s+FROM certops_agents\s+WHERE contact_group_id IS NOT NULL\s+AND btrim\(contact_group_id\) <> ''\s+ON CONFLICT DO NOTHING/,
    );
  });

  it("creates weekly_digest_recipient_log as the digest skip/claim key", () => {
    assert.match(
      migration.sql,
      /CREATE TABLE IF NOT EXISTS weekly_digest_recipient_log/,
    );
    assert.match(
      migration.sql,
      /CREATE UNIQUE INDEX IF NOT EXISTS uq_weekly_digest_recipient_week_channel\s+ON weekly_digest_recipient_log\(workspace_id, week_start_date, channel, recipient_key\)/,
    );
    assert.match(
      migration.sql,
      /status TEXT NOT NULL DEFAULT 'pending' CHECK \(status IN \('pending', 'sent'\)\)/,
    );
    assert.match(
      migration.sql,
      /attempt_count INTEGER NOT NULL DEFAULT 0 CHECK \(attempt_count >= 0\)/,
    );
    assert.match(migration.sql, /lease_expires_at TIMESTAMPTZ NULL/);
  });

  it("uses only additive DDL (no DROP TABLE/DROP COLUMN) and keeps singular contact_group_id", () => {
    assert.doesNotMatch(migration.sql, /DROP TABLE/i);
    assert.doesNotMatch(migration.sql, /DROP COLUMN/i);
    assert.doesNotMatch(
      migration.sql,
      /DROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?contact_group_id/i,
    );
  });
});

describe("migration 53 bootstrap contact_group_ids", () => {
  const migration = migrations.find((entry) => entry.version === 53);

  it("exists with the expected name", () => {
    assert.ok(migration, "migration 53 expected");
    assert.equal(migration.name, "bootstrap_contact_group_ids");
  });

  it("adds JSONB contact_group_ids and backfills from the singular mirror", () => {
    assert.match(
      migration.sql,
      /ALTER TABLE certops_agent_bootstrap_tokens\s+ADD COLUMN IF NOT EXISTS contact_group_ids JSONB NOT NULL DEFAULT '\[\]'::jsonb/,
    );
    assert.match(
      migration.sql,
      /SET contact_group_ids = jsonb_build_array\(contact_group_id\)/,
    );
    assert.doesNotMatch(migration.sql, /DROP TABLE/i);
    assert.doesNotMatch(migration.sql, /DROP COLUMN/i);
  });
});

describe("migration 54 rebuild join from singular", () => {
  const migration = migrations.find((entry) => entry.version === 54);

  it("exists with the expected name", () => {
    assert.ok(migration, "migration 54 expected");
    assert.equal(migration.name, "rebuild_contact_group_join_from_singular");
  });

  it("rebuilds both join tables from the singular column before switch-reads", () => {
    assert.match(migration.sql, /DELETE FROM token_contact_groups/);
    assert.match(migration.sql, /DELETE FROM certops_agent_contact_groups/);
    assert.match(
      migration.sql,
      /INSERT INTO token_contact_groups \(token_id, workspace_id, contact_group_id\)\s+SELECT id, workspace_id, contact_group_id\s+FROM tokens[\s\S]*?ON CONFLICT \(token_id, contact_group_id\) DO NOTHING/,
    );
    assert.match(
      migration.sql,
      /INSERT INTO certops_agent_contact_groups \(agent_id, workspace_id, contact_group_id\)\s+SELECT id, workspace_id, contact_group_id\s+FROM certops_agents[\s\S]*?ON CONFLICT \(agent_id, contact_group_id\) DO NOTHING/,
    );
  });
});
