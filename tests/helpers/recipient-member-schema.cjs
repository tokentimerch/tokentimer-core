"use strict";

const fs = require("node:fs");
const path = require("node:path");

module.exports = async function applyMemberSchema(pool) {
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT,
      ADD COLUMN IF NOT EXISTS email_original TEXT,
      ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS auth_method TEXT NOT NULL DEFAULT 'local';
    CREATE TABLE IF NOT EXISTS workspace_memberships (
      workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role TEXT NOT NULL DEFAULT 'viewer', PRIMARY KEY (workspace_id, user_id)
    );
  `);
  await pool.query(fs.readFileSync(path.join(__dirname,
    "../../packages/recipient-verification/member-verification-migration.sql"), "utf8"));
};
