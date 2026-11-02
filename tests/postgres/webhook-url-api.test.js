"use strict";

process.env.NODE_ENV = "test";
process.env.DB_HOST = process.env.DELIVERY_WORKER_DB_HOST || "127.0.0.1";
process.env.DB_PORT = process.env.DELIVERY_WORKER_DB_PORT || "54330";
process.env.DB_NAME = process.env.DELIVERY_WORKER_DB_NAME || "tokentimer_delivery_worker";
process.env.DB_USER = process.env.DELIVERY_WORKER_DB_USER || "tokentimer";
process.env.DB_PASSWORD = process.env.DELIVERY_WORKER_DB_PASSWORD || "password";
process.env.TT_DEPLOYMENT = "self-hosted";
delete process.env.DB_SSL;
delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { createRequire } = require("node:module");
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const test = require("node:test");

const ROOT = path.join(__dirname, "..", "..");
const requireFromApi = createRequire(path.join(ROOT, "apps/api/package.json"));
const express = requireFromApi("express");
const { pool } = requireFromApi("./db/database");
const alertsRouter = requireFromApi("./routes/alerts");
const { validateWebhookConfiguration } = requireFromApi("./utils/webhookSafety");

function migrate() {
  const result = spawnSync(process.execPath, ["apps/api/migrations/migrate.js"], {
    cwd: ROOT,
    env: process.env,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout || `migrate exited ${result.status}`);
  }
}

function appFor(userId) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = { id: userId, email_verified: true, auth_method: "local" };
    req.isAuthenticated = () => true;
    next();
  });
  app.use(alertsRouter);
  return app;
}

async function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => resolve(server));
  });
}

async function put(server, urlPath, body) {
  const response = await fetch(`http://127.0.0.1:${server.address().port}${urlPath}`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text };
  }
  return { status: response.status, body: json };
}

test("alert settings reject a malformed webhook before saving any of the list", async () => {
  migrate();
  const user = await pool.query(
    `INSERT INTO users (email, display_name, auth_method, password_hash, email_verified)
     VALUES ($1, 'Webhook', 'local', 'hash', true) RETURNING id`,
    [`webhook-api-${crypto.randomUUID()}@example.com`],
  );
  const userId = user.rows[0].id;
  const workspaceId = crypto.randomUUID();
  await pool.query(
    `INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1, 'Hooks', 'oss', $2)`,
    [workspaceId, userId],
  );
  await pool.query(
    `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
     VALUES ($1, $2, 'admin', $1)`,
    [userId, workspaceId],
  );
  const server = await listen(appFor(userId));
  try {
    const good = [{ name: "Ops", url: "https://example.com/hooks/tokentimer", kind: "generic" }];
    const saved = await put(server, `/api/v1/workspaces/${workspaceId}/alert-settings`, {
      webhook_urls: good,
    });
    assert.equal(saved.status, 200);
    const stored = await pool.query(
      "SELECT webhook_urls FROM workspace_settings WHERE workspace_id = $1",
      [workspaceId],
    );
    assert.equal(stored.rows[0].webhook_urls[0].url, good[0].url);

    for (const badUrl of ["not-a-url", "ftp://example.com/hook", ""]) {
      const rejected = await put(server, `/api/v1/workspaces/${workspaceId}/alert-settings`, {
        webhook_urls: [
          good[0],
          { name: "Broken", url: badUrl, kind: "generic" },
        ],
      });
      assert.equal(rejected.status, 400, badUrl);
      assert.equal(rejected.body.code, "WEBHOOK_INVALID_URL");
    }
    const unchanged = await pool.query(
      "SELECT webhook_urls FROM workspace_settings WHERE workspace_id = $1",
      [workspaceId],
    );
    assert.equal(unchanged.rows[0].webhook_urls.length, 1);
    assert.equal(unchanged.rows[0].webhook_urls[0].url, good[0].url);

    const accountBad = await put(server, "/api/account/alert-settings", {
      webhook_urls: [{ url: "not-a-url", kind: "generic" }],
    });
    assert.equal(accountBad.status, 400);
    assert.equal(accountBad.body.code, "WEBHOOK_INVALID_URL");
    const accountFtp = await put(server, "/api/account/alert-settings", {
      webhook_urls: [{ url: "ftp://example.com/hook", kind: "generic" }],
    });
    assert.equal(accountFtp.status, 400);
    assert.equal(accountFtp.body.code, "WEBHOOK_INVALID_URL");

    process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK = "true";
    const privateUrl = validateWebhookConfiguration([
      { url: "http://127.0.0.1/hook", kind: "generic" },
    ]);
    assert.equal(privateUrl.ok, false);
    assert.equal(privateUrl.code, "WEBHOOK_PRIVATE_IP_BLOCKED");
    const deniedHost = validateWebhookConfiguration([
      { url: "https://example.com/hook", kind: "slack" },
    ]);
    assert.equal(deniedHost.ok, false);
    assert.equal(deniedHost.code, "WEBHOOK_HOST_NOT_ALLOWED");
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
  } finally {
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  }
});

test.after(async () => {
  await pool.end();
});
