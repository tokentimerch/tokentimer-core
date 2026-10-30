"use strict";

// Run only against a migrated disposable *_issue364_test database. Every
// PagerDuty send is injected; this suite never contacts a real integration.
const { before, beforeEach, after, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const request = require("supertest");
const express = require("../../apps/api/node_modules/express");
const { pool } = require("../../apps/api/db/database");
const Token = require("../../apps/api/db/models/Token");
const {
  upsertImportedToken,
} = require("../../apps/api/services/autoSyncProvenance");
const {
  updateCertificateTokenFacts,
} = require("../../apps/api/services/certops/inventory");
const { requeueAlertsCore } = require("../../apps/api/services/alertQueue");

let lifecycle,
  worker,
  discovery,
  workerPool,
  client,
  userId,
  workspaceId,
  tokenId,
  app;
let sequence = 0;
let companionVerification, companionState;
let events = [];
const keyA = "A".repeat(32),
  keyB = "B".repeat(32);
const pd = {
  name: "pd",
  kind: "pagerduty",
  url: "https://events.pagerduty.com/v2/enqueue",
  routingKey: keyA,
};
const group = {
  id: "ops",
  name: "Operations",
  webhook_names: ["pd"],
  thresholds: [30, 7, 1, 0],
};
const accepted = { success: true, status: 202 };
const day = (days) =>
  new Date(Date.now() + days * 86400000).toISOString().slice(0, 10);

async function send(url, body, kind) {
  events.push({ url, body, kind });
  return accepted;
}
async function settings(webhooks = [pd], groups = [group]) {
  await pool.query(
    `UPDATE workspace_settings SET webhook_urls=$2, contact_groups=$3 WHERE workspace_id=$1`,
    [workspaceId, JSON.stringify(webhooks), JSON.stringify(groups)],
  );
}
async function queue(
  threshold = 1,
  targetId = tokenId,
  suffix = `${++sequence}`,
) {
  const result = await pool.query(
    `INSERT INTO alert_queue
    (user_id, token_id, alert_key, threshold_days, due_date, channels)
    VALUES ($1,$2,$3,$4,CURRENT_DATE,'["webhooks"]') RETURNING *`,
    [
      userId,
      targetId,
      `token_expiry:${targetId}:poswin:${threshold}:${suffix}`,
      threshold,
    ],
  );
  return { ...result.rows[0], workspace_id: workspaceId };
}
async function incidentRows() {
  return (
    await pool.query(
      "SELECT * FROM pagerduty_incidents WHERE workspace_id=$1 ORDER BY created_at, id",
      [workspaceId],
    )
  ).rows;
}
async function due(id = null) {
  await pool.query(
    `UPDATE pagerduty_incidents SET next_attempt_at=NOW()-INTERVAL '1 second'
    WHERE workspace_id=$1 AND ($2::uuid IS NULL OR id=$2)`,
    [workspaceId, id],
  );
}
async function reconcile(sender = send, options = {}) {
  return lifecycle.reconcilePagerDutyIncidents(client, {
    send: sender,
    ...options,
  });
}
async function trigger(webhook = pd) {
  const alert = await queue();
  const result = await lifecycle.deliverPagerDutyExpiration(client, {
    alert,
    webhook,
    send,
  });
  assert.equal(result.success, true);
  return {
    alert,
    incident: (await incidentRows()).find(
      (row) => row.trigger_alert_queue_id === alert.id,
    ),
  };
}
async function runWorker(sender = send) {
  return worker.deliveryWorkerJob({
    closePool: false,
    webhookSender: sender,
    incidentEmailSender: async () => ({ success: true }),
  });
}
async function certificate() {
  await pool.query(
    "UPDATE tokens SET type='ssl_cert',category='cert' WHERE id=$1",
    [tokenId],
  );
  return (
    await pool.query(
      `INSERT INTO managed_certificates
    (workspace_id,token_id,status,source,name,common_name,not_after,fingerprint_sha256)
    VALUES ($1,$2,'active','import','Certificate','certificate.example.test',$3,$4) RETURNING *`,
      [
        workspaceId,
        tokenId,
        `${day(1)}T00:00:00Z`,
        crypto.randomBytes(32).toString("hex"),
      ],
    )
  ).rows[0];
}

async function history(
  alert,
  channel,
  status,
  metadata,
  workspace = workspaceId,
) {
  await pool.query(
    `INSERT INTO alert_delivery_log(alert_queue_id,user_id,token_id,workspace_id,channel,status,metadata)
    VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)`,
    [
      alert.id,
      userId,
      alert.token_id,
      workspace,
      channel,
      status,
      JSON.stringify(metadata),
    ],
  );
}
async function blockParent(alert, channels = ["webhooks"]) {
  await pool.query(
    `UPDATE alert_queue SET status='blocked',channels=$2::jsonb,attempts=20,attempts_webhooks=20,
    error_message='webhooks: retries exhausted; MAX_ATTEMPTS',delivery_claim_id=NULL,next_attempt_at=NULL WHERE id=$1`,
    [alert.id, JSON.stringify(channels)],
  );
  const { raiseOperationalNotification } =
    await import("../../apps/worker/src/shared/opNotifications.js");
  await raiseOperationalNotification(client, {
    workspaceId,
    tokenId,
    category: "delivery",
    type: "delivery_blocked",
    severity: "critical",
    dedupeKey: `delivery_blocked:${alert.id}`,
    title: "Delivery blocked",
    message: "Retries exhausted",
    metadata: { alert_queue_id: alert.id },
  });
}
async function parentRow(alert) {
  return (await pool.query("SELECT * FROM alert_queue WHERE id=$1", [alert.id]))
    .rows[0];
}
async function legacyAsset() {
  await pool.query("DELETE FROM tokens WHERE id=$1", [tokenId]);
  tokenId = (
    await pool.query(
      `INSERT INTO tokens(user_id,created_by,workspace_id,name,type,category,expiration)
    VALUES($1,$1,NULL,'Legacy asset','api_key','key_secret',$2) RETURNING id`,
      [userId, day(1)],
    )
  ).rows[0].id;
}
async function openFailureNotifications(alert) {
  return (
    await pool.query(
      "SELECT id FROM operational_notifications WHERE workspace_id=$1 AND dedupe_key=$2 AND resolved_at IS NULL",
      [workspaceId, `delivery_blocked:${alert.id}`],
    )
  ).rowCount;
}

async function verifiedContact(email, status = "verified") {
  const id = crypto.randomUUID();
  await pool.query(
    "INSERT INTO workspace_contacts(id,workspace_id,first_name,last_name,details) VALUES($1,$2,'Cross','PR',$3::jsonb)",
    [id, workspaceId, JSON.stringify({ email })],
  );
  await pool.query(
    `INSERT INTO contact_channel_verifications
    (workspace_id,contact_id,channel,destination_normalized,destination_fingerprint,status,consent_at)
    VALUES($1,$2,'email',$3,$4,$5,CASE WHEN $5='verified' THEN NOW() END)`,
    [
      workspaceId,
      id,
      email,
      companionVerification.destinationFingerprint("email", email),
      status,
    ],
  );
  return id;
}

describe(
  "PostgreSQL PagerDuty expiration incident lifecycle",
  { concurrency: false },
  () => {
    before(async () => {
      assert.match(
        process.env.DB_NAME || "",
        /_issue364_test$/,
        "Use a disposable issue364 test database",
      );
      process.env.NODE_ENV = "test";
      process.env.ENABLE_METRICS = "false";
      process.env.ALERT_MAX_ATTEMPTS = "20";
      process.env.RECIPIENT_FINGERPRINT_SECRET = "pagerduty-cross-pr-test-only";
      if (process.env.PAGERDUTY_COMPANION_ROOT) {
        const root = path.resolve(process.env.PAGERDUTY_COMPANION_ROOT);
        companionVerification = require(
          path.join(root, "packages/recipient-verification"),
        );
        await pool.query(
          fs.readFileSync(
            path.join(root, "packages/recipient-verification/migration.sql"),
            "utf8",
          ),
        );
        const { createNotificationDeliveryState } =
          await import("../../apps/worker/src/shared/notificationDeliveryState.js");
        companionState = createNotificationDeliveryState(companionVerification);
      }
      lifecycle = await import("../../apps/worker/src/pagerduty-incidents.js");
      worker = await import("../../apps/worker/src/delivery-worker.js");
      discovery = await import("../../apps/worker/src/queue-manager.js");
      ({ pool: workerPool } = await import("../../apps/worker/src/db.js"));
      client = await pool.connect();
      assert.equal(
        (
          await pool.query(
            "SELECT 1 FROM migrations WHERE version=92 AND name='pagerduty_incident_lifecycle'",
          )
        ).rowCount,
        1,
      );
      // Old installations may retain the nullable v1 token shape. Simulate it
      // only in this guarded disposable database; production DDL is unchanged.
      await pool.query(
        "ALTER TABLE tokens ALTER COLUMN workspace_id DROP NOT NULL",
      );
      userId = (
        await pool.query(
          `INSERT INTO users(email,display_name,email_verified,password_hash)
      VALUES ($1,'PagerDuty test',TRUE,'test-only') RETURNING id`,
          [`issue364-${crypto.randomUUID()}@example.test`],
        )
      ).rows[0].id;
      app = express();
      app.use(express.json());
      app.use((req, _res, next) => {
        req.user = { id: userId, email_verified: true };
        req.isAuthenticated = () => true;
        next();
      });
      app.use(require("../../apps/api/routes/tokens"));
    });
    beforeEach(async () => {
      process.env.TT_DEPLOYMENT = "self-hosted";
      process.env.RECIPIENT_VERIFICATION_MODE = "off";
      await pool.query(
        "DELETE FROM tokens WHERE user_id=$1 AND workspace_id IS NULL",
        [userId],
      );
      if (workspaceId)
        await pool.query("DELETE FROM workspaces WHERE id=$1", [workspaceId]);
      workspaceId = crypto.randomUUID();
      await pool.query(
        "INSERT INTO workspaces(id,name,created_by) VALUES ($1,'PagerDuty test',$2)",
        [workspaceId, userId],
      );
      await pool.query(
        "INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'admin')",
        [workspaceId, userId],
      );
      await pool.query(
        `INSERT INTO workspace_settings
      (workspace_id,email_alerts_enabled,webhooks_alerts_enabled,default_contact_group_id,delivery_window_start,delivery_window_end)
      VALUES ($1,FALSE,TRUE,'ops','00:00','23:59')`,
        [workspaceId],
      );
      await settings();
      tokenId = (
        await pool.query(
          `INSERT INTO tokens(user_id,created_by,workspace_id,name,type,category,expiration)
      VALUES ($1,$1,$2,'Expiring asset','api_key','key_secret',$3) RETURNING id`,
          [userId, workspaceId, day(1)],
        )
      ).rows[0].id;
      events = [];
    });
    after(async () => {
      if (userId)
        await pool.query(
          "DELETE FROM tokens WHERE user_id=$1 AND workspace_id IS NULL",
          [userId],
        );
      await pool.query(
        "ALTER TABLE tokens ALTER COLUMN workspace_id SET NOT NULL",
      );
      if (workspaceId)
        await pool.query("DELETE FROM workspaces WHERE id=$1", [workspaceId]);
      client?.release();
      await workerPool?.end();
      await pool.end();
    });

    it("defers unaccepted triggers and retries across quiet-hour boundaries without spending attempts", async () => {
      await pool.query(
        "UPDATE workspace_settings SET delivery_window_start='09:00',delivery_window_end='17:00',delivery_window_tz='UTC' WHERE workspace_id=$1",
        [workspaceId],
      );
      const alert = await queue();
      const intent = await lifecycle.enqueuePagerDutyIncident(client, {
        alert,
        webhook: pd,
      });
      const at = (time) => new Date(`${day(0)}T${time}:00Z`);
      const first = await lifecycle.processPagerDutyIncident(
        client,
        intent.id,
        { send, now: at("08:59") },
      );
      assert.equal(first.error, "pagerduty_out_of_window");
      assert.equal((await incidentRows())[0].trigger_attempts, 0);
      assert.equal(events.length, 0);
      await due();
      await lifecycle.processPagerDutyIncident(client, intent.id, {
        now: at("09:00"),
        send: async (url, body) => {
          events.push({ url, body });
          return { success: false, status: 503 };
        },
      });
      assert.equal((await incidentRows())[0].trigger_attempts, 1);
      await due();
      const deferred = await lifecycle.processPagerDutyIncident(
        client,
        intent.id,
        { send, now: at("17:01") },
      );
      assert.equal(deferred.error, "pagerduty_out_of_window");
      const parked = (await incidentRows())[0];
      assert.equal(parked.trigger_attempts, 1);
      assert.equal(parked.action_attempts, 1);
      assert.equal(parked.retry_exhausted, false);
      assert.equal(parked.claim_id, null);
      assert.equal(events.length, 1);
      await due();
      await lifecycle.processPagerDutyIncident(client, intent.id, {
        send,
        now: at("09:00"),
      });
      const accepted = (await incidentRows())[0];
      assert.equal(accepted.state, "open");
      assert.equal(accepted.trigger_attempts, 2);
      assert.equal(accepted.dedup_key, intent.dedup_key);
      assert.equal(events[0].body.dedup_key, events[1].body.dedup_key);
    });

    it("resolves validated recovery outside quiet hours for an already accepted incident", async () => {
      const { incident } = await trigger();
      await pool.query(
        "UPDATE workspace_settings SET delivery_window_start='09:00',delivery_window_end='17:00',delivery_window_tz='UTC' WHERE workspace_id=$1",
        [workspaceId],
      );
      await Token.update(tokenId, { expiration: day(180) });
      await lifecycle.processPagerDutyIncident(client, incident.id, {
        send,
        now: new Date(`${day(0)}T22:00:00Z`),
      });
      assert.equal((await incidentRows())[0].state, "resolved");
      assert.deepEqual(
        events.map((row) => row.body.event_action),
        ["trigger", "resolve"],
      );
      assert.equal(events[0].body.dedup_key, events[1].body.dedup_key);
    });

    it("invalidates dispatch when its committed delivery-window settings change", async () => {
      const intent = await lifecycle.enqueuePagerDutyIncident(client, {
        alert: await queue(),
        webhook: pd,
      });
      let changed = false;
      const concurrent = {
        query: async (sql, parameters) => {
          if (
            !changed &&
            sql.includes("SET trigger_attempts = trigger_attempts + 1")
          ) {
            changed = true;
            await pool.query(
              "UPDATE workspace_settings SET delivery_window_start='22:00',delivery_window_end='23:00' WHERE workspace_id=$1",
              [workspaceId],
            );
          }
          return client.query(sql, parameters);
        },
      };
      const outcome = await lifecycle.processPagerDutyIncident(
        concurrent,
        intent.id,
        { send, now: new Date(`${day(0)}T09:00:00Z`) },
      );
      assert.equal(outcome.error, "dispatch_snapshot_changed");
      assert.equal(events.length, 0);
      assert.equal((await incidentRows())[0].action_attempts, 0);
      await due();
      const deferred = await lifecycle.processPagerDutyIncident(
        client,
        intent.id,
        { send, now: new Date(`${day(0)}T09:00:00Z`) },
      );
      assert.equal(deferred.error, "pagerduty_out_of_window");
    });

    it("keeps a legacy blocked alert's unsent escalation email open and retries its delivery", async () => {
      await legacyAsset();
      const alert = await queue();
      await blockParent(alert);
      const { retryPendingOperationalIncidentEmails } =
        await import("../../apps/worker/src/shared/opNotifications.js");
      let emails = 0;
      await retryPendingOperationalIncidentEmails(client, async () => {
        emails++;
        return { success: true };
      });
      assert.equal(emails, 1);
      assert.equal((await parentRow(alert)).status, "blocked");
      assert.equal(await openFailureNotifications(alert), 1);
      const row = (
        await pool.query(
          "SELECT email_sent_at,resolved_at FROM operational_notifications WHERE workspace_id=$1 AND dedupe_key=$2",
          [workspaceId, `delivery_blocked:${alert.id}`],
        )
      ).rows[0];
      assert.ok(row.email_sent_at);
      assert.equal(row.resolved_at, null);
    });

    it("retains blocked legacy escalation when ownership is ambiguous without sending across workspaces", async () => {
      await legacyAsset();
      const alert = await queue();
      await blockParent(alert);
      const other = crypto.randomUUID();
      await pool.query(
        "INSERT INTO workspaces(id,name,created_by) VALUES($1,'Other owner workspace',$2)",
        [other, userId],
      );
      try {
        const {
          retryPendingOperationalIncidentEmails,
          reconcileStaleDeliveryIncidents,
        } = await import("../../apps/worker/src/shared/opNotifications.js");
        let sent = 0;
        await retryPendingOperationalIncidentEmails(client, async () => {
          sent++;
          return { success: true };
        });
        await reconcileStaleDeliveryIncidents(client);
        assert.equal(sent, 0);
        assert.equal((await parentRow(alert)).status, "blocked");
        assert.equal(await openFailureNotifications(alert), 1);
      } finally {
        await pool.query("DELETE FROM workspaces WHERE id=$1", [other]);
      }
    });

    it("does not clear an escalation if its source becomes blocked before the resolution write", async () => {
      const alert = await queue();
      await blockParent(alert);
      await pool.query("UPDATE alert_queue SET status='sent' WHERE id=$1", [
        alert.id,
      ]);
      const { retryPendingOperationalIncidentEmails } =
        await import("../../apps/worker/src/shared/opNotifications.js");
      let changed = false;
      const concurrent = {
        query: async (sql, values) => {
          if (
            !changed &&
            sql.includes(
              "UPDATE operational_notifications SET resolved_at=NOW()",
            )
          ) {
            changed = true;
            await pool.query(
              "UPDATE alert_queue SET status='blocked' WHERE id=$1",
              [alert.id],
            );
          }
          return client.query(sql, values);
        },
      };
      await retryPendingOperationalIncidentEmails(concurrent, async () => {
        throw new Error("No stale escalation send");
      });
      assert.equal(changed, true);
      assert.equal(await openFailureNotifications(alert), 1);
    });

    it(
      "reconciles the actual #461 ledger using verified recipients and retains evidence extensions",
      { skip: !process.env.PAGERDUTY_COMPANION_ROOT },
      async () => {
        process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
        const first = await verifiedContact("alice@example.test"),
          second = await verifiedContact("bob@example.test", "pending");
        await settings(
          [pd],
          [{ ...group, email_contact_ids: [first, second] }],
        );
        await pool.query(
          "UPDATE workspace_settings SET email_alerts_enabled=TRUE WHERE workspace_id=$1",
          [workspaceId],
        );
        const alert = await queue();
        const intent = await lifecycle.enqueuePagerDutyIncident(client, {
          alert,
          webhook: pd,
        });
        const ledger = companionVerification.mergeDeliveryAttempt({
          prior: ["email", "webhooks"],
          liveChannels: ["email", "webhooks"],
          attempted: [
            { channel: "email", success: false },
            { channel: "webhooks", success: false },
          ],
        }).ledger;
        ledger.outcomes.email.receiptRevision = "keep";
        ledger.outcomes.webhooks.retryGeneration = 3;
        await history(alert, "email", "success", {
          recipient: "alice@example.test",
        });
        await blockParent(alert, ledger);
        await lifecycle.processPagerDutyIncident(client, intent.id, {
          send,
          deliveryState: companionState,
        });
        const parent = await parentRow(alert);
        assert.equal(parent.status, "sent");
        assert.equal(parent.channels.version, 1);
        assert.deepEqual(parent.channels.retry, []);
        assert.deepEqual(parent.channels.required, ["email", "webhooks"]);
        assert.equal(parent.channels.outcomes.email.state, "sent");
        assert.equal(parent.channels.outcomes.email.receiptRevision, "keep");
        assert.equal(parent.channels.outcomes.webhooks.retryGeneration, 3);
        assert.equal(await openFailureNotifications(alert), 0);
        assert.equal(events.length, 1);
        assert.equal(
          (
            await pool.query(
              "SELECT 1 FROM alert_delivery_log WHERE alert_queue_id=$1 AND channel='email'",
              [alert.id],
            )
          ).rowCount,
          1,
        );
      },
    );

    it(
      "retains a versioned ledger's unrelated failure and retry state until all eligible recipients have evidence",
      { skip: !process.env.PAGERDUTY_COMPANION_ROOT },
      async () => {
        process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
        const first = await verifiedContact("alice@example.test"),
          second = await verifiedContact("bob@example.test");
        await settings(
          [pd],
          [{ ...group, email_contact_ids: [first, second] }],
        );
        await pool.query(
          "UPDATE workspace_settings SET email_alerts_enabled=TRUE WHERE workspace_id=$1",
          [workspaceId],
        );
        const alert = await queue();
        const intent = await lifecycle.enqueuePagerDutyIncident(client, {
          alert,
          webhook: pd,
        });
        const failed = {
          state: "failed",
          terminal: false,
          code: "mail_retry",
          receiptRevision: "keep",
        };
        const ledger = {
          version: 1,
          required: ["email", "webhooks"],
          retry: ["email", "webhooks"],
          outcomes: {
            email: failed,
            webhooks: { state: "failed", terminal: false, retryGeneration: 2 },
          },
        };
        await blockParent(alert, ledger);
        await history(alert, "email", "success", {
          recipient: "alice@example.test",
        });
        await lifecycle.processPagerDutyIncident(client, intent.id, {
          send,
          deliveryState: companionState,
        });
        let parent = await parentRow(alert);
        assert.equal(parent.status, "blocked");
        assert.deepEqual(parent.channels.retry, ["email"]);
        assert.deepEqual(parent.channels.outcomes.email, failed);
        assert.equal(await openFailureNotifications(alert), 1);
        await history(alert, "email", "success", {
          recipient: "bob@example.test",
        });
        await due();
        await lifecycle.processPagerDutyIncident(client, intent.id, {
          send,
          deliveryState: companionState,
        });
        parent = await parentRow(alert);
        assert.equal(parent.status, "sent");
        assert.equal(await openFailureNotifications(alert), 0);
        assert.equal(events.length, 1);
      },
    );

    it(
      "keeps #461 verification lookup outages retryable and reconciles after consent lookup recovers",
      { skip: !process.env.PAGERDUTY_COMPANION_ROOT },
      async () => {
        process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
        const id = await verifiedContact("verified@example.test");
        await settings([pd], [{ ...group, email_contact_ids: [id] }]);
        await pool.query(
          "UPDATE workspace_settings SET email_alerts_enabled=TRUE WHERE workspace_id=$1",
          [workspaceId],
        );
        const { createNotificationDeliveryState } =
          await import("../../apps/worker/src/shared/notificationDeliveryState.js");
        let lookups = 0;
        const failingState = createNotificationDeliveryState({
          ...companionVerification,
          filterDeliveryRecipients: (args) =>
            companionVerification.filterDeliveryRecipients({
              ...args,
              client: {
                query(sql, values) {
                  if (sql.includes("RV_DELIVERY_LOOKUP")) {
                    lookups++;
                    return Promise.reject(
                      Object.assign(new Error("fixture timeout"), {
                        code: "57014",
                      }),
                    );
                  }
                  return args.client.query(sql, values);
                },
              },
            }),
        });
        const alert = await queue();
        await pool.query(
          "UPDATE alert_queue SET channels=$2::jsonb WHERE id=$1",
          [
            alert.id,
            JSON.stringify(
              companionVerification.mergeDeliveryAttempt({
                prior: ["email", "webhooks"],
                attempted: [],
                liveChannels: ["email", "webhooks"],
              }).ledger,
            ),
          ],
        );
        await worker.deliveryWorkerJob({
          closePool: false,
          webhookSender: send,
          incidentEmailSender: async () => ({ success: true }),
          deliveryState: failingState,
        });
        assert.ok(lookups > 0);
        let parent = await parentRow(alert);
        assert.equal(parent.status, "partial");
        assert.equal(
          parent.channels.outcomes.email.code,
          "RECIPIENT_VERIFICATION_UNAVAILABLE",
        );
        assert.equal(parent.channels.outcomes.email.terminal, false);
        assert.deepEqual(parent.channels.retry, ["email"]);
        const incident = (await incidentRows())[0];
        const snapshot = JSON.stringify(parent.channels);
        assert.equal(
          await lifecycle.reconcilePagerDutyParentAlert(client, incident, {
            deliveryState: failingState,
          }),
          false,
        );
        assert.equal(
          JSON.stringify((await parentRow(alert)).channels),
          snapshot,
        );
        await history(alert, "email", "success", {
          recipient: "verified@example.test",
        });
        assert.equal(
          await lifecycle.reconcilePagerDutyParentAlert(client, incident, {
            deliveryState: companionState,
          }),
          true,
        );
        parent = await parentRow(alert);
        assert.equal(parent.status, "sent");
        assert.deepEqual(parent.channels.retry, []);
        assert.equal(await openFailureNotifications(alert), 0);
        assert.equal(events.length, 1);
      },
    );

    it(
      "uses #461 recipient admission in foreground delivery without sending to unverified contacts",
      { skip: !process.env.PAGERDUTY_COMPANION_ROOT },
      async () => {
        process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
        const id = await verifiedContact("unverified@example.test", "pending");
        await settings([pd], [{ ...group, email_contact_ids: [id] }]);
        await pool.query(
          "UPDATE workspace_settings SET email_alerts_enabled=TRUE WHERE workspace_id=$1",
          [workspaceId],
        );
        const alert = await queue();
        await worker.deliveryWorkerJob({
          closePool: false,
          webhookSender: send,
          incidentEmailSender: async () => ({ success: true }),
          deliveryState: companionState,
        });
        const parent = await parentRow(alert);
        assert.equal(parent.status, "partial");
        assert.equal(parent.channels.version, 1);
        assert.deepEqual(parent.channels.retry, []);
        assert.equal(parent.channels.outcomes.email.reason, "eligibility");
        assert.equal(parent.attempts_email, 0);
        assert.equal(events.length, 1);
        assert.equal(
          (
            await pool.query(
              "SELECT 1 FROM alert_delivery_log WHERE alert_queue_id=$1 AND channel='email' AND status='success'",
              [alert.id],
            )
          ).rowCount,
          0,
        );
      },
    );

    it(
      "matches #461 terminal eligibility when every email recipient is unverified",
      { skip: !process.env.PAGERDUTY_COMPANION_ROOT },
      async () => {
        process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
        const id = await verifiedContact("pending@example.test", "pending");
        await settings([pd], [{ ...group, email_contact_ids: [id] }]);
        await pool.query(
          "UPDATE workspace_settings SET email_alerts_enabled=TRUE WHERE workspace_id=$1",
          [workspaceId],
        );
        const alert = await queue();
        const intent = await lifecycle.enqueuePagerDutyIncident(client, {
          alert,
          webhook: pd,
        });
        await blockParent(alert, {
          version: 1,
          required: ["email", "webhooks"],
          retry: [],
          outcomes: {
            email: {
              state: "blocked",
              terminal: true,
              reason: "eligibility",
              code: "NO_VERIFIED_RECIPIENTS",
            },
          },
        });
        await lifecycle.processPagerDutyIncident(client, intent.id, {
          send,
          deliveryState: companionState,
        });
        const parent = await parentRow(alert);
        assert.equal(parent.status, "partial");
        assert.deepEqual(parent.channels.retry, []);
        assert.equal(parent.channels.outcomes.email.reason, "eligibility");
        assert.equal(parent.channels.outcomes.email.state, "blocked");
        assert.equal(await openFailureNotifications(alert), 1);
      },
    );

    it("preserves versioned foreground settlement and does not reclaim terminal partial delivery", async () => {
      const alert = await queue();
      const { webhookDestinationId } =
        await import("../../apps/worker/src/shared/webhookDestinations.js");
      await history(alert, "webhooks", "success", {
        kind: "pagerduty",
        event_action: "trigger",
        destination_id: webhookDestinationId(workspaceId, pd),
      });
      const ledger = {
        version: 1,
        retry: ["webhooks"],
        required: ["email", "webhooks"],
        outcomes: {
          email: {
            state: "blocked",
            terminal: true,
            reason: "provider",
            code: "mail_permanent",
            receiptRevision: "keep",
          },
          webhooks: { state: "failed", terminal: false, retryGeneration: 4 },
        },
      };
      await pool.query(
        "UPDATE alert_queue SET channels=$2::jsonb,attempts=1 WHERE id=$1",
        [alert.id, JSON.stringify(ledger)],
      );
      await runWorker();
      const parent = await parentRow(alert);
      assert.equal(parent.status, "partial");
      assert.equal(parent.channels.version, 1);
      assert.deepEqual(parent.channels.retry, []);
      assert.equal(parent.channels.outcomes.email.receiptRevision, "keep");
      assert.equal(parent.channels.outcomes.webhooks.state, "sent");
      assert.equal(parent.channels.outcomes.webhooks.retryGeneration, 4);
      assert.equal(parent.next_attempt_at, null);
      await runWorker();
      assert.equal((await parentRow(alert)).attempts, parent.attempts);
      assert.equal(events.length, 0);
      assert.equal((await incidentRows()).length, 0);
    });

    it("preserves unknown ledger formats without pretending parent delivery completed", async () => {
      const alert = await queue();
      const intent = await lifecycle.enqueuePagerDutyIncident(client, {
        alert,
        webhook: pd,
      });
      const unknown = {
        version: 2,
        required: ["webhooks"],
        retry: ["webhooks"],
        outcomes: {},
      };
      await blockParent(alert, unknown);
      await lifecycle.processPagerDutyIncident(client, intent.id, { send });
      assert.equal((await parentRow(alert)).status, "blocked");
      assert.deepEqual((await parentRow(alert)).channels, unknown);
      assert.equal(await openFailureNotifications(alert), 1);
    });

    it("delivers and resolves an authorized legacy asset without changing its ownership", async () => {
      await legacyAsset();
      await discovery.queueDiscoveryJob({ closePool: false });
      await runWorker();
      assert.equal(events.length, 1);
      const [incident] = await incidentRows();
      assert.ok(incident);
      assert.equal(incident.token_id, null);
      assert.equal(incident.token_id_snapshot, tokenId);
      assert.equal(
        (
          await pool.query("SELECT workspace_id FROM tokens WHERE id=$1", [
            tokenId,
          ])
        ).rows[0].workspace_id,
        null,
      );
      const delivered = (
        await pool.query(
          "SELECT * FROM alert_delivery_log WHERE metadata->>'incident_id'=$1",
          [incident.id],
        )
      ).rows[0];
      assert.equal(delivered.workspace_id, workspaceId);
      assert.equal(delivered.token_id, tokenId);
      await Token.update(tokenId, { expiration: day(180) });
      await due();
      await reconcile();
      assert.equal(events.at(-1).body.event_action, "resolve");
      assert.equal(events[0].body.dedup_key, events[1].body.dedup_key);
    });

    it("reports missing legacy ownership as failure rather than successful delivery", async () => {
      await legacyAsset();
      const alert = await queue();
      await pool.query("DELETE FROM workspaces WHERE id=$1", [workspaceId]);
      const outcome = await lifecycle.deliverPagerDutyExpiration(client, {
        alert,
        webhook: pd,
        send,
      });
      assert.equal(outcome.success, false);
      assert.equal(outcome.error, "pagerduty_asset_workspace_unavailable");
      assert.equal(events.length, 0);
      assert.equal(
        (
          await pool.query(
            "SELECT 1 FROM pagerduty_incidents WHERE token_id_snapshot=$1",
            [tokenId],
          )
        ).rowCount,
        0,
      );
      assert.equal(
        (
          await pool.query(
            "SELECT 1 FROM alert_delivery_log WHERE alert_queue_id=$1",
            [alert.id],
          )
        ).rowCount,
        0,
      );
    });

    it("fails closed for ambiguous legacy owners and does not borrow another tenant's configuration", async () => {
      await legacyAsset();
      const other = crypto.randomUUID();
      await pool.query(
        "INSERT INTO workspaces(id,name,created_by) VALUES($1,'Ambiguous owner',$2)",
        [other, userId],
      );
      try {
        const alert = await queue();
        await runWorker();
        const row = await parentRow(alert);
        assert.equal(row.status, "failed");
        assert.match(row.error_message, /asset_workspace_unavailable/);
        assert.equal(events.length, 0);
        assert.equal((await incidentRows()).length, 0);
      } finally {
        await pool.query("DELETE FROM workspaces WHERE id=$1", [other]);
      }
    });

    for (const [role, allowed] of [
      ["workspace_manager", true],
      ["viewer", false],
    ]) {
      it(`legacy membership fallback ${allowed ? "accepts" : "rejects"} ${role}`, async () => {
        const otherUser = (
          await pool.query(
            "INSERT INTO users(email,display_name,password_hash) VALUES($1,'Workspace owner','test-only') RETURNING id",
            [`owner-${crypto.randomUUID()}@example.test`],
          )
        ).rows[0].id;
        await pool.query("UPDATE workspaces SET created_by=$2 WHERE id=$1", [
          workspaceId,
          otherUser,
        ]);
        await pool.query(
          "UPDATE workspace_memberships SET role=$3 WHERE workspace_id=$1 AND user_id=$2",
          [workspaceId, userId, role],
        );
        await legacyAsset();
        const outcome = await lifecycle.deliverPagerDutyExpiration(client, {
          alert: await queue(),
          webhook: pd,
          send,
        });
        assert.equal(outcome.success, allowed);
        assert.equal(events.length, allowed ? 1 : 0);
        if (!allowed)
          assert.equal(outcome.error, "pagerduty_asset_workspace_unavailable");
      });
    }

    it("retains a valid legacy failure notification and requeues it in the resolved workspace", async () => {
      await legacyAsset();
      const alert = await queue();
      await blockParent(alert);
      const { reconcileStaleDeliveryIncidents } =
        await import("../../apps/worker/src/shared/opNotifications.js");
      await reconcileStaleDeliveryIncidents(client);
      assert.equal(await openFailureNotifications(alert), 1);
      assert.equal(await requeueAlertsCore({ userId, workspaceId }), 1);
      assert.equal((await parentRow(alert)).status, "pending");
      await runWorker();
      assert.equal((await parentRow(alert)).status, "sent");
      assert.equal(events.length, 1);
      assert.equal(await openFailureNotifications(alert), 0);
    });

    for (const rotated of [false, true])
      it(`keeps URL-only success ambiguous with ${rotated ? "a rotated key" : "one current destination"}, including after requeue`, async () => {
        const alert = await queue();
        await history(alert, "webhooks", "success", {
          kind: "pagerduty",
          urlHash: crypto.createHash("sha256").update(pd.url).digest("hex"),
        });
        const current = rotated ? { ...pd, routingKey: keyB } : pd;
        await settings([current]);
        await pool.query(
          "UPDATE alert_queue SET status='partial',attempts=1 WHERE id=$1",
          [alert.id],
        );
        await runWorker();
        assert.equal(events.length, 0);
        assert.equal((await parentRow(alert)).status, "failed");
        assert.match(
          (await parentRow(alert)).error_message,
          /pagerduty_legacy_destination_ambiguous/,
        );
        assert.equal((await incidentRows()).length, 0);
        const direct = await lifecycle.deliverPagerDutyExpiration(client, {
          alert,
          webhook: current,
          send,
        });
        assert.equal(direct.success, false);
        assert.equal(direct.error, "pagerduty_legacy_destination_ambiguous");
        await pool.query(
          "UPDATE alert_queue SET attempts_webhooks=19,next_attempt_at=NOW()-INTERVAL '1 second' WHERE id=$1",
          [alert.id],
        );
        await runWorker();
        assert.equal((await parentRow(alert)).status, "blocked");
        assert.equal((await parentRow(alert)).next_attempt_at, null);
        assert.equal(await requeueAlertsCore({ userId, workspaceId }), 1);
        await runWorker();
        const retried = await parentRow(alert);
        assert.equal(retried.status, "failed");
        assert.match(
          retried.error_message,
          /pagerduty_legacy_destination_ambiguous/,
        );
        assert.doesNotMatch(
          retried.error_message,
          new RegExp(`${keyA}|${keyB}`),
        );
        assert.equal(events.length, 0);
        assert.equal((await incidentRows()).length, 0);
        assert.equal(
          (
            await pool.query(
              "SELECT 1 FROM alert_delivery_log WHERE alert_queue_id=$1 AND status='success'",
              [alert.id],
            )
          ).rowCount,
          1,
        );
      });

    it("parks ambiguous legacy URL evidence while retrying a provably pending independent endpoint", async () => {
      const independent = {
        ...pd,
        name: "independent",
        url: "https://events.eu.pagerduty.com/v2/enqueue",
      };
      await settings(
        [{ ...pd, routingKey: keyB }, independent],
        [{ ...group, webhook_names: ["pd", "independent"] }],
      );
      const alert = await queue();
      await history(alert, "webhooks", "success", {
        kind: "pagerduty",
        urlHash: crypto.createHash("sha256").update(pd.url).digest("hex"),
      });
      await pool.query(
        "UPDATE alert_queue SET status='partial',attempts=1 WHERE id=$1",
        [alert.id],
      );
      await runWorker();
      assert.equal(events.length, 1);
      assert.equal(events[0].url, independent.url);
      assert.match(
        (await parentRow(alert)).error_message,
        /pagerduty_legacy_destination_ambiguous/,
      );
      assert.equal((await incidentRows()).length, 1);
      assert.equal((await parentRow(alert)).status, "partial");
      await blockParent(alert);
      await due();
      await reconcile();
      assert.equal((await parentRow(alert)).status, "blocked");
      assert.deepEqual((await parentRow(alert)).channels, ["webhooks"]);
      assert.equal(await openFailureNotifications(alert), 1);
      assert.equal(await requeueAlertsCore({ userId, workspaceId }), 1);
      await runWorker();
      assert.equal((await parentRow(alert)).status, "partial");
      assert.equal(
        events.length,
        1,
        "neither old ambiguous destinations nor the new success may be resent",
      );
    });

    it("mixed new and URL-only evidence never assigns an old success to another routing key", async () => {
      const second = { ...pd, name: "second", routingKey: keyB };
      await settings(
        [pd, second],
        [{ ...group, webhook_names: ["pd", "second"] }],
      );
      const alert = await queue();
      const { webhookDestinationId } =
        await import("../../apps/worker/src/shared/webhookDestinations.js");
      await history(alert, "webhooks", "success", {
        kind: "pagerduty",
        urlHash: crypto.createHash("sha256").update(pd.url).digest("hex"),
      });
      await history(alert, "webhooks", "success", {
        kind: "pagerduty",
        destination_id: webhookDestinationId(workspaceId, pd),
        event_action: "trigger",
      });
      await pool.query(
        "UPDATE alert_queue SET status='partial',attempts=1 WHERE id=$1",
        [alert.id],
      );
      await runWorker();
      assert.equal(events.length, 0);
      assert.match(
        (await parentRow(alert)).error_message,
        /pagerduty_legacy_destination_ambiguous/,
      );
      assert.equal((await incidentRows()).length, 0);
    });

    it("recognizes exact modern destination acceptance even alongside old URL-only history", async () => {
      await settings([{ ...pd, routingKey: keyB }]);
      const alert = await queue();
      const { webhookDestinationId } =
        await import("../../apps/worker/src/shared/webhookDestinations.js");
      await history(alert, "webhooks", "success", {
        kind: "pagerduty",
        urlHash: crypto.createHash("sha256").update(pd.url).digest("hex"),
      });
      await history(alert, "webhooks", "success", {
        kind: "pagerduty",
        destination_id: webhookDestinationId(workspaceId, {
          ...pd,
          routingKey: keyB,
        }),
        event_action: "trigger",
      });
      await runWorker();
      assert.equal((await parentRow(alert)).status, "sent");
      assert.equal(events.length, 0);
      assert.equal((await incidentRows()).length, 0);
    });

    it("parks an older pending outbox intent when its source has ambiguous historical acceptance", async () => {
      const alert = await queue();
      const intent = await lifecycle.enqueuePagerDutyIncident(client, {
        alert,
        webhook: pd,
      });
      await history(alert, "webhooks", "success", {
        kind: "pagerduty",
        urlHash: crypto.createHash("sha256").update(pd.url).digest("hex"),
      });
      await blockParent(alert);
      await reconcile();
      let [incident] = await incidentRows();
      assert.equal(
        incident.last_error,
        "pagerduty_legacy_destination_ambiguous",
      );
      assert.equal(incident.retry_exhausted, true);
      assert.equal(incident.trigger_accepted_at, null);
      assert.equal(incident.action_attempts, 0);
      assert.equal(events.length, 0);
      assert.equal((await parentRow(alert)).status, "blocked");
      assert.equal(await openFailureNotifications(alert), 1);
      await requeueAlertsCore({ userId, workspaceId });
      await due(intent.id);
      await reconcile();
      [incident] = await incidentRows();
      assert.equal(incident.retry_exhausted, true);
      assert.equal(incident.action_attempts, 0);
      assert.equal(events.length, 0);
      assert.equal((await incidentRows()).length, 1);
    });

    it("successful independent delivery repairs a blocked PagerDuty-only parent and its bell notification", async () => {
      const alert = await queue(),
        incident = await lifecycle.enqueuePagerDutyIncident(client, {
          alert,
          webhook: pd,
        });
      await blockParent(alert);
      await reconcile();
      const row = await parentRow(alert);
      assert.equal(row.status, "sent");
      assert.equal(row.error_message, null);
      assert.equal(row.attempts_webhooks, 0);
      assert.equal(await openFailureNotifications(alert), 0);
      assert.equal(events.length, 1);
      assert.equal((await incidentRows())[0].state, "open");
      const count = (
        await pool.query(
          "SELECT 1 FROM alert_delivery_log WHERE alert_queue_id=$1",
          [alert.id],
        )
      ).rowCount;
      await due(incident.id);
      await reconcile();
      assert.equal(events.length, 1);
      assert.equal(
        (
          await pool.query(
            "SELECT 1 FROM alert_delivery_log WHERE alert_queue_id=$1",
            [alert.id],
          )
        ).rowCount,
        count,
      );
    });

    it("PagerDuty acceptance cannot recover another failed webhook or clear its notification", async () => {
      const other = {
        name: "generic",
        kind: "generic",
        url: "https://example.test/pending",
      };
      await settings(
        [pd, other],
        [{ ...group, webhook_names: ["pd", "generic"] }],
      );
      const alert = await queue();
      await lifecycle.enqueuePagerDutyIncident(client, { alert, webhook: pd });
      await history(alert, "webhooks", "failed", {
        kind: "generic",
        urlHash: crypto.createHash("sha256").update(other.url).digest("hex"),
      });
      await blockParent(alert);
      await reconcile();
      assert.equal((await parentRow(alert)).status, "blocked");
      assert.equal(await openFailureNotifications(alert), 1);
      assert.deepEqual((await parentRow(alert)).channels, ["webhooks"]);
      assert.equal(events.length, 1);
    });

    it("changes failed to partial until every PagerDuty destination has accepted delivery", async () => {
      const second = { ...pd, name: "second", routingKey: keyB };
      await settings(
        [pd, second],
        [{ ...group, webhook_names: ["pd", "second"] }],
      );
      const alert = await queue();
      const firstIntent = await lifecycle.enqueuePagerDutyIncident(client, {
        alert,
        webhook: pd,
      });
      const secondIntent = await lifecycle.enqueuePagerDutyIncident(client, {
        alert,
        webhook: second,
      });
      await blockParent(alert);
      await pool.query(
        "UPDATE alert_queue SET status='failed',attempts_webhooks=3 WHERE id=$1",
        [alert.id],
      );
      await lifecycle.processPagerDutyIncident(client, firstIntent.id, {
        send,
      });
      const partial = await parentRow(alert);
      assert.equal(partial.status, "partial");
      assert.deepEqual(partial.channels, ["webhooks"]);
      assert.equal(partial.attempts_webhooks, 3);
      assert.equal(await openFailureNotifications(alert), 1);
      await lifecycle.processPagerDutyIncident(client, secondIntent.id, {
        send,
      });
      assert.equal((await parentRow(alert)).status, "sent");
      assert.equal(await openFailureNotifications(alert), 0);
      assert.equal(events.length, 2);
    });

    it("aggregate repair requires every email recipient, preserving another channel's blocked status", async () => {
      const first = crypto.randomUUID(),
        second = crypto.randomUUID();
      for (const [id, email] of [
        [first, "alice@example.test"],
        [second, "bob@example.test"],
      ])
        await pool.query(
          `INSERT INTO workspace_contacts(id,workspace_id,first_name,last_name,details)
        VALUES($1,$2,'Recipient','Test',$3::jsonb)`,
          [id, workspaceId, JSON.stringify({ email })],
        );
      await settings([pd], [{ ...group, email_contact_ids: [first, second] }]);
      await pool.query(
        "UPDATE workspace_settings SET email_alerts_enabled=TRUE WHERE workspace_id=$1",
        [workspaceId],
      );
      const alert = await queue(),
        incident = await lifecycle.enqueuePagerDutyIncident(client, {
          alert,
          webhook: pd,
        });
      await history(alert, "email", "success", {
        recipient: "alice@example.test",
      });
      await history(alert, "email", "failed", {
        recipient: "bob@example.test",
      });
      await blockParent(alert, ["email", "webhooks"]);
      await reconcile();
      assert.equal((await parentRow(alert)).status, "blocked");
      assert.equal(await openFailureNotifications(alert), 1);
      assert.deepEqual((await parentRow(alert)).channels, ["email"]);
      await history(alert, "email", "success", {
        recipient: "bob@example.test",
      });
      await due(incident.id);
      await reconcile();
      assert.equal((await parentRow(alert)).status, "sent");
      assert.equal(await openFailureNotifications(alert), 0);
      assert.equal(events.length, 1);
      assert.equal(
        (
          await pool.query(
            "SELECT 1 FROM alert_delivery_log WHERE alert_queue_id=$1 AND channel='email' AND metadata->>'recipient'='alice@example.test'",
            [alert.id],
          )
        ).rowCount,
        1,
      );
    });

    it("fences a parent repair when email delivery is enabled after its routing snapshot", async () => {
      const contact = crypto.randomUUID();
      await pool.query(
        `INSERT INTO workspace_contacts(id,workspace_id,first_name,last_name,details)
        VALUES($1,$2,'New','Recipient','{"email":"new@example.test"}'::jsonb)`,
        [contact, workspaceId],
      );
      await settings([pd], [{ ...group, email_contact_ids: [contact] }]);
      const { alert, incident } = await trigger();
      await blockParent(alert);
      let changed = false;
      const concurrent = {
        query: async (sql, parameters) => {
          if (!changed && sql.includes("UPDATE alert_queue SET status=")) {
            changed = true;
            await pool.query(
              "UPDATE workspace_settings SET email_alerts_enabled=TRUE WHERE workspace_id=$1",
              [workspaceId],
            );
          }
          return client.query(sql, parameters);
        },
      };
      assert.equal(
        await lifecycle.reconcilePagerDutyParentAlert(concurrent, incident),
        false,
      );
      assert.equal(changed, true);
      assert.equal((await parentRow(alert)).status, "blocked");
      assert.equal(await openFailureNotifications(alert), 1);
      await due(incident.id);
      await reconcile();
      assert.equal((await parentRow(alert)).status, "blocked");
      assert.equal(events.length, 1);
    });

    it("normal-worker ownership fences parent repair until the claim is released", async () => {
      const alert = await queue(),
        incident = await lifecycle.enqueuePagerDutyIncident(client, {
          alert,
          webhook: pd,
        });
      const owner = crypto.randomUUID();
      await blockParent(alert);
      await pool.query(
        "UPDATE alert_queue SET status='pending',delivery_claim_id=$2,next_attempt_at=NOW()+INTERVAL '15 minutes' WHERE id=$1",
        [alert.id, owner],
      );
      await reconcile();
      const claimed = await parentRow(alert);
      assert.equal(claimed.status, "pending");
      assert.equal(claimed.delivery_claim_id, owner);
      assert.equal(await openFailureNotifications(alert), 1);
      await pool.query(
        "UPDATE alert_queue SET status='blocked',delivery_claim_id=NULL WHERE id=$1 AND delivery_claim_id=$2",
        [alert.id, owner],
      );
      await due(incident.id);
      await reconcile();
      assert.equal((await parentRow(alert)).status, "sent");
      assert.equal(events.length, 1);
    });

    it("recovers skipped parent repair after a row lock without sending another trigger", async () => {
      const { alert, incident } = await trigger();
      await blockParent(alert);
      const other = await pool.connect();
      try {
        await other.query("BEGIN");
        await other.query("SELECT id FROM alert_queue WHERE id=$1 FOR UPDATE", [
          alert.id,
        ]);
        assert.equal(
          await lifecycle.reconcilePagerDutyParentAlert(client, incident),
          false,
        );
        assert.equal((await parentRow(alert)).status, "blocked");
      } finally {
        await other.query("ROLLBACK");
        other.release();
      }
      await due(incident.id);
      await reconcile();
      assert.equal((await parentRow(alert)).status, "sent");
      assert.equal(events.length, 1);
    });

    for (const deleted of [false, true])
      it(`independent acceptance leaves ${deleted ? "a deleted" : "an archived"} parent alone`, async () => {
        const alert = await queue(),
          incident = await lifecycle.enqueuePagerDutyIncident(client, {
            alert,
            webhook: pd,
          });
        if (deleted)
          await pool.query("DELETE FROM alert_queue WHERE id=$1", [alert.id]);
        else await Token.update(tokenId, { expiration: day(5) });
        await reconcile();
        assert.equal((await incidentRows())[0].state, "open");
        assert.equal(events.length, 1);
        const row = await parentRow(alert);
        if (deleted) assert.equal(row, undefined);
        else {
          assert.equal(row.status, "sent");
          assert.match(row.alert_key, /:previous_expiration:/);
          assert.match(row.error_message, /Discarded:/);
        }
        assert.equal(events[0].body.dedup_key, incident.dedup_key);
      });

    it("replays persisted acceptance to repair an unclaimed blocked parent", async () => {
      const { alert, incident } = await trigger();
      await blockParent(alert);
      await lifecycle.reconcilePagerDutyParentAlert(client, incident);
      assert.equal((await parentRow(alert)).status, "sent");
    });

    it("unions group aliases, separates routing keys at one endpoint, and reuses an episode across thresholds", async () => {
      const other = { ...pd, name: "other", routingKey: keyB };
      const alias = { ...pd, name: "alias" };
      await settings(
        [pd, other, alias],
        [
          { ...group, webhook_names: ["pd", "other"], thresholds: [7, 1] },
          { id: "wide", webhook_names: ["alias"], thresholds: [30, 1] },
        ],
      );
      await pool.query(
        "INSERT INTO token_contact_groups(workspace_id,token_id,contact_group_id) VALUES ($1,$2,'ops'),($1,$2,'wide')",
        [workspaceId, tokenId],
      );
      await queue();
      await runWorker();
      assert.equal(events.length, 2);
      assert.deepEqual(
        new Set(events.map((event) => event.body.routing_key)),
        new Set([keyA, keyB]),
      );
      const rows = await incidentRows();
      assert.equal(rows.length, 2);
      assert.equal(
        rows.find((row) => row.risk_threshold_days === 30).state,
        "open",
      );
      assert.notEqual(rows[0].dedup_key, rows[1].dedup_key);
      await queue(7);
      await runWorker();
      assert.equal(
        events.length,
        2,
        "later thresholds preserve the existing incident and ACK",
      );
      assert.equal((await incidentRows()).length, 2);
    });

    it("correlates trigger, PagerDuty-side ACK, manual API renewal and one resolve on an empty queue", async () => {
      const state = new Map();
      const provider = async (url, body, kind) => {
        await send(url, body, kind);
        state.set(
          body.dedup_key,
          body.event_action === "resolve" ? "resolved" : "triggered",
        );
        return accepted;
      };
      await queue();
      await runWorker(provider);
      const [original] = await incidentRows();
      state.set(original.dedup_key, "acknowledged");
      const response = await request(app)
        .put(`/api/tokens/${tokenId}`)
        .send({ expiresAt: day(180) });
      assert.equal(response.status, 200, JSON.stringify(response.body));
      assert.equal(
        (
          await pool.query(
            "SELECT 1 FROM alert_queue WHERE token_id=$1 AND status IN ('pending','failed','partial')",
            [tokenId],
          )
        ).rowCount,
        0,
      );
      await runWorker(provider);
      await due();
      await runWorker(provider);
      assert.equal(state.get(original.dedup_key), "resolved");
      assert.deepEqual(
        events.map((event) => event.body.event_action),
        ["trigger", "resolve"],
      );
      assert.equal(events[0].body.dedup_key, events[1].body.dedup_key);
      assert.equal(events[1].body.routing_key, events[0].body.routing_key);
      assert.deepEqual(Object.keys(events[1].body).sort(), [
        "dedup_key",
        "event_action",
        "routing_key",
      ]);
      assert.equal((await incidentRows())[0].state, "resolved");
    });

    it("detects a provider import/automatic-sync Token.update without any API renewal hook", async () => {
      const source = {
        source_provider: "gitlab",
        source_instance: "gitlab.example.test",
        source_owner_key: "17",
        source_kind: "gitlab-pat",
        source_object_id: "42",
        source_observed_at: new Date(),
      };
      await Token.update(tokenId, { ...source, auto_sync_managed: true });
      await trigger();
      await upsertImportedToken({
        context: null,
        workspaceId,
        userId,
        manual: false,
        payload: {
          name: "Expiring asset",
          type: "api_key",
          category: "key_secret",
          expiration: day(180),
          ...source,
          source_observed_at: new Date(),
        },
        assignMembership() {},
      });
      await reconcile();
      assert.deepEqual(
        events.map((event) => event.body.event_action),
        ["trigger", "resolve"],
      );
      assert.equal((await incidentRows())[0].state, "resolved");
    });

    it("does not treat an unobserved provider-managed certificate edit as verified renewal", async () => {
      await Token.update(tokenId, {
        type: "ssl_cert",
        category: "cert",
        source_provider: "aws",
        source_observed_at: new Date(),
      });
      await trigger();
      const manual = await request(app)
        .put(`/api/tokens/${tokenId}`)
        .send({ expiration: day(180) });
      assert.equal(manual.status, 409);
      await Token.update(tokenId, { expiration: day(180) });
      await reconcile();
      assert.equal(events.length, 1);
      assert.equal((await incidentRows())[0].state, "open");
      await Token.update(tokenId, { source_observed_at: new Date() });
      await due();
      await reconcile();
      assert.equal((await incidentRows())[0].state, "resolved");
    });

    for (const [name, days] of [
      ["unchanged", 1],
      ["shortened", 0],
      ["extended but still at risk", 5],
    ]) {
      it(`keeps an incident open when expiration is ${name}`, async () => {
        await trigger();
        await Token.update(tokenId, { expiration: day(days) });
        await due();
        await reconcile();
        assert.equal(events.length, 1);
        assert.equal((await incidentRows())[0].state, "open");
      });
    }

    it("does not treat group removal, disabled webhooks or smaller thresholds as recovery", async () => {
      await trigger();
      await settings([pd], [{ ...group, thresholds: [1] }]);
      await pool.query(
        "UPDATE workspace_settings SET webhooks_alerts_enabled=FALSE WHERE workspace_id=$1",
        [workspaceId],
      );
      await Token.update(tokenId, { expiration: day(5) });
      await reconcile();
      await settings([pd], []);
      await due();
      await reconcile();
      assert.equal(events.length, 1);
      assert.equal((await incidentRows())[0].state, "open");
    });

    it("requires managed-certificate facts to match before accepting a verified CertOps renewal", async () => {
      const managed = await certificate();
      await trigger();
      await Token.update(tokenId, { expiration: day(180) });
      await reconcile();
      assert.equal(events.length, 1);
      assert.equal(
        (await incidentRows())[0].last_error,
        "expiry_evidence_unavailable",
      );
      await client.query("BEGIN");
      try {
        await client.query(
          "UPDATE managed_certificates SET not_after=$2 WHERE id=$1",
          [managed.id, `${day(180)}T00:00:00Z`],
        );
        await updateCertificateTokenFacts({
          client,
          workspaceId,
          tokenId,
          certificate: { notAfter: `${day(180)}T00:00:00Z` },
        });
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      }
      await due();
      await reconcile();
      assert.equal(events.at(-1).body.event_action, "resolve");
    });

    it("rejects unsupported manual certificate edits and accepts unchanged facts", async () => {
      await certificate();
      const response = await request(app)
        .put(`/api/tokens/${tokenId}`)
        .send({ expiresAt: day(180) });
      assert.equal(response.status, 409, JSON.stringify(response.body));
      assert.equal(response.body.code, "VERIFIED_CERTIFICATE_EXPIRY_REQUIRED");
      await Token.update(tokenId, { location: "certificate.example.test" });
      const duplicate = await request(app)
        .post("/api/tokens")
        .send({
          workspace_id: workspaceId,
          name: "Expiring asset",
          type: "ssl_cert",
          location: "certificate.example.test",
          category: "cert",
          expiresAt: day(180),
          confirm_duplicate: true,
        });
      assert.equal(duplicate.status, 409, JSON.stringify(duplicate.body));
      assert.equal(duplicate.body.code, "VERIFIED_CERTIFICATE_EXPIRY_REQUIRED");
      const unchanged = await request(app)
        .put(`/api/tokens/${tokenId}`)
        .send({ expiresAt: day(1), name: "Renamed certificate" });
      assert.equal(unchanged.status, 200, JSON.stringify(unchanged.body));
    });

    it("uses a verified TLS observation for the direct endpoint-monitor expiration write", async () => {
      const { persistEndpointCertificateResult } =
        await import("../../apps/worker/src/endpoint-check-worker.js");
      const monitorClaim = crypto.randomUUID();
      const monitor = (
        await pool.query(
          `INSERT INTO domain_monitors
        (workspace_id,token_id,url,created_by,ssl_valid_to,ssl_fingerprint,check_claim_id)
        VALUES ($1,$2,'https://certificate.example.test',$3,$4,$5,$6) RETURNING *`,
          [
            workspaceId,
            tokenId,
            userId,
            `${day(1)}T00:00:00Z`,
            "a".repeat(64),
            monitorClaim,
          ],
        )
      ).rows[0];
      await trigger();
      const manual = await request(app)
        .put(`/api/tokens/${tokenId}`)
        .send({ expiration: day(180) });
      assert.equal(manual.status, 409);
      const persisted = await persistEndpointCertificateResult(
        client,
        monitor,
        monitorClaim,
        {
          ssl_issuer: "CN=Test CA",
          ssl_subject: "CN=certificate.example.test",
          ssl_valid_from: new Date(`${day(0)}T00:00:00Z`),
          ssl_valid_to: new Date(`${day(180)}T00:00:00Z`),
          ssl_serial: "02",
          ssl_fingerprint: "b".repeat(64),
          public_certificate_pem: null,
        },
      );
      assert.equal(persisted.tokenId, tokenId);
      await reconcile();
      assert.equal((await incidentRows())[0].state, "resolved");
      assert.equal(events.at(-1).body.event_action, "resolve");
    });

    it("retains failed PagerDuty endpoints after partial webhook success and skips successful recipients on retry", async () => {
      const slack = {
        name: "slack",
        kind: "slack",
        url: "https://hooks.slack.com/services/issue364",
      };
      await settings(
        [slack, pd],
        [{ ...group, webhook_names: ["slack", "pd"] }],
      );
      const alert = await queue();
      await runWorker(async (url, body, kind) => {
        await send(url, body, kind);
        return kind === "pagerduty"
          ? { success: false, status: 429, error: keyA }
          : accepted;
      });
      const failed = (
        await pool.query("SELECT * FROM alert_queue WHERE id=$1", [alert.id])
      ).rows[0];
      assert.equal(failed.status, "partial");
      assert.deepEqual(failed.channels, ["webhooks"]);
      assert.equal(failed.attempts_webhooks, 1);
      await due();
      await runWorker();
      assert.equal(events.filter((event) => event.kind === "slack").length, 1);
      assert.equal(
        events.filter((event) => event.kind === "pagerduty").length,
        2,
      );
      assert.equal(
        (
          await pool.query("SELECT status FROM alert_queue WHERE id=$1", [
            alert.id,
          ])
        ).rows[0].status,
        "sent",
      );
      assert.equal((await incidentRows())[0].state, "open");
      assert.doesNotMatch(
        JSON.stringify(
          (
            await pool.query(
              "SELECT metadata,error_message FROM alert_delivery_log WHERE workspace_id=$1",
              [workspaceId],
            )
          ).rows,
        ),
        new RegExp(keyA),
      );
    });

    it("backs off 429/5xx/timeouts, bounds retries and preserves safe delivery history", async () => {
      const intent = await lifecycle.enqueuePagerDutyIncident(client, {
        alert: await queue(),
        webhook: pd,
      });
      const errors = [
        { success: false, status: 429 },
        { success: false, status: 503 },
        null,
      ];
      let calls = 0;
      const failure = async () => {
        calls++;
        const next = errors.shift();
        if (!next) throw new Error(`timeout with routing_key=${keyA}`);
        return next;
      };
      for (
        let attempt = 1;
        attempt <= lifecycle.MAX_PAGERDUTY_ATTEMPTS;
        attempt++
      ) {
        await due();
        const outcome = await lifecycle.processPagerDutyIncident(
          client,
          intent.id,
          { send: failure },
        );
        assert.equal(outcome.success, false);
        const [row] = await incidentRows();
        assert.equal(row.trigger_attempts, attempt);
        assert.ok(
          new Date(row.next_attempt_at) > new Date(row.last_attempt_at),
        );
        await lifecycle.processPagerDutyIncident(client, intent.id, {
          send: failure,
        });
        assert.equal(calls, attempt, "backoff also applies in test mode");
      }
      await due();
      await reconcile(failure);
      const [row] = await incidentRows();
      assert.equal(row.retry_exhausted, true);
      assert.equal(calls, lifecycle.MAX_PAGERDUTY_ATTEMPTS);
      assert.equal(row.trigger_accepted_at, null);
      assert.equal(
        (
          await pool.query(
            "SELECT 1 FROM alert_delivery_log WHERE workspace_id=$1",
            [workspaceId],
          )
        ).rowCount,
        calls,
      );
      assert.doesNotMatch(JSON.stringify(row), new RegExp(keyA));
    });

    it("parks non-retryable authentication errors without marking acceptance or resolving", async () => {
      const intent = await lifecycle.enqueuePagerDutyIncident(client, {
        alert: await queue(),
        webhook: pd,
      });
      await lifecycle.processPagerDutyIncident(client, intent.id, {
        send: async () => ({ success: false, status: 401 }),
      });
      await due();
      await reconcile();
      const [row] = await incidentRows();
      assert.equal(row.retry_exhausted, true);
      assert.equal(row.last_error, "pagerduty_http_401");
      assert.equal(row.trigger_attempts, 1);
      assert.equal(row.trigger_accepted_at, null);
      assert.equal(events.length, 0);
    });

    it("cancels definitely rejected triggers after renewal without inventing an uncertain incident", async () => {
      const intent = await lifecycle.enqueuePagerDutyIncident(client, {
        alert: await queue(),
        webhook: pd,
      });
      await lifecycle.processPagerDutyIncident(client, intent.id, {
        send: async () => ({ success: false, status: 401 }),
      });
      await Token.update(tokenId, { expiration: day(180) });
      await reconcile();
      assert.equal((await incidentRows())[0].state, "cancelled");
      assert.equal(events.length, 0);
    });

    it("retries parked resolution through the existing authorized requeue without resetting correlation/history", async () => {
      const { incident } = await trigger();
      await Token.update(tokenId, { expiration: day(180) });
      await reconcile(async () => ({ success: false, status: 403 }));
      assert.equal((await incidentRows())[0].retry_exhausted, true);
      const outsider = (
        await pool.query(
          `INSERT INTO users(email,display_name,password_hash)
      VALUES($1,'Outsider','test-only') RETURNING id`,
          [`outsider-${crypto.randomUUID()}@example.test`],
        )
      ).rows[0].id;
      await requeueAlertsCore({ userId: outsider, workspaceId });
      assert.equal((await incidentRows())[0].retry_exhausted, true);
      await requeueAlertsCore({ userId, workspaceId });
      assert.equal((await incidentRows())[0].retry_exhausted, false);
      await reconcile();
      const [resolved] = await incidentRows();
      assert.equal(resolved.state, "resolved");
      assert.equal(resolved.dedup_key, incident.dedup_key);
      assert.equal(resolved.resolve_attempts, 2);
    });

    it("invalidates a stale trigger snapshot when renewal commits immediately before dispatch", async () => {
      const intent = await lifecycle.enqueuePagerDutyIncident(client, {
        alert: await queue(),
        webhook: pd,
      });
      let changed = false;
      const concurrent = {
        query: async (sql, parameters) => {
          if (
            !changed &&
            sql.includes("SET trigger_attempts = trigger_attempts + 1")
          ) {
            changed = true;
            await Token.update(tokenId, { expiration: day(180) });
          }
          return client.query(sql, parameters);
        },
      };
      const result = await lifecycle.processPagerDutyIncident(
        concurrent,
        intent.id,
        { send },
      );
      assert.equal(result.error, "dispatch_snapshot_changed");
      assert.equal(events.length, 0);
      assert.equal((await incidentRows())[0].trigger_attempts, 0);
      await due();
      await reconcile();
      assert.equal((await incidentRows())[0].state, "cancelled");
    });

    it("invalidates a stale recovery snapshot when new risk commits before resolve intent", async () => {
      const { incident } = await trigger();
      await Token.update(tokenId, { expiration: day(180) });
      let changed = false;
      const concurrent = {
        query: async (sql, parameters) => {
          if (!changed && sql.includes("SET state = 'resolve_pending'")) {
            changed = true;
            await Token.update(tokenId, { expiration: day(1) });
          }
          return client.query(sql, parameters);
        },
      };
      const result = await lifecycle.processPagerDutyIncident(
        concurrent,
        incident.id,
        { send },
      );
      assert.equal(result.error, "reconciliation_snapshot_changed");
      assert.equal(events.length, 1);
      assert.equal((await incidentRows())[0].state, "open");
      await due();
      await reconcile();
      assert.equal((await incidentRows())[0].state, "open");
    });

    it("atomically joins concurrent threshold intents into one episode", async () => {
      const firstAlert = await queue(1),
        secondAlert = await queue(7);
      const other = await pool.connect();
      try {
        const [first, second] = await Promise.all([
          lifecycle.enqueuePagerDutyIncident(client, {
            alert: firstAlert,
            webhook: pd,
          }),
          lifecycle.enqueuePagerDutyIncident(other, {
            alert: secondAlert,
            webhook: pd,
          }),
        ]);
        assert.equal(first.id, second.id);
        assert.equal(first.dedup_key, second.dedup_key);
        assert.equal((await incidentRows()).length, 1);
      } finally {
        other.release();
      }
    });

    it("fences a stale completion instead of overwriting a replacement owner's claim", async () => {
      const intent = await lifecycle.enqueuePagerDutyIncident(client, {
        alert: await queue(),
        webhook: pd,
      });
      const replacement = crypto.randomUUID();
      const outcome = await lifecycle.processPagerDutyIncident(
        client,
        intent.id,
        {
          send: async () => {
            await pool.query(
              "UPDATE pagerduty_incidents SET claim_id=$2,claimed_until=NOW()+INTERVAL '1 minute' WHERE id=$1",
              [intent.id, replacement],
            );
            return accepted;
          },
        },
      );
      assert.equal(outcome.error, "pagerduty_ownership_lost");
      const [row] = await incidentRows();
      assert.equal(row.claim_id, replacement);
      assert.equal(row.trigger_accepted_at, null);
      assert.equal(
        (
          await pool.query(
            "SELECT 1 FROM alert_delivery_log WHERE workspace_id=$1",
            [workspaceId],
          )
        ).rowCount,
        0,
      );
    });

    it("serializes concurrent workers without holding a transaction during HTTP", async () => {
      const intent = await lifecycle.enqueuePagerDutyIncident(client, {
        alert: await queue(),
        webhook: pd,
      });
      const other = await pool.connect();
      let releaseSend, entered;
      const enteredPromise = new Promise((resolve) => {
        entered = resolve;
      });
      const gate = new Promise((resolve) => {
        releaseSend = resolve;
      });
      const first = lifecycle.processPagerDutyIncident(client, intent.id, {
        send: async (url, body, kind) => {
          entered();
          await gate;
          return send(url, body, kind);
        },
      });
      try {
        await enteredPromise;
        // Even an artificially expired lease cannot give another live session
        // the advisory lock while the original sender is still active.
        await other.query(
          "UPDATE pagerduty_incidents SET claimed_until=NOW()-INTERVAL '1 second' WHERE id=$1",
          [intent.id],
        );
        const activity = (
          await other.query(
            "SELECT state,xact_start FROM pg_stat_activity WHERE pid=$1",
            [client.processID],
          )
        ).rows[0];
        assert.equal(activity.state, "idle");
        assert.equal(activity.xact_start, null);
        const second = await lifecycle.processPagerDutyIncident(
          other,
          intent.id,
          { send },
        );
        assert.equal(second.error, "pagerduty_incident_busy");
      } finally {
        releaseSend();
        await first;
        other.release();
      }
      assert.equal(events.length, 1);
      assert.equal((await incidentRows())[0].state, "open");
    });

    it("recovers a real process crash with the original dedup key after its lease expires", async () => {
      const intent = await lifecycle.enqueuePagerDutyIncident(client, {
        alert: await queue(),
        webhook: pd,
      });
      const child = spawnSync(
        process.execPath,
        ["tests/postgres/fixtures/pagerduty-crash-worker.cjs", intent.id],
        { encoding: "utf8", env: process.env, timeout: 15000 },
      );
      assert.equal(child.status, 23, child.stderr);
      assert.equal(child.stdout.trim(), intent.dedup_key);
      const [abandoned] = await incidentRows();
      assert.equal(abandoned.trigger_attempts, 1);
      assert.equal(abandoned.trigger_accepted_at, null);
      await pool.query(
        "UPDATE pagerduty_incidents SET claimed_until=NOW()-INTERVAL '1 second' WHERE id=$1",
        [intent.id],
      );
      await reconcile();
      assert.equal(events.length, 1);
      assert.equal(events[0].body.dedup_key, intent.dedup_key);
      assert.equal((await incidentRows())[0].trigger_attempts, 2);
      assert.equal((await incidentRows())[0].state, "open");
    });

    it("enforces the persisted retry budget even if the last process crashed before recording an outcome", async () => {
      const intent = await lifecycle.enqueuePagerDutyIncident(client, {
        alert: await queue(),
        webhook: pd,
      });
      await pool.query(
        `UPDATE pagerduty_incidents SET trigger_attempts=$2,action_attempts=$2,
        trigger_delivery_uncertain=TRUE WHERE id=$1`,
        [intent.id, lifecycle.MAX_PAGERDUTY_ATTEMPTS],
      );
      await reconcile();
      const [row] = await incidentRows();
      assert.equal(row.trigger_attempts, lifecycle.MAX_PAGERDUTY_ATTEMPTS);
      assert.equal(row.retry_exhausted, true);
      assert.equal(row.last_error, "retry_budget_exhausted");
      assert.equal(events.length, 0);
      await requeueAlertsCore({ userId, workspaceId });
      await reconcile();
      assert.equal(events.length, 1);
      assert.equal(
        (await incidentRows())[0].trigger_attempts,
        lifecycle.MAX_PAGERDUTY_ATTEMPTS + 1,
      );
    });

    it("cancels a never-attempted trigger after renewal instead of dispatching a stale alert", async () => {
      await lifecycle.enqueuePagerDutyIncident(client, {
        alert: await queue(),
        webhook: pd,
      });
      await Token.update(tokenId, { expiration: day(180) });
      await reconcile();
      assert.equal(events.length, 0);
      assert.equal((await incidentRows())[0].state, "cancelled");
    });

    it("resolves a matching accepted trigger when renewal occurs during its HTTP call", async () => {
      const intent = await lifecycle.enqueuePagerDutyIncident(client, {
        alert: await queue(),
        webhook: pd,
      });
      await lifecycle.processPagerDutyIncident(client, intent.id, {
        send: async (url, body, kind) => {
          await Token.update(tokenId, { expiration: day(180) });
          return send(url, body, kind);
        },
      });
      assert.equal((await incidentRows())[0].state, "open");
      await due();
      await reconcile();
      assert.deepEqual(
        events.map((event) => event.body.event_action),
        ["trigger", "resolve"],
      );
      assert.equal(events[0].body.dedup_key, events[1].body.dedup_key);
    });

    it("keeps ambiguous timed-out acceptance observable after renewal, without a speculative resolve", async () => {
      const intent = await lifecycle.enqueuePagerDutyIncident(client, {
        alert: await queue(),
        webhook: pd,
      });
      await lifecycle.processPagerDutyIncident(client, intent.id, {
        send: async () => {
          throw new Error("timeout");
        },
      });
      await Token.update(tokenId, { expiration: day(180) });
      await reconcile();
      const [row] = await incidentRows();
      assert.equal(row.last_error, "trigger_acceptance_unknown");
      assert.equal(row.state, "trigger_pending");
      assert.equal(row.trigger_accepted_at, null);
      assert.equal(events.length, 0);
    });

    it("keeps a new episode open while an old resolve is pending and later succeeds", async () => {
      const { incident: original } = await trigger();
      await Token.update(tokenId, { expiration: day(180) });
      await reconcile(async () => ({ success: false, status: 503 }));
      assert.equal((await incidentRows())[0].state, "resolve_pending");
      await Token.update(tokenId, { expiration: day(1) });
      const fresh = await lifecycle.enqueuePagerDutyIncident(client, {
        alert: await queue(),
        webhook: pd,
      });
      assert.notEqual(fresh.dedup_key, original.dedup_key);
      await lifecycle.processPagerDutyIncident(client, fresh.id, { send });
      await due(original.id);
      await reconcile();
      const rows = await incidentRows();
      assert.equal(
        rows.find((row) => row.id === original.id).state,
        "resolved",
      );
      assert.equal(rows.find((row) => row.id === fresh.id).state, "open");
      assert.equal(events.at(-1).body.dedup_key, original.dedup_key);
    });

    it("does not resolve to rotated credentials; restores the exact destination independently of group membership", async () => {
      await trigger();
      await settings([{ ...pd, routingKey: keyB }], []);
      await Token.update(tokenId, { expiration: day(180) });
      await reconcile();
      assert.equal(events.length, 1);
      assert.equal((await incidentRows())[0].state, "resolve_pending");
      assert.equal(
        (await incidentRows())[0].last_error,
        "original_destination_unavailable",
      );
      await settings([{ ...pd, name: "renamed-original" }], []);
      await due();
      await reconcile();
      assert.equal(events.at(-1).body.routing_key, keyA);
      assert.equal((await incidentRows())[0].state, "resolved");
    });

    it("parks a missing original key and never attempts a resolve to its empty-key replacement", async () => {
      await trigger();
      await settings([{ ...pd, routingKey: "" }]);
      await Token.update(tokenId, { expiration: day(180) });
      await reconcile();
      const [row] = await incidentRows();
      assert.equal(row.state, "resolve_pending");
      assert.equal(row.last_error, "original_destination_unavailable");
      assert.equal(events.length, 1);
      assert.equal(row.resolved_at, null);
    });

    it("retains an unresolved historical anchor for deleted assets", async () => {
      await trigger();
      await pool.query("DELETE FROM tokens WHERE id=$1", [tokenId]);
      await due();
      await reconcile();
      const [row] = await incidentRows();
      assert.equal(row.token_id, null);
      assert.equal(row.token_id_snapshot, tokenId);
      assert.equal(row.state, "open");
      assert.equal(row.last_error, "asset_unavailable");
      assert.equal(events.length, 1);
    });

    it("does not create or resolve lifecycle records for legacy accepted alerts or non-PagerDuty channels", async () => {
      const legacy = await queue();
      await pool.query("UPDATE alert_queue SET status='sent' WHERE id=$1", [
        legacy.id,
      ]);
      await pool.query(
        `INSERT INTO alert_delivery_log(alert_queue_id,user_id,token_id,workspace_id,channel,status,metadata)
      VALUES ($1,$2,$3,$4,'webhooks','success','{"kind":"pagerduty","urlHash":"legacy"}')`,
        [legacy.id, userId, tokenId, workspaceId],
      );
      await Token.update(tokenId, { expiration: day(180) });
      await runWorker();
      assert.equal((await incidentRows()).length, 0);
      assert.equal(events.length, 0);
      await Token.update(tokenId, { expiration: day(1) });
      const generic = {
        name: "generic",
        kind: "generic",
        url: "https://example.test/webhook",
      };
      await settings(
        [generic, { ...generic, name: "alias" }],
        [{ ...group, webhook_names: ["generic", "alias"] }],
      );
      await queue();
      await runWorker();
      assert.equal(events.length, 1);
      assert.equal(events[0].kind, "generic");
      assert.equal((await incidentRows()).length, 0);
    });

    it("rearms a genuine expiration cycle while keeping original successful delivery evidence", async () => {
      await discovery.queueDiscoveryJob({ closePool: false });
      await runWorker();
      const [original] = await incidentRows();
      assert.ok(original);
      const logsBefore = (
        await pool.query(
          "SELECT id FROM alert_delivery_log WHERE workspace_id=$1",
          [workspaceId],
        )
      ).rows;
      await Token.update(tokenId, { expiration: day(180) });
      await reconcile();
      const archived = await pool.query(
        "SELECT alert_key FROM alert_queue WHERE token_id=$1",
        [tokenId],
      );
      assert.ok(
        archived.rows.every((row) =>
          row.alert_key.includes(":previous_expiration:"),
        ),
      );
      await Token.update(tokenId, { expiration: day(1) });
      await discovery.queueDiscoveryJob({ closePool: false });
      await runWorker();
      const rows = await incidentRows();
      assert.equal(rows.length, 2);
      assert.notEqual(rows[0].dedup_key, rows[1].dedup_key);
      assert.equal(
        (
          await pool.query(
            "SELECT id FROM alert_delivery_log WHERE id=ANY($1::int[])",
            [logsBefore.map((row) => row.id)],
          )
        ).rowCount,
        logsBefore.length,
      );
    });

    it("enforces workspace ownership and bounds independent reconciliation batches", async () => {
      const foreignWorkspace = crypto.randomUUID();
      await pool.query(
        "INSERT INTO workspaces(id,name,created_by) VALUES($1,'Other tenant',$2)",
        [foreignWorkspace, userId],
      );
      try {
        const alert = await queue();
        await assert.rejects(
          lifecycle.enqueuePagerDutyIncident(client, {
            alert: { ...alert, workspace_id: foreignWorkspace },
            webhook: pd,
          }),
          { code: "pagerduty_asset_workspace_unavailable" },
        );
        const intent = await lifecycle.enqueuePagerDutyIncident(client, {
          alert,
          webhook: pd,
        });
        await assert.rejects(
          pool.query(
            "UPDATE pagerduty_incidents SET workspace_id=$2 WHERE id=$1",
            [intent.id, foreignWorkspace],
          ),
          { code: "23503" },
        );
        const secondToken = (
          await pool.query(
            `INSERT INTO tokens(user_id,workspace_id,name,type,expiration)
        VALUES($1,$2,'Second asset','api_key',$3) RETURNING id`,
            [userId, workspaceId, day(1)],
          )
        ).rows[0].id;
        await lifecycle.enqueuePagerDutyIncident(client, {
          alert: await queue(1, secondToken),
          webhook: pd,
        });
        assert.equal(await reconcile(send, { batchSize: 1 }), 1);
        assert.equal(events.length, 1);
        assert.equal(await reconcile(send, { batchSize: 1 }), 1);
        assert.equal(events.length, 2);
        assert.notEqual(events[0].body.dedup_key, events[1].body.dedup_key);
      } finally {
        await pool.query("DELETE FROM workspaces WHERE id=$1", [
          foreignWorkspace,
        ]);
      }
    });
  },
);
