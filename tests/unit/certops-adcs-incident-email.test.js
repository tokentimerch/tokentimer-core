"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const W = "11111111-1111-4111-8111-111111111111",
  I = "22222222-2222-4222-8222-222222222222",
  N = "33333333-3333-4333-8333-333333333333";
const recipient = (n) => ({
  key: String(n).repeat(64),
  email: `admin${n}@example.test`,
});
const modulePromise =
  import("../../apps/worker/src/shared/adcsPreflightEmails.js");

// Stateful autocommit DB double: independent worker clients share incident
// storage and a serialized workspace lock, like the production SQL contract.
function fixture({ cap = 0, claim = null, stale = false } = {}) {
  const row = {
    resolved: false,
    sent: false,
    claim,
    stale,
    metadata: { issuerId: I },
  };
  const calls = [];
  let tail = Promise.resolve();
  function client() {
    let unlock;
    return {
      query: async (sql, params = []) => {
        calls.push({ sql, params });
        if (sql.includes("pg_advisory_lock(")) {
          const prior = tail;
          tail = new Promise((resolve) => {
            unlock = resolve;
          });
          await prior;
          return { rows: [] };
        }
        if (sql.includes("pg_advisory_unlock(")) {
          unlock();
          return { rows: [] };
        }
        if (sql.includes("SELECT COUNT(*)")) return { rows: [{ c: cap }] };
        assert.equal(params[0], N);
        assert.equal(params[1], W);
        if (sql.includes("AS issuer_id"))
          return { rows: row.resolved || row.sent ? [] : [{ issuer_id: I }] };
        if (sql.includes("RETURNING title")) {
          assert.match(sql, /type='adcs_preflight_blocked'/);
          assert.match(sql, /INTERVAL '10 minutes'/);
          if (row.resolved || row.sent || (row.claim && !row.stale))
            return { rows: [] };
          row.claim = params[2];
          row.stale = false;
          return {
            rows: [
              {
                title: "Renewal blocked",
                message: "Restore agent",
                metadata: structuredClone(row.metadata),
              },
            ],
          };
        }
        if (sql.includes("SELECT id FROM"))
          return {
            rows: !row.resolved && row.claim === params[2] ? [{ id: N }] : [],
          };
        if (sql.includes("jsonb_set")) {
          assert.equal(row.claim, params[2]);
          row.metadata.emailDelivery = JSON.parse(params[3]);
          return { rows: [], rowCount: 1 };
        }
        if (sql.includes("email_sent_at=CASE")) {
          assert.equal(row.claim, params[2]);
          row.claim = null;
          row.sent = Boolean(params[3]);
          return { rows: [], rowCount: 1 };
        }
        throw Error(sql);
      },
    };
  }
  let reconciled = 0;
  const options = {
    loadRecipients: async () => [recipient(1)],
    reconcile: async (args) => {
      assert.equal(args.workspaceId, W);
      assert.equal(args.issuerId, I);
      reconciled++;
    },
  };
  return {
    row,
    calls,
    client,
    options,
    get reconciled() {
      return reconciled;
    },
  };
}

describe("AD CS critical operational email delivery", () => {
  it("sends once across two workers, only after reconciliation and outside transactions", async () => {
    const { sendAdcsPreflightIncidentEmail: send } = await modulePromise,
      f = fixture();
    let sent = 0;
    const smtp = async (input) => {
      assert.ok(f.reconciled);
      assert.equal(f.row.resolved, false);
      assert.equal(
        f.calls.some((c) => /^(BEGIN|COMMIT|ROLLBACK)$/.test(c.sql)),
        false,
      );
      await input.onBeforeAttempt();
      sent++;
      return { success: true };
    };
    await Promise.all([
      send(f.client(), { notificationId: N, workspaceId: W }, smtp, f.options),
      send(f.client(), { notificationId: N, workspaceId: W }, smtp, f.options),
    ]);
    assert.equal(sent, 1);
    assert.equal(f.row.sent, true);
    assert.equal(f.row.claim, null);
    assert.equal(f.row.metadata.emailDelivery.accepted[recipient(1).key], true);
  });
  it("retains the in-app incident on SMTP failure and retries after restart", async () => {
    const { sendAdcsPreflightIncidentEmail: send } = await modulePromise,
      f = fixture();
    await send(
      f.client(),
      { notificationId: N, workspaceId: W },
      async () => {
        throw Error("SMTP unavailable");
      },
      f.options,
    );
    assert.equal(f.row.resolved, false);
    assert.equal(f.row.sent, false);
    assert.equal(f.row.claim, null);
    await send(
      f.client(),
      { notificationId: N, workspaceId: W },
      async () => ({ success: true }),
      f.options,
    );
    assert.equal(f.row.sent, true);
  });
  it("persists partial receipts and does not resend successful recipients after restart", async () => {
    const { sendAdcsPreflightIncidentEmail: send } = await modulePromise,
      f = fixture();
    const attempts = [];
    f.options.loadRecipients = async () => [recipient(1), recipient(2)];
    await send(
      f.client(),
      { notificationId: N, workspaceId: W },
      async ({ to }) => {
        attempts.push(to);
        return { success: to === recipient(1).email };
      },
      f.options,
    );
    assert.equal(f.row.sent, false);
    assert.equal(f.row.metadata.emailDelivery.accepted[recipient(1).key], true);
    await send(
      f.client(),
      { notificationId: N, workspaceId: W },
      async ({ to }) => {
        attempts.push(to);
        return { success: true };
      },
      f.options,
    );
    assert.deepEqual(attempts, [
      recipient(1).email,
      recipient(2).email,
      recipient(2).email,
    ]);
    assert.equal(f.row.sent, true);
  });
  it("honors the shared cap while allowing an already-counted partial incident to finish", async () => {
    const { sendAdcsPreflightIncidentEmail: send, INCIDENT_EMAIL_CAP_SQL } =
        await modulePromise,
      f = fixture({ cap: 10 });
    let sent = 0;
    const smtp = async () => {
      sent++;
      return { success: true };
    };
    await send(
      f.client(),
      { notificationId: N, workspaceId: W },
      smtp,
      f.options,
    );
    assert.equal(sent, 0);
    assert.equal(f.row.sent, false);
    f.row.metadata.emailDelivery = {
      lastAcceptedAt: new Date().toISOString(),
      accepted: { [recipient(2).key]: true },
    };
    await send(
      f.client(),
      { notificationId: N, workspaceId: W },
      smtp,
      f.options,
    );
    assert.equal(sent, 1);
    assert.match(INCIDENT_EMAIL_CAP_SQL, /lastAcceptedAt/);
    assert.match(INCIDENT_EMAIL_CAP_SQL, /workspace_id=\$1/);
  });
  it("recovers an expired process claim but never steals a live claim", async () => {
    const { sendAdcsPreflightIncidentEmail: send } = await modulePromise,
      f = fixture({ claim: "old" });
    let sent = 0;
    const smtp = async () => {
      sent++;
      return { success: true };
    };
    await send(
      f.client(),
      { notificationId: N, workspaceId: W },
      smtp,
      f.options,
    );
    assert.equal(sent, 0);
    f.row.stale = true;
    await send(
      f.client(),
      { notificationId: N, workspaceId: W },
      smtp,
      f.options,
    );
    assert.equal(sent, 1);
  });
  it("suppresses a recovered incident and rechecks recipient admission before transport", async () => {
    const { sendAdcsPreflightIncidentEmail: send } = await modulePromise,
      f = fixture();
    let sent = 0;
    f.options.reconcile = async () => {
      f.row.resolved = true;
    };
    const smtp = async () => {
      sent++;
      return { success: true };
    };
    await send(
      f.client(),
      { notificationId: N, workspaceId: W },
      smtp,
      f.options,
    );
    assert.equal(sent, 0);
    const changed = fixture();
    let lookups = 0;
    changed.options.loadRecipients = async () =>
      ++lookups === 1 ? [recipient(1)] : [];
    await send(
      changed.client(),
      { notificationId: N, workspaceId: W },
      smtp,
      changed.options,
    );
    assert.equal(sent, 0);
    assert.equal(changed.row.sent, false);
  });
  it("rechecks policies on each actual SMTP attempt, including fallback", async () => {
    const { sendAdcsPreflightIncidentEmail: send } = await modulePromise,
      f = fixture();
    let allowed = true;
    f.options.loadRecipients = async () => (allowed ? [recipient(1)] : []);
    await send(
      f.client(),
      { notificationId: N, workspaceId: W },
      async (input) => {
        allowed = false;
        await assert.rejects(input.onBeforeAttempt(), /NO_LONGER_ALLOWED/);
        return { success: false };
      },
      f.options,
    );
    assert.equal(f.row.sent, false);
  });
  it("does not opt unrelated CertOps incidents into operational delivery", async () => {
    const {
      sendOperationalIncidentEmail,
      retryPendingOperationalIncidentEmails,
    } = await import("../../apps/worker/src/shared/opNotifications.js");
    const client = {
      query: async (sql) => {
        assert.match(
          sql,
          /category <> 'certops' OR type = 'adcs_preflight_blocked'/,
        );
        return { rows: [] };
      },
    };
    const smtp = async () => {
      throw Error("must not send");
    };
    await sendOperationalIncidentEmail(
      {
        query: async () => {
          throw Error("must not query");
        },
      },
      {
        notificationId: N,
        workspaceId: W,
        category: "certops",
        type: "distribution_failed",
        title: "Unrelated",
      },
      smtp,
    );
    await retryPendingOperationalIncidentEmails(client, smtp);
  });
});

describe("AD CS recipient policy", () => {
  it("honors workspace opt-out, pause and delivery windows", async () => {
    const { adcsEmailPolicyAllows: allows } = await modulePromise,
      now = new Date("2026-11-16T12:00:00Z");
    assert.equal(allows({ email_alerts_enabled: false }, now), false);
    assert.equal(allows({ certops_paused: true }, now), false);
    assert.equal(
      allows(
        {
          delivery_window_start: "13:00",
          delivery_window_end: "14:00",
          delivery_window_tz: "UTC",
        },
        now,
      ),
      false,
    );
    assert.equal(
      allows(
        {
          delivery_window_start: "11:00",
          delivery_window_end: "14:00",
          delivery_window_tz: "UTC",
        },
        now,
      ),
      true,
    );
    assert.equal(allows(null, now), false);
  });
  it("selects current authorized verified destinations and honors suppression even with verification off", async () => {
    const { loadAdcsIncidentRecipients: load } = await modulePromise;
    const vars = {
      CERTOPS_ENABLED: "true",
      TT_DEPLOYMENT: "self-hosted",
      RECIPIENT_VERIFICATION_MODE: "off",
      RECIPIENT_FINGERPRINT_SECRET: "unit-test-secret",
    };
    const old = Object.fromEntries(
      Object.keys(vars).map((key) => [key, process.env[key]]),
    );
    Object.assign(process.env, vars);
    try {
      let suppress = false,
        enabled = true;
      const client = {
        query: async (sql, params) => {
          assert.equal(params[0], W);
          if (sql.includes("workspace_settings"))
            return { rows: [{ email_alerts_enabled: enabled }] };
          if (sql.includes("SELECT DISTINCT u.id")) {
            assert.match(sql, /m.role='admin'/);
            assert.match(sql, /u.id=w.created_by/);
            assert.match(sql, /u.email_verified=TRUE/);
            assert.match(sql, /u.recipient_verified_email/);
            return {
              rows: [
                { id: 1, email: "Admin1@Example.test" },
                { id: 2, email: "admin1@example.test" },
              ],
            };
          }
          if (sql.includes("notification_suppressions")) {
            assert.match(sql, /scope='global'/);
            assert.match(sql, /status IN \('opted_out','revoked'\)/);
            return { rows: suppress ? [{}] : [] };
          }
          throw Error(sql);
        },
      };
      const recipients = await load(client, W);
      assert.equal(recipients.length, 1);
      assert.equal(recipients[0].email, "admin1@example.test");
      assert.match(recipients[0].key, /^[a-f0-9]{64}$/);
      suppress = true;
      assert.deepEqual(await load(client, W), []);
      suppress = false;
      enabled = false;
      assert.deepEqual(await load(client, W), []);
      enabled = true;
      process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
      client.query = async (sql) =>
        sql.includes("RV_DESTINATION_CONTACTS")
          ? { rows: [] }
          : sql.includes("workspace_settings")
            ? { rows: [{}] }
            : sql.includes("SELECT DISTINCT")
              ? { rows: [{ email: "admin1@example.test" }] }
              : { rows: [] };
      assert.deepEqual(await load(client, W), []);
    } finally {
      for (const [key, value] of Object.entries(old)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }
  });
});
