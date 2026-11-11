"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.resolve(__dirname, "../..");
const apiRoot = fs.existsSync(path.join(ROOT, "apps/api/routes/alerts.js"))
  ? "apps/api"
  : "apps/saas";
const workspaceId = "11111111-1111-4111-8111-111111111111";

function queueHandler(client) {
  const source = fs.readFileSync(
    path.join(ROOT, apiRoot, "routes/alerts.js"),
    "utf8",
  );
  const start = source.search(
    /router\.get\(\s*["'](?:\/api)?\/alert-queue["']/,
  );
  const rest = source.slice(start);
  const end = rest.search(/router\.get\(\s*["'](?:\/api)?\/alert-stats["']/);
  assert.ok(start >= 0 && end > 0, "Load the actual alert queue route");
  let handler;
  const verification = path.join(
    ROOT,
    "packages/recipient-verification/index.js",
  );
  vm.runInNewContext(rest.slice(0, end), {
    router: {
      get: (_route, ...middleware) => {
        handler = middleware.at(-1);
      },
    },
    getApiLimiter: () => () => {},
    requireAuth: () => {},
    pool: client,
    recipientVerification: fs.existsSync(verification)
      ? require(verification)
      : {},
    logger: {
      error: (_message, details) => {
        throw new Error(details.error);
      },
    },
  });
  return handler;
}

async function callQueue(handler, scoped) {
  let status = 200;
  let payload;
  const response = {
    status(value) {
      status = value;
      return this;
    },
    json(value) {
      payload = JSON.parse(JSON.stringify(value));
    },
  };
  await handler(
    { user: { id: 42 }, query: scoped ? { workspace_id: workspaceId } : {} },
    response,
  );
  return { status, payload };
}

function expectDates(row, fixture, nested = false) {
  // Match the Control Center's visible date, then enforce the date-only contract.
  assert.equal(
    new Date(row.due_date).toISOString().slice(0, 10),
    fixture.day,
    "visible due date",
  );
  assert.equal(
    row.due_date,
    fixture.day,
    "SQL DATE must remain a calendar date",
  );
  for (const name of ["created_at", "updated_at"]) {
    assert.equal(row[name], fixture.at, name);
  }
  assert.equal(
    row[nested ? "last_attempt_at" : "last_attempt"],
    fixture.empty ? null : fixture.at,
  );
  assert.equal(
    row.next_attempt_at,
    fixture.empty
      ? null
      : new Date(Date.parse(fixture.at) + 60000).toISOString(),
  );
  assert.equal(
    nested ? (row.latest_attempt?.attempted_at ?? null) : row.latest_attempt_at,
    fixture.empty ? null : fixture.at,
  );
}

async function probe() {
  const { Client } = require("pg");
  const database =
    process.env.ALERT_TIMEZONE_DB_NAME ||
    process.env.DB_NAME ||
    "alert_timezone_test";
  assert.match(
    database,
    /_test$/,
    "Use an explicitly disposable test database",
  );
  const columnType = process.env.ALERT_TIMEZONE_COLUMN_TYPE;
  assert.ok(["timestamp", "timestamptz"].includes(columnType));
  const client = new Client({
    host:
      process.env.ALERT_TIMEZONE_DB_HOST || process.env.DB_HOST || "127.0.0.1",
    port: Number(
      process.env.ALERT_TIMEZONE_DB_PORT || process.env.DB_PORT || 54329,
    ),
    user:
      process.env.ALERT_TIMEZONE_DB_USER ||
      process.env.DB_USER ||
      "timezone_test",
    password: process.env.ALERT_TIMEZONE_DB_PASSWORD || process.env.DB_PASSWORD,
    database,
  });
  await client.connect();
  try {
    await client.query("SELECT set_config('TimeZone', $1, false)", [
      process.env.ALERT_TIMEZONE_DB_ZONE,
    ]);
    // Session-local tables exercise production queries without changing application data.
    await client.query(`
      CREATE TEMP TABLE workspaces (id uuid, created_by int, created_at timestamptz, is_frozen boolean);
      CREATE TEMP TABLE workspace_memberships (workspace_id uuid, user_id int, role text);
      CREATE TEMP TABLE workspace_settings (
        workspace_id uuid, alert_thresholds jsonb, webhook_urls jsonb, contact_groups jsonb,
        default_contact_group_id text, email_alerts_enabled boolean
      );
      CREATE TEMP TABLE token_contact_groups (workspace_id uuid, token_id int, contact_group_id text);
      CREATE TEMP TABLE tokens (
        id int, user_id int, workspace_id uuid, name text, type text, expiration date,
        imported_at timestamptz, contact_group_id text, cert_lifecycle_status text
      );
      CREATE TEMP TABLE audit_events (action text, target_type text, target_id int, metadata jsonb, occurred_at timestamptz);
      CREATE TEMP TABLE alert_queue (
        id int, user_id int, token_id int, alert_key text, threshold_days int, due_date date,
        status text, attempts int, error_message text, channels jsonb,
        created_at ${columnType}, updated_at ${columnType}, last_attempt ${columnType},
        next_attempt_at ${columnType}, attempts_email int, attempts_webhooks int, attempts_whatsapp int
      );
      CREATE TEMP TABLE alert_delivery_log (
        id int, alert_queue_id int, status text, channel text, sent_at ${columnType}, error_message text
      );
    `);
    await client.query(
      "INSERT INTO workspaces VALUES ($1, 42, '2026-01-01Z', false)",
      [workspaceId],
    );
    await client.query(
      "INSERT INTO workspace_memberships VALUES ($1, 42, 'admin')",
      [workspaceId],
    );
    await client.query(
      "INSERT INTO workspace_settings VALUES ($1, '[7]', '[]', '[]', NULL, false)",
      [workspaceId],
    );
    await client.query(
      "INSERT INTO tokens VALUES (1,42,$1,'Timezone fixture','token','2027-01-01','2026-01-01Z',NULL,'active')",
      [workspaceId],
    );

    const handler = queueHandler(client);
    let eligibility;
    const eligibilityFile = path.join(
      ROOT,
      apiRoot,
      "services/alertEligibility.js",
    );
    if (apiRoot === "apps/api") {
      // Inject the real session-local database client at the existing query boundary.
      const databaseFile = require.resolve(
        path.join(ROOT, apiRoot, "db/database.js"),
      );
      require.cache[databaseFile] = {
        id: databaseFile,
        filename: databaseFile,
        loaded: true,
        exports: { pool: client },
      };
      eligibility = require(eligibilityFile);
    }
    const fixtures = [
      { day: "2026-11-03", at: "2026-11-03T08:21:45.742Z" },
      { day: "2026-07-10", at: "2026-07-10T11:45:12.123Z" },
      { day: "2026-03-29", at: "2026-03-29T02:30:00.000Z" },
      { day: "2026-10-25", at: "2026-10-25T02:30:00.000Z", empty: true },
    ];
    for (const fixture of fixtures) {
      await client.query("TRUNCATE alert_queue, alert_delivery_log");
      await client.query(
        `INSERT INTO alert_queue VALUES
        (1,42,1,'token_expiry:1',7,$1::date,'pending',1,NULL,'["email"]',
         $2::timestamptz,$2::timestamptz,$3::timestamptz,$4::timestamptz,1,0,0)`,
        [
          fixture.day,
          fixture.at,
          fixture.empty ? null : fixture.at,
          fixture.empty
            ? null
            : new Date(Date.parse(fixture.at) + 60000).toISOString(),
        ],
      );
      if (!fixture.empty) {
        await client.query(
          "INSERT INTO alert_delivery_log VALUES (1,1,'failed','email',$1::timestamptz,'synthetic failure')",
          [fixture.at],
        );
      }
      for (const scoped of [true, false]) {
        const response = await callQueue(handler, scoped);
        assert.equal(response.status, 200);
        assert.equal(response.payload.alerts.length, 1);
        expectDates(response.payload.alerts[0], fixture);
      }
      if (eligibility) {
        const states = await eligibility.loadAlertStates([1], {
          queryable: client,
          referenceDate: "2026-11-01",
        });
        expectDates(
          JSON.parse(JSON.stringify(states.get("1").delivery)),
          fixture,
          true,
        );
      }
    }
    await client.query("UPDATE workspace_memberships SET role='viewer'");
    assert.equal(
      (await callQueue(handler, true)).status,
      403,
      "Workspace role checks stay in force",
    );
    process.stdout.write(
      JSON.stringify({
        hostZone: process.env.TZ,
        columnType,
        fixtures: fixtures.length,
      }),
    );
  } finally {
    await client.end();
  }
}

if (process.env.ALERT_TIMEZONE_PROBE === "1") {
  probe().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
} else {
  const test = require("node:test");
  for (const hostZone of [
    "Europe/Berlin",
    "UTC",
    "America/New_York",
    "Asia/Kolkata",
    "Pacific/Auckland",
  ]) {
    for (const databaseZone of ["UTC", "Asia/Kolkata"]) {
      for (const columnType of ["timestamp", "timestamptz"]) {
        test(`alert dates: host=${hostZone}, database=${databaseZone}, columns=${columnType}`, () => {
          const result = spawnSync(process.execPath, [__filename], {
            cwd: ROOT,
            env: {
              ...process.env,
              NODE_ENV: "test",
              TZ: hostZone,
              ALERT_TIMEZONE_PROBE: "1",
              ALERT_TIMEZONE_DB_ZONE: databaseZone,
              ALERT_TIMEZONE_COLUMN_TYPE: columnType,
            },
            encoding: "utf8",
            timeout: 20000,
          });
          assert.equal(
            result.status,
            0,
            result.stderr || result.stdout || String(result.error),
          );
          assert.equal(JSON.parse(result.stdout).fixtures, 4);
        });
      }
    }
  }
}
