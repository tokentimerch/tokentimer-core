#!/usr/bin/env node

// Orchestrates alert queue integration flow in docker-compose:
// 1) Injects test data directly into DB
// 2) Runs discovery job (node apps/worker/src/queue-manager.js)
// 3) Runs delivery job (node apps/worker/src/delivery-worker.js)
// 4) Then runs mocha tests for queue visibility and stats

const { Client } = require("pg");
const { spawn } = require("child_process");
const { logger } = require("./logger");

async function injectTestData() {
  const client = new Client({
    user: process.env.DB_USER || "tokentimer",
    host: process.env.DB_HOST || "localhost",
    database: process.env.DB_NAME || "tokentimer",
    password: process.env.DB_PASSWORD || "password",
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 5432,
    ssl: false,
  });

  await client.connect();
  try {
    // Plans coverage: oss
    const users = [];
    const nowTs = Date.now();
    for (const plan of ["oss"]) {
      const uRes = await client.query(
        `INSERT INTO users (email, display_name, auth_method, password_hash, plan, alert_thresholds, webhook_urls)
         VALUES ($1, $2, 'local', 'x', $3, $4, $5)
         RETURNING id, email, plan`,
        [
          `compose-${plan}-${nowTs}@example.com`,
          `Compose ${plan} ${nowTs}`,
          plan,
          JSON.stringify([30, 14, 7, 1, 0]),
          JSON.stringify([
            { kind: "discord", url: "https://discord.com/api/webhooks/test" },
            { kind: "teams", url: "https://outlook.office.com/webhook/test" },
            {
              kind: "slack",
              url: "https://hooks.slack.com/services/test",
            },
          ]),
        ],
      );
      users.push(uRes.rows[0]);
    }

    // Create one personal workspace per user and add tokens scoped to workspace
    for (const u of users) {
      await client.query(
        `INSERT INTO workspaces (id, name, plan, created_by) VALUES ($1,$2,$3,$4)`,
        [require("crypto").randomUUID(), `${u.email} WS`, u.plan, u.id],
      );
      await client.query(
        `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
         SELECT $1, w.id, 'admin', $1 FROM workspaces w WHERE w.created_by=$1 LIMIT 1
         ON CONFLICT DO NOTHING`,
        [u.id],
      );
    }

    // Tokens: one per user expiring at different thresholds
    const today = new Date();
    const mkDate = (d) => {
      const x = new Date(today);
      x.setDate(x.getDate() + d);
      return x.toISOString().slice(0, 10);
    };
    const tokenSpecs = [
      { plan: "oss", name: "OSS-7d", days: 7 },
      { plan: "oss", name: "OSS-7d-b", days: 7 },
      { plan: "oss", name: "OSS-1d", days: 1 },
      { plan: "oss", name: "OSS-30d", days: 30 },
      { plan: "oss", name: "OSS-0d", days: 0 },
    ];

    for (const spec of tokenSpecs) {
      const u = users.find((x) => x.plan === spec.plan);
      const ws = await client.query(
        `SELECT id FROM workspaces WHERE created_by=$1 ORDER BY created_at ASC LIMIT 1`,
        [u.id],
      );
      const workspaceId = ws.rows[0]?.id;
      await client.query(
        `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
         VALUES ($1, $2, $1, $3, $4, 'api_key', 'general')`,
        [u.id, workspaceId, spec.name, mkDate(spec.days)],
      );
    }

    // Pre-populate delivery_log for usage counting (simulate previous month deliveries)
    // Optional: Skip; current month will be filled by delivery worker

    logger.info(
      `Injected users: ${users.map((u) => `${u.plan}:${u.id}`).join(", ")} and ${tokenSpecs.length} tokens.`,
    );
  } finally {
    await client.end();
  }
}

function runNode(cmd, args, cwd = process.cwd(), env = process.env) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: "inherit", cwd, env });
    p.on("close", (code) =>
      code === 0
        ? resolve()
        : reject(new Error(`${cmd} ${args.join(" ")} exited ${code}`)),
    );
    p.on("error", reject);
  });
}

async function main() {
  await injectTestData();

  // Run discovery then delivery sequentially
  // Ensure runner sees SMTP settings (MailHog in compose)
  const runnerEnv = {
    ...process.env,
    SMTP_HOST: process.env.SMTP_HOST || "mailhog",
    SMTP_PORT: process.env.SMTP_PORT || "1025",
    SMTP_USER: process.env.SMTP_USER || "test@example.com",
    SMTP_PASS: process.env.SMTP_PASS || "test-password",
    FROM_EMAIL: process.env.FROM_EMAIL || "noreply@tokentimer.test",
  };
  await runNode("node", ["src/queue-manager.js"], "apps/worker", runnerEnv);
  await runNode("node", ["src/delivery-worker.js"], "apps/worker", runnerEnv);

  // Run the alert queue tests afterwards
  const testEnvBase = { ...process.env };
  // Keep env consistent with backend; for plan limits we expect enforcement true in compose
  const testEnvPlan = { ...testEnvBase, ENFORCE_TOKEN_LIMITS: "true" };
  await runNode(
    "pnpm",
    [
      "exec",
      "mocha",
      "tests/integration/alert-queue.test.js",
      "--timeout",
      "30000",
    ],
    process.cwd(),
    testEnvBase,
  );
  await runNode(
    "pnpm",
    [
      "exec",
      "mocha",
      "tests/integration/alert-notifications.test.js",
      "--timeout",
      "30000",
    ],
    process.cwd(),
    testEnvBase,
  );
  await runNode(
    "pnpm",
    [
      "exec",
      "mocha",
      "tests/integration/plan-limits.test.js",
      "--timeout",
      "30000",
    ],
    process.cwd(),
    testEnvPlan,
  );
}

main().catch((err) => {
  logger.error("Runner failed:", err);
  process.exit(1);
});
