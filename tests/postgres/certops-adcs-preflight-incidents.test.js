"use strict";

// Disposable PostgreSQL, actual SMTP over loopback, and independent processes.
// No customer CA, certificate store or mailbox is involved.
const { before, after, test } = require("node:test");
const assert = require("node:assert/strict");
const { randomUUID, randomBytes } = require("node:crypto");
const { spawnSync, spawn } = require("node:child_process");
const net = require("node:net");
const { createRequire } = require("node:module");
const path = require("node:path");
let pool, workerPool, incidents, emails, smtp, container;
const name = "tt-pr714-incidents-" + randomUUID();
const CA = "ca.example.test\\Disposable CA",
  TEMPLATE = "WebServer",
  KEY = "ab".repeat(32);
const received = [];
let rejectAddress = null,
  rejectCode = 450,
  onData = null,
  onGreeting = null;
function docker(args) {
  const result = spawnSync("docker", args, {
    encoding: "utf8",
    timeout: 120000,
  });
  assert.equal(result.status, 0, result.stderr || String(result.error));
  return result.stdout.trim();
}
before(
  async () => {
    container = docker([
      "run",
      "-d",
      "--name",
      name,
      "--label",
      "tokentimer.test=pr714-incidents",
      "-p",
      "127.0.0.1::5432",
      "-e",
      "POSTGRES_USER=qa",
      "-e",
      "POSTGRES_PASSWORD=disposable-only",
      "-e",
      "POSTGRES_DB=qa",
      "postgres:17-alpine",
    ]);
    const port = JSON.parse(docker(["inspect", container]))[0].NetworkSettings
      .Ports["5432/tcp"][0].HostPort;
    for (let i = 0; i < 120; i++) {
      if (
        spawnSync(
          "docker",
          ["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "qa"],
          { timeout: 10000 },
        ).status === 0
      )
        break;
      await new Promise((r) => setTimeout(r, 250));
    }
    Object.assign(process.env, {
      NODE_ENV: "test",
      CERTOPS_ENABLED: "true",
      DB_HOST: "127.0.0.1",
      DB_PORT: port,
      DB_NAME: "qa",
      DB_USER: "qa",
      DB_PASSWORD: "disposable-only",
      SESSION_SECRET: "pr714-isolated-test-only",
      RECIPIENT_FINGERPRINT_SECRET: "pr714-isolated-fingerprint-only",
      RECIPIENT_VERIFICATION_MODE: "off",
      TT_DEPLOYMENT: "self-hosted",
    });
    const migration = spawnSync(
      process.execPath,
      ["apps/api/migrations/migrate.js"],
      { encoding: "utf8", timeout: 120000, env: process.env },
    );
    assert.equal(
      migration.status,
      0,
      migration.stderr || String(migration.error),
    );
    ({ pool } = require("../../apps/api/db/database"));
    incidents = require("../../apps/api/services/certops/adcsPreflightIncidents");
    // A minimal real SMTP catcher also supports rejection and acceptance holds.
    smtp = net.createServer((socket) => {
      let buffer = "",
        data = false,
        body = "",
        to = "";
      socket.write("220 localhost PR714 disposable SMTP\r\n");
      socket.on("data", (chunk) => {
        buffer += chunk.toString();
        let split;
        while ((split = buffer.indexOf("\r\n")) >= 0) {
          const line = buffer.slice(0, split);
          buffer = buffer.slice(split + 2);
          if (data) {
            if (line !== ".") {
              body += line + "\n";
              continue;
            }
            data = false;
            received.push({ to, body });
            body = "";
            Promise.resolve(onData?.({ to, socket })).then(() => {
              if (!socket.destroyed) socket.write("250 accepted\r\n");
            });
          } else if (/^EHLO|^HELO/i.test(line))
            Promise.resolve(onGreeting?.()).then(() =>
              socket.write("250 localhost\r\n"),
            );
          else if (/^MAIL FROM/i.test(line)) socket.write("250 sender ok\r\n");
          else if (/^RCPT TO/i.test(line)) {
            to = line.match(/<([^>]+)>/)?.[1];
            socket.write(
              to === rejectAddress || rejectAddress === "*"
                ? `${rejectCode} disposable rejection\r\n`
                : "250 recipient ok\r\n",
            );
          } else if (/^DATA$/i.test(line)) {
            data = true;
            socket.write("354 end with dot\r\n");
          } else if (/^QUIT$/i.test(line)) {
            socket.end("221 bye\r\n");
          } else socket.write("250 ok\r\n");
        }
      });
      socket.on("error", () => {});
    });
    await new Promise((r) => smtp.listen(0, "127.0.0.1", r));
    Object.assign(process.env, {
      SMTP_HOST: "127.0.0.1",
      SMTP_PORT: String(smtp.address().port),
      SMTP_SECURE: "false",
      SMTP_REQUIRE_TLS: "false",
      FROM_EMAIL: "qa@example.test",
    });
    delete process.env.SMTP_USER;
    delete process.env.SMTP_PASS;
    emails =
      await import("../../apps/worker/src/shared/adcsPreflightEmails.js");
    ({ pool: workerPool } = await import("../../apps/worker/src/db.js"));
  },
  { timeout: 240000 },
);
after(async () => {
  if (workerPool) await workerPool.end();
  if (pool) await pool.end();
  if (smtp) await new Promise((r) => smtp.close(r));
  if (container) {
    const info = JSON.parse(docker(["inspect", container]))[0];
    assert.equal(info.Name, "/" + name);
    assert.equal(info.Config.Labels["tokentimer.test"], "pr714-incidents");
    docker(["rm", "--force", "--volumes", container]);
  }
});
async function fixture() {
  const workspaceId = randomUUID(),
    issuerId = randomUUID();
  async function user(prefix) {
    const email = `${prefix}-${randomUUID()}@example.test`;
    return (
      await pool.query(
        `INSERT INTO users(email,email_original,display_name,password_hash,auth_method,email_verified)
      VALUES($1::text,$1::text,'QA','synthetic','local',true) RETURNING id,email`,
        [email],
      )
    ).rows[0];
  }
  const owner = await user("owner"),
    admin = await user("admin"),
    member = await user("member");
  await pool.query(
    "INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'PR714 disposable',$2,'oss')",
    [workspaceId, owner.id],
  );
  await pool.query(
    "UPDATE workspace_memberships SET role='workspace_manager' WHERE workspace_id=$1 AND role='admin'",
    [workspaceId],
  );
  await pool.query(
    "INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'admin'),($1,$3,'viewer')",
    [workspaceId, admin.id, member.id],
  );
  await pool.query(
    "INSERT INTO certificate_issuers(id,workspace_id,kind,name,current_version,revalidation_required) VALUES($1,$2,'adcs','QA CA',1,false)",
    [issuerId, workspaceId],
  );
  await pool.query(
    `INSERT INTO certificate_issuer_versions(workspace_id,issuer_id,version,ca_config,template,transport,ca_key_sha256,confirmed_at)
    VALUES($1,$2,1,$3,$4,'dcom',$5,NOW()-interval '7 days')`,
    [workspaceId, issuerId, CA, TEMPLATE, KEY],
  );
  const agentId = (
    await pool.query(
      `INSERT INTO certops_agents(workspace_id,agent_id,name,agent_version,protocol_version,credential_prefix,credential_hash,status,platform,
    supported_operations,declared_target_selectors,declared_capabilities,capabilities_updated_at)
    VALUES($1,$2,'QA Windows','0.18.0','1.0.0',$3,$4,'active','win32','["renew","adcs-preflight"]','[]','["adcs-enroll-v1"]',NOW()) RETURNING id`,
      [
        workspaceId,
        randomUUID(),
        "ttagent_" + randomBytes(8).toString("hex"),
        randomBytes(32).toString("hex"),
      ],
    )
  ).rows[0].id;
  await pool.query(
    `INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status,source,assigned_agent_id,error_code)
    VALUES($1,'external',$2,'adcs-preflight','failed','automation',$3,'ADCS_TEMPLATE_UNSAFE')`,
    [workspaceId, issuerId, agentId],
  );
  const certs = [];
  for (const days of [1, 5, 25]) {
    const domain = `c${days}-${randomUUID()}.example.test`;
    const target = {
      type: "windows-iis",
      reference: domain,
      store: "My",
      binding: { site: "QA", port: 443, sniHost: domain },
    };
    const profileId = (
      await pool.query(
        `INSERT INTO certificate_profiles(workspace_id,name,status,source,source_ref,issuer_id,renew_before_days,key_mode,public_metadata,created_by)
      VALUES($1,$2,'active','manual',$2,$3,30,'os-store-managed',$4::jsonb,$5) RETURNING id`,
        [
          workspaceId,
          domain,
          issuerId,
          JSON.stringify({
            renewalProfile: {
              target,
              sanPolicy: { sans: [domain] },
              keyAlgorithm: "rsa",
              keySize: 2048,
            },
          }),
          owner.id,
        ],
      )
    ).rows[0].id;
    const id = (
      await pool.query(
        `INSERT INTO managed_certificates(workspace_id,status,source,source_ref,name,common_name,subject_alt_names,
      key_mode,key_reference,public_metadata,deployed_agent_id,profile_id,not_after,fingerprint_sha256)
      VALUES($1,'active','agent_issuance',$2,$3,$3,$4,'os-store-managed',$5,$6::jsonb,$7,$8,NOW()+($9*interval '1 day'),$10) RETURNING id`,
        [
          workspaceId,
          randomUUID(),
          domain,
          [domain],
          `winstore://My/QA:443`,
          JSON.stringify({
            issuance: { requestedAt: new Date().toISOString(), target },
          }),
          agentId,
          profileId,
          days,
          randomBytes(32).toString("hex"),
        ],
      )
    ).rows[0].id;
    await pool.query(
      "UPDATE certops_management_periods SET renewal_profile_id=$2,automation_enabled=TRUE WHERE managed_certificate_id=$1 AND ended_at IS NULL",
      [id, profileId],
    );
    certs.push({ id, profileId, domain });
  }
  await pool.query(
    "UPDATE certops_agents SET declared_target_selectors=$2::jsonb WHERE id=$1",
    [agentId, JSON.stringify(certs.map((c) => c.domain))],
  );
  const f = { workspaceId, issuerId, agentId, owner, admin, member, certs };
  f.reconcile = () =>
    incidents.reconcileIssuerPreflightIncident({
      db: pool,
      workspaceId,
      issuerId,
    });
  f.row = async () =>
    (
      await pool.query(
        "SELECT * FROM operational_notifications WHERE workspace_id=$1 AND dedupe_key=$2 AND resolved_at IS NULL",
        [workspaceId, `adcs-preflight:${issuerId}`],
      )
    ).rows[0];
  await f.reconcile();
  return f;
}
async function send(f, sender, options) {
  const row = await f.row(),
    client = await pool.connect();
  try {
    await emails.sendAdcsPreflightIncidentEmail(
      client,
      { notificationId: row.id, workspaceId: f.workspaceId },
      sender,
      options,
    );
  } finally {
    client.release();
  }
}
async function realSender(options = {}) {
  const requireWorker = createRequire(path.resolve("apps/worker/package.json"));
  const tx = requireWorker("nodemailer").createTransport({
    host: "127.0.0.1",
    port: smtp.address().port,
    secure: false,
    ignoreTLS: true,
    connectionTimeout: 500,
    greetingTimeout: 500,
    socketTimeout: 500,
    ...options,
  });
  return async (input) => {
    await input.onBeforeAttempt();
    try {
      await tx.sendMail({ from: "qa@example.test", ...input });
      return { success: true };
    } catch {
      return { success: false };
    }
  };
}
async function crashedDelivery(f, phase) {
  const row = await f.row();
  const script = `(async()=>{const {pool}=require('./apps/api/db/database');const m=await import('./apps/worker/src/shared/adcsPreflightEmails.js');const e=await import('./apps/worker/src/notify/email.js');const c=await pool.connect();const query=c.query.bind(c);c.query=async(sql,params)=>{const result=await query(sql,params);if((${JSON.stringify(phase)}==='before-claim'&&sql.includes('AS issuer_id'))||(${JSON.stringify(phase)}==='claim'&&sql.includes('RETURNING title')&&result.rows.length)||(${JSON.stringify(phase)}==='receipt'&&sql.includes('jsonb_set(metadata')))process.exit(86);return result;};await m.sendAdcsPreflightIncidentEmail(c,${JSON.stringify({ notificationId: row.id, workspaceId: f.workspaceId })},async input=>{const result=await e.sendEmailNotification(input);if(result.success&&${JSON.stringify(phase)}==='accepted')process.exit(86);return result;});process.exit(87);})().catch(()=>process.exit(88));`;
  await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["-e", script], {
      env: { ...process.env, NODE_ENV: "development" },
      stdio: "ignore",
    });
    const timer = setTimeout(() => {
      child.kill();
      reject(Error("crash fixture timed out"));
    }, 30000);
    child.on("error", reject);
    child.on("exit", (code) => {
      clearTimeout(timer);
      try {
        assert.equal(code, 86);
        resolve();
      } catch (error) {
        reject(error);
      }
    });
  });
}
test(
  "real process death releases workspace locks; live claims stay fenced and expired claims recover",
  async () => {
    const unclaimed = await fixture(),
      before = received.length;
    await crashedDelivery(unclaimed, "before-claim");
    assert.equal((await unclaimed.row()).email_claim_id, null);
    assert.equal(received.length, before);
    await send(unclaimed, await realSender());
    assert.equal(received.length - before, 2);
    for (const phase of ["claim", "accepted", "receipt"]) {
      const f = await fixture(),
        start = received.length;
      await crashedDelivery(f, phase);
      const row = await f.row();
      assert.ok(row.email_claim_id);
      assert.equal(row.email_sent_at, null);
      assert.equal(received.length - start, phase === "claim" ? 0 : 1);
      await send(f, await realSender());
      assert.equal(
        received.length - start,
        phase === "claim" ? 0 : 1,
        "live claim must not be stolen",
      );
      await pool.query(
        "UPDATE operational_notifications SET email_claimed_at=NOW()-interval '11 minutes' WHERE id=$1",
        [row.id],
      );
      await send(f, await realSender());
      assert.ok((await f.row()).email_sent_at);
      assert.equal(
        received.length - start,
        phase === "accepted" ? 3 : 2,
        "only acceptance without a receipt may repeat",
      );
    }
  },
  { timeout: 120000 },
);
test("real cap, delivery window, global disable and pause leave external email pending", async () => {
  const f = await fixture(),
    start = received.length,
    sender = await realSender();
  await send(f, sender, { dailyCap: 0 });
  assert.equal(received.length, start);
  assert.equal((await f.row()).email_sent_at, null);
  const closedTime = new Date(Date.now() + 12 * 3600000)
    .toISOString()
    .slice(11, 16);
  await pool.query(
    "INSERT INTO workspace_settings(workspace_id,email_alerts_enabled,delivery_window_start,delivery_window_end,delivery_window_tz) VALUES($1,TRUE,$2,$2,'UTC') ON CONFLICT(workspace_id) DO UPDATE SET delivery_window_start=$2,delivery_window_end=$2,delivery_window_tz='UTC'",
    [f.workspaceId, closedTime],
  );
  await send(f, sender);
  assert.equal(received.length, start);
  process.env.CERTOPS_ENABLED = "false";
  try {
    await send(f, sender);
    assert.equal(received.length, start);
    assert.equal(await f.row(), undefined);
  } finally {
    process.env.CERTOPS_ENABLED = "true";
  }
  const paused = await fixture();
  await pool.query("UPDATE workspaces SET certops_paused=TRUE WHERE id=$1", [
    paused.workspaceId,
  ]);
  await send(paused, sender);
  assert.equal(received.length, start);
  assert.equal(await paused.row(), undefined);
});
test("severity change and resolution during SMTP verification stop DATA without a scheduling transaction", async () => {
  for (const resolve of [false, true]) {
    const f = await fixture(),
      row = await f.row(),
      start = received.length;
    onGreeting = async () => {
      onGreeting = null;
      assert.equal(
        (
          await pool.query(
            "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname=current_database() AND state='idle in transaction'",
          )
        ).rows[0].n,
        0,
      );
      await pool.query(
        resolve
          ? "UPDATE operational_notifications SET resolved_at=NOW() WHERE id=$1"
          : "UPDATE operational_notifications SET severity='warning' WHERE id=$1",
        [row.id],
      );
    };
    process.env.NODE_ENV = "development";
    try {
      await send(f);
    } finally {
      process.env.NODE_ENV = "test";
      onGreeting = null;
    }
    assert.equal(received.length, start);
  }
});
test("actual SMTP acknowledgement loss has the same ambiguous acceptance limitation as a lost DB receipt", async () => {
  const f = await fixture(),
    start = received.length;
  let once = true;
  onData = ({ socket }) => {
    if (once) {
      once = false;
      socket.destroy();
    }
  };
  try {
    await send(f, await realSender());
  } finally {
    onData = null;
  }
  assert.equal((await f.row()).email_sent_at, null);
  assert.equal(received.length - start, 2); // one accepted with a lost ACK; the other succeeded
  await send(f, await realSender());
  assert.equal(received.length - start, 3);
  assert.ok((await f.row()).email_sent_at);
});
test("real SMTP connection failure, handshake timeout and 450/550 rejection remain retryable without resolving the incident", async () => {
  for (const failure of ["connection", "timeout", 450, 550]) {
    const f = await fixture(),
      start = received.length;
    if (typeof failure === "number") {
      rejectAddress = "*";
      rejectCode = failure;
    }
    if (failure === "timeout")
      onGreeting = () => new Promise((resolve) => setTimeout(resolve, 250));
    try {
      await send(
        f,
        await realSender(
          failure === "connection"
            ? { port: 1 }
            : failure === "timeout"
              ? { socketTimeout: 75 }
              : {},
        ),
      );
    } finally {
      rejectAddress = null;
      rejectCode = 450;
      onGreeting = null;
    }
    assert.equal(received.length, start);
    assert.equal((await f.row()).email_sent_at, null);
    assert.equal((await f.row()).resolved_at, null);
    await send(f, await realSender());
    assert.equal(received.length - start, 2);
    assert.ok((await f.row()).email_sent_at);
  }
});

async function runProcesses(script, count = 3) {
  await Promise.all(
    Array.from(
      { length: count },
      () =>
        new Promise((resolve, reject) => {
          let output = "";
          const child = spawn(process.execPath, ["-e", script], {
            env: process.env,
          });
          const timer = setTimeout(() => {
            child.kill();
            reject(Error("database worker timed out"));
          }, 60000);
          child.stdout.on("data", (b) => (output += b));
          child.stderr.on("data", (b) => (output += b));
          child.on("error", reject);
          child.on("exit", (code) => {
            clearTimeout(timer);
            code === 0 ? resolve() : reject(Error(output));
          });
        }),
    ),
  );
}
test(
  "independent API processes and scheduler processes dispatch one shared preflight",
  async () => {
    const f = await fixture();
    await pool.query("DELETE FROM certificate_jobs WHERE workspace_id=$1", [
      f.workspaceId,
    ]);
    const confirmedAt = (
      await pool.query(
        "SELECT confirmed_at FROM certificate_issuer_versions WHERE workspace_id=$1 AND issuer_id=$2",
        [f.workspaceId, f.issuerId],
      )
    ).rows[0].confirmed_at;
    const input = {
      workspaceId: f.workspaceId,
      issuerId: f.issuerId,
      agentId: f.agentId,
      caConfig: CA,
      template: TEMPLATE,
      automatic: true,
      confirmedAt,
    };
    await runProcesses(
      `(async()=>{const {pool}=require('./apps/api/db/database');try{await require('./apps/api/services/certops/certificateEnrollments').dispatchPreflight({client:pool,...${JSON.stringify(input)}});}finally{await pool.end();}})().catch(e=>{console.error(e.code||e.message);process.exitCode=1;});`,
    );
    assert.equal(
      (
        await pool.query(
          "SELECT count(*)::int AS n FROM certificate_jobs WHERE workspace_id=$1 AND operation='adcs-preflight'",
          [f.workspaceId],
        )
      ).rows[0].n,
      1,
    );
    await runProcesses(
      `(async()=>{const {pool}=require('./apps/api/db/database');try{await require('./apps/api/services/certops/renewalScheduler').runRenewalSchedulerSweep({dbPool:pool,env:process.env});}finally{await pool.end();}})().catch(e=>{console.error(e.code||e.message);process.exitCode=1;});`,
    );
    assert.equal(
      (
        await pool.query(
          "SELECT count(*)::int AS n FROM certificate_jobs WHERE workspace_id=$1 AND operation='adcs-preflight'",
          [f.workspaceId],
        )
      ).rows[0].n,
      1,
    );
  },
  { timeout: 180000 },
);
test("large shared issuer counts every due certificate without unbounded incident metadata", async () => {
  const f = await fixture(),
    started = performance.now();
  await pool.query(
    `INSERT INTO managed_certificates(workspace_id,status,source,source_ref,name,common_name,subject_alt_names,key_mode,key_reference,public_metadata,deployed_agent_id,profile_id,not_after,fingerprint_sha256)
    SELECT workspace_id,status,source,gen_random_uuid()::text,name,common_name,subject_alt_names,key_mode,key_reference,public_metadata,deployed_agent_id,profile_id,not_after,
      md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text) FROM managed_certificates CROSS JOIN generate_series(1,1000)
    WHERE id=$1`,
    [f.certs[0].id],
  );
  await pool.query(
    "UPDATE certops_management_periods SET automation_enabled=TRUE WHERE workspace_id=$1 AND ended_at IS NULL",
    [f.workspaceId],
  );
  await f.reconcile();
  const row = await f.row();
  assert.equal(row.metadata.affectedCount, 1003);
  assert.ok(JSON.stringify(row.metadata).length < 2048);
  const readiness = await incidents.loadIssuerPreflightReadiness({
    db: pool,
    workspaceId: f.workspaceId,
    issuerId: f.issuerId,
  });
  assert.equal(readiness.dueCount, 1003);
  assert.ok(readiness.checks.length <= 20);
  console.log(
    `PR714 large-workspace fixture: 1003 paths, ${Math.round(performance.now() - started)}ms including inserts and reconciliation; bounded incident ${JSON.stringify(row.metadata).length} bytes`,
  );
});
test("real shared issuer SQL preserves earliest risk, count, downgrade, retirement and recovery", async () => {
  const f = await fixture();
  const initial = await f.row();
  const link = new URL(initial.metadata.href, "http://disposable.example.test");
  assert.equal(link.pathname, "/certops/renewals");
  assert.equal(link.searchParams.get("action"), "check-adcs-issuer");
  assert.equal(link.searchParams.get("workspace"), f.workspaceId);
  assert.equal(link.searchParams.get("issuerId"), f.issuerId);
  assert.equal(initial.metadata.affectedCount, 3);
  assert.equal(initial.metadata.mostUrgentCertificateId, f.certs[0].id);
  assert.equal(initial.severity, "critical");
  await Promise.all(Array.from({ length: 6 }, () => f.reconcile()));
  assert.equal(
    (
      await pool.query(
        "SELECT count(*)::int AS n FROM operational_notifications WHERE workspace_id=$1 AND resolved_at IS NULL",
        [f.workspaceId],
      )
    ).rows[0].n,
    1,
  );
  await pool.query(
    "UPDATE certops_management_periods SET automation_enabled=FALSE WHERE managed_certificate_id=$1",
    [f.certs[0].id],
  );
  await f.reconcile();
  assert.equal((await f.row()).metadata.affectedCount, 2);
  assert.equal((await f.row()).metadata.mostUrgentCertificateId, f.certs[1].id);
  await pool.query(
    "UPDATE certificate_profiles SET status='disabled' WHERE id=$1",
    [f.certs[1].profileId],
  );
  await f.reconcile();
  assert.equal((await f.row()).severity, "warning");
  assert.equal((await f.row()).metadata.affectedCount, 1);
  await pool.query("UPDATE workspaces SET certops_paused=TRUE WHERE id=$1", [
    f.workspaceId,
  ]);
  await f.reconcile();
  assert.equal(await f.row(), undefined);
  await pool.query("UPDATE workspaces SET certops_paused=FALSE WHERE id=$1", [
    f.workspaceId,
  ]);
  await f.reconcile();
  assert.equal((await f.row()).metadata.affectedCount, 1);
  await pool.query(
    `UPDATE certificate_jobs SET status='succeeded',error_code=NULL,result_metadata=$3::jsonb
    WHERE workspace_id=$1 AND subject_id=$2`,
    [
      f.workspaceId,
      f.issuerId,
      JSON.stringify({
        preflightVerdict: {
          caConfig: CA,
          template: TEMPLATE,
          caKeySha256s: [KEY],
          caCheck: "safe",
          templateCheck: "safe",
        },
      }),
    ],
  );
  await f.reconcile();
  assert.equal(await f.row(), undefined);
});
test("real recipient SQL excludes nonadmins, removed/unverified/changed destinations and suppressions", async () => {
  const f = await fixture(),
    load = () => emails.loadAdcsIncidentRecipients(pool, f.workspaceId);
  assert.deepEqual(
    (await load()).map((r) => r.email).sort(),
    [f.owner.email, f.admin.email].sort(),
  );
  await pool.query(
    "DELETE FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2",
    [f.workspaceId, f.admin.id],
  );
  assert.equal((await load()).length, 1);
  await pool.query("UPDATE users SET email_verified=FALSE WHERE id=$1", [
    f.owner.id,
  ]);
  assert.equal((await load()).length, 0);
  await pool.query(
    "UPDATE users SET email_verified=TRUE,email_original=$2 WHERE id=$1",
    [f.owner.id, "changed@example.test"],
  );
  assert.equal((await load()).length, 0);
  await pool.query("UPDATE users SET email_original=email WHERE id=$1", [
    f.owner.id,
  ]);
  const key = (await load())[0].key;
  await pool.query(
    "INSERT INTO notification_suppressions(channel,destination_fingerprint,scope,reason) VALUES('email',$1,'global','qa')",
    [key],
  );
  assert.equal((await load()).length, 0);
  await pool.query(
    "DELETE FROM notification_suppressions WHERE destination_fingerprint=$1",
    [key],
  );
  await pool.query(
    "INSERT INTO notification_suppressions(channel,destination_fingerprint,scope,workspace_id,reason) VALUES('email',$1,'workspace',$2,'qa')",
    [key, f.workspaceId],
  );
  assert.equal((await load()).length, 0);
  await pool.query(
    "DELETE FROM notification_suppressions WHERE destination_fingerprint=$1",
    [key],
  );
  const contactId = (
    await pool.query(
      "INSERT INTO workspace_contacts(workspace_id,first_name,last_name,phone_e164,details) VALUES($1,'QA','Recipient','+12025550123',$2::jsonb) RETURNING id",
      [f.workspaceId, JSON.stringify({ email: f.owner.email })],
    )
  ).rows[0].id;
  await pool.query(
    `INSERT INTO contact_channel_verifications(workspace_id,contact_id,channel,destination_normalized,destination_fingerprint,status)
    VALUES($1,$2,'email',$3,$4,'opted_out')`,
    [f.workspaceId, contactId, f.owner.email, key],
  );
  assert.equal((await load()).length, 0);
  await pool.query(
    "UPDATE contact_channel_verifications SET status='revoked' WHERE contact_id=$1",
    [contactId],
  );
  assert.equal((await load()).length, 0);
  await pool.query(
    "UPDATE contact_channel_verifications SET status='verified',verified_at=NOW() WHERE contact_id=$1",
    [contactId],
  );
  process.env.RECIPIENT_VERIFICATION_MODE = "enforce";
  try {
    assert.equal(
      (await load()).length,
      0,
      "verification without consent cannot authorize delivery",
    );
    await pool.query(
      "UPDATE contact_channel_verifications SET consent_at=NOW() WHERE contact_id=$1",
      [contactId],
    );
    const decision =
      await require("../../packages/recipient-verification").canDeliverToDestination(
        {
          client: pool,
          workspaceId: f.workspaceId,
          channel: "email",
          destination: f.owner.email,
        },
      );
    assert.equal(
      decision.allowed,
      false,
      "a status edit must not remove durable opt-out/revocation suppressions",
    );
    assert.ok(
      ["RECIPIENT_OPTED_OUT", "RECIPIENT_REVOKED"].includes(decision.code),
    );
    const fresh = await fixture();
    const freshKey =
      require("../../packages/recipient-verification").destinationFingerprint(
        "email",
        fresh.owner.email,
      );
    const freshContact = (
      await pool.query(
        "INSERT INTO workspace_contacts(workspace_id,first_name,last_name,phone_e164,details) VALUES($1,'QA','Consent','+12025550124',$2::jsonb) RETURNING id",
        [fresh.workspaceId, JSON.stringify({ email: fresh.owner.email })],
      )
    ).rows[0].id;
    await pool.query(
      `INSERT INTO contact_channel_verifications(workspace_id,contact_id,channel,destination_normalized,destination_fingerprint,status,verified_at)
      VALUES($1,$2,'email',$3,$4,'verified',NOW())`,
      [fresh.workspaceId, freshContact, fresh.owner.email, freshKey],
    );
    assert.equal(
      (await emails.loadAdcsIncidentRecipients(pool, fresh.workspaceId)).length,
      0,
    );
    await pool.query(
      "UPDATE contact_channel_verifications SET consent_at=NOW() WHERE contact_id=$1",
      [freshContact],
    );
    assert.equal(
      (await emails.loadAdcsIncidentRecipients(pool, fresh.workspaceId)).length,
      1,
    );
    await pool.query(
      "INSERT INTO workspace_settings(workspace_id,email_alerts_enabled) VALUES($1,FALSE) ON CONFLICT(workspace_id) DO UPDATE SET email_alerts_enabled=FALSE",
      [fresh.workspaceId],
    );
    assert.equal(
      (await emails.loadAdcsIncidentRecipients(pool, fresh.workspaceId)).length,
      0,
    );
  } finally {
    process.env.RECIPIENT_VERIFICATION_MODE = "off";
  }
  await pool.query(
    "INSERT INTO workspace_settings(workspace_id,email_alerts_enabled) VALUES($1,FALSE) ON CONFLICT(workspace_id) DO UPDATE SET email_alerts_enabled=FALSE",
    [f.workspaceId],
  );
  assert.equal((await load()).length, 0);
});
test("production email sender reaches only the disposable SMTP catcher and records transport receipts", async () => {
  const f = await fixture(),
    start = received.length;
  process.env.NODE_ENV = "development";
  try {
    await send(f);
  } finally {
    process.env.NODE_ENV = "test";
  }
  assert.equal(received.length - start, 2);
  assert.deepEqual(
    received
      .slice(start)
      .map((r) => r.to)
      .sort(),
    [f.owner.email, f.admin.email].sort(),
  );
  assert.ok((await f.row()).email_sent_at);
  assert.equal(
    Object.keys((await f.row()).metadata.emailDelivery.accepted).length,
    2,
  );
});
test("real SMTP partial success survives restart and known successful destinations are not repeated", async () => {
  const f = await fixture(),
    start = received.length;
  rejectAddress = f.admin.email;
  await send(f, await realSender());
  assert.equal((await f.row()).email_sent_at, null);
  assert.equal(received.length - start, 1);
  rejectAddress = null;
  await send(f, await realSender());
  assert.equal(received.length - start, 2);
  assert.ok((await f.row()).email_sent_at);
});
test(
  "actual processes compete for one incident without duplicate SMTP sends",
  async () => {
    const f = await fixture(),
      row = await f.row(),
      start = received.length;
    const script = `(async()=>{const {pool}=require('./apps/api/db/database');const m=await import('./apps/worker/src/shared/adcsPreflightEmails.js');const c=await pool.connect();try{await m.sendAdcsPreflightIncidentEmail(c,${JSON.stringify({ notificationId: row.id, workspaceId: f.workspaceId })});}finally{c.release();await pool.end();const w=await import('./apps/worker/src/db.js');await w.pool.end();}})().catch(e=>{console.error(e.code||e.message);process.exitCode=1;});`;
    const run = () =>
      new Promise((resolve, reject) => {
        let output = "";
        const child = spawn(process.execPath, ["-e", script], {
          env: { ...process.env, NODE_ENV: "development" },
        });
        child.stdout.on("data", (b) => (output += b));
        child.stderr.on("data", (b) => (output += b));
        child.on("error", reject);
        child.on("exit", (code) =>
          code === 0 ? resolve() : reject(Error(output)),
        );
      });
    await Promise.all([run(), run(), run()]);
    assert.equal(received.length - start, 2);
    assert.ok((await f.row()).email_sent_at);
  },
  { timeout: 60000 },
);
test("SMTP failure and ambiguous acceptance preserve incident state; saved receipts survive claim-release crashes", async () => {
  const f = await fixture(),
    start = received.length;
  // Simulate losing the process immediately after the SMTP server accepted.
  const smtpSender = await realSender();
  let first = true;
  await send(f, async (input) => {
    const result = await smtpSender(input);
    if (first) {
      first = false;
      throw Error("crash before receipt");
    }
    return result;
  });
  assert.equal(received.length - start, 1);
  assert.equal((await f.row()).email_sent_at, null);
  await send(f, await realSender());
  assert.equal(received.length - start, 3);
  assert.ok((await f.row()).email_sent_at);
  // A crash after receipt persistence leaves a stale claim; it must not resend.
  const row = await f.row();
  await pool.query(
    "UPDATE operational_notifications SET email_sent_at=NULL,email_claim_id=$2,email_claimed_at=NOW()-interval '11 minutes' WHERE id=$1",
    [row.id, randomUUID()],
  );
  await send(f, await realSender());
  assert.equal(received.length - start, 3);
  assert.ok((await f.row()).email_sent_at);
});
test("recipient authorization is rechecked after the SMTP handshake before message submission", async () => {
  const f = await fixture(),
    start = received.length;
  // The actual production sender performs verify() before sendMail(). A role
  // or consent change during that handshake must prevent DATA submission.
  onGreeting = async () => {
    onGreeting = null;
    await pool.query(
      "UPDATE users SET email_verified=FALSE WHERE id=ANY($1::int[])",
      [[f.owner.id, f.admin.id]],
    );
  };
  process.env.NODE_ENV = "development";
  try {
    await send(f);
  } finally {
    process.env.NODE_ENV = "test";
    onGreeting = null;
  }
  assert.equal(received.length, start);
  assert.equal((await f.row()).email_sent_at, null);
});

test("SMTP AD CS email preserves authoritative workspace and issuer destination", async () => {
  const f = await fixture(),
    start = received.length;
  const original = process.env.NODE_ENV;
  process.env.NODE_ENV = "development";
  try {
    await send(f);
  } finally {
    process.env.NODE_ENV = original;
  }
  assert.equal(received.length - start, 2);
  for (const mail of received.slice(start)) {
    const decoded = mail.body
      .replace(/=\r?\n/g, "")
      .replace(/=([0-9A-F]{2})/gi, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16)),
      );
    assert.ok(
      decoded.includes("/certops/renewals?workspace=" + f.workspaceId),
      "actual SMTP message must link to Renewals",
    );
    assert.ok(decoded.includes(f.issuerId));
    assert.ok(decoded.includes("check-adcs-issuer"));
  }
});
test("automatic preflight finds eligible agent 101 among 125 declarations", async () => {
  const f = await fixture();
  await pool.query("UPDATE certops_agents SET status='offline' WHERE id=$1", [
    f.agentId,
  ]);
  const agents = (
    await pool.query(
      `INSERT INTO certops_agents(workspace_id,agent_id,name,agent_version,protocol_version,credential_prefix,credential_hash,status,platform,supported_operations,declared_target_selectors,declared_capabilities,capabilities_updated_at,last_seen_at)
    SELECT $1,gen_random_uuid(),'Large fixture '||n,'0.18.0','1.0.0','ttagent_'||substr(replace(gen_random_uuid()::text,'-',''),1,16),md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'active','win32','["renew","adcs-preflight"]',$2::jsonb,
      CASE WHEN n>100 THEN '["adcs-enroll-v1"]'::jsonb ELSE '[]'::jsonb END,NOW(),NOW()-n*interval '1 second'
    FROM generate_series(1,125) n RETURNING id,name`,
      [f.workspaceId, JSON.stringify(f.certs.map((c) => c.domain))],
    )
  ).rows;
  const certificate = (
    await pool.query(
      `SELECT mc.*,cp.issuer_id AS profile_issuer_id,cp.public_metadata AS profile_public_metadata FROM managed_certificates mc JOIN certificate_profiles cp ON cp.id=mc.profile_id WHERE mc.id=$1`,
      [f.certs[0].id],
    )
  ).rows[0];
  const calls = [];
  await assert.rejects(
    require("../../apps/api/services/certops/renewalScheduler").createAutomaticAdcsRenewal(
      {
        dbPool: pool,
        certificate,
        mode: "execute",
        env: process.env,
        preflightDispatcher: async (value) => calls.push(value),
      },
    ),
  );
  assert.equal(calls.length, 1);
  assert.equal(
    calls[0].agentId,
    agents.find((a) => a.name === "Large fixture 101").id,
  );
  assert.equal(calls[0].unavailableTarget, undefined);
  // Heartbeats may move an unseen eligible row ahead of the page cursor.
  // Selection must retain one database snapshot across all bounded pages.
  const selected = agents.find((a) => a.name === "Large fixture 101").id;
  await pool.query(
    "UPDATE certops_agents SET declared_capabilities='[]'::jsonb WHERE workspace_id=$1 AND id<>$2",
    [f.workspaceId, selected],
  );
  let moved = false;
  async function observedQuery(connection, sql, params) {
    const result = await connection.query(sql, params);
    if (
      !moved &&
      sql.includes("cursor_seen_at") &&
      result.rows.length === 100
    ) {
      moved = true;
      await pool.query(
        "UPDATE certops_agents SET last_seen_at=NOW() WHERE id=$1",
        [selected],
      );
    }
    return result;
  }
  const observed = {
    idleCount: pool.idleCount,
    query: (sql, params) => observedQuery(pool, sql, params),
    connect: async () => {
      const client = await pool.connect();
      return {
        query: (sql, params) => observedQuery(client, sql, params),
        release: () => client.release(),
      };
    },
  };
  const candidate =
    await require("../../apps/api/services/certops/adcsPreflightGate").findEligibleAdcsPreflightAgent(
      {
        db: observed,
        workspaceId: f.workspaceId,
        reference:
          certificate.profile_public_metadata.renewalProfile.target.reference,
        target: certificate.profile_public_metadata.renewalProfile.target,
        env: process.env,
      },
    );
  assert.ok(moved);
  assert.equal(
    candidate?.id,
    selected,
    "a concurrent heartbeat must not hide the only eligible later-page agent",
  );
});

test("paged selection keeps ownership, capability, compatibility and exact cursor boundaries", async () => {
  const f = await fixture(),
    gate = require("../../apps/api/services/certops/adcsPreflightGate");
  const target = {
    type: "windows-iis",
    reference: f.certs[0].domain,
    store: "My",
    binding: { site: "QA", port: 443 },
  };
  const choose = async (ownerId = null, selectedTarget = target) =>
    gate.findEligibleAdcsPreflightAgent({
      db: pool,
      workspaceId: f.workspaceId,
      reference: target.reference,
      target: selectedTarget,
      ownerId,
      env: process.env,
    });
  assert.equal((await choose()).id, f.agentId);
  assert.equal(await choose(randomUUID()), null);
  for (const [column, value] of [
    ["status", "offline"],
    ["agent_version", "0.0.1"],
    ["declared_capabilities", "[]"],
    ["supported_operations", '["adcs-preflight"]'],
  ]) {
    const old = (
      await pool.query(
        "SELECT " + column + " FROM certops_agents WHERE id=$1",
        [f.agentId],
      )
    ).rows[0][column];
    await pool.query(
      "UPDATE certops_agents SET " + column + "=$2 WHERE id=$1",
      [f.agentId, value],
    );
    assert.equal(await choose(), null, column);
    await pool.query(
      "UPDATE certops_agents SET " + column + "=$2 WHERE id=$1",
      [f.agentId, Array.isArray(old) ? JSON.stringify(old) : old],
    );
  }
  await pool.query(
    "UPDATE certops_agents SET capabilities_updated_at=NOW()-interval '1 day' WHERE id=$1",
    [f.agentId],
  );
  assert.equal(await choose(), null);
  await pool.query(
    "UPDATE certops_agents SET capabilities_updated_at=NOW(),status='retired',retired_at=NOW() WHERE id=$1",
    [f.agentId],
  );
  assert.equal(await choose(), null);
  await pool.query(
    "UPDATE certops_agents SET status='active',retired_at=NULL WHERE id=$1",
    [f.agentId],
  );
  const store = {
    type: "windows-cert-store",
    reference: target.reference,
    store: "My",
  };
  assert.equal(await choose(f.agentId, store), null);
  await pool.query(
    "UPDATE certops_agents SET declared_capabilities=$2::jsonb WHERE id=$1",
    [
      f.agentId,
      JSON.stringify([
        "adcs-enroll-v1",
        "windows-store-only-adcs-v1",
        "evidence-claim-binding-v1",
        "iis-explicit-ip-v1",
      ]),
    ],
  );
  assert.equal((await choose(f.agentId, store)).id, f.agentId);
  assert.equal(
    (
      await choose(f.agentId, {
        ...target,
        binding: { ...target.binding, address: "192.0.2.10" },
      })
    ).id,
    f.agentId,
  );
  // >100 identical microsecond timestamps and NULL timestamps must not lose a row to JS Date rounding.
  for (const timestamp of [
    "TIMESTAMPTZ '2026-11-16 12:00:00.123456+00'",
    "NULL",
  ]) {
    await pool.query(
      "UPDATE certops_agents SET status='offline' WHERE workspace_id=$1",
      [f.workspaceId],
    );
    const ids = Array.from({ length: 125 }, () => randomUUID()).sort();
    await pool.query(
      `INSERT INTO certops_agents(id,workspace_id,agent_id,name,agent_version,protocol_version,credential_prefix,credential_hash,status,platform,supported_operations,declared_target_selectors,declared_capabilities,capabilities_updated_at,last_seen_at)
      SELECT id,$1,gen_random_uuid(),'Cursor fixture','0.18.0','1.0.0','ttagent_'||substr(md5(id::text),1,16),md5(id::text)||md5(id::text),'active','win32','["renew","adcs-preflight"]',$3::jsonb,
        CASE WHEN id=$4::uuid THEN '["adcs-enroll-v1"]'::jsonb ELSE '[]'::jsonb END,NOW(),${timestamp} FROM unnest($2::uuid[]) id`,
      [f.workspaceId, ids, JSON.stringify([target.reference]), ids[100]],
    );
    assert.equal((await choose()).id, ids[100]);
  }
});

test(
  "issuer list batches readiness for 100 issuers and 1000 certificates",
  { timeout: 180000 },
  async () => {
    const f = await fixture(),
      ids = Array.from({ length: 100 }, () => randomUUID());
    const extra = (
      await pool.query(
        `INSERT INTO certops_agents(workspace_id,agent_id,name,agent_version,protocol_version,credential_prefix,credential_hash,status,platform,supported_operations,declared_target_selectors,declared_capabilities,capabilities_updated_at,last_seen_at)
      SELECT workspace_id,gen_random_uuid(),'Scale agent '||n,agent_version,protocol_version,'ttagent_'||substr(md5(gen_random_uuid()::text),1,16),md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'active',platform,supported_operations,declared_target_selectors,declared_capabilities,NOW(),NOW()
      FROM certops_agents CROSS JOIN generate_series(1,2) n WHERE id=$1 RETURNING id`,
        [f.agentId],
      )
    ).rows.map((row) => row.id);
    await pool.query(
      `INSERT INTO certificate_issuers(id,workspace_id,kind,name,current_version,revalidation_required)
    SELECT id,$1,'adcs','000-scale-'||id,1,false FROM unnest($2::uuid[]) id`,
      [f.workspaceId, ids],
    );
    await pool.query(
      `INSERT INTO certificate_issuer_versions(workspace_id,issuer_id,version,ca_config,template,transport,ca_key_sha256,confirmed_at)
    SELECT $1,id,1,$3,$4,'dcom',$5,NOW()-interval '7 days' FROM unnest($2::uuid[]) id`,
      [f.workspaceId, ids, CA, TEMPLATE, KEY],
    );
    const profiles = (
      await pool.query(
        `INSERT INTO certificate_profiles(workspace_id,name,status,source,source_ref,issuer_id,renew_before_days,key_mode,public_metadata,created_by)
    SELECT $1,'Scale '||i.id,'active','manual',i.id::text,i.id,30,'os-store-managed',cp.public_metadata,cp.created_by FROM unnest($2::uuid[]) i(id)
    CROSS JOIN certificate_profiles cp WHERE cp.id=$3 RETURNING id,issuer_id`,
        [f.workspaceId, ids, f.certs[0].profileId],
      )
    ).rows;
    await pool.query(
      `INSERT INTO managed_certificates(workspace_id,status,source,source_ref,name,common_name,subject_alt_names,key_mode,key_reference,public_metadata,deployed_agent_id,profile_id,not_after,fingerprint_sha256)
    SELECT $1,'active','agent_issuance',gen_random_uuid()::text,'Scale certificate',mc.common_name,mc.subject_alt_names,mc.key_mode,mc.key_reference,mc.public_metadata,mc.deployed_agent_id,p.id,NOW()+(1+n%25)*interval '1 day',md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)
    FROM unnest($2::uuid[]) p(id) CROSS JOIN generate_series(1,10) n CROSS JOIN managed_certificates mc WHERE mc.id=$3`,
      [f.workspaceId, profiles.map((p) => p.id), f.certs[0].id],
    );
    await pool.query(
      `UPDATE certops_management_periods p SET renewal_profile_id=mc.profile_id,automation_enabled=TRUE FROM managed_certificates mc WHERE p.managed_certificate_id=mc.id AND mc.workspace_id=$1 AND p.ended_at IS NULL`,
      [f.workspaceId],
    );
    await pool.query(
      `INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status,source,assigned_agent_id,error_code,created_at)
      SELECT $1,'external',id::text,'adcs-preflight','failed','automation',agent,'ADCS_TEMPLATE_UNSAFE',NOW()-n*interval '1 second' FROM unnest($2::uuid[]) id CROSS JOIN unnest($3::uuid[]) agent CROSS JOIN generate_series(1,100) n`,
      [f.workspaceId, ids, [f.agentId, ...extra]],
    );
    // Upgrade an already populated history, then replay the same DDL. No rows
    // or ledger identities may be rewritten to install this lookup index.
    const migration =
      require("../../apps/api/migrations/migrate").migrations.find(
        (m) => m.name === "certops_adcs_preflight_lookup_index",
      );
    assert.equal(migration.version, 125);
    const countBefore = (
      await pool.query(
        "SELECT count(*)::int AS n FROM certificate_jobs WHERE workspace_id=$1",
        [f.workspaceId],
      )
    ).rows[0].n;
    await pool.query("DROP INDEX idx_certificate_jobs_adcs_preflight_lookup");
    await pool.query(migration.sql);
    await pool.query(migration.sql);
    assert.equal(
      (
        await pool.query(
          "SELECT count(*)::int AS n FROM certificate_jobs WHERE workspace_id=$1",
          [f.workspaceId],
        )
      ).rows[0].n,
      countBefore,
    );
    const queries = [];
    const db = {
      query: async (sql, params) => {
        queries.push({ sql, params });
        return pool.query(sql, params);
      },
    };
    const start = performance.now(),
      heapBefore = process.memoryUsage().heapUsed;
    const result =
      await require("../../apps/api/services/certops/certificateEnrollments").listIssuers(
        { client: db, workspaceId: f.workspaceId, limit: 100 },
      );
    const metric = {
      issuers: result.items.length,
      certificates: 1000,
      historyJobs: 30000,
      agentsPerIssuer: 3,
      queries: queries.length,
      elapsedMs: Math.round(performance.now() - start),
      heapDeltaBytes: process.memoryUsage().heapUsed - heapBefore,
      heapUsedBytes: process.memoryUsage().heapUsed,
    };
    console.log("READINESS_PERFORMANCE " + JSON.stringify(metric));
    let referenceQueries = 0;
    const referenceStart = performance.now();
    const reference =
      await require("../../apps/api/services/certops/certificateEnrollments").listIssuers(
        {
          client: {
            query: async (sql, params) => {
              referenceQueries++;
              return pool.query(sql, params);
            },
          },
          workspaceId: f.workspaceId,
          limit: 100,
          readinessLoader: (args) =>
            incidents.loadIssuerPreflightReadiness(args),
        },
      );
    Object.assign(metric, {
      referenceQueries,
      referenceElapsedMs: Math.round(performance.now() - referenceStart),
      lockWaiters: (
        await pool.query(
          "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'",
        )
      ).rows[0].n,
    });
    assert.deepEqual(
      result,
      reference,
      "batching must preserve every public readiness and history field",
    );
    for (const item of result.items) {
      assert.equal(item.renewalReadiness.dueCount, 10);
      assert.equal(item.renewalReadiness.affectedCount, 10);
    }
    if (process.env.ADCS_QUALIFICATION_PERF_OUT) {
      const plans = [];
      for (const q of queries
        .filter(
          (q) =>
            q.sql.includes("FROM managed_certificates mc") ||
            q.sql.includes("preflight_jobs") ||
            q.sql.includes("scope.issuer_id"),
        )
        .slice(0, 2))
        plans.push(
          (
            await pool.query(
              "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) " + q.sql,
              q.params,
            )
          ).rows[0],
        );
      require("fs").writeFileSync(
        process.env.ADCS_QUALIFICATION_PERF_OUT,
        JSON.stringify({ metric, plans }, null, 2),
      );
    }
    assert.ok(
      queries.length <= 6,
      "issuer page readiness must not run per-issuer SQL: " + queries.length,
    );
  },
);
