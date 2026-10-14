"use strict";

// Real PostgreSQL tests. This suite owns a uniquely named disposable database;
// no mocks or timing guesses are used for the transaction/trigger assertions.
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { Pool, Client } = require("pg");
const {
  migrations,
  applyMigrationSql,
} = require("../../apps/api/migrations/migrate");
const {
  listCertificateIdentities,
  retireCertificateIdentity,
  stopManagingSource,
  readdManagingSource,
  replaceManagingSource,
} = require("../../apps/api/services/certops/certificateIdentity");
const {
  countActiveManagedCertificatesWithClient,
  countQuotaConsumingNewFingerprints,
  upsertManagedCertificateByMonitorSource,
  listManagedCertificates,
} = require("../../apps/api/services/certops/inventory");

const A = "a".repeat(64),
  B = "b".repeat(64),
  C = "c".repeat(64);
const dbConfig = {
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || "tokentimer",
  password: process.env.DB_PASSWORD || "password",
};
const dbName = `certops_identity_${process.pid}_${Date.now()}`;
const time = (seconds = 0) => new Date(Date.now() - 60000 + seconds * 1000);

describe("CertOps identity invariants on PostgreSQL", function () {
  this.timeout(90000);
  let db, userId, worker;
  const fixture = {};
  async function workspace(limit = null) {
    return (
      await db.query(
        `INSERT INTO workspaces(id, name, plan, created_by, certops_managed_identity_limit)
      VALUES(gen_random_uuid(), 'Identity test', 'oss', $1, $2) RETURNING id`,
        [userId, limit],
      )
    ).rows[0].id;
  }
  async function source(
    ws,
    fp,
    {
      name = "certificate",
      source = "agent_filesystem",
      sourceRef = randomUUID(),
      tokenId = null,
      observedAt = time(),
      status = "discovered",
      notAfter = "2027-01-01",
    } = {},
  ) {
    return (
      await db.query(
        `INSERT INTO managed_certificates(workspace_id, source, source_ref, fingerprint_sha256,
      name, common_name, token_id, identity_observed_at, status, not_after)
      VALUES($1,$2,$3,$4,$5,$5,$6,$7,$8,$9) RETURNING *`,
        [
          ws,
          source,
          sourceRef,
          fp,
          name,
          tokenId,
          observedAt,
          status,
          notAfter,
        ],
      )
    ).rows[0];
  }
  async function period(mc) {
    return (
      await db.query(
        "SELECT * FROM certops_management_periods WHERE managed_certificate_id=$1 ORDER BY started_at DESC,id DESC LIMIT 1",
        [mc.id],
      )
    ).rows[0];
  }
  async function identity(ws, fp) {
    return (
      await db.query(
        "SELECT * FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2",
        [ws, fp],
      )
    ).rows[0];
  }
  async function endpoint(ws) {
    return (
      await db.query(
        `INSERT INTO domain_monitors(workspace_id,created_by,url) VALUES($1,$2,$3) RETURNING *`,
        [ws, userId, `https://${randomUUID()}.example.test`],
      )
    ).rows[0];
  }
  async function token(ws) {
    return (
      await db.query(
        `INSERT INTO tokens(workspace_id,user_id,name,type,expiration)
      VALUES($1,$2,'Identity token','ssl_cert','2027-01-01') RETURNING id`,
        [ws, userId],
      )
    ).rows[0].id;
  }
  async function job(ws, mc, status = "pending", operation = "renew") {
    return (
      await db.query(
        `INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status)
      VALUES($1,'managed_certificate',$2,$3,$4) RETURNING *`,
        [ws, mc.id, operation, status],
      )
    ).rows[0];
  }
  async function observation(ws, mc, fp, observedAt, options = {}) {
    const targetId =
      options.targetId ||
      (
        await db.query(
          `INSERT INTO certificate_targets(workspace_id,name,target_type)
      VALUES($1,'Observed host','host') RETURNING id`,
          [ws],
        )
      ).rows[0].id;
    return (
      await db.query(
        `INSERT INTO certificate_instances(workspace_id,managed_certificate_id,source,source_ref,
      target_id,domain_monitor_id,observed_fingerprint_sha256,observed_at,location_kind,deployment_reference)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
        [
          ws,
          mc.id,
          options.source || "agent_filesystem",
          options.sourceRef || mc.source_ref,
          targetId,
          options.domainMonitorId || null,
          fp,
          observedAt,
          options.locationKind || "filesystem",
          options.locationRef || "file:///cert.pem",
        ],
      )
    ).rows[0];
  }
  async function blockedBy(client, blocker) {
    const pid = (await client.query("SELECT pg_backend_pid() pid")).rows[0].pid;
    const blockerPid = (await blocker.query("SELECT pg_backend_pid() pid"))
      .rows[0].pid;
    return { pid, blockerPid };
  }
  async function waitForBlock(pids) {
    for (let n = 0; n < 500; n++) {
      const r = await db.query(
        "SELECT $2::int = ANY(pg_blocking_pids($1::int)) blocked",
        [pids.pid, pids.blockerPid],
      );
      if (r.rows[0].blocked) return;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.fail("Expected PostgreSQL lock dependency did not occur");
  }
  async function clients(fn) {
    const one = await db.connect(),
      two = await db.connect();
    try {
      await fn(one, two);
    } finally {
      await one.query("ROLLBACK");
      await two.query("ROLLBACK");
      one.release();
      two.release();
    }
  }
  before(async () => {
    const admin = new Client({
      ...dbConfig,
      database: process.env.DB_NAME || "tokentimer",
    });
    await admin.connect();
    await admin.query(`CREATE DATABASE ${dbName}`);
    await admin.end();
    db = new Pool({ ...dbConfig, database: dbName, max: 8 });
    for (const migration of migrations.filter((m) => m.version <= 61))
      await db.query(migration.sql);
    userId = (
      await db.query(`INSERT INTO users(email,email_original,display_name,password_hash,auth_method)
      VALUES('identity@example.test','identity@example.test','Identity Test','x','local') RETURNING id`)
    ).rows[0].id;
    fixture.ws = (
      await db.query(
        `INSERT INTO workspaces(id,name,plan,created_by)
      VALUES(gen_random_uuid(),'Pre-v62','oss',$1) RETURNING id`,
        [userId],
      )
    ).rows[0].id;
    fixture.rotated = (
      await db.query(
        `INSERT INTO managed_certificates(workspace_id,source,source_ref,fingerprint_sha256,
      status,common_name,created_at,updated_at) VALUES($1,'endpoint_monitor',$2,$3,'revoked','Current B',NOW()-INTERVAL '2 days',NOW()-INTERVAL '1 day') RETURNING *`,
        [fixture.ws, randomUUID(), B],
      )
    ).rows[0];
    await db.query(
      `INSERT INTO audit_events(action,workspace_id,metadata) VALUES('CERTOPS_CERTIFICATE_RETIRED',$1,$2::jsonb)`,
      [
        fixture.ws,
        JSON.stringify({
          managedCertificateId: fixture.rotated.id,
          fingerprintSha256: A,
          status: "revoked",
          reason: "Retired A",
        }),
      ],
    );
    fixture.target = (
      await db.query(
        `INSERT INTO certificate_targets(workspace_id,name,target_type)
      VALUES($1,'Historic host','host') RETURNING id`,
        [fixture.ws],
      )
    ).rows[0].id;
    await db.query(
      `INSERT INTO certificate_instances(workspace_id,managed_certificate_id,target_id,source,observed_fingerprint_sha256,observed_at)
      VALUES($1,$2,$3,'endpoint_monitor',$4,NOW()-INTERVAL '2 days')`,
      [fixture.ws, fixture.rotated.id, fixture.target, A],
    );
    fixture.job = (
      await db.query(
        `INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,created_at)
      VALUES($1,'managed_certificate',$2,'renew',NOW()-INTERVAL '1 day') RETURNING id`,
        [fixture.ws, fixture.rotated.id],
      )
    ).rows[0];
    fixture.whitespace = (
      await db.query(
        `INSERT INTO managed_certificates(workspace_id,source,source_ref,fingerprint_sha256,common_name)
      VALUES($1,'agent_filesystem','whitespace',$2,'Canonical name') RETURNING *`,
        [fixture.ws, ` ${C.toUpperCase().match(/../g).join(":")} `],
      )
    ).rows[0];
    fixture.orphan = (
      await db.query(
        `INSERT INTO managed_certificates(workspace_id,source,source_ref,fingerprint_sha256,public_metadata)
      VALUES($1,'domain_checker','orphan.example.test',$2,$3::jsonb) RETURNING *`,
        [fixture.ws, A, JSON.stringify({ domainMonitorId: randomUUID() })],
      )
    ).rows[0];
    fixture.ambiguous = (
      await db.query(
        `INSERT INTO managed_certificates(workspace_id,source,source_ref,fingerprint_sha256,status)
      VALUES($1,'agent_filesystem','ambiguous',$2,'decommissioned') RETURNING *`,
        [fixture.ws, "d".repeat(64)],
      )
    ).rows[0];
    fixture.erasedAuditMetadata = {
      fingerprintSha256: "f5".repeat(32),
      status: "revoked",
      reason: "Erased workspace audit",
    };
    fixture.erasedAudit = (
      await db.query(
        "INSERT INTO audit_events(action, metadata) VALUES('CERTOPS_CERTIFICATE_RETIRED',$1::jsonb) RETURNING id",
        [JSON.stringify(fixture.erasedAuditMetadata)],
      )
    ).rows[0].id;
    for (const migration of migrations.filter((m) => m.version >= 62)) {
      const c = await db.connect();
      await c.query("BEGIN");
      try {
        if (migration.version === 72) {
          fixture.auditBefore = (await c.query(`INSERT INTO audit_events(action,workspace_id,metadata,occurred_at)
            SELECT action,$1,'{"enrollmentId":"historic-enrollment","requestId":0}'::jsonb,'2026-10-01T12:00:00Z'
            FROM unnest(ARRAY['certops.issuer.created','certops.issuer.preflight_dispatched','certops.issuer.key_confirmed',
              'certops.enrollment.created','certops.enrollment.reconcile_proposed','certops.enrollment.cancelled',
              'certops.enrollment.abandoned','certops.agent_log.rejected']) action RETURNING *`, [fixture.ws])).rows;
        }
        if (migration.version === 62) {
          await assert.rejects(c.query(migration.sql), { code: "23502" });
          await c.query("ROLLBACK");
          await c.query("BEGIN");
        }
        await applyMigrationSql(c, migration);
        await c.query("COMMIT");
      } catch (e) {
        await c.query("ROLLBACK");
        throw e;
      } finally {
        c.release();
      }
    }
    worker = await import("../../apps/worker/src/endpoint-check-worker.js");
  });
  after(async () => {
    if (db) await db.end();
    const admin = new Client({
      ...dbConfig,
      database: process.env.DB_NAME || "tokentimer",
    });
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS ${dbName}`);
    await admin.end();
  });
  it("normalizes legacy audit reads without changing immutable metadata or timestamps", async () => {
    const { auditActionSql } = require("../../apps/api/services/audit");
    const ids = fixture.auditBefore.map(row => row.id);
    const after = (await db.query(`SELECT ae.*, ${auditActionSql("ae.action")} AS action FROM audit_events ae WHERE id=ANY($1::bigint[]) ORDER BY id`, [ids])).rows;
    for (const row of fixture.auditBefore) {
      const normalized = after.find(item => item.id === row.id);
      assert.deepEqual(normalized, { ...row, action: row.action.toUpperCase().replaceAll('.', '_') });
    }
    assert.deepEqual((await db.query("SELECT * FROM audit_events WHERE id=ANY($1::bigint[]) ORDER BY id", [ids])).rows, fixture.auditBefore);
    for (const row of after) {
      const filtered = await db.query(`SELECT id FROM audit_events ae WHERE workspace_id=$1 AND ${auditActionSql("ae.action")}=$2`, [fixture.ws,row.action]);
      assert.equal(filtered.rows[0].id, row.id);
    }
  });

  it("returns real AD CS metadata in every audit feed and JSON/CSV export", async () => {
    const { fork } = require("node:child_process");
    const path = require("node:path");
    const request = require("supertest");
    const {
      createIssuer,
      confirmIssuerKey,
      createEnrollment,
      abandonEnrollment,
    } = require("../../apps/api/services/certops/certificateEnrollments");
    const ws = await workspace();
    await db.query(
      `INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'admin')
      ON CONFLICT(workspace_id,user_id) DO UPDATE SET role='admin'`,
      [ws, userId],
    );
    const outsider = (
      await db.query(
        `INSERT INTO users(email,email_original,display_name,password_hash,auth_method)
      VALUES($1::text,$1::text,'Outside audit','unused','local') RETURNING id`,
        [`audit-outsider-${randomUUID()}@example.test`],
      )
    ).rows[0].id;
    const issuer = await createIssuer({
      client: db,
      workspaceId: ws,
      kind: "adcs",
      name: "Audit CA",
      actorUserId: userId,
    });
    await db.query(
      `UPDATE certificate_issuers SET last_preflight=$2::jsonb WHERE id=$1`,
      [
        issuer.id,
        JSON.stringify({
          caConfig: "ca.example.test\\Audit CA",
          template: "WebServer",
          templateCheck: { verdict: "safe" },
          caCheck: { verdict: "safe" },
          caCertificates: [{ keySha256: A }],
        }),
      ],
    );
    await confirmIssuerKey({
      client: db,
      workspaceId: ws,
      issuerId: issuer.id,
      caKeySha256: A,
      actorUserId: userId,
    });
    const mc = await source(ws, A);
    await db.query(
      "UPDATE managed_certificates SET key_mode='agent-local' WHERE id=$1",
      [mc.id],
    );
    const agent = (
      await db.query(
        `INSERT INTO certops_agents(workspace_id,agent_id,name,agent_version,protocol_version,credential_prefix,credential_hash,status)
      VALUES($1,$2,'Audit agent','0.1.0','1.0.0','ttagent_1234567812345678',$3,'active') RETURNING id`,
        [ws, randomUUID(), B],
      )
    ).rows[0].id;
    const enrollment = await createEnrollment({
      client: db,
      workspaceId: ws,
      issuerId: issuer.id,
      certificateId: mc.id,
      agentId: agent,
      target: {
        type: "windows-iis",
        reference: "iis-01/webhosting",
        store: "WebHosting",
        binding: { site: "Shop", port: 443, sniHost: "app.example.test" },
      },
      authorizedDnsNames: ["app.example.test"],
      keyAlgorithm: "rsa",
      keySize: 2048,
      actorUserId: userId,
      mode: "dry_run",
      env: { CERTOPS_ENABLED: "true" },
    });
    await db.query(
      "UPDATE certificate_enrollments SET state='submission_uncertain' WHERE id=$1",
      [enrollment.enrollmentId],
    );
    await abandonEnrollment({
      client: db,
      workspaceId: ws,
      enrollmentId: enrollment.enrollmentId,
      actorUserId: userId,
    });
    const expected = [
      ["CERTOPS_ISSUER_CREATED", { issuerId: issuer.id, kind: "adcs" }],
      [
        "CERTOPS_ISSUER_KEY_CONFIRMED",
        { issuerId: issuer.id, version: 1, caKeySha256: A },
      ],
      [
        "CERTOPS_ENROLLMENT_CREATED",
        {
          enrollmentId: enrollment.enrollmentId,
          issuerId: issuer.id,
          jobId: enrollment.jobId,
        },
      ],
      [
        "CERTOPS_ENROLLMENT_ABANDONED",
        { enrollmentId: enrollment.enrollmentId },
      ],
    ];
    for (const [action, metadata] of expected) {
      const stored = (
        await db.query(
          "SELECT metadata FROM audit_events WHERE workspace_id=$1 AND action=$2",
          [ws, action],
        )
      ).rows;
      assert.equal(stored.length, 1, action);
      assert.deepEqual(stored[0].metadata, metadata, action);
    }
    const child = fork(
      path.join(__dirname, "helpers/audit-http-server.js"),
      [],
      {
        stdio: ["ignore", "ignore", "pipe", "ipc"],
        env: {
          ...process.env,
          NODE_ENV: "test",
          DB_NAME: dbName,
          TT_AUDIT_TEST_ACTORS: JSON.stringify({
            owner: { id: userId, is_admin: false, auth_method: "local" },
            outsider: { id: outsider, is_admin: false, auth_method: "local" },
          }),
        },
      },
    );
    let childError = "";
    child.stderr.on("data", (data) => {
      childError += data.toString();
    });
    try {
      const port = await new Promise((resolve, reject) => {
        const timeout = setTimeout(
          () =>
            reject(new Error("Audit fixture startup timed out: " + childError)),
          15000,
        );
        child.once("message", (message) => {
          clearTimeout(timeout);
          resolve(message.port);
        });
        child.once("exit", (code) => {
          clearTimeout(timeout);
          reject(new Error("Audit fixture exited " + code + ": " + childError));
        });
      });
      const api = request(`http://127.0.0.1:${port}`);
      for (const [action, metadata] of expected) {
        for (const [url, query, wrapped] of [
          ["/api/audit-events", { action }, false],
          ["/api/audit-events", { scope: "organization", action }, false],
          [`/api/v1/workspaces/${ws}/audit-events`, { action }, false],
          ["/api/v1/audit", { workspace_id: ws, event_type: action }, true],
        ]) {
          const response = await api.get(url).query(query).expect(200);
          const items = wrapped ? response.body.items : response.body;
          assert.equal(items.length, 1, url + " " + action);
          assert.equal(items[0].action, action);
          assert.deepEqual(items[0].metadata, metadata, url + " " + action);
        }
        for (const scope of ["user", "workspace", "organization"]) {
          const query = { scope, workspace_id: ws, action };
          const json = await api
            .get("/api/account/export-audit")
            .query({ ...query, format: "json" })
            .expect(200);
          assert.equal(json.body.events.length, 1);
          assert.deepEqual(json.body.events[0].metadata, metadata);
          const csv = await api
            .get("/api/account/export-audit")
            .query({ ...query, format: "csv" })
            .expect(200);
          assert(csv.text.includes(action));
          const metadataCell = csv.text.match(/,"((?:[^"]|"")*)"$/);
          assert(metadataCell, "CSV metadata column must be quoted");
          assert.deepEqual(
            JSON.parse(metadataCell[1].replaceAll('""', '"')),
            metadata,
          );
        }
      }
      // Historical dotted actions remain immutable, but their public action,
      // filtering and metadata must behave exactly like newly emitted events.
      for (const [legacy, canonical] of [
        ["certops.issuer.key_confirmed", "CERTOPS_ISSUER_KEY_CONFIRMED"],
        ["certops.enrollment.created", "CERTOPS_ENROLLMENT_CREATED"],
        ["certops.enrollment.abandoned", "CERTOPS_ENROLLMENT_ABANDONED"],
      ]) {
        const metadata = expected.find(([action]) => action === canonical)[1];
        const id = (
          await db.query(
            `INSERT INTO audit_events(actor_user_id,subject_user_id,workspace_id,action,metadata)
          VALUES($1,$1,$2,$3,$4::jsonb) RETURNING id`,
            [userId, ws, legacy, JSON.stringify(metadata)],
          )
        ).rows[0].id;
        for (const action of [legacy, canonical]) {
          const feed = await api
            .get(`/api/v1/workspaces/${ws}/audit-events`)
            .query({ action })
            .expect(200);
          assert.equal(feed.body.length, 2);
          for (const event of feed.body) {
            assert.equal(event.action, canonical);
            assert.deepEqual(event.metadata, metadata);
          }
          const exported = await api
            .get("/api/account/export-audit")
            .query({
              scope: "workspace",
              workspace_id: ws,
              action,
              format: "json",
            })
            .expect(200);
          assert.equal(exported.body.events.length, 2);
          for (const event of exported.body.events) {
            assert.equal(event.action, canonical);
            assert.deepEqual(event.metadata, metadata);
          }
        }
        const search = await api
          .get(`/api/v1/workspaces/${ws}/audit-events`)
          .query({ query: canonical })
          .expect(200);
        assert.equal(search.body.length, 2);
        assert.equal(
          (await db.query("SELECT action FROM audit_events WHERE id=$1", [id]))
            .rows[0].action,
          legacy,
        );
      }
      const machineMetadata = {
        jobId: enrollment.jobId,
        claimId: randomUUID(),
        code: "CERTOPS_AGENT_LOG_PRIVATE_MATERIAL",
      };
      await require("../../apps/api/services/audit").writeAudit({
        client: db,
        workspaceId: ws,
        action: "certops.agent_log.rejected",
        metadata: machineMetadata,
      });
      for (const url of [
        `/api/v1/workspaces/${ws}/audit-events`,
        "/api/audit-events?scope=organization",
      ]) {
        const feed = await api
          .get(url)
          .query({ action: "CERTOPS_AGENT_LOG_REJECTED" })
          .expect(200);
        assert.equal(feed.body.length, 1);
        assert.deepEqual(feed.body[0].metadata, machineMetadata);
      }
      await api
        .get(`/api/v1/workspaces/${ws}/audit-events`)
        .set("X-Audit-Test-Actor", "outsider")
        .expect(403);
      await api
        .get("/api/account/export-audit")
        .query({ scope: "workspace", workspace_id: ws })
        .set("X-Audit-Test-Actor", "outsider")
        .expect(403);
    } finally {
      if (child.exitCode === null) {
        child.send("close");
        await new Promise((resolve) => child.once("exit", resolve));
      }
    }
  });

  it("upgrades representative pre-v62 history without guessing lifecycle or historical job identity", async () => {
    assert.equal((await identity(fixture.ws, A)).lifecycle_status, "revoked");
    assert.equal((await identity(fixture.ws, B)).lifecycle_status, "active");
    assert.equal((await identity(fixture.ws, C)).common_name, "Canonical name");
    assert((await period(fixture.orphan)).ended_at);
    assert((await period(fixture.rotated)).ended_at);
    assert.equal(
      (
        await db.query(
          "SELECT certificate_identity_id FROM certificate_jobs WHERE id=$1",
          [fixture.job.id],
        )
      ).rows[0].certificate_identity_id,
      null,
    );
    assert.equal(
      (await identity(fixture.ws, "d".repeat(64))).lifecycle_status,
      "active",
    );
    assert(
      (
        await db.query(
          "SELECT 1 FROM certops_identity_backfill_issues WHERE managed_certificate_id=$1",
          [fixture.ambiguous.id],
        )
      ).rowCount,
    );
    assert.equal(
      (
        await db.query(
          "SELECT current_identity_id FROM certops_management_periods WHERE managed_certificate_id=$1",
          [fixture.whitespace.id],
        )
      ).rows[0].current_identity_id,
      (await identity(fixture.ws, C)).id,
    );
  });
  it("v62 compatibility preserves erased-workspace audit metadata and rolls preparation back on failure", async () => {
    const readAudit = () =>
      db.query("SELECT workspace_id,metadata FROM audit_events WHERE id=$1", [
        fixture.erasedAudit,
      ]);
    assert.deepEqual((await readAudit()).rows[0], {
      workspace_id: null,
      metadata: fixture.erasedAuditMetadata,
    });
    assert.equal(
      (
        await db.query(
          "SELECT COUNT(*)::int n FROM certops_certificate_identities WHERE fingerprint_sha256=$1",
          [fixture.erasedAuditMetadata.fingerprintSha256],
        )
      ).rows[0].n,
      0,
    );
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      await assert.rejects(
        applyMigrationSql(client, { version: 62, sql: "SELECT 1/0" }),
        { code: "22012" },
      );
      await client.query("ROLLBACK");
      assert.deepEqual(
        (await readAudit()).rows[0].metadata,
        fixture.erasedAuditMetadata,
      );
      assert.equal(
        (
          await client.query(
            "SELECT to_regclass('pg_temp.audit_events') AS shadow",
          )
        ).rows[0].shadow,
        null,
      );
      await assert.rejects(
        client.query(
          "UPDATE audit_events SET metadata='{}'::jsonb WHERE id=$1",
          [fixture.erasedAudit],
        ),
        /audit_events are immutable/,
      );
    } finally {
      await client.query("ROLLBACK");
      client.release();
    }
  });
  it("raw v63 is idempotent with live records and immutable closed periods", async () => {
    const before = await db.query(
      "SELECT * FROM certops_management_periods ORDER BY id",
    );
    await db.query(migrations.find((m) => m.version === 63).sql);
    await db.query(migrations.find((m) => m.version === 64).sql);
    await db.query(migrations.find((m) => m.version === 65).sql);
    assert.deepEqual(
      (await db.query("SELECT * FROM certops_management_periods ORDER BY id"))
        .rows,
      before.rows,
    );
  });
  it("deduplicates normalized fingerprints concurrently within a workspace and isolates workspaces", async () => {
    const ws = await workspace(),
      other = await workspace();
    await Promise.all(
      Array.from({ length: 8 }, (_, n) =>
        source(ws, n % 2 ? A : ` ${A.toUpperCase().match(/../g).join(":")} `),
      ),
    );
    await source(other, A);
    assert.equal(
      (
        await db.query(
          "SELECT COUNT(*)::int n FROM certops_certificate_identities WHERE workspace_id=$1",
          [ws],
        )
      ).rows[0].n,
      1,
    );
    assert.notEqual((await identity(ws, A)).id, (await identity(other, A)).id);
    assert.equal(await countActiveManagedCertificatesWithClient(db, ws), 1);
  });
  it("endpoint deletion/recreation preserves identity, observations and separate source periods", async () => {
    const ws = await workspace(),
      dm = await endpoint(ws);
    const first = await source(ws, A, {
      source: "endpoint_monitor",
      sourceRef: dm.id,
    });
    await observation(ws, first, A, time(), {
      source: "endpoint_monitor",
      domainMonitorId: dm.id,
    });
    const old = await period(first),
      pending = await job(ws, first);
    await db.query("DELETE FROM domain_monitors WHERE id=$1", [dm.id]);
    assert((await period(first)).ended_at);
    assert.equal(
      (
        await db.query("SELECT status FROM certificate_jobs WHERE id=$1", [
          pending.id,
        ])
      ).rows[0].status,
      "cancelled",
    );
    const recreated = await endpoint(ws),
      second = await source(ws, A, {
        source: "endpoint_monitor",
        sourceRef: recreated.id,
      });
    const list = await listCertificateIdentities({
      workspaceId: ws,
      client: db,
    });
    assert.equal(list.items.length, 1);
    assert.equal(list.items[0].sourceCount, 2);
    assert.equal(list.items[0].activeSourceCount, 1);
    assert(
      list.items[0].sources.some(
        (s) => s.periodId === old.id && s.periodEndedAt,
      ),
    );
    assert.equal(
      (
        await db.query(
          "SELECT COUNT(*)::int n FROM certificate_instances WHERE managed_certificate_id=$1",
          [first.id],
        )
      ).rows[0].n,
      1,
    );
    assert.equal(
      (await period(second)).current_identity_id,
      (await identity(ws, A)).id,
    );
  });
  it("deletion closes a Domain Checker source reused by an endpoint", async () => {
    const ws = await workspace(),
      dm = await endpoint(ws),
      mc = await source(ws, A, { source: "domain_checker" });
    await observation(ws, mc, A, time(), {
      source: "domain_checker",
      domainMonitorId: dm.id,
    });
    await db.query("DELETE FROM domain_monitors WHERE id=$1", [dm.id]);
    assert.equal((await period(mc)).ended_reason, "endpoint_monitor_deleted");
  });
  it("retired rediscovery remains retired; revoked A does not leak into rotated B", async () => {
    const ws = await workspace(),
      mc = await source(ws, A),
      id = await identity(ws, A);
    await retireCertificateIdentity({
      workspaceId: ws,
      identityId: id.id,
      expectedFingerprintSha256: A,
      status: "revoked",
      reason: "Revoked test",
      client: db,
    });
    await upsertManagedCertificateByMonitorSource(
      db,
      { fingerprintSha256: A, notAfter: "2027-01-01" },
      {
        workspaceId: ws,
        source: mc.source,
        sourceRef: mc.source_ref,
        status: "active",
        observedAt: time(5),
      },
      0,
    );
    assert.equal((await identity(ws, A)).lifecycle_status, "revoked");
    await upsertManagedCertificateByMonitorSource(
      db,
      { fingerprintSha256: B, notAfter: "2027-01-01" },
      {
        workspaceId: ws,
        source: mc.source,
        sourceRef: mc.source_ref,
        status: "active",
        observedAt: time(10),
      },
      0,
    );
    assert.equal((await identity(ws, B)).lifecycle_status, "active");
    assert.equal(
      (await period(mc)).current_identity_id,
      (await identity(ws, B)).id,
    );
    assert.equal(
      (
        await db.query("SELECT status FROM managed_certificates WHERE id=$1", [
          mc.id,
        ])
      ).rows[0].status,
      "discovered",
    );
  });
  it("late A observations update history without moving B's management association backwards", async () => {
    const ws = await workspace(),
      mc = await source(ws, A, { observedAt: time(0) });
    const observe = async (fp, seconds) => {
      await upsertManagedCertificateByMonitorSource(
        db,
        { fingerprintSha256: fp, notAfter: "2027-01-01", commonName: fp[0] },
        {
          workspaceId: ws,
          source: mc.source,
          sourceRef: mc.source_ref,
          observedAt: time(seconds),
        },
        0,
      );
      await observation(ws, mc, fp, time(seconds));
    };
    await observe(B, 20);
    await observe(A, 10);
    assert.equal(
      (await period(mc)).current_identity_id,
      (await identity(ws, B)).id,
    );
    const history = await db.query(
      "SELECT identity_id,superseded_at FROM certops_management_associations WHERE period_id=$1 ORDER BY associated_at",
      [(await period(mc)).id],
    );
    assert.equal(history.rows.length, 2);
    assert(history.rows[0].superseded_at);
    assert.equal(history.rows[1].identity_id, (await identity(ws, B)).id);
    assert.equal(
      (
        await db.query(
          "SELECT COUNT(*)::int n FROM certificate_instances WHERE managed_certificate_id=$1",
          [mc.id],
        )
      ).rows[0].n,
      2,
    );
  });
  it("retirement and rotation respect active fingerprints sharing one token", async () => {
    const ws = await workspace(),
      tid = await token(ws),
      first = await source(ws, A, { tokenId: tid });
    await source(ws, B, { tokenId: tid });
    await retireCertificateIdentity({
      workspaceId: ws,
      identityId: (await identity(ws, A)).id,
      expectedFingerprintSha256: A,
      status: "revoked",
      reason: "A only",
      client: db,
    });
    assert.equal(
      (
        await db.query("SELECT cert_lifecycle_status FROM tokens WHERE id=$1", [
          tid,
        ])
      ).rows[0].cert_lifecycle_status,
      "active",
    );
    assert.equal((await identity(ws, B)).lifecycle_status, "active");
    assert.equal(await countActiveManagedCertificatesWithClient(db, ws), 2);
    await db.query(
      "UPDATE managed_certificates SET fingerprint_sha256=$2,identity_observed_at=clock_timestamp() WHERE id=$1",
      [first.id, C],
    );
    assert.equal((await identity(ws, C)).lifecycle_status, "active");
  });
  it("database lifecycle rejects retired reactivation and revoked downgrade", async () => {
    const ws = await workspace();
    await source(ws, A);
    const id = await identity(ws, A);
    await db.query(
      "UPDATE certops_certificate_identities SET lifecycle_status='revoked' WHERE id=$1",
      [id.id],
    );
    for (const status of ["active", "decommissioned"])
      await assert.rejects(
        db.query(
          "UPDATE certops_certificate_identities SET lifecycle_status=$2 WHERE id=$1",
          [id.id, status],
        ),
        { code: "23514" },
      );
  });
  it("stop/re-add creates a new admitted period and old periods stay immutable", async () => {
    const ws = await workspace(1),
      mc = await source(ws, A),
      old = await period(mc);
    await stopManagingSource({ workspaceId: ws, periodId: old.id, client: db });
    assert.equal(await countActiveManagedCertificatesWithClient(db, ws), 0);
    await readdManagingSource({
      workspaceId: ws,
      managedCertificateId: mc.id,
      renewalProfileId: null,
      automationEnabled: false,
      client: db,
    });
    assert.notEqual((await period(mc)).id, old.id);
    for (const assignment of [
      "ended_at=NULL",
      "ended_reason='rewritten'",
      "automation_enabled=TRUE",
    ]) {
      await assert.rejects(
        db.query(
          `UPDATE certops_management_periods SET ${assignment} WHERE id=$1`,
          [old.id],
        ),
        { code: "23514" },
      );
    }
  });
  it("replace-management refuses another certificate's period and leaves both sources managed", async () => {
    const ws = await workspace(),
      mcA = await source(ws, A),
      mcB = await source(ws, B),
      periodA = await period(mcA);
    await assert.rejects(
      replaceManagingSource({
        workspaceId: ws,
        periodId: periodA.id,
        managedCertificateId: mcB.id,
        renewalProfileId: null,
        automationEnabled: false,
        client: db,
      }),
      { code: "CERTOPS_MANAGEMENT_PERIOD_MISMATCH" },
    );
    assert.equal((await period(mcA)).id, periodA.id);
    assert.equal((await period(mcA)).ended_at, null);
    assert.equal((await period(mcB)).ended_at, null);
  });

  it("replace-management rolls back the stop when the re-attach is refused", async () => {
    const ws = await workspace(),
      mc = await source(ws, A),
      open = await period(mc);
    await assert.rejects(
      replaceManagingSource({
        workspaceId: ws,
        periodId: open.id,
        managedCertificateId: mc.id,
        renewalProfileId: null,
        automationEnabled: true,
        client: db,
      }),
      { code: "CERTOPS_MANAGEMENT_CONFIG_REQUIRED" },
    );
    assert.equal((await period(mc)).id, open.id);
    assert.equal((await period(mc)).ended_at, null);
  });

  it("a re-added provisional source reports its actual new management start time", async () => {
    const ws = await workspace(1),
      mc = await source(ws, null);
    await db.query(
      "UPDATE managed_certificates SET created_at=NOW()-INTERVAL '1 day' WHERE id=$1",
      [mc.id],
    );
    const old = await period(mc);
    await stopManagingSource({ workspaceId: ws, periodId: old.id, client: db });
    await readdManagingSource({
      workspaceId: ws,
      managedCertificateId: mc.id,
      renewalProfileId: null,
      automationEnabled: false,
      client: db,
    });
    const current = await period(mc);
    const record = (
      await listCertificateIdentities({ workspaceId: ws, client: db })
    ).items[0];
    assert.equal(record.identityId, null);
    assert.notEqual(current.id, old.id);
    assert.equal(record.sources[0].periodId, current.id);
    assert.equal(
      new Date(record.sources[0].startedAt).toISOString(),
      new Date(current.started_at).toISOString(),
    );
  });
  it("quota admission does not serialize lifecycle or unchanged source captures", async () => {
    const ws = await workspace(1),
      mc = await source(ws, A),
      id = await identity(ws, A);
    await clients(async (holder, writer) => {
      await holder.query("BEGIN");
      await holder.query(
        "SELECT pg_advisory_xact_lock(hashtext('certops_managed_cert_quota_' || $1::text))",
        [ws],
      );
      await writer.query("BEGIN");
      await writer.query("SET LOCAL statement_timeout = '1500ms'");
      await writer.query(
        "UPDATE managed_certificates SET updated_at=updated_at WHERE id=$1",
        [mc.id],
      );
      await upsertManagedCertificateByMonitorSource(
        writer,
        {
          fingerprintSha256: A,
          commonName: "unchanged",
          notAfter: "2027-01-01",
        },
        {
          workspaceId: ws,
          source: mc.source,
          sourceRef: mc.source_ref,
          observedAt: new Date(),
        },
        0,
      );
      const result = await retireCertificateIdentity({
        workspaceId: ws,
        identityId: id.id,
        expectedFingerprintSha256: A,
        status: "revoked",
        reason: "Scoped lifecycle lock",
        client: writer,
      });
      assert.equal(result.lifecycleStatus, "revoked");
      // Calling the compatibility helper must not reintroduce a quota lock.
      const {
        retireManagedCertificate,
      } = require("../../apps/api/services/certops/inventory");
      await retireManagedCertificate(writer, {
        workspaceId: ws,
        certificateId: mc.id,
        status: "revoked",
        reason: "Idempotent scoped retirement",
      });
      await writer.query("ROLLBACK");
      await writer.query("BEGIN");
      const pids = await blockedBy(writer, holder);
      const enrolled = writer.query(
        "INSERT INTO managed_certificates(workspace_id,source,source_ref,fingerprint_sha256) VALUES($1,'agent_filesystem',$2,$3)",
        [ws, randomUUID(), A],
      );
      await waitForBlock(pids);
      await holder.query("COMMIT");
      await enrolled;
      await writer.query("COMMIT");
    });
    assert.equal(await countActiveManagedCertificatesWithClient(db, ws), 1);
  });
  it("existing identity lifecycle row locks do not block source captures or observation foreign keys", async () => {
    const ws = await workspace(),
      mc = await source(ws, A),
      id = await identity(ws, A),
      target = (
        await db.query(
          "INSERT INTO certificate_targets(workspace_id,name,target_type) VALUES($1,'Lock fixture','host') RETURNING id",
          [ws],
        )
      ).rows[0];
    await clients(async (lifecycle, capture) => {
      await lifecycle.query("BEGIN");
      await lifecycle.query(
        "SELECT id FROM certops_certificate_identities WHERE id=$1 FOR NO KEY UPDATE",
        [id.id],
      );
      await capture.query("BEGIN");
      await capture.query("SET LOCAL statement_timeout = '1500ms'");
      await capture.query(
        "UPDATE managed_certificates SET common_name='more metadata' WHERE id=$1",
        [mc.id],
      );
      await capture.query(
        "INSERT INTO certificate_instances(workspace_id,managed_certificate_id,source,source_ref,observed_fingerprint_sha256,observed_at,target_id) VALUES($1,$2,'endpoint_monitor',$3,$4,clock_timestamp(),$5)",
        [ws, mc.id, randomUUID(), A, target.id],
      );
      await capture.query("COMMIT");
      await lifecycle.query("COMMIT");
    });
  });
  for (const observationFirst of [true, false]) {
    it(`observation/decommission races derive the conflict when observation commits ${observationFirst ? "first" : "last"}`, async () => {
      const ws = await workspace(),
        mc = await source(ws, A),
        id = await identity(ws, A),
        monitor = await endpoint(ws),
        target = (
          await db.query(
            "INSERT INTO certificate_targets(workspace_id,name,target_type) VALUES($1,'Race fixture','host') RETURNING id",
            [ws],
          )
        ).rows[0];
      await clients(async (lifecycle, capture) => {
        await lifecycle.query("BEGIN");
        await capture.query("BEGIN");
        await lifecycle.query("SET LOCAL statement_timeout = '1500ms'");
        await capture.query("SET LOCAL statement_timeout = '1500ms'");
        await retireCertificateIdentity({
          workspaceId: ws,
          identityId: id.id,
          expectedFingerprintSha256: A,
          status: "decommissioned",
          reason: "No known service usage",
          acknowledgeUncertainty: true,
          client: lifecycle,
        });
        await capture.query(
          "INSERT INTO certificate_instances(workspace_id,managed_certificate_id,source,source_ref,domain_monitor_id,observed_fingerprint_sha256,observed_at,target_id) VALUES($1,$2,'endpoint_monitor',$3,$4,$5,clock_timestamp(),$6)",
          [ws, mc.id, monitor.id, monitor.id, A, target.id],
        );
        await (observationFirst ? capture : lifecycle).query("COMMIT");
        await (observationFirst ? lifecycle : capture).query("COMMIT");
      });
      const hidden = await listCertificateIdentities({
        client: db,
        workspaceId: ws,
        excludeRetired: true,
      });
      assert.equal(
        hidden.items.find((item) => item.identityId === id.id),
        undefined,
      );
      const listing = await listCertificateIdentities({
        client: db,
        workspaceId: ws,
      });
      const row = listing.items.find((item) => item.identityId === id.id);
      assert(row, "Retired certificate stays visible when retired rows are included");
      assert.equal(row.lifecycleStatus, "decommissioned");
      assert.equal(row.stillObserved, true);
      assert.match(String(row.lifecycleDisplay), /Still observed/);
    });
  }
  it("retirement skips a contended source while preserving authoritative lifecycle and token state", async () => {
    const ws = await workspace(),
      t = await token(ws),
      mc = await source(ws, A, { tokenId: t }),
      id = await identity(ws, A);
    await clients(async (writer, lifecycle) => {
      await writer.query("BEGIN");
      await writer.query(
        "SELECT id FROM managed_certificates WHERE id=$1 FOR UPDATE",
        [mc.id],
      );
      await lifecycle.query("BEGIN");
      await lifecycle.query("SET LOCAL statement_timeout = '1500ms'");
      await retireCertificateIdentity({
        workspaceId: ws,
        identityId: id.id,
        expectedFingerprintSha256: A,
        status: "revoked",
        reason: "Contended source cache",
        client: lifecycle,
      });
      await lifecycle.query("COMMIT");
      assert.equal(
        (
          await db.query(
            "SELECT cert_lifecycle_status FROM tokens WHERE id=$1",
            [t],
          )
        ).rows[0].cert_lifecycle_status,
        "revoked",
      );
      await writer.query(
        "UPDATE managed_certificates SET common_name='refreshed after retirement' WHERE id=$1",
        [mc.id],
      );
      await writer.query("COMMIT");
    });
    assert.equal(
      (
        await db.query("SELECT status FROM managed_certificates WHERE id=$1", [
          mc.id,
        ])
      ).rows[0].status,
      "revoked",
    );
  });
  it("endpoint token-first ingestion and retirement cannot invert token/source locks", async () => {
    const ws = await workspace(),
      t = await token(ws),
      mc = await source(ws, A, { tokenId: t }),
      id = await identity(ws, A);
    await clients(async (ingestion, lifecycle) => {
      await ingestion.query("BEGIN");
      await ingestion.query(
        "SELECT id FROM tokens WHERE id=$1 FOR NO KEY UPDATE",
        [t],
      );
      await lifecycle.query("BEGIN");
      const pids = await blockedBy(lifecycle, ingestion);
      const retired = retireCertificateIdentity({
        workspaceId: ws,
        identityId: id.id,
        expectedFingerprintSha256: A,
        status: "revoked",
        reason: "Token-first endpoint interleaving",
        client: lifecycle,
      });
      await waitForBlock(pids);
      await ingestion.query("SET LOCAL statement_timeout = '1500ms'");
      await ingestion.query(
        "UPDATE managed_certificates SET common_name='endpoint capture' WHERE id=$1",
        [mc.id],
      );
      await ingestion.query("COMMIT");
      await retired;
      await lifecycle.query("COMMIT");
    });
    assert.equal((await identity(ws, A)).lifecycle_status, "revoked");
  });
  it("retirement cancellation locks only work for the affected fingerprint", async () => {
    const ws = await workspace(),
      mc = await source(ws, A),
      other = await source(ws, B),
      id = await identity(ws, A);
    await job(ws, mc);
    const unrelated = await job(ws, other);
    await clients(async (lifecycle, unrelatedWorker) => {
      await lifecycle.query("BEGIN");
      await retireCertificateIdentity({
        workspaceId: ws,
        identityId: id.id,
        expectedFingerprintSha256: A,
        status: "revoked",
        reason: "Targeted cancellation",
        client: lifecycle,
      });
      await unrelatedWorker.query("BEGIN");
      await unrelatedWorker.query("SET LOCAL statement_timeout='1500ms'");
      await unrelatedWorker.query(
        "SELECT id FROM certificate_jobs WHERE id=$1 FOR UPDATE",
        [unrelated.id],
      );
      await unrelatedWorker.query("COMMIT");
      await lifecycle.query("COMMIT");
    });
    assert.equal(
      (
        await db.query("SELECT status FROM certificate_jobs WHERE id=$1", [
          unrelated.id,
        ])
      ).rows[0].status,
      "pending",
    );
  });
  it("quota counts distinct managed identities plus provisionals, regardless of lifecycle", async () => {
    const ws = await workspace(2),
      first = await source(ws, A),
      second = await source(ws, A);
    await source(ws, null, { status: "provisioning" });
    assert.equal(await countActiveManagedCertificatesWithClient(db, ws), 2);
    assert.equal(
      await countQuotaConsumingNewFingerprints(db, ws, [A, B, B]),
      1,
    );
    await assert.rejects(source(ws, B), {
      detail: "CERTOPS_MANAGED_CERT_LIMIT",
    });
    await stopManagingSource({
      workspaceId: ws,
      periodId: (await period(first)).id,
      client: db,
    });
    assert.equal(await countActiveManagedCertificatesWithClient(db, ws), 2);
    await stopManagingSource({
      workspaceId: ws,
      periodId: (await period(second)).id,
      client: db,
    });
    assert.equal(await countActiveManagedCertificatesWithClient(db, ws), 1);
  });
  it("re-add fails admission when another identity took the freed slot", async () => {
    const ws = await workspace(1),
      mc = await source(ws, A),
      old = await period(mc);
    await stopManagingSource({ workspaceId: ws, periodId: old.id, client: db });
    await source(ws, B);
    await assert.rejects(
      readdManagingSource({
        workspaceId: ws,
        managedCertificateId: mc.id,
        renewalProfileId: null,
        automationEnabled: false,
        client: db,
      }),
      { detail: "CERTOPS_MANAGED_CERT_LIMIT" },
    );
    assert((await period(mc)).ended_at);
  });
  it("two concurrent admissions with one remaining slot cannot both succeed", async () => {
    const ws = await workspace(1);
    const results = await Promise.allSettled([source(ws, A), source(ws, B)]);
    assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
    assert.equal(
      results.find((r) => r.status === "rejected").reason.detail,
      "CERTOPS_MANAGED_CERT_LIMIT",
    );
    assert.equal(await countActiveManagedCertificatesWithClient(db, ws), 1);
  });
  it("existing-source rotation allows temporary overage while new enrollment remains blocked", async () => {
    const ws = await workspace(1),
      first = await source(ws, A),
      second = await source(ws, A);
    await db.query(
      "UPDATE managed_certificates SET fingerprint_sha256=$2,identity_observed_at=clock_timestamp() WHERE id=$1",
      [first.id, B],
    );
    assert.equal(await countActiveManagedCertificatesWithClient(db, ws), 2);
    assert.equal(
      (await period(first)).current_identity_id,
      (await identity(ws, B)).id,
    );
    await assert.rejects(source(ws, C), {
      detail: "CERTOPS_MANAGED_CERT_LIMIT",
    });
    await source(ws, B);
    assert.equal(await countActiveManagedCertificatesWithClient(db, ws), 2);
    await stopManagingSource({
      workspaceId: ws,
      periodId: (await period(second)).id,
      client: db,
    });
    assert.equal(await countActiveManagedCertificatesWithClient(db, ws), 1);
  });
  it("keeps certificate tokens current across discovery and repeated agent renewals", async () => {
    const ws = await workspace(), tid = await token(ws), ref = randomUUID();
    await db.query("UPDATE tokens SET expiration='2026-10-20',notes='Operator notes' WHERE id=$1", [tid]);
    const mc = await source(ws, A, {
      source: "agent_issuance", sourceRef: ref, status: "active",
      tokenId: tid, notAfter: "2026-10-20",
    });
    await upsertManagedCertificateByMonitorSource(db,
      { fingerprintSha256: A, commonName: "app.example", notAfter: "2026-10-20" },
      { workspaceId: ws, source: "agent_issuance", sourceRef: ref,
        reuseCertificateId: mc.id, tokenId: tid, status: "discovered", observedAt: new Date() }, 0);
    const refresh = require("../../apps/api/services/certops/agentDispatch")._test.refreshRenewedCertificateEvidence;
    for (const [fingerprint, expiry] of [[B, "2027-01-12"], [C, "2027-04-12"]]) {
      const renewed = await job(ws, mc, "claimed");
      renewed.claim_id = randomUUID();
      await db.query("UPDATE certificate_jobs SET claim_id=$2 WHERE id=$1", [renewed.id, renewed.claim_id]);
      await db.query(
        "INSERT INTO certificate_evidence(workspace_id,job_id,evidence_type,claim_id,metadata) VALUES($1,$2,'validation.passed',$3,$4::jsonb)",
        [ws, renewed.id, renewed.claim_id, JSON.stringify({ step: "verify",
          fingerprintSha256: fingerprint, validTo: expiry + "T00:00:00.000Z",
          subject: "CN=app.example", serialNumber: fingerprint.slice(0, 8),
          subjectAltNames: "app.example" })]);
      const client = await db.connect();
      try {
        await client.query("BEGIN");
        const result = await refresh({ client, workspaceId: ws, job: renewed });
        assert.equal(result?.refreshed, true, "discovered certificates must accept verified renewals");
        await client.query("COMMIT");
      } catch (error) { await client.query("ROLLBACK"); throw error; }
      finally { client.release(); }
      const t = (await db.query("SELECT expiration::text,notes,serial_number FROM tokens WHERE id=$1", [tid])).rows[0];
      assert.equal(t.expiration, expiry);
      assert.equal(t.serial_number, fingerprint.slice(0, 8));
      assert.equal(t.notes, "Operator notes");
      assert.equal(
        (await db.query("SELECT token_id FROM managed_certificates WHERE id=$1", [mc.id])).rows[0].token_id,
        tid,
        "renewal keeps the same token while adding another fingerprint identity",
      );
      await db.query("UPDATE certificate_jobs SET status='succeeded' WHERE id=$1", [renewed.id]);
    }
    assert.equal(
      (await db.query("SELECT COUNT(*)::int n FROM certops_certificate_identities WHERE workspace_id=$1", [ws])).rows[0].n,
      3,
      "original certificate and both renewed identities remain in history",
    );
    assert.equal(
      (await db.query("SELECT COUNT(DISTINCT identity_id)::int n FROM certops_identity_detail_history WHERE workspace_id=$1 AND token_id=$2", [ws, tid])).rows[0].n,
      3,
      "all three certificate identity snapshots retain their association to the same token",
    );
    assert.equal(
      (await db.query("SELECT COUNT(*)::int n FROM certops_management_associations WHERE workspace_id=$1", [ws])).rows[0].n,
      3,
    );
    assert.equal(
      (await db.query("SELECT COUNT(*)::int n FROM tokens WHERE workspace_id=$1", [ws])).rows[0].n,
      1,
    );
    const linked = (await listManagedCertificates({ workspaceId: ws, client: db })).items;
    assert.deepEqual(linked.map(item => item.fingerprintSha256), [C],
      "renewal snapshots alone do not become additional token action targets");
  });
  it("updates a shared token even when another source has a different certificate identity", async () => {
    const ws = await workspace(), tid = await token(ws);
    const selected = await source(ws, A, { tokenId: tid, notAfter: "2026-10-20" });
    await source(ws, B, { tokenId: tid, notAfter: "2027-02-12" });
    await upsertManagedCertificateByMonitorSource(db,
      { fingerprintSha256: C, commonName: "app.example", serialNumber: "third-leaf", notAfter: "2027-04-12" },
      { workspaceId: ws, source: selected.source, sourceRef: selected.source_ref,
        tokenId: tid, status: "discovered", observedAt: new Date() }, 0);
    const t = (await db.query("SELECT expiration::text,serial_number FROM tokens WHERE id=$1", [tid])).rows[0];
    assert.deepEqual(t, { expiration: "2027-04-12", serial_number: "third-leaf" });
    assert.equal(
      (await db.query("SELECT COUNT(DISTINCT fingerprint_sha256)::int n FROM managed_certificates WHERE token_id=$1", [tid])).rows[0].n,
      2,
      "different live source identities do not gate the token write",
    );
    const linked = (await listManagedCertificates({ workspaceId: ws, client: db })).items;
    assert.deepEqual(new Set(linked.map(item => item.fingerprintSha256)), new Set([B, C]),
      "a second source on the older fingerprint creates the actual token UI ambiguity");
    await retireCertificateIdentity({ workspaceId: ws, identityId: (await identity(ws, C)).id,
      expectedFingerprintSha256: C, status: "revoked", reason: "Selected certificate revoked", client: db });
    assert.equal((await identity(ws, C)).lifecycle_status, "revoked");
    assert.equal((await identity(ws, B)).lifecycle_status, "active",
      "explicit retirement does not retire another fingerprint sharing the token");
    assert.equal((await db.query("SELECT cert_lifecycle_status FROM tokens WHERE id=$1", [tid])).rows[0].cert_lifecycle_status,
      "active", "the token stays active while another live source identity remains");
    await retireCertificateIdentity({ workspaceId: ws, identityId: (await identity(ws, B)).id,
      expectedFingerprintSha256: B, status: "revoked", reason: "Other certificate revoked", client: db });
    assert.equal((await db.query("SELECT cert_lifecycle_status FROM tokens WHERE id=$1", [tid])).rows[0].cert_lifecycle_status,
      "revoked", "retiring all linked live identities retires the token");
  });
  it("updates the token before fencing a renewal result whose source already rotated", async () => {
    const ws = await workspace(), tid = await token(ws);
    const mc = await source(ws, A, { status: "active", tokenId: tid, notAfter: "2026-10-20" });
    const renewed = await job(ws, mc, "claimed");
    renewed.claim_id = randomUUID();
    await db.query("UPDATE certificate_jobs SET claim_id=$2 WHERE id=$1", [renewed.id, renewed.claim_id]);
    await db.query(
      "INSERT INTO certificate_evidence(workspace_id,job_id,evidence_type,claim_id,metadata) VALUES($1,$2,'validation.passed',$3,$4::jsonb)",
      [ws, renewed.id, renewed.claim_id, JSON.stringify({ step: "verify",
        fingerprintSha256: B, validTo: "2027-01-12T00:00:00.000Z", serialNumber: "renewed-leaf" })]);
    await upsertManagedCertificateByMonitorSource(db,
      { fingerprintSha256: B, commonName: "app.example", serialNumber: "renewed-leaf", notAfter: "2027-01-12" },
      { workspaceId: ws, source: mc.source, sourceRef: mc.source_ref,
        tokenId: tid, status: "active", observedAt: new Date() }, 0);
    const refresh = require("../../apps/api/services/certops/agentDispatch")._test.refreshRenewedCertificateEvidence;
    assert.equal(await refresh({ client: db, workspaceId: ws, job: renewed }), null,
      "a result for the old management association stays fenced");
    assert.equal(
      (await db.query("SELECT expiration::text FROM tokens WHERE id=$1", [tid])).rows[0].expiration,
      "2027-01-12",
      "accepted discovery already synchronized the renewed identity's token",
    );
    assert.equal((await period(mc)).current_identity_id, (await identity(ws, B)).id);
  });
  for (const observedSource of ["agent_filesystem", "agent_windows", "cert_manager"]) {
    it("synchronizes token facts from accepted " + observedSource + " observations and rejects stale projection", async () => {
      const ws = await workspace(), tid = await token(ws), ref = randomUUID();
      await db.query("UPDATE tokens SET expiration='2026-10-20',notes='Keep my notes' WHERE id=$1", [tid]);
      const mc = await source(ws, A, { source: observedSource, sourceRef: ref, tokenId: tid, notAfter: "2026-10-20" });
      const observedAt = new Date();
      const options = { workspaceId: ws, source: observedSource, sourceRef: ref, tokenId: tid, status: "discovered", observedAt };
      const material = { fingerprintSha256: B, commonName: "app.example", subject: "CN=app.example",
        subjectAltNames: ["DNS:app.example"], issuer: "New issuer", serialNumber: "new-serial", notAfter: "2027-01-12" };
      await upsertManagedCertificateByMonitorSource(db, material, options, 0);
      const read = async () => (await db.query("SELECT expiration::text,issuer,serial_number,notes FROM tokens WHERE id=$1", [tid])).rows[0];
      assert.deepEqual(await read(), { expiration: "2027-01-12", issuer: "New issuer", serial_number: "new-serial", notes: "Keep my notes" });
      await upsertManagedCertificateByMonitorSource(db,
        { ...material, fingerprintSha256: A, notAfter: "2026-10-20", serialNumber: "stale" },
        { ...options, observedAt: new Date(observedAt.getTime() - 30000) }, 0);
      assert.equal((await read()).expiration, "2027-01-12");
      assert.equal((await read()).serial_number, "new-serial");
      const client = await db.connect();
      try {
        await client.query("BEGIN");
        await upsertManagedCertificateByMonitorSource(client,
          { ...material, fingerprintSha256: C, notAfter: "2027-04-12" },
          { ...options, observedAt: new Date(observedAt.getTime() + 1000) }, 0);
        assert.equal((await client.query("SELECT expiration::text FROM tokens WHERE id=$1", [tid])).rows[0].expiration, "2027-04-12");
        await client.query("ROLLBACK");
      } finally { client.release(); }
      assert.equal((await read()).expiration, "2027-01-12");
      assert.equal((await period(mc)).current_identity_id, (await identity(ws, B)).id);
    });
  }
  for (const retiredStatus of ["revoked", "decommissioned"]) {
    it("synchronizes token lifecycle through " + retiredStatus + ", replacement, and another renewal", async () => {
      const ws = await workspace(), tid = await token(ws);
      await db.query("UPDATE tokens SET expiration='2026-10-20',notes='Lifecycle notes' WHERE id=$1", [tid]);
      const mc = await source(ws, A, { status: "active", tokenId: tid, notAfter: "2026-10-20" });
      await retireCertificateIdentity({
        workspaceId: ws, identityId: (await identity(ws, A)).id,
        expectedFingerprintSha256: A, status: retiredStatus,
        reason: "Lifecycle verification", acknowledgeUncertainty: true, client: db,
      });
      const readToken = async () => (await db.query(
        "SELECT expiration::text,cert_lifecycle_status,serial_number,notes FROM tokens WHERE id=$1", [tid])).rows[0];
      assert.equal((await readToken()).cert_lifecycle_status, retiredStatus);
      assert.equal((await readToken()).expiration, "2026-10-20");
      await assert.rejects(job(ws, mc, "claimed", "renew"),
        error => error.code === "55000" && /lifecycle blocks/.test(error.message),
        "ordinary renewal of the retired fingerprint must remain blocked");
      await upsertManagedCertificateByMonitorSource(db,
        { fingerprintSha256: A, commonName: "app.example", notAfter: "2026-10-20" },
        { workspaceId: ws, source: mc.source, sourceRef: mc.source_ref,
          tokenId: tid, status: "active", observedAt: new Date() }, 0);
      assert.equal((await identity(ws, A)).lifecycle_status, retiredStatus);
      assert.equal((await readToken()).cert_lifecycle_status, retiredStatus,
        "rediscovery of the same fingerprint does not reactivate its token");
      await upsertManagedCertificateByMonitorSource(db,
        { fingerprintSha256: B, commonName: "app.example", notAfter: "2027-01-12", serialNumber: "replacement-leaf" },
        { workspaceId: ws, source: mc.source, sourceRef: mc.source_ref,
          tokenId: tid, status: "active", observedAt: new Date() }, 0);
      assert.equal((await identity(ws, A)).lifecycle_status, retiredStatus);
      assert.equal((await identity(ws, B)).lifecycle_status, "active");
      assert.deepEqual(await readToken(), { expiration: "2027-01-12",
        cert_lifecycle_status: "active", serial_number: "replacement-leaf", notes: "Lifecycle notes" });
      const renewed = await job(ws, mc, "claimed", "renew");
      renewed.claim_id = randomUUID();
      await db.query("UPDATE certificate_jobs SET claim_id=$2 WHERE id=$1", [renewed.id, renewed.claim_id]);
      await db.query(
        "INSERT INTO certificate_evidence(workspace_id,job_id,evidence_type,claim_id,metadata) VALUES($1,$2,'validation.passed',$3,$4::jsonb)",
        [ws, renewed.id, renewed.claim_id, JSON.stringify({ step: "verify",
          fingerprintSha256: C, validTo: "2027-04-12T00:00:00.000Z", serialNumber: "next-renewal" })]);
      const client = await db.connect();
      try {
        await client.query("BEGIN");
        const result = await require("../../apps/api/services/certops/agentDispatch")._test.refreshRenewedCertificateEvidence({
          client, workspaceId: ws, job: renewed,
        });
        assert.equal(result?.refreshed, true);
        await client.query("COMMIT");
      } catch (error) { await client.query("ROLLBACK"); throw error; }
      finally { client.release(); }
      assert.deepEqual(await readToken(), { expiration: "2027-04-12",
        cert_lifecycle_status: "active", serial_number: "next-renewal", notes: "Lifecycle notes" });
      assert.equal((await identity(ws, A)).lifecycle_status, retiredStatus);
    });
  }
  it("v64 repairs already-applied v63 without exempting closed or foreign periods from admission", async () => {
    const ws = await workspace(1),
      first = await source(ws, A),
      second = await source(ws, A);
    const originalPeriod = await period(first);
    await db.query(migrations.find((m) => m.version === 63).sql);
    await assert.rejects(
      db.query(
        "UPDATE managed_certificates SET fingerprint_sha256=$2,identity_observed_at=clock_timestamp() WHERE id=$1",
        [first.id, B],
      ),
      { detail: "CERTOPS_MANAGED_CERT_LIMIT" },
    );
    const repair = migrations.find((m) => m.version === 64);
    await db.query(repair.sql);
    await db.query(repair.sql);
    const foreign = await source(await workspace(), C);
    await assert.rejects(
      db.query("SELECT certops_admit_management($1,$2,$3)", [
        ws,
        null,
        (await period(foreign)).id,
      ]),
      { detail: "CERTOPS_MANAGED_CERT_LIMIT" },
    );
    const closed = await period(second);
    await stopManagingSource({
      workspaceId: ws,
      periodId: closed.id,
      client: db,
    });
    await assert.rejects(
      db.query("SELECT certops_admit_management($1,$2,$3)", [
        ws,
        null,
        closed.id,
      ]),
      { detail: "CERTOPS_MANAGED_CERT_LIMIT" },
    );
    await source(ws, A);
    await db.query(
      "UPDATE managed_certificates SET fingerprint_sha256=$2,identity_observed_at=clock_timestamp() WHERE id=$1",
      [first.id, B],
    );
    assert.equal(await countActiveManagedCertificatesWithClient(db, ws), 2);
    assert.equal((await period(first)).id, originalPeriod.id);
    assert((await period(second)).ended_at);
    await db.query(migrations.find((m) => m.version === 65).sql);
  });
  it("closing cancels only unstarted period jobs and preserves claimed/running reconciliation", async () => {
    const ws = await workspace(),
      mc = await source(ws, A),
      other = await source(ws, A);
    const jobs = await Promise.all(
      ["pending", "approved", "pending_approval", "claimed", "running"].map(
        (s) => job(ws, mc, s),
      ),
    );
    const unrelated = await job(ws, other);
    await stopManagingSource({
      workspaceId: ws,
      periodId: (await period(mc)).id,
      client: db,
    });
    for (let n = 0; n < jobs.length; n++) {
      const row = (
        await db.query("SELECT * FROM certificate_jobs WHERE id=$1", [
          jobs[n].id,
        ])
      ).rows[0];
      assert.equal(row.status, n < 3 ? "cancelled" : jobs[n].status);
      if (n >= 3) assert(row.needs_operator_reconciliation);
    }
    assert.equal(
      (
        await db.query("SELECT status FROM certificate_jobs WHERE id=$1", [
          unrelated.id,
        ])
      ).rows[0].status,
      "pending",
    );
    await assert.rejects(job(ws, mc, "claimed"), { code: "55000" });
  });
  it("claim-first versus stop has a deterministic claimed result with reconciliation", async () => {
    const ws = await workspace(),
      mc = await source(ws, A),
      j = await job(ws, mc),
      p = await period(mc);
    await clients(async (one, two) => {
      const pids = await blockedBy(two, one);
      await one.query("BEGIN");
      await two.query("BEGIN");
      await one.query(
        "UPDATE certificate_jobs SET status='claimed' WHERE id=$1",
        [j.id],
      );
      const close = two.query(
        "UPDATE certops_management_periods SET ended_at=NOW() WHERE id=$1",
        [p.id],
      );
      await waitForBlock(pids);
      await one.query("COMMIT");
      await close;
      await two.query("COMMIT");
    });
    const row = (
      await db.query(
        "SELECT status,needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",
        [j.id],
      )
    ).rows[0];
    assert.equal(row.status, "claimed");
    assert(row.needs_operator_reconciliation);
  });
  it("stop-first while claimant holds job row cancels the claim without a deadlock", async () => {
    const ws = await workspace(),
      mc = await source(ws, A),
      j = await job(ws, mc),
      p = await period(mc);
    await clients(async (one, two) => {
      const pids = await blockedBy(two, one);
      await one.query("BEGIN");
      await two.query("BEGIN");
      await two.query(
        "SELECT id FROM certificate_jobs WHERE id=$1 FOR UPDATE",
        [j.id],
      );
      await one.query(
        "UPDATE certops_management_periods SET ended_at=NOW() WHERE id=$1",
        [p.id],
      );
      const claim = two.query(
        "UPDATE certificate_jobs SET status='claimed',claim_id=gen_random_uuid() WHERE id=$1 RETURNING status,claim_id",
        [j.id],
      );
      await waitForBlock(pids);
      await one.query("COMMIT");
      const result = await claim;
      await two.query("COMMIT");
      assert.equal(result.rows[0].status, "cancelled");
      assert.equal(result.rows[0].claim_id, null);
    });
  });
  it("INSERT cannot bypass lifecycle protection by directly creating claimed work", async () => {
    const ws = await workspace(),
      mc = await source(ws, A);
    await db.query(
      "UPDATE certops_certificate_identities SET lifecycle_status='revoked' WHERE workspace_id=$1",
      [ws],
    );
    await assert.rejects(job(ws, mc, "claimed"), { code: "55000" });
  });
  it("unchanged endpoint captures remain independent of a held quota lock", async () => {
    const ws = await workspace(),
      dm = await endpoint(ws),
      claim = randomUUID();
    await source(ws, A, {
      source: "endpoint_monitor",
      sourceRef: String(dm.id),
    });
    await db.query("UPDATE domain_monitors SET check_claim_id=$2 WHERE id=$1", [
      dm.id,
      claim,
    ]);
    await clients(async (quota, capture) => {
      await quota.query("BEGIN");
      await quota.query(
        "SELECT pg_advisory_xact_lock(hashtext('certops_managed_cert_quota_' || $1::text))",
        [ws],
      );
      await capture.query("SET statement_timeout='1500ms'");
      assert.equal(
        await worker.withOwnedEndpointResult(
          capture,
          dm,
          claim,
          async () => "unchanged",
          A,
        ),
        "unchanged",
      );
      await quota.query("COMMIT");
    });
  });
  it("endpoint rotation acquires quota before monitor ownership, allowing deletion to finish", async () => {
    const ws = await workspace(),
      dm = await endpoint(ws),
      claim = randomUUID();
    await source(ws, A, {
      source: "endpoint_monitor",
      sourceRef: String(dm.id),
    });
    await db.query("UPDATE domain_monitors SET check_claim_id=$2 WHERE id=$1", [
      dm.id,
      claim,
    ]);
    await clients(async (quota, capture) => {
      await quota.query("BEGIN");
      await quota.query(
        "SELECT pg_advisory_xact_lock(hashtext('certops_managed_cert_quota_' || $1::text))",
        [ws],
      );
      const pids = await blockedBy(capture, quota);
      let applied = false;
      const persisted = worker.withOwnedEndpointResult(
        capture,
        dm,
        claim,
        async () => {
          applied = true;
        },
        B,
      );
      await waitForBlock(pids);
      await quota.query("SET LOCAL statement_timeout='1500ms'");
      await quota.query("DELETE FROM domain_monitors WHERE id=$1", [dm.id]);
      await quota.query("COMMIT");
      assert.equal(await persisted, null);
      assert.equal(applied, false);
    });
  });
  it("late endpoint result cannot create tokens, management or mutate a recreated endpoint", async () => {
    const ws = await workspace(),
      old = await endpoint(ws),
      claimId = randomUUID();
    await db.query("UPDATE domain_monitors SET check_claim_id=$2 WHERE id=$1", [
      old.id,
      claimId,
    ]);
    await db.query("DELETE FROM domain_monitors WHERE id=$1", [old.id]);
    const replacement = await endpoint(ws);
    const client = await db.connect();
    try {
      assert.equal(
        await worker.persistEndpointCertificateResult(client, old, claimId, {
          ssl_fingerprint: A,
          ssl_valid_to: new Date("2027-01-01"),
          ssl_subject: "CN=old.example.test",
        }),
        null,
      );
    } finally {
      client.release();
    }
    assert.equal(
      (
        await db.query(
          "SELECT COUNT(*)::int n FROM tokens WHERE workspace_id=$1",
          [ws],
        )
      ).rows[0].n,
      0,
    );
    assert.equal(await countActiveManagedCertificatesWithClient(db, ws), 0);
    assert.equal(
      (
        await db.query(
          "SELECT ssl_fingerprint FROM domain_monitors WHERE id=$1",
          [replacement.id],
        )
      ).rows[0].ssl_fingerprint,
      null,
    );
  });
  it("lease takeover suppresses the complete old worker side-effect path", async () => {
    const ws = await workspace(),
      dm = await endpoint(ws),
      oldClaim = randomUUID();
    await db.query("UPDATE domain_monitors SET check_claim_id=$2 WHERE id=$1", [
      dm.id,
      randomUUID(),
    ]);
    const client = await db.connect();
    let called = false;
    try {
      assert.equal(
        await worker.withOwnedEndpointResult(client, dm, oldClaim, () => {
          called = true;
        }),
        null,
      );
    } finally {
      client.release();
    }
    assert.equal(called, false);
  });
  it("global identity/provisional pagination is stable for every sort and direction", async () => {
    const ws = await workspace();
    for (let n = 0; n < 9; n++)
      await source(ws, n % 2 ? n.toString(16).repeat(64) : null, {
        name: `name-${8 - n}`,
        source: n % 3 ? "agent_filesystem" : "cert_manager",
        status: n % 2 ? "active" : "provisioning",
        notAfter: n % 3 ? `2027-01-${10 + n}` : null,
      });
    for (const sort of [
      "expiry",
      "name",
      "status",
      "source",
      "created",
      "keyLocality",
    ])
      for (const direction of ["asc", "desc"]) {
        const all = await listCertificateIdentities({
          workspaceId: ws,
          sort,
          direction,
          limit: 100,
          client: db,
        });
        const paged = [];
        for (let offset = 0; offset < 9; offset += 3) {
          const page = await listCertificateIdentities({
            workspaceId: ws,
            sort,
            direction,
            limit: 3,
            offset,
            client: db,
          });
          assert.equal(page.pagination.total, 9);
          paged.push(...page.items);
        }
        assert.deepEqual(
          paged.map((r) => r.id),
          all.items.map((r) => r.id),
        );
        assert.equal(new Set(paged.map((r) => r.id)).size, 9);
        if (sort === "name")
          assert.deepEqual(
            all.items.map((r) => r.name),
            Array.from(
              { length: 9 },
              (_, n) => `name-${direction === "asc" ? n : 8 - n}`,
            ),
          );
      }
    const beyond = await listCertificateIdentities({
      workspaceId: ws,
      offset: 999,
      client: db,
    });
    assert.equal(beyond.items.length, 0);
    assert.equal(beyond.pagination.total, 9);
  });
  it("source, lifecycle and management operations cannot cross workspace boundaries", async () => {
    const ws = await workspace(),
      other = await workspace(),
      mc = await source(ws, A),
      p = await period(mc),
      id = await identity(ws, A);
    assert.equal(
      (
        await listCertificateIdentities({
          workspaceId: other,
          identityId: id.id,
          client: db,
        })
      ).items.length,
      0,
    );
    await assert.rejects(
      stopManagingSource({ workspaceId: other, periodId: p.id, client: db }),
      { code: "CERTOPS_MANAGEMENT_PERIOD_NOT_FOUND" },
    );
    await assert.rejects(
      readdManagingSource({
        workspaceId: other,
        managedCertificateId: mc.id,
        renewalProfileId: null,
        automationEnabled: false,
        client: db,
      }),
      { code: "CERTOPS_CERTIFICATE_NOT_FOUND" },
    );
    await assert.rejects(
      retireCertificateIdentity({
        workspaceId: other,
        identityId: id.id,
        expectedFingerprintSha256: A,
        status: "revoked",
        reason: "No access",
        client: db,
      }),
      { code: "CERTOPS_CERTIFICATE_NOT_FOUND" },
    );
    await assert.rejects(
      db.query(
        "INSERT INTO certops_management_associations(workspace_id,period_id,identity_id,superseded_at) VALUES($1,$2,$3,NOW())",
        [other, p.id, id.id],
      ),
      { code: "23503" },
    );
  });
  it("physical source deletion preserves immutable periods, observations and identity", async () => {
    const ws = await workspace(),
      tid = await token(ws),
      mc = await source(ws, A, { tokenId: tid }),
      p = await period(mc);
    const observed = await observation(ws, mc, A, time(10));
    const pending = await job(ws, mc);
    await db.query("DELETE FROM managed_certificates WHERE id=$1", [mc.id]);
    const history = (
      await db.query("SELECT * FROM certops_management_periods WHERE id=$1", [
        p.id,
      ])
    ).rows[0];
    assert(history.ended_at);
    assert.equal(history.source_ref, mc.source_ref);
    assert.equal(history.ended_reason, "management_source_deleted");
    assert.equal((await identity(ws, A)).lifecycle_status, "active");
    assert.equal(
      (
        await db.query(
          "SELECT managed_certificate_id FROM certificate_instances WHERE id=$1",
          [observed.id],
        )
      ).rows[0].managed_certificate_id,
      null,
    );
    assert.equal(
      (
        await db.query("SELECT status FROM certificate_jobs WHERE id=$1", [
          pending.id,
        ])
      ).rows[0].status,
      "cancelled",
    );
    const detail = await listCertificateIdentities({
      workspaceId: ws,
      identityId: (await identity(ws, A)).id,
      client: db,
    });
    const certificate = detail.items[0];
    assert.equal(certificate.sourceCount, 1);
    assert.deepEqual(certificate.sources[0], {
      periodId: p.id,
      managedCertificateId: mc.id,
      source: p.source,
      sourceRef: p.source_ref,
      tokenId: null,
      startedAt: p.started_at,
      endedAt: history.ended_at,
      periodEndedAt: history.ended_at,
      endedReason: "management_source_deleted",
      currentIdentityId: p.current_identity_id,
      renewalProfileId: p.renewal_profile_id,
    });
    assert.equal(certificate.managed, false);
    assert.equal(certificate.tokenId, null);
    assert.equal(certificate.locationCount, 1);
    assert.equal(
      certificate.locations[0].capturedAt.getTime(),
      observed.captured_at.getTime(),
    );
    assert(certificate.sources.every((source) => source.tokenId === null));
    const stopped = await stopManagingSource({
      workspaceId: ws,
      periodId: p.id,
      client: db,
    });
    assert.equal(stopped.endedAt.getTime(), history.ended_at.getTime());
    assert.equal(await countActiveManagedCertificatesWithClient(db, ws), 0);
  });
  it("equal timestamps fail closed, and controller resource versions cannot regress the current fingerprint", async () => {
    const ws = await workspace(),
      captured = time(5),
      plain = await source(ws, A, { observedAt: captured });
    await db.query(
      "UPDATE managed_certificates SET fingerprint_sha256=$2,identity_observed_at=$3 WHERE id=$1",
      [plain.id, B, captured],
    );
    assert.equal(
      (
        await db.query(
          "SELECT fingerprint_sha256 FROM managed_certificates WHERE id=$1",
          [plain.id],
        )
      ).rows[0].fingerprint_sha256,
      A,
    );
    const controller = await source(ws, A, {
      source: "cert_manager",
      observedAt: captured,
    });
    await db.query(
      "UPDATE managed_certificates SET public_metadata=$2::jsonb WHERE id=$1",
      [
        controller.id,
        JSON.stringify({ controllerObservation: { resourceVersion: "100" } }),
      ],
    );
    const update = (fp, version) =>
      db.query(
        "UPDATE managed_certificates SET fingerprint_sha256=$2,identity_observed_at=$3,public_metadata=$4::jsonb WHERE id=$1",
        [
          controller.id,
          fp,
          captured,
          JSON.stringify({
            controllerObservation: { resourceVersion: version },
          }),
        ],
      );
    await update(B, "101");
    await update(B, "98");
    await update(A, "99");
    assert.equal(
      (await period(controller)).current_identity_id,
      (await identity(ws, B)).id,
    );
    assert.equal(
      (
        await db.query(
          "SELECT public_metadata#>>'{controllerObservation,resourceVersion}' version FROM managed_certificates WHERE id=$1",
          [controller.id],
        )
      ).rows[0].version,
      "101",
    );
  });
  it("every direct period opening, including provisional management, passes admission", async () => {
    const ws = await workspace(1),
      mc = await source(ws, null);
    await assert.rejects(source(ws, null), {
      detail: "CERTOPS_MANAGED_CERT_LIMIT",
    });
    await stopManagingSource({
      workspaceId: ws,
      periodId: (await period(mc)).id,
      client: db,
    });
    await source(ws, B);
    await assert.rejects(
      db.query(
        "INSERT INTO certops_management_periods(workspace_id,managed_certificate_id) VALUES($1,$2)",
        [ws, mc.id],
      ),
      { detail: "CERTOPS_MANAGED_CERT_LIMIT" },
    );
    assert.equal(await countActiveManagedCertificatesWithClient(db, ws), 1);
  });
  it("decommission respects fresh serving evidence and proven absence after binding rotation", async () => {
    const ws = await workspace(),
      dm = await endpoint(ws),
      mc = await source(ws, A, {
        source: "endpoint_monitor",
        sourceRef: dm.id,
      });
    const target = (
      await db.query(
        "INSERT INTO certificate_targets(workspace_id,name,target_type) VALUES($1,'TLS service','host') RETURNING id",
        [ws],
      )
    ).rows[0].id;
    await observation(ws, mc, A, time(5), {
      targetId: target,
      domainMonitorId: dm.id,
      source: "endpoint_monitor",
      locationKind: "iis_binding",
    });
    const retire = (acknowledgeUncertainty = false) =>
      retireCertificateIdentity({
        workspaceId: ws,
        identityId: identityA.id,
        expectedFingerprintSha256: A,
        status: "decommissioned",
        reason: "Replacement verified",
        acknowledgeUncertainty,
        client: db,
      });
    const identityA = await identity(ws, A);
    await assert.rejects(retire(true), {
      code: "CERTOPS_CERTIFICATE_STILL_SERVING",
    });
    await db.query(
      "UPDATE managed_certificates SET fingerprint_sha256=$2,identity_observed_at=$3 WHERE id=$1",
      [mc.id, B, time(20)],
    );
    await observation(ws, mc, B, time(20), {
      targetId: target,
      domainMonitorId: dm.id,
      source: "endpoint_monitor",
      locationKind: "iis_binding",
    });
    await db.query(
      "UPDATE certificate_instances SET observed_at=$3 WHERE workspace_id=$1 AND observed_fingerprint_sha256=$2",
      [ws, A, time(10)],
    );
    const old = (
      await db.query(
        "SELECT presence_state FROM certificate_instances WHERE workspace_id=$1 AND observed_fingerprint_sha256=$2",
        [ws, A],
      )
    ).rows;
    assert(old.every((r) => r.presence_state === "confirmed_absent"));
    assert.equal((await retire()).lifecycleStatus, "decommissioned");
    assert.equal((await identity(ws, B)).lifecycle_status, "active");
  });
  it("legacy raw service-binding fingerprints block decommission on the safety read path", async () => {
    const ws = await workspace(),
      dm = await endpoint(ws),
      mc = await source(ws, A, {
        source: "endpoint_monitor",
        sourceRef: dm.id,
      }),
      identityA = await identity(ws, A),
      observed = await observation(ws, mc, A, time(5), {
        source: "endpoint_monitor",
        domainMonitorId: dm.id,
        locationKind: "iis_binding",
      });
    const rawFingerprint = `  ${A.match(/../g).join(":").toUpperCase()}  `;
    const legacy = await db.connect();
    try {
      await legacy.query("BEGIN");
      // Preserve a pre-migration format while leaving every other trigger active.
      await legacy.query(
        "ALTER TABLE certificate_instances DISABLE TRIGGER trg_certops_record_positive_observation",
      );
      await legacy.query(
        "UPDATE certificate_instances SET observed_fingerprint_sha256=$2 WHERE id=$1",
        [observed.id, rawFingerprint],
      );
      await legacy.query(
        "ALTER TABLE certificate_instances ENABLE TRIGGER trg_certops_record_positive_observation",
      );
      await legacy.query("COMMIT");
    } catch (error) {
      await legacy.query("ROLLBACK");
      throw error;
    } finally {
      legacy.release();
    }
    const readObservation = async () =>
      (
        await db.query("SELECT * FROM certificate_instances WHERE id=$1", [
          observed.id,
        ])
      ).rows[0];
    const raw = await readObservation();
    assert.equal(raw.observed_fingerprint_sha256, rawFingerprint);
    assert.equal(raw.presence_state, "confirmed_present");
    assert.equal(raw.evidence_kind, "service_binding");
    assert.equal(raw.captured_at.getTime(), observed.captured_at.getTime());
    assert.equal(
      (
        await db.query(
          "SELECT tgenabled FROM pg_trigger WHERE tgrelid='certificate_instances'::regclass AND tgname='trg_certops_record_positive_observation'",
        )
      ).rows[0].tgenabled,
      "O",
    );
    await assert.rejects(
      retireCertificateIdentity({
        workspaceId: ws,
        identityId: identityA.id,
        expectedFingerprintSha256: A,
        status: "decommissioned",
        reason: "Legacy service still uses this certificate",
        acknowledgeUncertainty: true,
        client: db,
      }),
      { code: "CERTOPS_CERTIFICATE_STILL_SERVING" },
    );
    assert.equal((await identity(ws, A)).lifecycle_status, "active");
    assert.equal(
      (await readObservation()).observed_fingerprint_sha256,
      rawFingerprint,
    );
  });
  for (const jobStatus of ["running", "pending"]) {
    it(`retirement normalizes ${jobStatus} job targets and keeps invalid targets conservative`, async () => {
      for (const targetFingerprint of [
        A.match(/../g).join(":").toUpperCase(),
        "invalid",
        B,
      ]) {
        const ws = await workspace(),
          mc = await source(ws, A),
          identityA = await identity(ws, A),
          mutation = await job(ws, mc, jobStatus, "deploy");
        await db.query(
          "UPDATE certificate_jobs SET payload=$2::jsonb WHERE id=$1",
          [
            mutation.id,
            JSON.stringify({
              targetFingerprintSha256: targetFingerprint,
              canRestoreOriginal: false,
            }),
          ],
        );
        const retire = () =>
          retireCertificateIdentity({
            workspaceId: ws,
            identityId: identityA.id,
            expectedFingerprintSha256: A,
            status: "decommissioned",
            reason: "Check job target identity",
            acknowledgeUncertainty: true,
            client: db,
          });
        if (jobStatus === "running" && targetFingerprint !== B) {
          await assert.rejects(retire(), { code: "CERTOPS_MUTATION_RUNNING" });
          assert.equal((await identity(ws, A)).lifecycle_status, "active");
        } else {
          await retire();
        }
        const expectedStatus =
          jobStatus === "pending" && targetFingerprint !== B
            ? "cancelled"
            : jobStatus;
        assert.equal(
          (
            await db.query("SELECT status FROM certificate_jobs WHERE id=$1", [
              mutation.id,
            ])
          ).rows[0].status,
          expectedStatus,
        );
      }
    });
  }
  for (const unknownSource of ["instance", "unmanaged endpoint", "slot"]) {
    it(`visibility includes an unknown ${unknownSource} beyond the first 20 locations in list and detail`, async () => {
      const ws = await workspace(),
        mc = await source(ws, A),
        identityA = await identity(ws, A);
      for (let n = 0; n < 20; n++) {
        await observation(ws, mc, A, time(n), {
          locationRef: `file:///fresh-${n}.pem`,
        });
      }
      let unknown;
      if (unknownSource === "instance") {
        unknown = await observation(
          ws,
          mc,
          A,
          new Date(Date.now() - 30 * 60000),
          {
            source: "cert_manager",
            locationRef: "file:///stale.pem",
          },
        );
        await db.query(
          "UPDATE certificate_instances SET scan_interval_seconds=60 WHERE id=$1",
          [unknown.id],
        );
      } else if (unknownSource === "unmanaged endpoint") {
        unknown = (
          await db.query(
            `INSERT INTO certops_unmanaged_observations(workspace_id,source_ref,fingerprint_sha256,captured_at)
           VALUES($1,'deleted endpoint',$2,NOW()-INTERVAL '2 minutes') RETURNING id`,
            [ws, A],
          )
        ).rows[0];
      } else {
        unknown = (
          await db.query(
            `INSERT INTO certops_slot_observations(workspace_id,source_ref,fingerprint_sha256,location_ref,captured_at)
           VALUES($1,'stale slot',$2,'file:///stale.pem',NOW()-INTERVAL '2 days') RETURNING id`,
            [ws, A],
          )
        ).rows[0];
      }
      for (const selectedIdentity of [undefined, identityA.id]) {
        const certificate = (
          await listCertificateIdentities({
            workspaceId: ws,
            identityId: selectedIdentity,
            client: db,
          })
        ).items[0];
        assert.equal(certificate.locations.length, 20);
        assert.equal(certificate.locationCount, 21);
        assert(
          certificate.locations.every(
            (location) => location.presenceState === "confirmed_present",
          ),
        );
        assert(
          !certificate.locations.some((location) => location.id === unknown.id),
        );
        assert.equal(certificate.stillObserved, true);
        assert.equal(certificate.visibilityUnknown, true);
      }
    });
  }
  it("groups recreated endpoint monitors before pagination without hiding genuine visibility gaps", async () => {
    const ws = await workspace(),
      mc = await source(ws, A);
    const url = "https://shared.example.test:10443";
    for (let n = 0; n < 25; n++) {
      await observation(ws, mc, A, time(n), {
        source: "endpoint_monitor",
        locationRef: url,
      });
    }
    const monitor = await endpoint(ws);
    const current = await observation(ws, mc, A, time(30), {
      source: "endpoint_monitor",
      locationRef: url,
      domainMonitorId: monitor.id,
    });
    const lost = await observation(ws, mc, A, time(31), {
      source: "endpoint_monitor",
      locationRef: "https://removed.example.test:10443",
    });
    await observation(ws, mc, A, time(32), { locationRef: "file:///same.pem" });
    await observation(ws, mc, A, time(33), { locationRef: "file:///same.pem" });
    const detail = (
      await listCertificateIdentities({ workspaceId: ws, client: db })
    ).items[0];
    assert.equal(detail.locationCount, 4);
    assert.equal(detail.locations.length, 4);
    const endpointLocation = detail.locations.find((l) => l.id === current.id);
    assert.equal(endpointLocation.presenceState, "confirmed_present");
    assert.equal(endpointLocation.previousObservationCount, 25);
    assert.equal(endpointLocation.previousObservations.length, 20);
    assert(
      endpointLocation.previousObservations.every((l) => l.monitoringEnded),
    );
    assert.equal(
      detail.locations.find((l) => l.id === lost.id).observationReason,
      "monitoring_ended",
    );
    assert.equal(detail.visibilityUnknown, true);
    assert.equal(
      (
        await db.query(
          "SELECT COUNT(*)::int n FROM certificate_instances WHERE workspace_id=$1",
          [ws],
        )
      ).rows[0].n,
      29,
    );
    await assert.rejects(
      retireCertificateIdentity({
        workspaceId: ws,
        identityId: detail.identityId,
        expectedFingerprintSha256: A,
        status: "decommissioned",
        reason: "Not in use",
        acknowledgeUncertainty: true,
        client: db,
      }),
      { code: "CERTOPS_CERTIFICATE_STILL_SERVING" },
    );
  });
  it("previous deleted monitors do not make a freshly observed endpoint uncertain", async () => {
    const ws = await workspace(),
      mc = await source(ws, A),
      monitor = await endpoint(ws);
    await observation(ws, mc, A, time(20), {
      source: "endpoint_monitor",
      locationRef: monitor.url,
    });
    await observation(ws, mc, A, time(10), {
      source: "endpoint_monitor",
      locationRef: monitor.url,
      domainMonitorId: monitor.id,
    });
    const certificate = (
      await listCertificateIdentities({ workspaceId: ws, client: db })
    ).items[0];
    assert.equal(certificate.locationCount, 1);
    assert.equal(certificate.visibilityUnknown, false);
    assert.equal(certificate.locations[0].monitoringEnded, false);
    assert.equal(certificate.locations[0].presenceState, "confirmed_present");
  });
  it("visibility is known when all 21 locations are fresh in list and detail", async () => {
    const ws = await workspace(),
      mc = await source(ws, A),
      identityA = await identity(ws, A);
    for (let n = 0; n < 21; n++) {
      await observation(ws, mc, A, time(n), {
        locationRef: `file:///fresh-${n}.pem`,
      });
    }
    for (const selectedIdentity of [undefined, identityA.id]) {
      const certificate = (
        await listCertificateIdentities({
          workspaceId: ws,
          identityId: selectedIdentity,
          client: db,
        })
      ).items[0];
      assert.equal(certificate.locations.length, 20);
      assert.equal(certificate.locationCount, 21);
      assert.equal(certificate.visibilityUnknown, false);
    }
  });
  it("visibility distinguishes no evidence from fresh confirmed absence", async () => {
    const ws = await workspace(),
      mc = await source(ws, A),
      identityA = await identity(ws, A);
    const detail = async () =>
      (
        await listCertificateIdentities({
          workspaceId: ws,
          identityId: identityA.id,
          client: db,
        })
      ).items[0];
    assert.equal((await detail()).visibilityUnknown, true);
    const observed = await observation(ws, mc, A, time(5), {
      source: "cert_manager",
    });
    await db.query(
      "UPDATE certificate_instances SET presence_state='confirmed_absent' WHERE id=$1",
      [observed.id],
    );
    const certificate = await detail();
    assert.equal(certificate.stillObserved, false);
    assert.equal(certificate.locations[0].presenceState, "confirmed_absent");
    assert.equal(certificate.visibilityUnknown, false);
  });
  it("stored-copy uncertainty requires acknowledgment and decommissioned rediscovery stays visible", async () => {
    const ws = await workspace(),
      mc = await source(ws, A),
      identityA = await identity(ws, A);
    await observation(ws, mc, A, time(10));
    const retire = (acknowledgeUncertainty) =>
      retireCertificateIdentity({
        workspaceId: ws,
        identityId: identityA.id,
        expectedFingerprintSha256: A,
        status: "decommissioned",
        reason: "Stored copies reviewed",
        acknowledgeUncertainty,
        client: db,
      });
    await assert.rejects(retire(false), {
      code: "CERTOPS_VISIBILITY_ACK_REQUIRED",
    });
    await retire(true);
    await db.query(
      "UPDATE managed_certificates SET status='discovered',identity_observed_at=$2 WHERE id=$1",
      [mc.id, time(20)],
    );
    await observation(ws, mc, A, time(20));
    const detail = (
      await listCertificateIdentities({
        workspaceId: ws,
        identityId: identityA.id,
        client: db,
      })
    ).items[0];
    assert.equal(detail.lifecycleStatus, "decommissioned");
    assert(detail.stillObserved);
    assert(detail.locationCount >= 1);
  });
  it("late claimed results cannot update a re-added provisioning source or a rotated active source", async () => {
    const {
      reconcileProvisionedCertificate,
      refreshRenewedCertificateEvidence,
    } = require("../../apps/api/services/certops/agentDispatch")._test;
    const ws = await workspace(),
      provisional = await source(ws, null, {
        status: "provisioning",
        source: "agent_issuance",
      });
    const issued = await job(ws, provisional, "claimed", "issue");
    await stopManagingSource({
      workspaceId: ws,
      periodId: (await period(provisional)).id,
      client: db,
    });
    await readdManagingSource({
      workspaceId: ws,
      managedCertificateId: provisional.id,
      renewalProfileId: null,
      automationEnabled: false,
      client: db,
    });
    const active = await source(ws, A, { status: "active" }),
      renewed = await job(ws, active, "claimed");
    await db.query(
      "UPDATE managed_certificates SET fingerprint_sha256=$2,identity_observed_at=$3 WHERE id=$1",
      [active.id, B, time(25)],
    );
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      assert.equal(
        await reconcileProvisionedCertificate({
          client,
          workspaceId: ws,
          job: issued,
        }),
        null,
      );
      assert.equal(
        await refreshRenewedCertificateEvidence({
          client,
          workspaceId: ws,
          job: renewed,
        }),
        null,
      );
      await client.query("COMMIT");
    } finally {
      await client.query("ROLLBACK");
      client.release();
    }
    assert.equal(
      (
        await db.query(
          "SELECT status,token_id,fingerprint_sha256 FROM managed_certificates WHERE id=$1",
          [provisional.id],
        )
      ).rows[0].status,
      "provisioning",
    );
    assert.equal(
      (await period(active)).current_identity_id,
      (await identity(ws, B)).id,
    );
    assert.equal(
      (
        await db.query(
          "SELECT status,needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",
          [issued.id],
        )
      ).rows[0].status,
      "claimed",
    );
    assert.equal(
      (
        await db.query(
          "SELECT COUNT(*)::int n FROM tokens WHERE workspace_id=$1",
          [ws],
        )
      ).rows[0].n,
      0,
    );
  });
  it("filters grouped inventory by Windows observation source", async () => {
    const ws = await workspace();
    const mc = await source(ws, A, { source: "import" });
    const target = (await db.query(`INSERT INTO certificate_targets(workspace_id,name,target_type)
      VALUES($1,'Windows host','host') RETURNING id`, [ws])).rows[0].id;
    await db.query(`INSERT INTO certificate_instances(workspace_id,managed_certificate_id,target_id,source,observed_fingerprint_sha256,observed_at)
      VALUES($1,$2,$3,'agent_windows',$4,NOW())`, [ws, mc.id, target, A]);
    const page = await listCertificateIdentities({ workspaceId: ws, source: "agent_windows", client: db });
    assert.equal(page.pagination.total, 1);
    assert.equal(page.items[0].managedCertificateId, mc.id);
  });

  it("searches every associated managed certificate's public properties", async () => {
    const ws = await workspace();
    const first = await source(ws, A, { name: "primary" });
    const other = await source(ws, A, { name: "secondary" });
    await db.query(`UPDATE managed_certificates SET subject_alt_names=ARRAY['alt.search.test'],
      serial_number='serial-search-123', public_key_algorithm='ecdsa-search',
      public_key_size=384, key_mode='agent-local', key_reference='file://private-topology-marker' WHERE id=$1`, [other.id]);
    for (const q of [first.id, other.id, "alt.search.test", "serial-search-123", "ecdsa-search", "384", "agent-local"]) {
      const page = await listCertificateIdentities({ workspaceId: ws, q, client: db });
      assert.equal(page.pagination.total, 1, q);
      assert.equal(page.items[0].identityId, (await identity(ws, A)).id);
    }
    assert.equal((await listCertificateIdentities({ workspaceId: await workspace(), q: other.id, client: db })).pagination.total, 0);
    assert.equal((await listCertificateIdentities({ workspaceId: ws, q: 'private-topology-marker', client: db })).pagination.total, 0);
    assert.equal((await listCertificateIdentities({ workspaceId: ws, q: 'private-topology-marker', canReadTopology: true, client: db })).pagination.total, 1);
  });

  it("transfers several tokens with managed certificate histories atomically", async () => {
    const { transferTokenAssociations } = require("../../apps/api/services/workspaceTokenTransfer");
    const from = await workspace(), to = await workspace();
    const t1 = await token(from), t2 = await token(from);
    const one = await source(from, A, { tokenId: t1 });
    const two = await source(from, B, { tokenId: t2 });
    const j1 = await job(from, one, "succeeded"), j2 = await job(from, two);
    const issuer = (await db.query(`INSERT INTO certificate_issuers(workspace_id,kind,name) VALUES($1,'adcs','Transfer CA') RETURNING id`, [from])).rows[0].id;
    const enrollment = (await db.query(`INSERT INTO certificate_enrollments(workspace_id,certificate_id,issuer_id,issuer_version,state,snapshot_bytes,snapshot_sha256,deploy_target,current_job_id)
      VALUES($1,$2,$3,1,'installed','snapshot',$4,'{}',$5) RETURNING id`, [from,one.id,issuer,A,j1.id])).rows[0].id;
    await db.query("UPDATE certificate_jobs SET enrollment_id=$1 WHERE id=$2", [enrollment,j1.id]);
    for (const j of [j1, j2]) {
      await db.query(`INSERT INTO certops_agent_log_job_state(workspace_id,job_id,next_ingest_order) VALUES($1,$2,7)`, [from, j.id]);
      const claim = randomUUID();
      await db.query(`INSERT INTO certops_agent_log_stream(workspace_id,job_id,claim_id,agent_id,attempt_number,status)
        VALUES($1,$2,$3,$4,1,'final')`, [from, j.id, claim, randomUUID()]);
      await db.query(`INSERT INTO certops_agent_job_log(workspace_id,job_id,claim_id,seq,ts,level,step,message,fields,content_hash,ingest_order)
        VALUES($1,$2,$3,1,NOW(),'info','verify','Certificate verified','{"result":"verified"}',$4,7)`, [from,j.id,claim,A]);
    }
    const c = await db.connect();
    try {
      await c.query("BEGIN");
      const result = await transferTokenAssociations(c, { tokenIds: [t1,t2], fromWorkspaceId: from, toWorkspaceId: to, targetOwnerId: userId });
      assert.equal(result.movedCertificates, 2);
      await c.query("COMMIT");
    } finally { await c.query("ROLLBACK"); c.release(); }
    assert.equal((await listCertificateIdentities({ workspaceId: to, client: db })).pagination.total, 2);
    assert.equal((await db.query("SELECT COUNT(*)::int n FROM tokens WHERE workspace_id=$1", [to])).rows[0].n, 2);
    assert.equal((await db.query("SELECT COUNT(*)::int n FROM certops_agent_log_stream WHERE workspace_id=$1", [to])).rows[0].n, 2);
    assert.equal((await db.query("SELECT SUM(next_ingest_order)::int n FROM certops_agent_log_job_state WHERE workspace_id=$1", [to])).rows[0].n, 14);
    const logs = (await db.query("SELECT message,fields,ingest_order FROM certops_agent_job_log WHERE workspace_id=$1", [to])).rows;
    assert.equal(logs.length, 2);
    assert(logs.every(row => row.message === "Certificate verified" && row.fields.result === "verified" && Number(row.ingest_order) === 7));
    assert.equal((await db.query("SELECT enrollment_id FROM certificate_jobs WHERE id=$1", [j1.id])).rows[0].enrollment_id, null);
    assert.equal((await db.query("SELECT workspace_id FROM certificate_enrollments WHERE id=$1", [enrollment])).rows[0].workspace_id, from);
  });

  it("refuses transfer during an active AD CS enrollment without moving any token", async () => {
    const { transferTokenAssociations } = require("../../apps/api/services/workspaceTokenTransfer");
    const from = await workspace(), to = await workspace(), tid = await token(from);
    const mc = await source(from, A, { tokenId: tid });
    const issuer = (await db.query(`INSERT INTO certificate_issuers(workspace_id,kind,name) VALUES($1,'adcs','Pending CA') RETURNING id`, [from])).rows[0].id;
    const enrollment = (await db.query(`INSERT INTO certificate_enrollments(workspace_id,certificate_id,issuer_id,issuer_version,state,snapshot_bytes,snapshot_sha256,deploy_target)
      VALUES($1,$2,$3,1,'pending_issuance','snapshot',$4,'{}') RETURNING id`, [from,mc.id,issuer,A])).rows[0].id;
    const c = await db.connect();
    try {
      await c.query("BEGIN");
      await assert.rejects(transferTokenAssociations(c, { tokenIds: [tid], fromWorkspaceId: from, toWorkspaceId: to }),
        error => error.code === 'TRANSFER_CONFLICT' && error.details[0].enrollment_id === enrollment);
      await c.query("ROLLBACK");
    } finally { await c.query("ROLLBACK"); c.release(); }
    assert.equal((await db.query("SELECT workspace_id FROM tokens WHERE id=$1", [tid])).rows[0].workspace_id, from);
  });

  it("workspace transfers deduplicate independently, retain closed provenance and admit destination management", async () => {
    const from = await workspace(),
      to = await workspace(1),
      mc = await source(from, A);
    const identityA = await identity(from, A);
    await retireCertificateIdentity({
      workspaceId: from,
      identityId: identityA.id,
      expectedFingerprintSha256: A,
      status: "revoked",
      reason: "Old fingerprint",
      client: db,
    });
    await db.query(
      "UPDATE managed_certificates SET fingerprint_sha256=$2,identity_observed_at=$3 WHERE id=$1",
      [mc.id, B, time(25)],
    );
    await source(to, B);
    const original = await period(mc),
      pending = await job(from, mc);
    await db.query(
      "SELECT certops_transfer_management_sources($1,$2,$3::uuid[])",
      [from, to, [mc.id]],
    );
    assert.equal(
      (
        await db.query(
          "SELECT workspace_id FROM managed_certificates WHERE id=$1",
          [mc.id],
        )
      ).rows[0].workspace_id,
      to,
    );
    assert(
      (
        await db.query(
          "SELECT ended_at FROM certops_management_periods WHERE id=$1",
          [original.id],
        )
      ).rows[0].ended_at,
    );
    assert.equal((await identity(from, A)).lifecycle_status, "revoked");
    assert.equal((await identity(to, A)).lifecycle_status, "revoked");
    assert.equal((await identity(to, B)).lifecycle_status, "active");
    assert.equal(await countActiveManagedCertificatesWithClient(db, to), 1);
    assert.equal(
      (
        await db.query(
          "SELECT workspace_id,status FROM certificate_jobs WHERE id=$1",
          [pending.id],
        )
      ).rows[0].workspace_id,
      to,
    );
    const detail = (
      await listCertificateIdentities({
        workspaceId: from,
        identityId: (await identity(from, B)).id,
        client: db,
      })
    ).items[0];
    assert.equal(detail.managed, false);
    assert.equal(detail.tokenId, null);
    assert.equal(detail.keyReference, null);
    assert(detail.sources.length);
    await db.query("DELETE FROM workspaces WHERE id=$1", [from]);
    assert(await identity(to, B));
    await db.query("DELETE FROM workspaces WHERE id=$1", [to]);
  });
  it("workspace transfer preserves source snapshots without hydrating destination token or source data", async () => {
    const from = await workspace(),
      to = await workspace(1),
      tid = await token(from),
      mc = await source(from, A, { tokenId: tid }),
      original = await period(mc),
      identityA = await identity(from, A);
    await source(to, A);
    const before = (
      await listCertificateIdentities({
        workspaceId: from,
        identityId: identityA.id,
        client: db,
      })
    ).items[0];
    assert.equal(before.sources[0].tokenId, tid);
    await db.query(
      "SELECT certops_transfer_management_sources($1,$2,$3::uuid[])",
      [from, to, [mc.id]],
    );
    await db.query("UPDATE tokens SET workspace_id=$2 WHERE id=$1", [tid, to]);
    const destinationRef = `destination-${randomUUID()}`;
    await db.query(
      "UPDATE managed_certificates SET source_ref=$2,name=$2 WHERE id=$1",
      [mc.id, destinationRef],
    );
    for (const selectedIdentity of [undefined, identityA.id]) {
      const certificate = (
        await listCertificateIdentities({
          workspaceId: from,
          identityId: selectedIdentity,
          client: db,
        })
      ).items[0];
      assert.equal(certificate.sourceCount, 1);
      assert.equal(certificate.managed, false);
      assert.equal(certificate.tokenId, null);
      assert.equal(certificate.sources[0].periodId, original.id);
      assert.equal(certificate.sources[0].managedCertificateId, mc.id);
      assert.equal(certificate.sources[0].source, original.source);
      assert.equal(certificate.sources[0].sourceRef, original.source_ref);
      assert.equal(certificate.sources[0].tokenId, null);
      assert.equal(certificate.sources[0].currentIdentityId, identityA.id);
      assert.equal(certificate.sources[0].endedReason, "workspace_transfer");
      assert(certificate.sources[0].endedAt);
      assert(certificate.sources.every((source) => source.tokenId === null));
      assert(!JSON.stringify(certificate).includes(destinationRef));
    }
    const destinationIdentity = await identity(to, A);
    const destination = (
      await listCertificateIdentities({
        workspaceId: to,
        identityId: destinationIdentity.id,
        client: db,
      })
    ).items[0];
    assert.equal(destination.managed, true);
    assert.equal(destination.tokenId, tid);
    assert.equal(destination.activeSourceCount, 2);
    const currentSource = destination.sources.find(
      (source) => source.managedCertificateId === mc.id && !source.endedAt,
    );
    assert(currentSource);
    assert.equal(currentSource.tokenId, tid);
    assert.equal(currentSource.currentIdentityId, destinationIdentity.id);
    assert.notEqual(currentSource.periodId, original.id);
    assert.equal(await countActiveManagedCertificatesWithClient(db, to), 1);
    assert.equal(
      (await db.query("SELECT workspace_id FROM tokens WHERE id=$1", [tid]))
        .rows[0].workspace_id,
      to,
    );
    const stopped = await stopManagingSource({
      workspaceId: from,
      periodId: original.id,
      client: db,
    });
    assert(stopped.endedAt);
    assert.equal(stopped.runningJobs, 0);
  });
  it("workspace transfer rolls back completely on quota denial or in-flight work", async () => {
    const from = await workspace(),
      to = await workspace(0),
      mc = await source(from, A),
      original = await period(mc);
    await assert.rejects(
      db.query("SELECT certops_transfer_management_sources($1,$2,$3::uuid[])", [
        from,
        to,
        [mc.id],
      ]),
      { detail: "CERTOPS_MANAGED_CERT_LIMIT" },
    );
    assert.equal((await period(mc)).ended_at, null);
    assert.equal(
      (
        await db.query(
          "SELECT workspace_id FROM managed_certificates WHERE id=$1",
          [mc.id],
        )
      ).rows[0].workspace_id,
      from,
    );
    await job(from, mc, "claimed");
    await assert.rejects(
      db.query("SELECT certops_transfer_management_sources($1,$2,$3::uuid[])", [
        from,
        to,
        [mc.id],
      ]),
      { code: "55000" },
    );
    assert.equal((await period(mc)).id, original.id);
  });
  it("source detail retains every historical period beyond the list summary limit", async () => {
    const ws = await workspace(),
      mc = await source(ws, A);
    for (let n = 0; n < 22; n++) {
      await stopManagingSource({
        workspaceId: ws,
        periodId: (await period(mc)).id,
        client: db,
      });
      await readdManagingSource({
        workspaceId: ws,
        managedCertificateId: mc.id,
        renewalProfileId: null,
        automationEnabled: false,
        client: db,
      });
    }
    const list = (
      await listCertificateIdentities({ workspaceId: ws, client: db })
    ).items[0];
    const detail = (
      await listCertificateIdentities({
        workspaceId: ws,
        identityId: (await identity(ws, A)).id,
        client: db,
      })
    ).items[0];
    assert.equal(list.sources.length, 20);
    assert.equal(list.sourceCount, 23);
    assert.equal(list.activeSourceCount, 1);
    assert.equal(detail.sources.length, 23);
  });
  it("identity and legacy retirement helpers preserve a caller-owned PostgreSQL transaction", async () => {
    const {
      retireManagedCertificate,
    } = require("../../apps/api/services/certops/inventory");
    const ws = await workspace(),
      mc = await source(ws, A),
      identityA = await identity(ws, A);
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      const result = await retireManagedCertificate(client, {
        workspaceId: ws,
        certificateId: mc.id,
        status: "revoked",
        reason: "Uncommitted retirement",
      });
      assert.equal(result.lifecycleStatus, "revoked");
      assert.equal(
        (
          await client.query(
            "SELECT lifecycle_status FROM certops_certificate_identities WHERE id=$1",
            [identityA.id],
          )
        ).rows[0].lifecycle_status,
        "revoked",
      );
      assert.equal((await identity(ws, A)).lifecycle_status, "active");
      await client.query("ROLLBACK");
      assert.equal((await identity(ws, A)).lifecycle_status, "active");
      await client.query("BEGIN");
      await stopManagingSource({
        workspaceId: ws,
        periodId: (await period(mc)).id,
        client,
      });
      await readdManagingSource({
        workspaceId: ws,
        managedCertificateId: mc.id,
        renewalProfileId: null,
        automationEnabled: false,
        client,
      });
      await client.query("ROLLBACK");
      assert.equal(
        (
          await db.query(
            "SELECT COUNT(*)::int n FROM certops_management_periods WHERE managed_certificate_id=$1",
            [mc.id],
          )
        ).rows[0].n,
        1,
      );
      assert.equal((await period(mc)).ended_at, null);
    } finally {
      await client.query("ROLLBACK");
      client.release();
    }
  });
  it("fingerprint-only instance changes create normalized identities without moving management", async () => {
    const ws = await workspace(),
      mc = await source(ws, A);
    const observed = await observation(ws, mc, A, time(5));
    const newer = time(15);
    await db.query(
      "UPDATE certificate_instances SET observed_at=$2 WHERE id=$1",
      [observed.id, newer],
    );
    const slots = await db.query(
      "SELECT captured_at FROM certops_slot_observations WHERE workspace_id=$1 AND fingerprint_sha256=$2",
      [ws, A],
    );
    assert.equal(slots.rowCount, 1);
    assert.equal(
      new Date(slots.rows[0].captured_at).toISOString(),
      newer.toISOString(),
    );
    assert.equal(await identity(ws, B), undefined);
    const updated = await db.query(
      "UPDATE certificate_instances SET observed_fingerprint_sha256=$2 WHERE id=$1 RETURNING observed_fingerprint_sha256",
      [observed.id, ` ${B.toUpperCase().match(/../g).join(":")} `],
    );
    assert.equal(updated.rows[0].observed_fingerprint_sha256, B);
    assert.equal((await identity(ws, B)).lifecycle_status, "active");
    assert.equal(
      (await period(mc)).current_identity_id,
      (await identity(ws, A)).id,
    );
  });
  it("v63 reruns after workspace erasure without attributing orphaned audit fingerprints", async () => {
    await db.query(
      "INSERT INTO audit_events(action,metadata) VALUES('CERTOPS_CERTIFICATE_RETIRED',$1::jsonb)",
      [
        JSON.stringify({
          fingerprintSha256: "f4".repeat(32),
          status: "revoked",
        }),
      ],
    );
    const beforeCount = (
      await db.query(
        "SELECT COUNT(*)::int n FROM certops_certificate_identities",
      )
    ).rows[0].n;
    await db.query(migrations.find((m) => m.version === 63).sql);
    await db.query(migrations.find((m) => m.version === 64).sql);
    await db.query(migrations.find((m) => m.version === 65).sql);
    assert.equal(
      (
        await db.query(
          "SELECT COUNT(*)::int n FROM certops_certificate_identities",
        )
      ).rows[0].n,
      beforeCount,
    );
  });
});
