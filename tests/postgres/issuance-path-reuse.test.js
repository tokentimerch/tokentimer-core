"use strict";

// Dedicated migrated PostgreSQL only. A first ACME order that never produced a
// certificate must not reserve its certificate path forever.
const { before, beforeEach, after, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.match(process.env.DB_NAME || "", /^pr329_.*_test$/);
assert.equal(process.env.NODE_ENV, "test");
const { pool } = require("../../apps/api/db/database");
const {
  createCertificateIssuanceJob,
} = require("../../apps/api/services/certops/issuance");

const hex = (bytes) => crypto.randomBytes(bytes).toString("hex");
let userId, workspaceId, agentId;

async function createOnClient(client, idempotencyKey, certPath, overrides = {}) {
  return createCertificateIssuanceJob({
    workspaceId,
    idempotencyKey,
    assignedAgentId: agentId,
    requestedByUserId: userId,
    mode: "real",
    payload: {
      target: { type: "domain", reference: "path-reuse.example.com" },
      certPath,
      caEndpoint: "https://acme-staging-v02.api.letsencrypt.org/directory",
      commandRef: "certbot-dns-cloudflare",
      dnsProvider: "cloudflare",
      dnsZone: "example.com",
    },
    ...overrides,
    client,
  });
}

async function issue(idempotencyKey, certPath, overrides = {}) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const outcome = await createOnClient(client, idempotencyKey, certPath, overrides);
    await client.query("COMMIT");
    return outcome;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function setJobStatus(jobId, status) {
  await pool.query(
    "UPDATE certificate_jobs SET status=$2, updated_at=NOW() WHERE id=$1",
    [jobId, status],
  );
}

async function certificate(id) {
  return (
    await pool.query("SELECT * FROM managed_certificates WHERE id=$1", [id])
  ).rows[0];
}

describe(
  "Issuance certificate path reuse (real PostgreSQL)",
  { concurrency: false },
  () => {
    before(async () => {
      userId = (
        await pool.query(
          `INSERT INTO users(email,display_name,email_verified,password_hash)
           VALUES($1,'Path reuse test',TRUE,'synthetic-fixture') RETURNING id`,
          [`path-reuse-${crypto.randomUUID()}@example.test`],
        )
      ).rows[0].id;
    });
    // A fresh workspace isolates the real per-CA capacity quota for each case.
    beforeEach(async () => {
      workspaceId = crypto.randomUUID();
      await pool.query(
        "INSERT INTO workspaces(id,name,created_by) VALUES($1,'Path reuse',$2)",
        [workspaceId, userId],
      );
      agentId = (
        await pool.query(
          `INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash)
           VALUES($1,$2,'1.0.0','1.0.0',$3,$4) RETURNING id`,
          [workspaceId, `agent-${hex(4)}`, `ttagent_${hex(8)}`, hex(32)],
        )
      ).rows[0].id;
    });
    after(async () => {
      await pool.end();
    });

    it("lets a retry reuse the path after the first order failed", async () => {
      const certPath = `/etc/ssl/tokentimer/${hex(4)}.pem`;
      const first = await issue(`first-${hex(4)}`, certPath);
      assert.equal(
        (await certificate(first.job.subjectId)).status,
        "provisioning",
      );
      await setJobStatus(first.job.id, "failed");

      const retryKey = `retry-${hex(4)}`;
      const retry = await issue(retryKey, certPath);
      assert.equal(retry.created, true);
      assert.equal(
        retry.job.subjectId,
        first.job.subjectId,
        "the abandoned identity is reused, not duplicated",
      );
      const replay = await issue(retryKey, certPath);
      assert.equal(replay.created, false);
      assert.equal(replay.job.id, retry.job.id);
      const rows = await pool.query(
        "SELECT count(*)::int AS n FROM managed_certificates WHERE workspace_id=$1 AND deployed_cert_path=$2",
        [workspaceId, certPath],
      );
      assert.equal(rows.rows[0].n, 1);
    });

    for (const winnerAction of ["COMMIT", "ROLLBACK"]) {
      it(`rechecks path ownership after the blocking retry ${winnerAction.toLowerCase()}s`, { timeout: 15000 }, async () => {
        const certPath = `/etc/ssl/tokentimer/${hex(4)}.pem`;
        const first = await issue(`abandoned-${hex(4)}`, certPath);
        await setJobStatus(first.job.id, "failed");
        const winner = await pool.connect();
        const contender = await pool.connect();
        let pending;
        try {
          await winner.query("BEGIN");
          await contender.query("BEGIN");
          await contender.query("SET LOCAL statement_timeout = '8s'");
          const winnerPid = (await winner.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
          const contenderPid = (await contender.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
          const winnerKey = `winner-${hex(4)}`;
          const contenderKey = `contender-${hex(4)}`;
          const retry = await createOnClient(winner, winnerKey, certPath);
          // Hold an actual uncommitted retry while a second connection takes
          // its statement snapshot and waits for this transaction in PostgreSQL.
          pending = createOnClient(contender, contenderKey, certPath)
            .then(value => ({ value }), error => ({ error }));
          let blocked = false;
          const deadline = Date.now() + 5000;
          while (Date.now() < deadline) {
            const { rows } = await pool.query(
              "SELECT $1::int = ANY(pg_blocking_pids($2::int)) AS blocked",
              [winnerPid, contenderPid],
            );
            if (rows[0].blocked) { blocked = true; break; }
            await new Promise(resolve => setTimeout(resolve, 10));
          }
          assert.equal(blocked, true, "contender must really wait on the winner's transaction");
          await winner.query(winnerAction);
          const result = await pending;
          let admitted;
          let admittedKey;
          if (winnerAction === "COMMIT") {
            assert.equal(result.error?.code, "CERTOPS_CERTIFICATE_PATH_IN_USE",
              "a fresh post-lock read must see the newly committed issue job");
            await contender.query("ROLLBACK");
            admitted = retry;
            admittedKey = winnerKey;
          } else {
            assert.ifError(result.error);
            assert.equal(result.value.created, true, "a rolled-back retry must not reserve the path");
            await contender.query("COMMIT");
            admitted = result.value;
            admittedKey = contenderKey;
          }
          assert.equal(admitted.job.subjectId, first.job.subjectId);
          const { rows } = await pool.query(
            "SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND status='pending'",
            [workspaceId, first.job.subjectId],
          );
          assert.deepEqual(rows.map(row => row.id), [admitted.job.id]);
          assert.equal((await certificate(first.job.subjectId)).source_ref, admittedKey);
          const replay = await issue(admittedKey, certPath);
          assert.equal(replay.created, false);
          assert.equal(replay.job.id, admitted.job.id);
        } finally {
          // Releasing the first transaction unblocks cleanup even if the
          // barrier/assertion fails. The contender statement also has a deadline.
          await winner.query("ROLLBACK");
          if (pending) await pending;
          await contender.query("ROLLBACK");
          winner.release();
          contender.release();
        }
      });
    }

    it("still replays the original request for the same idempotency key", async () => {
      const certPath = `/etc/ssl/tokentimer/${hex(4)}.pem`;
      const key = `replay-${hex(4)}`;
      const first = await issue(key, certPath);
      const replay = await issue(key, certPath);
      assert.equal(replay.created, false);
      assert.equal(replay.job.id, first.job.id);
    });

    for (const status of ["pending", "running", "succeeded"]) {
      it(`refuses the path with a plain error while the first order is ${status}`, async () => {
        const certPath = `/etc/ssl/tokentimer/${hex(4)}.pem`;
        const first = await issue(`busy-${hex(4)}`, certPath);
        await setJobStatus(first.job.id, status);
        await assert.rejects(
          () => issue(`other-${hex(4)}`, certPath),
          (error) => {
            assert.equal(error.code, "CERTOPS_CERTIFICATE_PATH_IN_USE");
            assert.match(error.message, /already uses this certificate path/);
            assert.match(error.message, /retire|different/i);
            return true;
          },
        );
      });
    }

    it("refuses the path once the first order produced a certificate", async () => {
      const certPath = `/etc/ssl/tokentimer/${hex(4)}.pem`;
      const first = await issue(`issued-${hex(4)}`, certPath);
      await setJobStatus(first.job.id, "failed");
      await pool.query(
        "UPDATE managed_certificates SET fingerprint_sha256=$2 WHERE id=$1",
        [first.job.subjectId, hex(32)],
      );
      await assert.rejects(
        () => issue(`later-${hex(4)}`, certPath),
        (error) => error.code === "CERTOPS_CERTIFICATE_PATH_IN_USE",
      );
    });

    it("admits only one of two concurrent abandoned-path reuses", async () => {
      const certPath = `/etc/ssl/tokentimer/${hex(4)}.pem`;
      const abandoned = await issue(`abandoned-${hex(4)}`, certPath);
      await setJobStatus(abandoned.job.id, "failed");

      const keyA = `contend-a-${hex(4)}`;
      const keyB = `contend-b-${hex(4)}`;
      // Each issue() takes its own pool connection and transaction.
      const results = await Promise.allSettled([
        issue(keyA, certPath),
        issue(keyB, certPath),
      ]);
      const fulfilled = results.filter((result) => result.status === "fulfilled");
      const rejected = results.filter((result) => result.status === "rejected");
      assert.equal(fulfilled.length, 1, "exactly one admission must win");
      assert.equal(rejected.length, 1, "the loser must conflict");
      assert.equal(
        rejected[0].reason.code,
        "CERTOPS_CERTIFICATE_PATH_IN_USE",
      );

      const winner = fulfilled[0].value;
      assert.equal(winner.created, true);
      assert.equal(
        winner.job.subjectId,
        abandoned.job.subjectId,
        "the abandoned identity is reused, not duplicated",
      );
      const winnerKey =
        results[0].status === "fulfilled" ? keyA : keyB;
      const replay = await issue(winnerKey, certPath);
      assert.equal(replay.created, false);
      assert.equal(replay.job.id, winner.job.id);

      const rows = await pool.query(
        "SELECT count(*)::int AS n FROM managed_certificates WHERE workspace_id=$1 AND deployed_cert_path=$2",
        [workspaceId, certPath],
      );
      assert.equal(rows.rows[0].n, 1);
    });
  },
);
