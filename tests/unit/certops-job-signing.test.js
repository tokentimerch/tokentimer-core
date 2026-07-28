"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");

const {
  CERTOPS_SIGNING_ENCRYPTION_KEY_MISSING,
  CERTOPS_SIGNING_KEY_UNAVAILABLE,
  CERTOPS_SIGNING_PAYLOAD_INVALID,
  CERTOPS_NONCE_REPLAYED,
  CERTOPS_NONCE_UNKNOWN_OR_EXPIRED,
  DEFAULT_NONCE_TTL_SECONDS,
  ensureActiveSigningKey,
  getActiveSigningKeyPublicInfo,
  beginSigningKeyRotation,
  completeSigningKeyRotation,
  getSigningKeyRotationStatus,
  signJobForDispatch,
  consumeNonce,
  extendJobNonceExpiry,
  sweepExpiredNonces,
  _test,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/jobSigning.js"),
);

// The agent-side verifier: the interop tests below prove that what the
// control plane signs, the agent accepts (and tampering is rejected).
const {
  verifyJobSignature,
} = require(
  path.resolve(__dirname, "../../packages/agent/src/signing/index.js"),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";
const VALID_ENV_KEY = "a".repeat(64);

function baseJob(overrides = {}) {
  return {
    schemaVersion: 1,
    jobId: "job-0001",
    workspaceId: WORKSPACE_A,
    certificateId: "cert-0001",
    action: "renew",
    target: { type: "domain", reference: "example.com" },
    keyMode: "agent-local",
    requestedAt: "2026-07-21T00:00:00.000Z",
    ...overrides,
  };
}

/**
 * Minimal in-memory stand-in for the pg client, covering exactly the queries
 * jobSigning.js issues against certops_signing_keys and
 * certops_consumed_nonces.
 */
function createMemoryClient() {
  const signingKeyRows = [];
  const nonceRows = [];
  let nextId = 1;

  const client = {
    signingKeyRows,
    nonceRows,
    queries: [],
    // Simulates losing the single-active race under ON CONFLICT DO NOTHING:
    // the insert is silently skipped (no error, no returned row) and the
    // winner's row becomes visible to the follow-up re-select.
    skipNextInsertAsConflict: false,
    conflictWinnerRow: null,
    // Rotation fixtures: fleet size and per-signing-key acknowledgements
    // drive the completeSigningKeyRotation gate.
    activeAgents: 0,
    acks: new Map(),
    async query(sql, params = []) {
      const normalizedSql = sql.replace(/\s+/g, " ").trim();
      client.queries.push({ sql: normalizedSql, params });

      if (
        normalizedSql.includes("FROM certops_signing_keys") &&
        normalizedSql.includes("WHERE status = 'active'")
      ) {
        return {
          rows: signingKeyRows.filter((row) => row.status === "active"),
        };
      }

      if (normalizedSql.includes("INSERT INTO certops_signing_keys")) {
        if (client.skipNextInsertAsConflict) {
          client.skipNextInsertAsConflict = false;
          if (client.conflictWinnerRow) {
            signingKeyRows.push(client.conflictWinnerRow);
          }
          return { rows: [] };
        }
        const row = {
          id: `key-${nextId++}`,
          signing_key_id: params[0],
          public_key_pem: params[1],
          private_key_encrypted: params[2],
          encryption_version: params[3],
          status: "active",
          // Only the rotation insert passes a 5th param.
          supersedes_signing_key_id: params[4] || null,
          rotation_started_at: params[4] ? new Date() : null,
        };
        signingKeyRows.push(row);
        return {
          rows: [
            {
              id: row.id,
              signing_key_id: row.signing_key_id,
              public_key_pem: row.public_key_pem,
            },
          ],
        };
      }

      if (
        normalizedSql.includes("FROM certops_signing_keys") &&
        normalizedSql.includes("WHERE status = 'retiring'")
      ) {
        return {
          rows: signingKeyRows.filter((row) => row.status === "retiring"),
        };
      }

      if (
        normalizedSql.includes("UPDATE certops_signing_keys") &&
        normalizedSql.includes("SET status = 'retiring'")
      ) {
        const row = signingKeyRows.find(
          (item) => item.id === params[0] && item.status === "active",
        );
        if (row) {
          row.status = "retiring";
          row.rotation_started_at = row.rotation_started_at || new Date();
        }
        return { rowCount: row ? 1 : 0, rows: [] };
      }

      if (
        normalizedSql.includes("UPDATE certops_signing_keys") &&
        normalizedSql.includes("SET status = 'retired'")
      ) {
        const row = signingKeyRows.find(
          (item) => item.id === params[0] && item.status === "retiring",
        );
        if (row) {
          row.status = "retired";
          row.retired_at = new Date();
          if (params[1] === true) {
            row.rotation_forced_at = new Date();
            row.rotation_force_reason = params[2];
          }
        }
        return { rowCount: row ? 1 : 0, rows: [] };
      }

      if (normalizedSql.includes("FROM certops_agents")) {
        return { rows: [{ active_agents: client.activeAgents }] };
      }

      if (normalizedSql.includes("FROM certops_signing_key_acks")) {
        const acked = client.acks.get(params[0]);
        return { rows: [{ ack_count: acked ? acked.size : 0 }] };
      }

      if (normalizedSql.includes("INSERT INTO certops_consumed_nonces")) {
        const row = {
          nonce: params[0],
          job_id: params[1],
          workspace_id: params[2],
          issued_to_agent_id: params[3],
          expires_at: new Date(params[4]),
          consumed_at: null,
        };
        nonceRows.push(row);
        return { rows: [] };
      }

      if (
        normalizedSql.includes("UPDATE certops_consumed_nonces") &&
        normalizedSql.includes("SET consumed_at = NOW()")
      ) {
        const row = nonceRows.find(
          (item) =>
            item.nonce === params[0] &&
            item.job_id === params[1] &&
            item.consumed_at === null &&
            item.expires_at.getTime() > Date.now(),
        );
        if (!row) return { rows: [] };
        row.consumed_at = new Date();
        return { rows: [{ nonce: row.nonce }] };
      }

      if (
        normalizedSql.includes("UPDATE certops_consumed_nonces") &&
        normalizedSql.includes("SET expires_at = NOW()")
      ) {
        const jobId = params[0];
        const workspaceId = params[1];
        const agentRowId = params[2];
        const ttlSeconds = params[3];
        const matches = nonceRows.filter(
          (item) =>
            item.job_id === jobId &&
            item.workspace_id === workspaceId &&
            item.consumed_at === null &&
            (agentRowId == null ||
              item.issued_to_agent_id == null ||
              item.issued_to_agent_id === agentRowId),
        );
        const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
        for (const row of matches) {
          row.expires_at = expiresAt;
        }
        return {
          rows: matches.length ? [{ expires_at: expiresAt }] : [],
        };
      }

      if (
        normalizedSql.includes("SELECT consumed_at") &&
        normalizedSql.includes("FROM certops_consumed_nonces")
      ) {
        const row = nonceRows.find(
          (item) => item.nonce === params[0] && item.job_id === params[1],
        );
        return { rows: row ? [{ consumed_at: row.consumed_at }] : [] };
      }

      if (normalizedSql.includes("DELETE FROM certops_consumed_nonces")) {
        const cutoffMs = Date.now() - _test.SWEEP_GRACE_SECONDS * 1000;
        const limit = params[0];
        const doomed = nonceRows
          .filter((item) => item.expires_at.getTime() < cutoffMs)
          .slice(0, limit);
        for (const row of doomed) {
          nonceRows.splice(nonceRows.indexOf(row), 1);
        }
        return { rowCount: doomed.length, rows: [] };
      }

      throw new Error(`memory client: unhandled query: ${normalizedSql}`);
    },
  };

  return client;
}

describe("certops job signing service", () => {
  let savedEnvKey;

  beforeEach(() => {
    savedEnvKey = process.env[_test.ENV_KEY_NAME];
    process.env[_test.ENV_KEY_NAME] = VALID_ENV_KEY;
  });

  afterEach(() => {
    if (savedEnvKey === undefined) {
      delete process.env[_test.ENV_KEY_NAME];
    } else {
      process.env[_test.ENV_KEY_NAME] = savedEnvKey;
    }
  });

  describe("encryption envelope", () => {
    it("fails closed when the env encryption key is missing", () => {
      delete process.env[_test.ENV_KEY_NAME];
      assert.throws(
        () => _test.getEncryptionKey(),
        (err) => err.code === CERTOPS_SIGNING_ENCRYPTION_KEY_MISSING,
      );
    });

    it("fails closed when the env encryption key is malformed", () => {
      process.env[_test.ENV_KEY_NAME] = "not-hex";
      assert.throws(
        () => _test.getEncryptionKey(),
        (err) => err.code === CERTOPS_SIGNING_ENCRYPTION_KEY_MISSING,
      );
    });

    it("round-trips a PEM through the AES-256-GCM envelope", () => {
      const pem = "-----BEGIN PRIVATE KEY-----\nRkFLRQ==\n-----END PRIVATE KEY-----\n";
      const envelope = _test.encryptPrivateKeyPem(pem);
      assert.match(envelope, /^[a-f0-9]+:[a-f0-9]+:[a-f0-9]+$/);
      assert.ok(!envelope.includes("PRIVATE KEY"));
      assert.equal(
        _test.decryptPrivateKeyPem(envelope, _test.ENCRYPTION_VERSION),
        pem,
      );
    });

    it("rejects a wrong wrap key without echoing key material", () => {
      const pem = "-----BEGIN PRIVATE KEY-----\nRkFLRQ==\n-----END PRIVATE KEY-----\n";
      const envelope = _test.encryptPrivateKeyPem(pem);
      process.env[_test.ENV_KEY_NAME] = "b".repeat(64);
      assert.throws(
        () => _test.decryptPrivateKeyPem(envelope, _test.ENCRYPTION_VERSION),
        (err) =>
          err.code === CERTOPS_SIGNING_KEY_UNAVAILABLE &&
          !err.message.includes("RkFLRQ"),
      );
    });

    it("rejects an unsupported encryption version", () => {
      assert.throws(
        () => _test.decryptPrivateKeyPem("aa:bb:cc", 99),
        (err) => err.code === CERTOPS_SIGNING_KEY_UNAVAILABLE,
      );
    });
  });

  describe("rotation lifecycle (H3)", () => {
    it("reports no rotation in progress for a single active key", async () => {
      const client = createMemoryClient();
      const active = await ensureActiveSigningKey({ client });

      const status = await getSigningKeyRotationStatus({ client });
      assert.equal(status.active.signingKeyId, active.signingKeyId);
      assert.equal(status.retiring, null);
      assert.equal(status.rotationInProgress, false);
      // An empty fleet counts as fully acknowledged so a fresh deployment
      // is never blocked from completing a rotation.
      assert.equal(status.fullyAcked, true);
    });

    it("generates a first key when rotation is begun with no active key", async () => {
      const client = createMemoryClient();
      const result = await beginSigningKeyRotation({ client });

      assert.match(result.signingKeyId, _test.SIGNING_KEY_ID_PATTERN);
      const status = await getSigningKeyRotationStatus({ client });
      assert.equal(status.rotationInProgress, false);
    });

    it("begin creates a new active key and retires the previous one", async () => {
      const client = createMemoryClient();
      const first = await ensureActiveSigningKey({ client });

      const rotated = await beginSigningKeyRotation({ client });
      assert.notEqual(rotated.signingKeyId, first.signingKeyId);
      assert.equal(rotated.supersedesSigningKeyId, first.signingKeyId);
      assert.equal(rotated.status, "active");

      const status = await getSigningKeyRotationStatus({ client });
      assert.equal(status.active.signingKeyId, rotated.signingKeyId);
      assert.equal(status.retiring.signingKeyId, first.signingKeyId);
      assert.equal(status.rotationInProgress, true);
      // The superseded key stays verifiable while agents re-pin.
      const old = client.signingKeyRows.find(
        (row) => row.signing_key_id === first.signingKeyId,
      );
      assert.equal(old.status, "retiring");
    });

    it("refuses to begin a second overlapping rotation", async () => {
      const client = createMemoryClient();
      await ensureActiveSigningKey({ client });
      await beginSigningKeyRotation({ client });

      await assert.rejects(
        () => beginSigningKeyRotation({ client }),
        (err) => err.code === CERTOPS_SIGNING_KEY_UNAVAILABLE,
      );
    });

    it("never persists or returns private material during rotation", async () => {
      const client = createMemoryClient();
      await ensureActiveSigningKey({ client });
      const rotated = await beginSigningKeyRotation({ client });

      assert.equal(rotated.privateKeyPem, undefined);
      assert.ok(!JSON.stringify(rotated).includes("PRIVATE KEY"));
      for (const row of client.signingKeyRows) {
        assert.ok(!row.private_key_encrypted.includes("PRIVATE KEY"));
      }
    });

    it("fails closed when the env key is missing before generating a key", async () => {
      const client = createMemoryClient();
      await ensureActiveSigningKey({ client });
      delete process.env[_test.ENV_KEY_NAME];

      await assert.rejects(
        () => beginSigningKeyRotation({ client }),
        (err) => err.code === CERTOPS_SIGNING_ENCRYPTION_KEY_MISSING,
      );
    });

    it("complete is a no-op when no rotation is in progress", async () => {
      const client = createMemoryClient();
      await ensureActiveSigningKey({ client });

      const result = await completeSigningKeyRotation({ client });
      assert.equal(result.completed, false);
      assert.equal(result.reason, "no_retiring_key");
    });

    it("blocks completion while part of the fleet has not acknowledged", async () => {
      const client = createMemoryClient();
      await ensureActiveSigningKey({ client });
      const rotated = await beginSigningKeyRotation({ client });

      client.activeAgents = 3;
      client.acks.set(rotated.signingKeyId, new Set(["agent-1"]));

      const status = await getSigningKeyRotationStatus({ client });
      assert.equal(status.fullyAcked, false);
      assert.equal(status.ackCount, 1);
      assert.equal(status.activeAgents, 3);

      const result = await completeSigningKeyRotation({ client });
      assert.equal(result.completed, false);
      assert.equal(result.reason, "fleet_incomplete");
      assert.equal(result.ackCount, 1);
      assert.equal(result.activeAgents, 3);
      // The old key must remain verifiable so unacknowledged agents keep working.
      const old = client.signingKeyRows.find(
        (row) => row.signing_key_id === rotated.supersedesSigningKeyId,
      );
      assert.equal(old.status, "retiring");
    });

    it("completes once the whole fleet acknowledged the new key", async () => {
      const client = createMemoryClient();
      await ensureActiveSigningKey({ client });
      const rotated = await beginSigningKeyRotation({ client });

      client.activeAgents = 2;
      client.acks.set(rotated.signingKeyId, new Set(["agent-1", "agent-2"]));

      const result = await completeSigningKeyRotation({ client });
      assert.equal(result.completed, true);
      assert.equal(result.forced, false);
      assert.equal(result.retiredSigningKeyId, rotated.supersedesSigningKeyId);
      assert.equal(result.activeSigningKeyId, rotated.signingKeyId);

      const old = client.signingKeyRows.find(
        (row) => row.signing_key_id === rotated.supersedesSigningKeyId,
      );
      assert.equal(old.status, "retired");
      const status = await getSigningKeyRotationStatus({ client });
      assert.equal(status.rotationInProgress, false);
    });

    it("force-completes an incomplete rotation and records the reason", async () => {
      const client = createMemoryClient();
      await ensureActiveSigningKey({ client });
      const rotated = await beginSigningKeyRotation({ client });

      client.activeAgents = 4;
      client.acks.set(rotated.signingKeyId, new Set(["agent-1"]));

      const result = await completeSigningKeyRotation({
        client,
        force: true,
        reason: "suspected key compromise",
      });
      assert.equal(result.completed, true);
      assert.equal(result.forced, true);

      const old = client.signingKeyRows.find(
        (row) => row.signing_key_id === rotated.supersedesSigningKeyId,
      );
      assert.equal(old.status, "retired");
      assert.ok(old.rotation_forced_at instanceof Date);
      assert.equal(old.rotation_force_reason, "suspected key compromise");
    });

    it("does not mark a fully acknowledged completion as forced", async () => {
      const client = createMemoryClient();
      await ensureActiveSigningKey({ client });
      const rotated = await beginSigningKeyRotation({ client });

      client.activeAgents = 1;
      client.acks.set(rotated.signingKeyId, new Set(["agent-1"]));

      const result = await completeSigningKeyRotation({
        client,
        force: true,
        reason: "belt and braces",
      });
      assert.equal(result.completed, true);
      // force was redundant here, so the rotation is not flagged as forced.
      assert.equal(result.forced, false);
    });

    it("signs jobs with the new key immediately after begin", async () => {
      const client = createMemoryClient();
      await ensureActiveSigningKey({ client });
      const rotated = await beginSigningKeyRotation({ client });

      const signed = await signJobForDispatch({
        client,
        job: baseJob(),
        workspaceId: WORKSPACE_A,
      });
      assert.equal(signed.signingKeyId, rotated.signingKeyId);

      const verdict = verifyJobSignature({
        job: signed,
        publicKeyPem: rotated.publicKeyPem,
        pinnedSigningKeyId: rotated.signingKeyId,
      });
      assert.deepEqual(verdict, { allowed: true });
    });
  });

  describe("key lifecycle", () => {
    it("returns null public info when no active key exists", async () => {
      const client = createMemoryClient();
      assert.equal(await getActiveSigningKeyPublicInfo({ client }), null);
    });

    it("generates a first-boot key and returns only public material", async () => {
      const client = createMemoryClient();
      const info = await ensureActiveSigningKey({ client });

      assert.match(info.signingKeyId, _test.SIGNING_KEY_ID_PATTERN);
      assert.ok(info.signingKeyId.startsWith(_test.SIGNING_KEY_ID_PREFIX));
      assert.match(info.publicKeyPem, /^-----BEGIN PUBLIC KEY-----/);
      assert.equal(info.privateKeyPem, undefined);
      assert.equal(info.private_key_encrypted, undefined);

      const stored = client.signingKeyRows[0];
      assert.ok(!stored.private_key_encrypted.includes("PRIVATE KEY"));
      assert.match(stored.private_key_encrypted, /^[a-f0-9]+:[a-f0-9]+:[a-f0-9]+$/);
    });

    it("is idempotent: a second call returns the same key", async () => {
      const client = createMemoryClient();
      const first = await ensureActiveSigningKey({ client });
      const second = await ensureActiveSigningKey({ client });
      assert.equal(second.signingKeyId, first.signingKeyId);
      assert.equal(client.signingKeyRows.length, 1);
    });

    it("refuses first-boot keygen without the env encryption key", async () => {
      delete process.env[_test.ENV_KEY_NAME];
      const client = createMemoryClient();
      await assert.rejects(
        () => ensureActiveSigningKey({ client }),
        (err) => err.code === CERTOPS_SIGNING_ENCRYPTION_KEY_MISSING,
      );
      assert.equal(client.signingKeyRows.length, 0);
    });

    it("re-selects the winner after losing the single-active insert race", async () => {
      const client = createMemoryClient();

      // Simulate the concurrent winner: our ON CONFLICT DO NOTHING insert
      // returns no row (no 23505 is raised, so a surrounding transaction
      // stays healthy) and the winner's row is visible to the re-select.
      client.skipNextInsertAsConflict = true;
      client.conflictWinnerRow = {
        id: "key-winner",
        signing_key_id: "ttsk_winner",
        public_key_pem: "-----BEGIN PUBLIC KEY-----\nwinner\n-----END PUBLIC KEY-----\n",
        private_key_encrypted: "aa:bb:cc",
        encryption_version: 1,
        status: "active",
      };

      const info = await ensureActiveSigningKey({ client });
      assert.equal(info.signingKeyId, "ttsk_winner");
      // Exactly one active row remains: the winner's.
      assert.equal(
        client.signingKeyRows.filter((row) => row.status === "active").length,
        1,
      );
    });
  });

  describe("dispatch signing", () => {
    it("signs a job the agent verifier accepts (cross-side interop)", async () => {
      const client = createMemoryClient();
      const { signingKeyId, publicKeyPem } = await ensureActiveSigningKey({
        client,
      });

      const signedJob = await signJobForDispatch({
        client,
        job: baseJob(),
        workspaceId: WORKSPACE_A,
        agentId: null,
      });

      assert.equal(signedJob.signingKeyId, signingKeyId);
      assert.match(signedJob.nonce, _test.NONCE_PATTERN);
      assert.ok(Date.parse(signedJob.expiresAt) > Date.parse(signedJob.issuedAt));
      assert.equal(
        Date.parse(signedJob.expiresAt) - Date.parse(signedJob.issuedAt),
        DEFAULT_NONCE_TTL_SECONDS * 1000,
      );

      const verdict = verifyJobSignature({
        job: signedJob,
        publicKeyPem,
        pinnedSigningKeyId: signingKeyId,
      });
      assert.deepEqual(verdict, { allowed: true });
    });

    it("produces signatures the agent rejects after tampering", async () => {
      const client = createMemoryClient();
      const { signingKeyId, publicKeyPem } = await ensureActiveSigningKey({
        client,
      });
      const signedJob = await signJobForDispatch({
        client,
        job: baseJob(),
        workspaceId: WORKSPACE_A,
      });

      const tampered = { ...signedJob, action: "deploy" };
      const verdict = verifyJobSignature({
        job: tampered,
        publicKeyPem,
        pinnedSigningKeyId: signingKeyId,
      });
      assert.equal(verdict.allowed, false);
      assert.equal(verdict.rejectionReason, "job_integrity_failed");
    });

    it("records the issued nonce in the replay ledger", async () => {
      const client = createMemoryClient();
      await ensureActiveSigningKey({ client });
      const signedJob = await signJobForDispatch({
        client,
        job: baseJob(),
        workspaceId: WORKSPACE_A,
        agentId: "22222222-2222-4222-8222-222222222222",
      });

      assert.equal(client.nonceRows.length, 1);
      const ledger = client.nonceRows[0];
      assert.equal(ledger.nonce, signedJob.nonce);
      assert.equal(ledger.job_id, signedJob.jobId);
      assert.equal(ledger.workspace_id, WORKSPACE_A);
      assert.equal(
        ledger.issued_to_agent_id,
        "22222222-2222-4222-8222-222222222222",
      );
      assert.equal(ledger.consumed_at, null);
    });

    it("rejects jobs without a jobId", async () => {
      const client = createMemoryClient();
      await ensureActiveSigningKey({ client });
      await assert.rejects(
        () =>
          signJobForDispatch({
            client,
            job: { action: "renew" },
            workspaceId: WORKSPACE_A,
          }),
        (err) => err.code === CERTOPS_SIGNING_PAYLOAD_INVALID,
      );
    });

    it("rejects a missing workspaceId", async () => {
      const client = createMemoryClient();
      await ensureActiveSigningKey({ client });
      await assert.rejects(
        () => signJobForDispatch({ client, job: baseJob() }),
        (err) => err.code === CERTOPS_SIGNING_PAYLOAD_INVALID,
      );
    });

    it("fails when no active signing key exists", async () => {
      const client = createMemoryClient();
      await assert.rejects(
        () =>
          signJobForDispatch({
            client,
            job: baseJob(),
            workspaceId: WORKSPACE_A,
          }),
        (err) => err.code === CERTOPS_SIGNING_KEY_UNAVAILABLE,
      );
    });

    it("strips any caller-supplied signature before signing", async () => {
      const client = createMemoryClient();
      const { signingKeyId, publicKeyPem } = await ensureActiveSigningKey({
        client,
      });
      const signedJob = await signJobForDispatch({
        client,
        job: baseJob({ signature: "attacker-supplied" }),
        workspaceId: WORKSPACE_A,
      });
      assert.notEqual(signedJob.signature, "attacker-supplied");
      assert.deepEqual(
        verifyJobSignature({
          job: signedJob,
          publicKeyPem,
          pinnedSigningKeyId: signingKeyId,
        }),
        { allowed: true },
      );
    });
  });

  describe("nonce consumption", () => {
    async function issueSignedJob(client) {
      await ensureActiveSigningKey({ client });
      return signJobForDispatch({
        client,
        job: baseJob(),
        workspaceId: WORKSPACE_A,
      });
    }

    it("consumes an issued nonce exactly once", async () => {
      const client = createMemoryClient();
      const signedJob = await issueSignedJob(client);

      const first = await consumeNonce({
        client,
        nonce: signedJob.nonce,
        jobId: signedJob.jobId,
      });
      assert.deepEqual(first, { consumed: true });

      const replay = await consumeNonce({
        client,
        nonce: signedJob.nonce,
        jobId: signedJob.jobId,
      });
      assert.equal(replay.consumed, false);
      assert.equal(replay.code, CERTOPS_NONCE_REPLAYED);
    });

    it("rejects never-issued nonces as unknown", async () => {
      const client = createMemoryClient();
      const result = await consumeNonce({
        client,
        nonce: crypto.randomBytes(24).toString("base64url"),
        jobId: "job-0001",
      });
      assert.equal(result.consumed, false);
      assert.equal(result.code, CERTOPS_NONCE_UNKNOWN_OR_EXPIRED);
    });

    it("rejects malformed nonces without hitting the database", async () => {
      const client = createMemoryClient();
      const result = await consumeNonce({
        client,
        nonce: "short",
        jobId: "job-0001",
      });
      assert.equal(result.consumed, false);
      assert.equal(result.code, CERTOPS_NONCE_UNKNOWN_OR_EXPIRED);
      assert.equal(client.queries.length, 0);
    });

    it("rejects expired nonces as unknown-or-expired", async () => {
      const client = createMemoryClient();
      const signedJob = await issueSignedJob(client);
      client.nonceRows[0].expires_at = new Date(Date.now() - 1000);

      const result = await consumeNonce({
        client,
        nonce: signedJob.nonce,
        jobId: signedJob.jobId,
      });
      assert.equal(result.consumed, false);
      assert.equal(result.code, CERTOPS_NONCE_UNKNOWN_OR_EXPIRED);
    });

    it("binds nonce consumption to the job id", async () => {
      const client = createMemoryClient();
      const signedJob = await issueSignedJob(client);

      const wrongJob = await consumeNonce({
        client,
        nonce: signedJob.nonce,
        jobId: "job-other",
      });
      assert.equal(wrongJob.consumed, false);
      assert.equal(wrongJob.code, CERTOPS_NONCE_UNKNOWN_OR_EXPIRED);
    });
  });

  describe("nonce sweeping", () => {
    it("deletes only nonces past the grace window", async () => {
      const client = createMemoryClient();
      const staleMs = (_test.SWEEP_GRACE_SECONDS + 60) * 1000;
      client.nonceRows.push(
        {
          nonce: "stale-nonce-000000000001",
          job_id: "job-a",
          workspace_id: WORKSPACE_A,
          issued_to_agent_id: null,
          expires_at: new Date(Date.now() - staleMs),
          consumed_at: null,
        },
        {
          nonce: "fresh-nonce-000000000002",
          job_id: "job-b",
          workspace_id: WORKSPACE_A,
          issued_to_agent_id: null,
          expires_at: new Date(Date.now() - 1000),
          consumed_at: null,
        },
      );

      const deleted = await sweepExpiredNonces({ client });
      assert.equal(deleted, 1);
      assert.equal(client.nonceRows.length, 1);
      assert.equal(client.nonceRows[0].job_id, "job-b");
    });

    it("returns zero when nothing is sweepable", async () => {
      const client = createMemoryClient();
      assert.equal(await sweepExpiredNonces({ client }), 0);
    });
  });
});
