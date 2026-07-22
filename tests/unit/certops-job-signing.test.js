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
  signJobForDispatch,
  consumeNonce,
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
    failNextInsertWith23505: false,
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
        if (client.failNextInsertWith23505) {
          client.failNextInsertWith23505 = false;
          const err = new Error("duplicate key value");
          err.code = "23505";
          throw err;
        }
        const row = {
          id: `key-${nextId++}`,
          signing_key_id: params[0],
          public_key_pem: params[1],
          private_key_encrypted: params[2],
          encryption_version: params[3],
          status: "active",
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
      client.failNextInsertWith23505 = true;

      // Simulate the concurrent winner's row appearing before the re-select.
      const winner = {
        id: "key-winner",
        signing_key_id: "ttsk_winner",
        public_key_pem: "-----BEGIN PUBLIC KEY-----\nwinner\n-----END PUBLIC KEY-----\n",
        private_key_encrypted: "aa:bb:cc",
        encryption_version: 1,
        status: "active",
      };
      const originalQuery = client.query.bind(client);
      let insertFailed = false;
      client.query = async (sql, params) => {
        try {
          return await originalQuery(sql, params);
        } catch (err) {
          if (err.code === "23505") {
            insertFailed = true;
            client.signingKeyRows.push(winner);
          }
          throw err;
        }
      };

      const info = await ensureActiveSigningKey({ client });
      assert.equal(insertFailed, true);
      assert.equal(info.signingKeyId, "ttsk_winner");
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
