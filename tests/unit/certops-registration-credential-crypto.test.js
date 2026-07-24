"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_REGISTRATION_CREDENTIAL_UNAVAILABLE,
  CERTOPS_REGISTRATION_ENCRYPTION_KEY_MISSING,
  ENCRYPTION_VERSION,
  decryptRegistrationCredential,
  encryptRegistrationCredential,
  sweepExpiredRegistrationReplays,
  _test,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/registrationCredentialCrypto.js",
  ),
);

const VALID_ENV_KEY = "a".repeat(64);
const SAMPLE_CREDENTIAL = `ttagent_0123456789abcdef_${"b".repeat(64)}`;

describe("certops registration credential crypto", () => {
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
        (err) => err.code === CERTOPS_REGISTRATION_ENCRYPTION_KEY_MISSING,
      );
      assert.throws(
        () => encryptRegistrationCredential(SAMPLE_CREDENTIAL),
        (err) =>
          err.code === CERTOPS_REGISTRATION_ENCRYPTION_KEY_MISSING &&
          !err.message.includes("ttagent_"),
      );
    });

    it("fails closed when the env encryption key is malformed", () => {
      process.env[_test.ENV_KEY_NAME] = "not-hex";
      assert.throws(
        () => encryptRegistrationCredential(SAMPLE_CREDENTIAL),
        (err) => err.code === CERTOPS_REGISTRATION_ENCRYPTION_KEY_MISSING,
      );
    });

    it("round-trips a credential through the AES-256-GCM envelope", () => {
      const envelope = encryptRegistrationCredential(SAMPLE_CREDENTIAL);
      assert.match(envelope, /^[a-f0-9]+:[a-f0-9]+:[a-f0-9]+$/);
      assert.equal(envelope.includes("ttagent_"), false);
      assert.equal(
        decryptRegistrationCredential(envelope, ENCRYPTION_VERSION),
        SAMPLE_CREDENTIAL,
      );
    });

    it("rejects a wrong wrap key without echoing credential material", () => {
      const envelope = encryptRegistrationCredential(SAMPLE_CREDENTIAL);
      process.env[_test.ENV_KEY_NAME] = "b".repeat(64);
      assert.throws(
        () => decryptRegistrationCredential(envelope, ENCRYPTION_VERSION),
        (err) =>
          err.code === CERTOPS_REGISTRATION_CREDENTIAL_UNAVAILABLE &&
          !err.message.includes("ttagent_") &&
          !err.message.includes(envelope),
      );
    });

    it("rejects an unsupported encryption version", () => {
      assert.throws(
        () => decryptRegistrationCredential("aa:bb:cc", 99),
        (err) => err.code === CERTOPS_REGISTRATION_CREDENTIAL_UNAVAILABLE,
      );
    });

    it("rejects a malformed envelope", () => {
      assert.throws(
        () => decryptRegistrationCredential("not-an-envelope", ENCRYPTION_VERSION),
        (err) => err.code === CERTOPS_REGISTRATION_CREDENTIAL_UNAVAILABLE,
      );
    });
  });

  describe("sweepExpiredRegistrationReplays", () => {
    it("deletes expired rows via a bounded subquery", async () => {
      const queries = [];
      const client = {
        async query(sql, params) {
          queries.push({ sql, params });
          return { rowCount: 2, rows: [] };
        },
      };
      const deleted = await sweepExpiredRegistrationReplays({
        client,
        batchSize: 50,
      });
      assert.equal(deleted, 2);
      assert.equal(queries.length, 1);
      assert.match(queries[0].sql, /DELETE FROM certops_agent_registration_replays/);
      assert.match(queries[0].sql, /expires_at < NOW\(\)/);
      assert.match(queries[0].sql, /LIMIT \$1/);
      assert.deepEqual(queries[0].params, [50]);
    });

    it("defaults the batch size to 1000", async () => {
      let seenParams;
      const client = {
        async query(_sql, params) {
          seenParams = params;
          return { rowCount: 0, rows: [] };
        },
      };
      const deleted = await sweepExpiredRegistrationReplays({ client });
      assert.equal(deleted, 0);
      assert.deepEqual(seenParams, [1000]);
    });
  });
});
