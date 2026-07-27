"use strict";

/**
 * Adoption-intent service surface: invalidation, retry, the location count the
 * adoption block depends on, and the profile ownership that makes an operator's
 * edits survive a later derivation.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const servicePath = (name) =>
  path.resolve(__dirname, "../../apps/api/services/certops", name);

const {
  invalidateProfileDerivationIntents,
  resetOutboxEventForRetry,
} = require(servicePath("outbox.js"));
const {
  adoptionIntentDedupeKey,
  countCertificateDeploymentLocations,
  detachRenewalProfile,
  enqueueRenewalAdoptionIntent,
} = require(servicePath("renewalAdoption.js"));
const {
  OPERATOR_OWNED_METADATA_KEY,
  ensureDerivedRenewalProfile,
} = require(servicePath("renewalProfileDerivation.js"));

const WORKSPACE = "11111111-1111-4111-8111-111111111111";
const CERT_ID = "22222222-2222-4222-8222-222222222222";
const PROFILE_ID = "33333333-3333-4333-8333-333333333333";
const JOB_ID = "44444444-4444-4444-8444-444444444444";
const OUTBOX_ID = "55555555-5555-4555-8555-555555555555";

function normalize(sql) {
  return String(sql).replace(/\s+/g, " ").trim();
}

function recordingClient(handler) {
  const queries = [];
  return {
    queries,
    async query(text, params = []) {
      const sql = normalize(typeof text === "string" ? text : text?.text || "");
      queries.push({ sql, params });
      if (["BEGIN", "COMMIT", "ROLLBACK"].includes(sql)) return { rows: [] };
      return handler(sql, params) || { rows: [], rowCount: 1 };
    },
  };
}

describe("outbox intent invalidation", () => {
  it("locks the non-terminal rows and marks them skipped as detached", async () => {
    const client = recordingClient((sql) => {
      if (sql.startsWith("SELECT id FROM certops_outbox")) {
        return { rows: [{ id: OUTBOX_ID }] };
      }
      return { rows: [], rowCount: 1 };
    });

    const result = await invalidateProfileDerivationIntents({
      client,
      workspaceId: WORKSPACE,
      certificateId: CERT_ID,
    });

    assert.equal(result.invalidated, 1);
    const select = client.queries[0];
    // The lock is the whole mechanism: the handler locks the same row at the
    // start of its derivation transaction, so the two cannot interleave.
    assert.match(select.sql, /FOR UPDATE$/);
    assert.equal(select.params[2], CERT_ID);
    const update = client.queries[1];
    assert.match(update.sql, /SET status = 'skipped'/);
    assert.equal(update.params[1], "detached");
  });

  it("includes a parked failed row, which retry could otherwise revive", async () => {
    const client = recordingClient((sql) => {
      if (sql.startsWith("SELECT id FROM certops_outbox")) {
        return { rows: [] };
      }
      return { rows: [], rowCount: 0 };
    });

    await invalidateProfileDerivationIntents({
      client,
      workspaceId: WORKSPACE,
      certificateId: CERT_ID,
    });

    const statuses = client.queries[0].params[3];
    assert.deepEqual(statuses, ["pending", "failed"]);
  });

  it("requires the caller's transaction client", async () => {
    await assert.rejects(
      () =>
        invalidateProfileDerivationIntents({
          workspaceId: WORKSPACE,
          certificateId: CERT_ID,
        }),
      /transaction client/,
    );
  });
});

describe("outbox retry", () => {
  it("resets a failed row to pending with a clean slate", async () => {
    const client = recordingClient((sql) => {
      if (sql.startsWith("SELECT id, status, event_type")) {
        return { rows: [{ id: OUTBOX_ID, status: "failed" }] };
      }
      return {
        rows: [
          {
            id: OUTBOX_ID,
            event_type: "profile_derivation_requested",
            status: "pending",
            attempt_count: 0,
          },
        ],
      };
    });

    const result = await resetOutboxEventForRetry({
      client,
      workspaceId: WORKSPACE,
      outboxId: OUTBOX_ID,
    });

    assert.equal(result.status, "pending");
    assert.equal(result.attemptCount, 0);
    const update = client.queries[1];
    assert.match(update.sql, /attempt_count = 0/);
    assert.match(update.sql, /next_retry_at = NOW\(\)/);
    assert.match(update.sql, /last_error = NULL/);
  });

  it("refuses a skipped row, which is a decision rather than a failure", async () => {
    const client = recordingClient(() => ({
      rows: [{ id: OUTBOX_ID, status: "skipped" }],
    }));

    await assert.rejects(
      () =>
        resetOutboxEventForRetry({
          client,
          workspaceId: WORKSPACE,
          outboxId: OUTBOX_ID,
        }),
      (error) => {
        assert.equal(error.code, "CERTOPS_OUTBOX_EVENT_NOT_RETRYABLE");
        return true;
      },
    );
    assert.equal(
      client.queries.filter((q) => q.sql.startsWith("UPDATE")).length,
      0,
      "a detached intent must not be revivable",
    );
  });
});

describe("adoption intent enqueue", () => {
  it("keys the intent on the job so a replayed creation arms nothing twice", async () => {
    assert.equal(adoptionIntentDedupeKey(JOB_ID), `derive-profile:${JOB_ID}`);

    const client = recordingClient(() => ({ rows: [{ id: OUTBOX_ID }] }));
    const first = await enqueueRenewalAdoptionIntent({
      client,
      workspaceId: WORKSPACE,
      jobId: JOB_ID,
      certificateId: CERT_ID,
      operation: "renew",
    });

    assert.equal(first.enqueued, true);
    const insert = client.queries[0];
    assert.match(insert.sql, /ON CONFLICT \(workspace_id, event_type, dedupe_key\) DO NOTHING/);
    assert.equal(insert.params[1], "profile_derivation_requested");
    assert.equal(insert.params[2], `derive-profile:${JOB_ID}`);
    assert.deepEqual(JSON.parse(insert.params[3]), {
      jobId: JOB_ID,
      certificateId: CERT_ID,
      operation: "renew",
    });
  });

  it("reports a duplicate as enqueued:false rather than failing", async () => {
    const client = recordingClient(() => ({ rows: [] }));
    const result = await enqueueRenewalAdoptionIntent({
      client,
      workspaceId: WORKSPACE,
      jobId: JOB_ID,
      certificateId: CERT_ID,
    });
    assert.deepEqual(result, { enqueued: false, id: null });
  });
});

/**
 * The count predicate is the defect, so the fake evaluates the filters the
 * query actually sends against real-shaped instance rows instead of returning a
 * canned number.
 */
function createInstancePool(instances) {
  return {
    async query(sql, params) {
      assert.match(
        normalize(sql),
        /COUNT\(DISTINCT ci\.target_id\)/,
        "COUNT(*) would count rotations, not locations",
      );
      const sources = params[2];
      const retired = params[3];
      const live = instances.filter(
        (row) => sources.includes(row.source) && !retired.includes(row.status),
      );
      return {
        rows: [{ locations: new Set(live.map((row) => row.target_id)).size }],
      };
    },
  };
}

describe("deployment location count", () => {
  it("counts one location for a certificate with several rotation rows", async () => {
    // certificate_instances appends a row per observed fingerprint at the same
    // target, and superseded rotation rows are never restatused, so a status
    // filter does not deduplicate them either.
    const db = createInstancePool([
      { target_id: "t-1", source: "agent_filesystem", status: "active" },
      { target_id: "t-1", source: "agent_filesystem", status: "active" },
      { target_id: "t-1", source: "agent_filesystem", status: "deployed" },
    ]);

    const locations = await countCertificateDeploymentLocations({
      db,
      workspaceId: WORKSPACE,
      certificateId: CERT_ID,
    });
    assert.equal(locations, 1);
  });

  it("counts each distinct deployment target once", async () => {
    const db = createInstancePool([
      { target_id: "t-1", source: "agent_filesystem", status: "active" },
      { target_id: "t-2", source: "cert_manager", status: "deployed" },
      { target_id: "t-2", source: "cert_manager", status: "deployed" },
    ]);

    assert.equal(
      await countCertificateDeploymentLocations({
        db,
        workspaceId: WORKSPACE,
        certificateId: CERT_ID,
      }),
      2,
    );
  });

  it("ignores observation-only sources and retired locations", async () => {
    const db = createInstancePool([
      { target_id: "t-1", source: "agent_filesystem", status: "active" },
      { target_id: "t-2", source: "endpoint_monitor", status: "active" },
      { target_id: "t-3", source: "domain_checker", status: "active" },
      { target_id: "t-4", source: "agent_filesystem", status: "decommissioned" },
      { target_id: "t-5", source: "cert_manager", status: "missing" },
    ]);

    assert.equal(
      await countCertificateDeploymentLocations({
        db,
        workspaceId: WORKSPACE,
        certificateId: CERT_ID,
      }),
      1,
    );
  });
});

describe("detach", () => {
  function createDetachPool({ profileId = PROFILE_ID, intents = [OUTBOX_ID] } = {}) {
    const client = recordingClient((sql) => {
      if (sql.includes("FROM managed_certificates mc")) {
        return {
          rows: profileId
            ? [
                {
                  id: CERT_ID,
                  common_name: "app.example.com",
                  profile_id: profileId,
                  profile_name: "Derived: app.example.com",
                },
              ]
            : [{ id: CERT_ID, common_name: "app.example.com", profile_id: null }],
        };
      }
      if (sql.startsWith("SELECT id FROM certops_outbox")) {
        return { rows: intents.map((id) => ({ id })) };
      }
      return { rows: [], rowCount: 1 };
    });
    client.release = () => {};
    return { client, dbPool: { connect: async () => client } };
  }

  it("nulls the link, invalidates the intent and audits, in one transaction", async () => {
    const { client, dbPool } = createDetachPool();
    const audits = [];

    const result = await detachRenewalProfile({
      dbPool,
      workspaceId: WORKSPACE,
      certificateId: CERT_ID,
      actorUserId: 7,
      auditWriter: async (event) => audits.push(event),
    });

    assert.equal(result.detachedProfileId, PROFILE_ID);
    assert.equal(result.invalidatedIntents, 1);
    assert.equal(client.queries[0].sql, "BEGIN");
    assert.equal(client.queries.at(-1).sql, "COMMIT");
    assert.ok(
      client.queries.some((q) => q.sql.includes("SET profile_id = NULL")),
      "the link must be removed",
    );
    assert.ok(
      client.queries.some((q) => q.sql.includes("SET status = 'skipped'")),
      "an outstanding intent must be invalidated in the same transaction",
    );
    assert.equal(audits.length, 1);
    assert.equal(audits[0].action, "CERTOPS_RENEWAL_PROFILE_DETACHED");
    assert.equal(audits[0].client, client, "the audit shares the transaction");
    assert.equal(audits[0].metadata.invalidatedIntents, 1);
  });

  it("refuses a certificate that has no profile, without writing", async () => {
    const { client, dbPool } = createDetachPool({ profileId: null });

    await assert.rejects(
      () =>
        detachRenewalProfile({
          dbPool,
          workspaceId: WORKSPACE,
          certificateId: CERT_ID,
          auditWriter: async () => {},
        }),
      (error) => {
        assert.equal(error.code, "CERTOPS_CERTIFICATE_NOT_PROFILED");
        return true;
      },
    );
    assert.equal(client.queries.at(-1).sql, "ROLLBACK");
  });
});

describe("profile ownership against re-derivation", () => {
  const issuePayload = () => ({
    caEndpoint: "https://acme.example.com/directory",
    commandRef: "certbot-dns-standard",
    dnsProvider: "route53",
    dnsZone: "example.com",
    certPath: "/etc/ssl/app/fullchain.pem",
    keyAlgorithm: "rsa",
    keySize: 2048,
  });

  /**
   * Stands in for the ON CONFLICT: an operator-owned stored row is only
   * protected if the statement carries the guard, so the fake honours the guard
   * rather than assuming it.
   */
  function createDerivationClient(storedProfile) {
    const state = { storedProfile, queries: [] };
    const client = {
      state,
      query: async (text, params = []) => {
        const sql = normalize(typeof text === "string" ? text : text?.text || "");
        state.queries.push({ sql, params });
        if (sql.includes("SELECT profile_id FROM managed_certificates")) {
          return { rows: [{ profile_id: null }] };
        }
        if (sql.includes("INSERT INTO certificate_profiles")) {
          const guarded = /WHERE COALESCE\( certificate_profiles\.public_metadata->>\$8/.test(
            sql,
          );
          const owned = state.storedProfile?.metadata?.[OPERATOR_OWNED_METADATA_KEY];
          if (state.storedProfile && guarded && owned === true) {
            return { rows: [] };
          }
          if (state.storedProfile) {
            state.storedProfile.metadata = JSON.parse(params[6]);
            return { rows: [{ id: PROFILE_ID, inserted: false }] };
          }
          return { rows: [{ id: PROFILE_ID, inserted: true }] };
        }
        if (sql.includes("UPDATE managed_certificates")) {
          return { rows: [], rowCount: state.linkRowCount ?? 1 };
        }
        if (sql.includes("INSERT INTO audit_events")) return { rows: [] };
        throw new Error(`unexpected query: ${sql}`);
      },
    };
    return { state, client };
  }

  it("leaves an operator-edited profile untouched and reports the refusal", async () => {
    const stored = {
      metadata: {
        renewalProfile: { keySize: 4096 },
        [OPERATOR_OWNED_METADATA_KEY]: true,
      },
    };
    const { state, client } = createDerivationClient(stored);
    const warnings = [];

    const result = await ensureDerivedRenewalProfile({
      client,
      workspaceId: WORKSPACE,
      certificateId: CERT_ID,
      payload: issuePayload(),
      certificate: { commonName: "app.example.com", subjectAltNames: [] },
      logger: { warn: (msg) => warnings.push(msg) },
    });

    // RETURNING yields no row when the guard filters it out. Reading rows[0].id
    // there would throw and break the never-throws-for-derivation contract.
    assert.equal(result.profileId, null);
    assert.equal(result.created, false);
    assert.equal(result.reason, "profile_operator_owned");
    assert.equal(
      state.storedProfile.metadata.renewalProfile.keySize,
      4096,
      "the operator's edit must survive the re-issuance",
    );
    assert.deepEqual(warnings, ["certops-renewal-profile-derivation-refused"]);
    assert.equal(
      state.queries.filter((q) => q.sql.includes("INSERT INTO audit_events")).length,
      0,
      "nothing was granted, so nothing is audited",
    );
  });

  it("still derives over a profile no operator has claimed", async () => {
    const stored = { metadata: { renewalProfile: { keySize: 4096 } } };
    const { client } = createDerivationClient(stored);

    const result = await ensureDerivedRenewalProfile({
      client,
      workspaceId: WORKSPACE,
      certificateId: CERT_ID,
      payload: issuePayload(),
      certificate: { commonName: "app.example.com", subjectAltNames: [] },
    });

    assert.equal(result.profileId, PROFILE_ID);
    assert.equal(stored.metadata.renewalProfile.keySize, 2048);
  });

  it("does not claim success when the certificate link affects no row", async () => {
    const { state, client } = createDerivationClient(null);
    state.linkRowCount = 0;

    const result = await ensureDerivedRenewalProfile({
      client,
      workspaceId: WORKSPACE,
      certificateId: CERT_ID,
      payload: issuePayload(),
      certificate: { commonName: "app.example.com", subjectAltNames: [] },
    });

    assert.equal(result.profileId, null);
    assert.equal(result.reason, "certificate_link_conflict");
    assert.equal(
      state.queries.filter((q) => q.sql.includes("INSERT INTO audit_events")).length,
      0,
      "auditing a profile the certificate does not use would be a false claim",
    );
  });
});
