"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  computeAgentCompatibility,
  fenceAgentInFlightWork,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/agentRegistry.js"),
);
const { getSigningKeyRotationNotice } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/jobSigning.js"),
);
const approvals = require(
  path.resolve(__dirname, "../../apps/api/services/certops/jobApprovals.js"),
);

describe("agent compatibility (H8)", () => {
  it("marks agents below minimum protocol as blocked", () => {
    const result = computeAgentCompatibility(
      {
        protocolVersion: "0.9.0",
        agentVersion: "0.11.0",
        clockOffsetMs: 100,
      },
      {
        CERTOPS_AGENT_MIN_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MAX_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MIN_AGENT_VERSION: "0.10.0",
        CERTOPS_AGENT_MAX_AGENT_VERSION: "0.12.0",
        CERTOPS_AGENT_CLOCK_DRIFT_WARN_MS: "5000",
        CERTOPS_AGENT_CLOCK_DRIFT_ALERT_MS: "30000",
      },
    );
    assert.equal(result.compatibilityState, "blocked");
    assert.equal(result.clockDriftState, "ok");
  });

  it("flags excessive clock drift as alert", () => {
    const result = computeAgentCompatibility(
      {
        protocolVersion: "1.0.0",
        agentVersion: "0.11.0",
        clockOffsetMs: -60_000,
      },
      {
        CERTOPS_AGENT_MIN_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MAX_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MIN_AGENT_VERSION: "0.10.0",
        CERTOPS_AGENT_MAX_AGENT_VERSION: "0.12.0",
        CERTOPS_AGENT_CLOCK_DRIFT_WARN_MS: "5000",
        CERTOPS_AGENT_CLOCK_DRIFT_ALERT_MS: "30000",
      },
    );
    assert.equal(result.compatibilityState, "compatible");
    assert.equal(result.clockDriftState, "alert");
    assert.equal(result.clockDriftMs, 60_000);
  });
});

describe("fenceAgentInFlightWork (H12)", () => {
  it("cancels claimed jobs and orphans running jobs", async () => {
    const updates = [];
    const db = {
      async query(sql, params) {
        updates.push({ sql, params });
        if (sql.includes("status = 'cancelled'")) {
          return { rows: [{ id: "job-claimed" }] };
        }
        if (sql.includes("orphaned_unknown_effect")) {
          return { rows: [{ id: "job-running" }] };
        }
        return { rows: [] };
      },
    };

    const result = await fenceAgentInFlightWork({
      client: db,
      agentId: "agent-row-1",
      reason: "forced retire",
    });

    assert.deepEqual(result.cancelledJobIds, ["job-claimed"]);
    assert.deepEqual(result.orphanedJobIds, ["job-running"]);
    assert.equal(updates.length, 2);
  });
});

describe("jobApprovals H2 helpers", () => {
  it("rejects approval reasons that look like secrets", () => {
    assert.throws(
      () => approvals._test.normalizeReason("password=super-secret-value"),
      (error) => error.code === "CERTOPS_APPROVAL_REASON_INVALID",
    );
  });

  it("computes a stable canonical intent hash over operation+subject+payload", () => {
    const hashA = approvals.computeCanonicalIntentHash({
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { action: "renew", targetId: "tgt-1", profileId: "prof-1" },
    });
    const hashB = approvals.computeCanonicalIntentHash({
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { profileId: "prof-1", targetId: "tgt-1", action: "renew" },
    });
    assert.equal(hashA, hashB);
    assert.match(hashA, /^[a-f0-9]{64}$/);
  });

  it("writes audit inside the approval transaction", async () => {
    const statements = [];
    const job = {
      id: "33333333-3333-4333-8333-333333333333",
      workspace_id: "11111111-1111-4111-8111-111111111111",
      operation: "renew",
      status: "pending_approval",
      payload: { action: "renew", targetId: "t1" },
      subject_type: "managed_certificate",
      subject_id: "c1",
      requested_by_user_id: 7,
      requested_by_api_token_id: null,
      approved_by_user_id: null,
      approved_at: null,
      approved_payload_hash: null,
      approved_canonical_intent_hash: null,
    };
    const client = {
      async query(sql) {
        statements.push(sql);
        if (sql.includes("FROM certificate_jobs")) {
          return { rows: [job] };
        }
        if (sql.includes("UPDATE certificate_jobs")) {
          return {
            rows: [
              {
                id: job.id,
                status: "pending",
                approved_by_user_id: 9,
                approved_at: new Date("2026-07-24T08:00:00.000Z"),
                approved_payload_hash: "a".repeat(64),
                approved_canonical_intent_hash: "b".repeat(64),
              },
            ],
          };
        }
        if (sql.includes("INSERT INTO certops_job_approvals")) {
          return {
            rows: [
              {
                id: "appr-1",
                workspace_id: job.workspace_id,
                job_id: job.id,
                decision: "approved",
                approved_by_user_id: 9,
                payload_hash: "a".repeat(64),
                canonical_intent_hash: "b".repeat(64),
                reason: null,
                created_at: new Date("2026-07-24T08:00:00.000Z"),
              },
            ],
          };
        }
        if (sql.includes("INSERT INTO audit_events")) {
          return { rows: [] };
        }
        return { rows: [] };
      },
    };

    const result = await approvals.approveJob({
      client,
      workspaceId: job.workspace_id,
      jobId: job.id,
      approverUserId: 9,
      logAppender: async () => ({ id: "log-1" }),
    });

    assert.equal(result.status, "pending");
    assert.ok(statements.some((sql) => sql.includes("INSERT INTO audit_events")));
    assert.ok(result.canonicalIntentHash);
  });
});

describe("signing key rotation notice (H3)", () => {
  it("returns pending_ack notice when agent has not pinned the new key", async () => {
    const db = {
      async query(sql) {
        if (sql.includes("status = 'active'")) {
          return {
            rows: [
              {
                id: "k2",
                signing_key_id: "ttsk_new",
                public_key_pem:
                  "-----BEGIN PUBLIC KEY-----\nNEW\n-----END PUBLIC KEY-----\n",
                private_key_encrypted: "x",
                encryption_version: 1,
                status: "active",
                supersedes_signing_key_id: "ttsk_old",
              },
            ],
          };
        }
        if (sql.includes("status = 'retiring'")) {
          return {
            rows: [
              {
                id: "k1",
                signing_key_id: "ttsk_old",
                public_key_pem:
                  "-----BEGIN PUBLIC KEY-----\nOLD\n-----END PUBLIC KEY-----\n",
                status: "retiring",
              },
            ],
          };
        }
        return { rows: [] };
      },
    };

    const notice = await getSigningKeyRotationNotice({
      client: db,
      pinnedSigningKeyId: "ttsk_old",
    });
    assert.equal(notice.status, "pending_ack");
    assert.equal(notice.pendingSigningKeyId, "ttsk_new");
    assert.equal(notice.supersedesSigningKeyId, "ttsk_old");
  });
});
