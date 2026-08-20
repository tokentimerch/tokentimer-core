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
        agentVersion: "0.11.1",
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
        agentVersion: "0.11.1",
        clockOffsetMs: -60_000,
      },
      {
        CERTOPS_AGENT_MIN_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MAX_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MIN_AGENT_VERSION: "0.10.0",
        CERTOPS_AGENT_MAX_AGENT_VERSION: "0.12.0",
        // Pinned explicitly so this clock-drift assertion doesn't drift with
        // packages/agent/package.json's version on every release (that default
        // is intentional for the real "outdated" heuristic, but this test is
        // about clockDriftState, not the outdated label).
        CERTOPS_AGENT_LATEST_KNOWN_VERSION: "0.12.0",
        CERTOPS_AGENT_CLOCK_DRIFT_WARN_MS: "5000",
        CERTOPS_AGENT_CLOCK_DRIFT_ALERT_MS: "30000",
      },
    );
    assert.equal(result.compatibilityState, "compatible");
    assert.equal(result.clockDriftState, "alert");
    assert.equal(result.clockDriftMs, 60_000);
  });

  it("flags an agent more than one minor behind CERTOPS_AGENT_LATEST_KNOWN_VERSION as outdated", () => {
    // Both bounds pinned explicitly (not left to the packages/agent/package.json
    // default) so this is the one deterministic, release-proof test asserting
    // computeAgentCompatibility can actually produce "outdated" — see the
    // clock-drift test above for why that one pins the same var away from it.
    const result = computeAgentCompatibility(
      {
        protocolVersion: "1.0.0",
        agentVersion: "0.10.0",
        clockOffsetMs: 0,
      },
      {
        CERTOPS_AGENT_MIN_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MAX_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MIN_AGENT_VERSION: "0.1.0",
        CERTOPS_AGENT_MAX_AGENT_VERSION: "99.999.999",
        CERTOPS_AGENT_LATEST_KNOWN_VERSION: "0.12.0",
      },
    );
    assert.equal(result.compatibilityState, "outdated");
  });

  it("does not flag an agent exactly one minor behind CERTOPS_AGENT_LATEST_KNOWN_VERSION as outdated", () => {
    const result = computeAgentCompatibility(
      {
        protocolVersion: "1.0.0",
        agentVersion: "0.11.0",
        clockOffsetMs: 0,
      },
      {
        CERTOPS_AGENT_MIN_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MAX_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MIN_AGENT_VERSION: "0.1.0",
        CERTOPS_AGENT_MAX_AGENT_VERSION: "99.999.999",
        CERTOPS_AGENT_LATEST_KNOWN_VERSION: "0.12.0",
      },
    );
    assert.equal(result.compatibilityState, "compatible");
  });

  it("marks an agent live within the offline threshold", () => {
    const result = computeAgentCompatibility(
      {
        protocolVersion: "1.0.0",
        agentVersion: "0.11.1",
        clockOffsetMs: 0,
        status: "active",
        lastSeenAt: new Date(Date.now() - 60_000).toISOString(),
      },
      {
        CERTOPS_AGENT_MIN_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MAX_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MIN_AGENT_VERSION: "0.10.0",
        CERTOPS_AGENT_MAX_AGENT_VERSION: "0.12.0",
        CERTOPS_AGENT_OFFLINE_AFTER_MS: "600000",
      },
    );
    assert.equal(result.livenessState, "live");
  });

  it("marks an agent stale once last_seen_at exceeds the offline threshold, even if status is still 'active' (sweep has not yet run)", () => {
    const result = computeAgentCompatibility(
      {
        protocolVersion: "1.0.0",
        agentVersion: "0.11.1",
        clockOffsetMs: 0,
        status: "active",
        lastSeenAt: new Date(Date.now() - 20 * 60 * 1000).toISOString(),
      },
      {
        CERTOPS_AGENT_MIN_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MAX_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MIN_AGENT_VERSION: "0.10.0",
        CERTOPS_AGENT_MAX_AGENT_VERSION: "0.12.0",
        CERTOPS_AGENT_OFFLINE_AFTER_MS: "600000",
      },
    );
    assert.equal(result.livenessState, "stale");
  });

  it("judges a never-heartbeated agent on created_at, so registration alone cannot look permanently live", () => {
    const result = computeAgentCompatibility(
      {
        protocolVersion: "1.0.0",
        agentVersion: "0.11.1",
        clockOffsetMs: 0,
        status: "active",
        lastSeenAt: null,
        createdAt: new Date(Date.now() - 20 * 60 * 1000).toISOString(),
      },
      {
        CERTOPS_AGENT_MIN_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MAX_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MIN_AGENT_VERSION: "0.10.0",
        CERTOPS_AGENT_MAX_AGENT_VERSION: "0.12.0",
        CERTOPS_AGENT_OFFLINE_AFTER_MS: "600000",
      },
    );
    assert.equal(result.livenessState, "stale");
  });

  it("always reports retired agents as 'retired', never 'stale'", () => {
    const result = computeAgentCompatibility(
      {
        protocolVersion: "1.0.0",
        agentVersion: "0.11.1",
        clockOffsetMs: 0,
        status: "retired",
        lastSeenAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(),
      },
      {
        CERTOPS_AGENT_MIN_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MAX_PROTOCOL_VERSION: "1.0.0",
        CERTOPS_AGENT_MIN_AGENT_VERSION: "0.10.0",
        CERTOPS_AGENT_MAX_AGENT_VERSION: "0.12.0",
        CERTOPS_AGENT_OFFLINE_AFTER_MS: "600000",
      },
    );
    assert.equal(result.livenessState, "retired");
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

  // Forced retirement is a terminal-failure path, so it owes the alert every
  // other terminal path pays. Before this, the two UPDATEs committed and nothing
  // else happened: retiring an agent mid-renewal produced a dead renewal that
  // notified no one, which is exactly what an operator cannot detect on their
  // own. The assertion is on the outbox INSERT, not on an email, because the
  // intent is the part that must be atomic with the status change.
  it("enqueues one renewal-alert intent per fenced renew job, in the same transaction", async () => {
    const inserts = [];
    const db = {
      async query(sql, params) {
        if (sql.includes("INSERT INTO certops_outbox")) {
          inserts.push({ sql, params });
          return { rows: [{ id: `outbox-${inserts.length}` }] };
        }
        if (sql.includes("status = 'cancelled'")) {
          return {
            rows: [
              {
                id: "job-claimed",
                workspace_id: "11111111-1111-4111-8111-111111111111",
                operation: "renew",
                subject_type: "managed_certificate",
                subject_id: "cert-1",
              },
            ],
          };
        }
        if (sql.includes("orphaned_unknown_effect")) {
          return {
            rows: [
              {
                id: "job-running",
                workspace_id: "11111111-1111-4111-8111-111111111111",
                operation: "renew",
                subject_type: "managed_certificate",
                subject_id: "cert-2",
              },
            ],
          };
        }
        return { rows: [] };
      },
    };

    await fenceAgentInFlightWork({ client: db, agentId: "agent-row-1" });

    assert.equal(inserts.length, 2);
    const payloads = inserts.map((row) =>
      typeof row.params[3] === "string" ? JSON.parse(row.params[3]) : row.params[3],
    );
    assert.deepEqual(
      payloads.map((p) => p.jobId).sort(),
      ["job-claimed", "job-running"],
    );
    for (const payload of payloads) {
      assert.equal(payload.origin, "forced_retirement");
      assert.equal(payload.operation, "renew");
    }
    // The orphan is the case where side effects may already have landed, so it
    // must carry the higher priority the policy assigns it.
    const orphanPayload = payloads.find((p) => p.jobId === "job-running");
    assert.equal(orphanPayload.jobStatus, "orphaned_unknown_effect");
    assert.equal(orphanPayload.priority, "high");
    // Dedupe key is the job id, matching every other origin, so a job already
    // alerted for by the reaper is not alerted for twice by retirement.
    assert.deepEqual(
      inserts.map((row) => row.params[2]).sort(),
      ["job-claimed", "job-running"],
    );
  });

  it("does not enqueue for fenced jobs whose operation never alerts", async () => {
    const inserts = [];
    const db = {
      async query(sql, params) {
        if (sql.includes("INSERT INTO certops_outbox")) {
          inserts.push(params);
          return { rows: [{ id: "outbox-1" }] };
        }
        if (sql.includes("status = 'cancelled'")) {
          return {
            rows: [
              {
                id: "job-deploy",
                workspace_id: "11111111-1111-4111-8111-111111111111",
                operation: "deploy",
                subject_type: "managed_certificate",
                subject_id: "cert-1",
              },
            ],
          };
        }
        return { rows: [] };
      },
    };

    const result = await fenceAgentInFlightWork({
      client: db,
      agentId: "agent-row-1",
    });

    assert.deepEqual(result.cancelledJobIds, ["job-deploy"]);
    assert.equal(inserts.length, 0);
  });

  // enqueueOutboxEvent refuses a non-transactional caller by design, which is
  // the only thing guaranteeing the intent commits with the status change. If a
  // future refactor calls the fencing on the bare pool, this fails loudly here
  // instead of silently dropping alerts in production.
  it("propagates an enqueue failure rather than committing a silent status change", async () => {
    const db = {
      async query(sql) {
        if (sql.includes("INSERT INTO certops_outbox")) {
          throw new Error("outbox unavailable");
        }
        if (sql.includes("status = 'cancelled'")) {
          return {
            rows: [
              {
                id: "job-claimed",
                workspace_id: "11111111-1111-4111-8111-111111111111",
                operation: "renew",
                subject_type: "managed_certificate",
                subject_id: "cert-1",
              },
            ],
          };
        }
        return { rows: [] };
      },
    };

    await assert.rejects(
      fenceAgentInFlightWork({ client: db, agentId: "agent-row-1" }),
      /outbox unavailable/,
    );
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
    const renewalProfile = {
      schemaVersion: 1,
      profileId: "profile-1",
      profileName: "web-tls",
      sanPolicy: {
        mode: "exact",
        sans: ["app.example.com"],
        allowWildcards: false,
      },
      keyAlgorithm: "rsa",
      keySize: 2048,
      keyRotationPolicy: { rotateOnRenew: true },
      preferredChain: null,
      ca: {
        endpoint: "https://acme-v02.api.letsencrypt.org/directory",
        accountRef: "le-prod",
        eabRef: null,
      },
      acme: { kind: "certbot", commandRef: "renew.web" },
      dns: { provider: "cloudflare", zone: "example.com" },
      deploymentTargets: [
        {
          type: "endpoint",
          reference: "host/web",
          certPath: "/etc/ssl/certs/app.pem",
          reloadService: "nginx",
        },
      ],
      target: {
        type: "endpoint",
        reference: "host/web",
        certPath: "/etc/ssl/certs/app.pem",
      },
      verification: { host: "app.example.com", port: 443, requireMatch: true },
    };
    const job = {
      id: "33333333-3333-4333-8333-333333333333",
      workspace_id: "11111111-1111-4111-8111-111111111111",
      operation: "renew",
      status: "pending_approval",
      payload: { action: "renew", targetId: "t1", renewalProfile },
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
