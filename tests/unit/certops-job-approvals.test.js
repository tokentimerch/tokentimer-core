"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");

const {
  CERTOPS_APPROVAL_APPROVER_REQUIRED,
  CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL,
  CERTOPS_APPROVAL_STORE_ENROLLMENT_UNAVAILABLE,
  CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN,
  approveJob,
  computeJobPayloadApprovalHash,
  computeCanonicalIntentHash,
  loadStoreApprovalBinding,
  rejectJob,
  requestApprovalState,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/jobApprovals.js"),
);
const { claimJobs: claimJobsImpl } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/agentDispatch.js"),
);
const claimJobs = options => claimJobsImpl({ ...options, deps: { assertCurrentAgentCredential: async () => {}, ...options.deps } });
const {
  canonicalizeJobPayload,
} = require(
  path.resolve(__dirname, "../../packages/contracts/certops/canonical-json.cjs"),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";
const JOB_ID = "33333333-3333-4333-8333-333333333333";

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function jobRow(overrides = {}) {
  return {
    id: JOB_ID,
    workspace_id: WORKSPACE_A,
    status: "pending_approval",
    payload: { domain: "example.com", commandRef: "nginx-reload" },
    requested_by_user_id: 7,
    requested_by_api_token_id: null,
    approved_by_user_id: null,
    approved_at: null,
    approved_payload_hash: null,
    ...overrides,
  };
}

/**
 * Minimal single-client mock in the certops-agent-dispatch.test.js style:
 * SQL is routed by shape, every statement is recorded, and the handler
 * decides the returned rows.
 */
function createMockDb(handler) {
  const state = { queries: [] };
  return {
    state,
    query: async (text, params) => {
      if (String(typeof text === "string" ? text : text?.text || "").includes("certops_managed_cert_quota_")) return { rows: [] };
      const sql = typeof text === "string" ? text : text?.text || "";
      state.queries.push({ text: sql, params });
      return handler(sql, params, state);
    },
  };
}

function noopLogAppender(calls = []) {
  return async (options) => {
    calls.push(options);
    return { id: `log-${calls.length}` };
  };
}

describe("jobApprovals.computeJobPayloadApprovalHash", () => {
  it("hashes the canonical serialization from canonical-json.cjs", () => {
    const payload = { b: 2, a: { z: 1, y: [3, 2] } };
    assert.equal(
      computeJobPayloadApprovalHash(payload),
      sha256Hex(canonicalizeJobPayload(payload)),
    );
  });

  it("is key-order independent (canonicalization property)", () => {
    assert.equal(
      computeJobPayloadApprovalHash({ a: 1, b: 2 }),
      computeJobPayloadApprovalHash({ b: 2, a: 1 }),
    );
  });
});

describe("jobApprovals.approveJob", () => {
  it("binds AD CS approval to the persisted snapshot and assigned agent", async () => {
    const { freezeSnapshot } = require("../../apps/api/services/certops/enrollmentLifecycle");
    const target = { type: "windows-cert-store", reference: "web.example.com", store: "My" };
    const issuerId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const agentId = "11111111-2222-4333-8444-555555555555";
    const enrollmentId = "66666666-7777-4888-8999-aaaaaaaaaaaa";
    const destinationSha256 = sha256Hex(JSON.stringify(target));
    const frozen = freezeSnapshot({ issuerId, issuerVersion: 1, caConfig: "ca\\CA", caKeySha256: "ab".repeat(32), template: "WebServer",
      authorizedDnsNames: [target.reference], keyAlgorithm: "rsa", keySize: 2048, destinationType: target.type, destinationSha256, predecessorFingerprintSha256: null });
    const payload = { keyMode: "os-store-managed", target };
    const db = createMockDb((sql, params) => {
      if (sql.includes("FROM certificate_jobs")) return { rows: [jobRow({ operation: "issue", payload, subject_type: "managed_certificate", subject_id: JOB_ID, enrollment_id: enrollmentId, assigned_agent_id: agentId })] };
      if (sql.includes("FROM certificate_enrollments")) return { rows: [{ id: enrollmentId, agent_id: agentId, issuer_id: issuerId, snapshot_bytes: frozen.bytes, snapshot_sha256: frozen.sha256, deploy_target: target, state: "requested" }] };
      if (sql.includes("UPDATE certificate_jobs")) return { rows: [{ id: JOB_ID, status: "pending", approved_by_user_id: params[2], approved_payload_hash: params[3], approved_canonical_intent_hash: params[4] }] };
      if (sql.includes("INSERT INTO certops_job_approvals")) return { rows: [{ id: "approval", workspace_id: WORKSPACE_A, job_id: JOB_ID, decision: "approved", payload_hash: params[4], canonical_intent_hash: params[5] }] };
      if (sql.includes("INSERT INTO audit_events")) return { rows: [] };
      throw new Error(sql);
    });
    const result = await approveJob({ client: db, workspaceId: WORKSPACE_A, jobId: JOB_ID, approverUserId: 9, logAppender: noopLogAppender() });
    const binding = { enrollmentId, agentId, issuerId, snapshotSha256: frozen.sha256 };
    assert.equal(result.canonicalIntentHash, computeCanonicalIntentHash({ operation: "issue", subjectType: "managed_certificate", subjectId: JOB_ID, payload, adcsApprovalBinding: binding }));
    const record = db.state.queries.find(q => q.text.includes("FROM certificate_enrollments"));
    assert.match(record.text, /FOR SHARE OF e/);
    assert.deepEqual(record.params.slice(0, 4), [WORKSPACE_A, enrollmentId, agentId, JOB_ID]);
    const continuationDb = createMockDb(() => ({ rows: [{ id: enrollmentId, agent_id: agentId, issuer_id: issuerId,
      snapshot_bytes: frozen.bytes, snapshot_sha256: frozen.sha256, deploy_target: target, state: "installing" }] }));
    assert.deepEqual(await loadStoreApprovalBinding(continuationDb, { workspaceId: WORKSPACE_A, operation: "continue-enrollment",
      enrollmentId, assignedAgentId: agentId, subjectType: "managed_certificate", subjectId: JOB_ID, payload }), binding);
    let queries = 0;
    const busyDb = createMockDb(() => ({ rows: ++queries === 1 ? [] : [{ id: enrollmentId }] }));
    assert.equal(await loadStoreApprovalBinding(busyDb, { workspaceId: WORKSPACE_A, operation: "issue", enrollmentId,
      assignedAgentId: agentId, subjectType: "managed_certificate", subjectId: JOB_ID, payload }), undefined);
  });
  for (const operation of ["issue", "renew"]) {
    it(`refuses ${operation} store approval until the enrollment snapshot is bound`, async () => {
      const db = createMockDb((sql) => {
        if (sql.includes("FROM certificate_jobs")) return { rows: [jobRow({ operation,
          payload: { target: { type: "windows-cert-store", reference: "web.example.com", store: "My" } } })] };
        throw new Error(`unexpected query: ${sql}`);
      });
      await assert.rejects(approveJob({ client: db, workspaceId: WORKSPACE_A, jobId: JOB_ID, approverUserId: 9 }),
        (error) => error.code === CERTOPS_APPROVAL_STORE_ENROLLMENT_UNAVAILABLE);
      assert.equal(db.state.queries.some((q) => q.text.includes("UPDATE certificate_jobs")), false);
    });
  }
  it("still refuses an ACME renewal lacking its approved profile", async () => {
    const db = createMockDb((sql) => {
      if (sql.includes("FROM certificate_jobs")) return { rows: [jobRow({ operation: "renew", payload: { target: { type: "domain", reference: "web.example.com" } } })] };
      throw new Error(`unexpected query: ${sql}`);
    });
    await assert.rejects(approveJob({ client: db, workspaceId: WORKSPACE_A, jobId: JOB_ID, approverUserId: 9 }),
      (error) => ["CERTOPS_RENEWAL_PROFILE_INCOMPLETE", "CERTOPS_RENEWAL_PROFILE_INVALID"].includes(error.code));
  });
  it("rejects the requester approving their own job with the 403-shaped code", async () => {
    const db = createMockDb((sql) => {
      if (sql.includes("FROM certificate_jobs")) {
        return { rows: [jobRow({ requested_by_user_id: 7 })] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    await assert.rejects(
      approveJob({
        client: db,
        workspaceId: WORKSPACE_A,
        jobId: JOB_ID,
        approverUserId: 7,
      }),
      (error) => error.code === CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN,
    );
    // No status write and no ledger row after the 403.
    assert.equal(
      db.state.queries.some((q) => q.text.includes("UPDATE certificate_jobs")),
      false,
    );
    assert.equal(
      db.state.queries.some((q) =>
        q.text.includes("INSERT INTO certops_job_approvals"),
      ),
      false,
    );
  });

  it("approves: flips status to pending, binds the canonical payload hash, records ledger + log", async () => {
    const payload = { domain: "example.com", commandRef: "nginx-reload" };
    const expectedHash = sha256Hex(canonicalizeJobPayload(payload));
    const logCalls = [];
    let updateParams = null;
    let ledgerParams = null;
    let auditParams = null;

    const db = createMockDb((sql, params) => {
      if (sql.includes("FROM certificate_jobs")) {
        return { rows: [jobRow({ payload })] };
      }
      if (sql.includes("UPDATE certificate_jobs")) {
        updateParams = params;
        assert.match(sql, /SET status = 'pending'/);
        assert.match(sql, /AND status = 'pending_approval'/);
        return {
          rows: [
            {
              id: JOB_ID,
              status: "pending",
              approved_by_user_id: params[2],
              approved_at: new Date("2026-07-22T12:00:00.000Z"),
              approved_payload_hash: params[3],
              approved_canonical_intent_hash: params[4],
            },
          ],
        };
      }
      if (sql.includes("INSERT INTO certops_job_approvals")) {
        ledgerParams = params;
        return {
          rows: [
            {
              id: "approval-1",
              workspace_id: params[0],
              job_id: params[1],
              decision: params[2],
              approved_by_user_id: params[3],
              payload_hash: params[4],
              canonical_intent_hash: params[5],
              reason: params[6],
              created_at: new Date("2026-07-22T12:00:00.000Z"),
            },
          ],
        };
      }
      if (sql.includes("INSERT INTO audit_events")) {
        auditParams = params;
        return { rows: [] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    const result = await approveJob({
      client: db,
      workspaceId: WORKSPACE_A,
      jobId: JOB_ID,
      approverUserId: 9,
      reason: "Looks safe",
      logAppender: noopLogAppender(logCalls),
    });

    assert.equal(result.status, "pending");
    assert.equal(result.approvedByUserId, 9);
    assert.equal(result.payloadHash, expectedHash);
    assert.equal(updateParams[2], 9);
    assert.equal(updateParams[3], expectedHash);
    assert.equal(ledgerParams[2], "approved");
    assert.equal(ledgerParams[4], expectedHash);
    assert.equal(result.approval.decision, "approved");
    assert.equal(logCalls.length, 1);
    assert.equal(logCalls[0].eventType, "approval.granted");
    assert.equal(logCalls[0].status, "pending");
    assert.equal(logCalls[0].metadata.payloadHash, expectedHash);
    assert.equal(auditParams[2], "CERTOPS_JOB_APPROVAL_GRANTED");
    assert.equal(auditParams[6].reason, "Looks safe");
  });

  it("answers double-approve (job already pending) with the 409-shaped conflict code", async () => {
    const db = createMockDb((sql) => {
      if (sql.includes("FROM certificate_jobs")) {
        return {
          rows: [
            jobRow({
              status: "pending",
              approved_by_user_id: 9,
              approved_payload_hash: "a".repeat(64),
            }),
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    await assert.rejects(
      approveJob({
        client: db,
        workspaceId: WORKSPACE_A,
        jobId: JOB_ID,
        approverUserId: 10,
      }),
      (error) => error.code === CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL,
    );
  });

  it("answers a lost compare-and-swap race with the 409-shaped conflict code", async () => {
    const db = createMockDb((sql) => {
      if (sql.includes("FROM certificate_jobs")) {
        return { rows: [jobRow()] };
      }
      if (sql.includes("UPDATE certificate_jobs")) {
        // A concurrent decision won between the read and the CAS write.
        return { rows: [] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    await assert.rejects(
      approveJob({
        client: db,
        workspaceId: WORKSPACE_A,
        jobId: JOB_ID,
        approverUserId: 9,
      }),
      (error) => error.code === CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL,
    );
  });

  it("allows any member to approve an API-token-requested job (no session requester)", async () => {
    const db = createMockDb((sql, params) => {
      if (sql.includes("FROM certificate_jobs")) {
        return {
          rows: [
            jobRow({
              requested_by_user_id: null,
              requested_by_api_token_id: "token-1",
            }),
          ],
        };
      }
      if (sql.includes("UPDATE certificate_jobs")) {
        return {
          rows: [
            {
              id: JOB_ID,
              status: "pending",
              approved_by_user_id: params[2],
              approved_at: new Date(),
              approved_payload_hash: params[3],
              approved_canonical_intent_hash: params[4],
            },
          ],
        };
      }
      if (sql.includes("INSERT INTO certops_job_approvals")) {
        return {
          rows: [
            {
              id: "approval-1",
              workspace_id: params[0],
              job_id: params[1],
              decision: params[2],
              approved_by_user_id: params[3],
              payload_hash: params[4],
              canonical_intent_hash: params[5],
              reason: params[6],
              created_at: new Date(),
            },
          ],
        };
      }
      if (sql.includes("INSERT INTO audit_events")) {
        return { rows: [] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    const result = await approveJob({
      client: db,
      workspaceId: WORKSPACE_A,
      jobId: JOB_ID,
      approverUserId: 7,
      logAppender: noopLogAppender(),
    });
    assert.equal(result.status, "pending");
  });

  it("requires an authenticated approver", async () => {
    const db = createMockDb(() => {
      throw new Error("no query expected");
    });
    await assert.rejects(
      approveJob({
        client: db,
        workspaceId: WORKSPACE_A,
        jobId: JOB_ID,
        approverUserId: null,
      }),
      (error) => error.code === CERTOPS_APPROVAL_APPROVER_REQUIRED,
    );
  });
});

describe("jobApprovals.rejectJob", () => {
  it("rejects: terminal status, ledger row, approval.rejected log event, audited reason", async () => {
    const logCalls = [];
    let updateParams = null;
    let auditParams = null;

    const db = createMockDb((sql, params) => {
      if (sql.includes("FROM certificate_jobs")) {
        return { rows: [jobRow()] };
      }
      if (sql.includes("UPDATE certificate_jobs")) {
        updateParams = params;
        assert.match(sql, /SET status = 'rejected'/);
        assert.match(sql, /error_code = 'CERTOPS_APPROVAL_REJECTED'/);
        assert.match(sql, /AND status = 'pending_approval'/);
        return { rows: [{ id: JOB_ID, status: "rejected" }] };
      }
      if (sql.includes("INSERT INTO certops_job_approvals")) {
        assert.equal(params[2], "rejected");
        assert.equal(params[4], null);
        return {
          rows: [
            {
              id: "approval-1",
              workspace_id: params[0],
              job_id: params[1],
              decision: params[2],
              approved_by_user_id: params[3],
              payload_hash: params[4],
              canonical_intent_hash: params[5],
              reason: params[6],
              created_at: new Date(),
            },
          ],
        };
      }
      if (sql.includes("INSERT INTO audit_events")) {
        auditParams = params;
        return { rows: [] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    const result = await rejectJob({
      client: db,
      workspaceId: WORKSPACE_A,
      jobId: JOB_ID,
      approverUserId: 9,
      reason: "Not during the freeze window",
      logAppender: noopLogAppender(logCalls),
    });

    assert.equal(result.status, "rejected");
    assert.equal(result.approval.decision, "rejected");
    assert.equal(updateParams[2], "Not during the freeze window");
    assert.equal(logCalls.length, 1);
    assert.equal(logCalls[0].eventType, "approval.rejected");
    assert.equal(logCalls[0].status, "rejected");
    // writeAudit(actorUserId, subjectUserId, action, targetType, targetId, channel, metadata, workspaceId)
    assert.equal(auditParams[2], "CERTOPS_JOB_APPROVAL_REJECTED");
    assert.equal(auditParams[6].reason, "Not during the freeze window");
  });

  it("omits reason from the audit metadata when no reason was given", async () => {
    let auditParams = null;

    const db = createMockDb((sql, params) => {
      if (sql.includes("FROM certificate_jobs")) {
        return { rows: [jobRow()] };
      }
      if (sql.includes("UPDATE certificate_jobs")) {
        return { rows: [{ id: JOB_ID, status: "rejected" }] };
      }
      if (sql.includes("INSERT INTO certops_job_approvals")) {
        return {
          rows: [
            {
              id: "approval-1",
              workspace_id: params[0],
              job_id: params[1],
              decision: params[2],
              approved_by_user_id: params[3],
              payload_hash: params[4],
              canonical_intent_hash: params[5],
              reason: params[6],
              created_at: new Date(),
            },
          ],
        };
      }
      if (sql.includes("INSERT INTO audit_events")) {
        auditParams = params;
        return { rows: [] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    await rejectJob({
      client: db,
      workspaceId: WORKSPACE_A,
      jobId: JOB_ID,
      approverUserId: 9,
      logAppender: noopLogAppender(),
    });

    assert.equal("reason" in auditParams[6], false);
  });

  it("answers reject on a non-pending_approval job with the conflict code", async () => {
    const db = createMockDb((sql) => {
      if (sql.includes("FROM certificate_jobs")) {
        return { rows: [jobRow({ status: "running" })] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    await assert.rejects(
      rejectJob({
        client: db,
        workspaceId: WORKSPACE_A,
        jobId: JOB_ID,
        approverUserId: 9,
      }),
      (error) => error.code === CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL,
    );
  });
});

describe("jobApprovals.requestApprovalState", () => {
  it("reports a stale approval as invalid after a payload edit", async () => {
    const originalPayload = { domain: "example.com" };
    const editedPayload = { domain: "evil.example.com" };
    const staleHash = sha256Hex(canonicalizeJobPayload(originalPayload));

    const db = createMockDb((sql) => {
      if (sql.includes("FROM certificate_jobs")) {
        return {
          rows: [
            jobRow({
              status: "pending",
              payload: editedPayload,
              approved_by_user_id: 9,
              approved_at: new Date("2026-07-22T12:00:00.000Z"),
              approved_payload_hash: staleHash,
            }),
          ],
        };
      }
      if (sql.includes("FROM certops_job_approvals")) {
        return { rows: [] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    const state = await requestApprovalState({
      client: db,
      workspaceId: WORKSPACE_A,
      jobId: JOB_ID,
    });

    assert.equal(state.awaitingApproval, false);
    assert.equal(state.approvedPayloadHash, staleHash);
    assert.equal(
      state.currentPayloadHash,
      sha256Hex(canonicalizeJobPayload(editedPayload)),
    );
    assert.equal(state.approvalValid, false);
  });
});

describe("agentDispatch.claimJobs approval-hash guard", () => {
  const CLAIM_DEPS_BASE = {
    lockWorkspaceForCertOpsSideEffect: async () => ({ locked: true }),
    signJobForDispatch: async ({ job }) => ({ ...job, signature: "sig" }),
    enforceAgentSequence: async () => {},
  };

  function agentFixture() {
    return {
      id: "agent-row-1",
      workspaceId: WORKSPACE_A,
      status: "active",
      protocolVersion: "1.0.0",
      agentVersion: "1.0.0",
    };
  }

  function createMockPool(handler) {
    const state = { queries: [], transaction: [], released: false };
    const client = {
      query: async (text, params) => {
      if (String(typeof text === "string" ? text : text?.text || "").includes("certops_managed_cert_quota_")) return { rows: [] };
        const sql = typeof text === "string" ? text : text?.text || "";
        state.queries.push({ text: sql, params });
        const trimmed = sql.trim().toUpperCase();
        if (
          trimmed === "BEGIN" ||
          trimmed === "COMMIT" ||
          trimmed === "ROLLBACK"
        ) {
          state.transaction.push(trimmed);
          return { rows: [] };
        }
        return handler(sql, params, state);
      },
      release: () => {
        state.released = true;
      },
    };
    return {
      state,
      client,
      connect: async () => client,
      query: client.query,
    };
  }

  it("invalidates a legacy approved store job even with a matching payload hash and qualified agent", async () => {
    const payload = { target: { type: "windows-cert-store", reference: "web.example.com", store: "My" } };
    const hash = sha256Hex(canonicalizeJobPayload(payload));
    const invalidations = [];
    const dbPool = createMockPool((sql) => {
      if (sql.includes("SET last_seen_at = NOW()")) return { rows: [] };
      if (sql.includes("declared_target_selectors")) return { rows: [{ platform: "win32", declared_capabilities: ["windows-store-only-adcs-v1", "adcs-enroll-v1", "evidence-claim-binding-v1"], capabilities_updated_at: new Date() }] };
      if (sql.includes("FOR UPDATE SKIP LOCKED")) return { rows: [{ id: JOB_ID, workspace_id: WORKSPACE_A, operation: "renew", subject_type: null,
        subject_id: null, payload, enrollment_id: "enrollment-1", assigned_agent_id: "agent-row-1", approved_payload_hash: hash }] };
      throw new Error(`unexpected query: ${sql}`);
    });
    const result = await claimJobs({ dbPool, agent: agentFixture(), body: { maxJobs: 1, supportedActions: ["renew"] }, env: {},
      deps: { ...CLAIM_DEPS_BASE, invalidateApprovalForClaim: async (options) => { invalidations.push(options); } } });
    assert.deepEqual(result.jobs, []);
    assert.equal(invalidations.length, 1);
    assert.equal(invalidations[0].jobId, JOB_ID);
  });

  it("invalidates a store approval when the enrollment snapshot is substituted", async () => {
    const { freezeSnapshot } = require("../../apps/api/services/certops/enrollmentLifecycle");
    const target = { type: "windows-cert-store", reference: "web.example.com", store: "My" };
    const issuerId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const enrollmentId = "66666666-7777-4888-8999-aaaaaaaaaaaa";
    const payload = { keyMode: "os-store-managed", target };
    const original = freezeSnapshot({ issuerId, issuerVersion: 1, caConfig: "ca\\CA", caKeySha256: "ab".repeat(32), template: "WebServer",
      authorizedDnsNames: [target.reference], keyAlgorithm: "rsa", keySize: 2048, destinationType: target.type,
      destinationSha256: sha256Hex(JSON.stringify(target)), predecessorFingerprintSha256: null });
    const changed = freezeSnapshot({ ...original.snapshot, template: "OtherTemplate" });
    const binding = { enrollmentId, agentId: "agent-row-1", issuerId, snapshotSha256: original.sha256 };
    const originalIntent = computeCanonicalIntentHash({ operation: "renew", subjectType: "managed_certificate", subjectId: JOB_ID, payload, adcsApprovalBinding: binding });
    const invalidations = [];
    const dbPool = createMockPool((sql) => {
      if (sql.includes("SET last_seen_at = NOW()")) return { rows: [] };
      if (sql.includes("declared_target_selectors")) return { rows: [{ platform: "win32", declared_capabilities: ["windows-store-only-adcs-v1", "adcs-enroll-v1", "evidence-claim-binding-v1"], capabilities_updated_at: new Date() }] };
      if (sql.includes("FOR UPDATE SKIP LOCKED")) return { rows: [{ id: JOB_ID, workspace_id: WORKSPACE_A, operation: "renew", subject_type: "managed_certificate",
        subject_id: JOB_ID, payload, enrollment_id: enrollmentId, assigned_agent_id: "agent-row-1", approved_payload_hash: sha256Hex(canonicalizeJobPayload(payload)), approved_canonical_intent_hash: originalIntent }] };
      if (sql.includes("SELECT state FROM certificate_enrollments")) return { rows: [{ state: "requested" }] };
      if (sql.includes("SELECT e.id,e.agent_id")) return { rows: [{ id: enrollmentId, agent_id: "agent-row-1", issuer_id: issuerId, snapshot_bytes: changed.bytes, snapshot_sha256: changed.sha256, deploy_target: target, state: "requested" }] };
      throw new Error(`unexpected query: ${sql}`);
    });
    const result = await claimJobs({ dbPool, agent: agentFixture(), body: { maxJobs: 1, supportedActions: ["renew"] }, env: {},
      deps: { ...CLAIM_DEPS_BASE, invalidateApprovalForClaim: async (options) => { invalidations.push(options); } } });
    assert.deepEqual(result.jobs, []);
    assert.equal(invalidations.length, 1);
  });

  it("skips a payload-edited approved job and flips it back to pending_approval", async () => {
    const editedPayload = { domain: "evil.example.com" };
    const staleHash = sha256Hex(canonicalizeJobPayload({ domain: "example.com" }));
    const invalidations = [];

    const dbPool = createMockPool((sql) => {
      if (sql.includes("SET last_seen_at = NOW()")) {
        return { rows: [] };
      }
      if (sql.includes("declared_target_selectors")) {
        return { rows: [{}] };
      }
      if (sql.includes("FOR UPDATE SKIP LOCKED")) {
        return {
          rows: [
            {
              id: JOB_ID,
              workspace_id: WORKSPACE_A,
              operation: "renew",
              subject_type: null,
              subject_id: null,
              payload: editedPayload,
              approved_payload_hash: staleHash,
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    const result = await claimJobs({
      dbPool,
      agent: agentFixture(),
      body: { maxJobs: 1, supportedActions: ["renew"] },
      env: {},
      deps: {
        ...CLAIM_DEPS_BASE,
        invalidateApprovalForClaim: async (options) => {
          invalidations.push(options);
          return { decision: "invalidated" };
        },
      },
    });

    assert.deepEqual(result.jobs, []);
    assert.equal(invalidations.length, 1);
    assert.equal(invalidations[0].jobId, JOB_ID);
    assert.equal(invalidations[0].staleHash, staleHash);
    assert.equal(
      invalidations[0].currentHash,
      sha256Hex(canonicalizeJobPayload(editedPayload)),
    );
    // No claim update ran for the invalidated job.
    assert.equal(
      dbPool.state.queries.some((q) =>
        q.text.includes("SET status = 'claimed'"),
      ),
      false,
    );
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "COMMIT"]);
  });

  it("dispatches an approved job whose hash still matches", async () => {
    const payload = { domain: "example.com" };
    const boundHash = sha256Hex(canonicalizeJobPayload(payload));

    const dbPool = createMockPool((sql) => {
      if (sql.includes("SET last_seen_at = NOW()")) {
        return { rows: [] };
      }
      if (sql.includes("declared_target_selectors")) {
        return { rows: [{}] };
      }
      if (sql.includes("FOR UPDATE SKIP LOCKED")) {
        return {
          rows: [
            {
              id: JOB_ID,
              workspace_id: WORKSPACE_A,
              operation: "renew",
              subject_type: null,
              subject_id: null,
              payload,
              approved_payload_hash: boundHash,
            },
          ],
        };
      }
      if (sql.includes("SET status = 'claimed'")) {
        return {
          rows: [
            {
              id: JOB_ID,
              claim_id: "claim-1",
              lease_expires_at: new Date(),
              attempt_count: 1,
              operation: "renew",
              subject_type: null,
              subject_id: null,
              payload,
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    const result = await claimJobs({
      dbPool,
      agent: agentFixture(),
      body: { maxJobs: 1, supportedActions: ["renew"] },
      env: {},
      deps: {
        ...CLAIM_DEPS_BASE,
        invalidateApprovalForClaim: async () => {
          throw new Error("must not invalidate a matching hash");
        },
      },
    });

    assert.equal(result.jobs.length, 1);
    assert.equal(result.jobs[0].jobId, JOB_ID);
  });

  it("leaves never-gated jobs (no stored hash) untouched", async () => {
    const dbPool = createMockPool((sql) => {
      if (sql.includes("SET last_seen_at = NOW()")) {
        return { rows: [] };
      }
      if (sql.includes("declared_target_selectors")) {
        return { rows: [{}] };
      }
      if (sql.includes("FOR UPDATE SKIP LOCKED")) {
        return {
          rows: [
            {
              id: JOB_ID,
              workspace_id: WORKSPACE_A,
              operation: "renew",
              subject_type: null,
              subject_id: null,
              payload: { domain: "example.com" },
              approved_payload_hash: null,
            },
          ],
        };
      }
      if (sql.includes("SET status = 'claimed'")) {
        return {
          rows: [
            {
              id: JOB_ID,
              claim_id: "claim-1",
              lease_expires_at: new Date(),
              attempt_count: 1,
              operation: "renew",
              subject_type: null,
              subject_id: null,
              payload: { domain: "example.com" },
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    const result = await claimJobs({
      dbPool,
      agent: agentFixture(),
      body: { maxJobs: 1, supportedActions: ["renew"] },
      env: {},
      deps: {
        ...CLAIM_DEPS_BASE,
        invalidateApprovalForClaim: async () => {
          throw new Error("must not run for ungated jobs");
        },
      },
    });
    assert.equal(result.jobs.length, 1);
  });
});
