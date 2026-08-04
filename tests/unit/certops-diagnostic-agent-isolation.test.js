"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const { can, authorize } = require("../../apps/api/services/rbac");
const {
  CERTOPS_JOB_MODE_INVALID,
  CERTOPS_JOB_MODE_TERMINAL_INVALID,
  CERTOPS_JOB_OPERATION_INVALID,
  assertModeAllowsTerminalStatus,
  createCertificateJob,
} = require("../../apps/api/services/certops/jobs");
const {
  CERTOPS_DIAGNOSTIC_BOOTSTRAP_ALREADY_CONSUMED,
  createDiagnosticBootstrap,
} = require("../../apps/api/services/certops/diagnosticBootstrap");

// --- certops.agents.diagnose RBAC -----------------------------------------
//
// The diagnostic-bootstrap route mints a new machine credential, so it is
// admin-gated like the kill switch and renewal-profile permissions (see
// rbac.js and certops-routes-hardening.test.js for the route-wiring half of
// this coverage). These tests exercise the actual can()/authorize() runtime
// behavior rather than just the route's middleware ordering.

describe("certops.agents.diagnose permission", () => {
  it("denies viewer and workspace_manager, allows admin", () => {
    assert.equal(can("viewer", "certops.agents.diagnose"), false);
    assert.equal(can("workspace_manager", "certops.agents.diagnose"), false);
    assert.equal(can("admin", "certops.agents.diagnose"), true);
  });

  it("rejects a viewer-role diagnostic-bootstrap request with 403 via authorize()", () => {
    const middleware = authorize("certops.agents.diagnose");
    let statusCode = null;
    let body = null;
    const req = { authz: { workspaceRole: "viewer" } };
    const res = {
      status(code) {
        statusCode = code;
        return this;
      },
      json(payload) {
        body = payload;
        return this;
      },
    };
    let nextCalled = false;

    middleware(req, res, () => {
      nextCalled = true;
    });

    assert.equal(statusCode, 403);
    assert.ok(body && typeof body.error === "string");
    assert.equal(nextCalled, false);
  });

  it("lets an admin-role request through authorize()", () => {
    const middleware = authorize("certops.agents.diagnose");
    const req = { authz: { workspaceRole: "admin" } };
    let nextCalled = false;

    middleware(req, {}, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, true);
  });
});

// --- protocol_smoke job creation and terminal-status guards ---------------

describe("protocol_smoke job creation guard", () => {
  it("rejects protocol_smoke through the general job-creation path", async () => {
    await assert.rejects(
      createCertificateJob({
        workspaceId: "11111111-1111-1111-1111-111111111111",
        operation: "protocol_smoke",
      }),
      (err) => {
        assert.equal(err.code, CERTOPS_JOB_OPERATION_INVALID);
        return true;
      },
    );
  });

  it("rejects mode: real for protocol_smoke even with allowDiagnosticOperation", async () => {
    // This also proves allowDiagnosticOperation actually lifted the operation
    // guard above: the rejection here is CERTOPS_JOB_MODE_INVALID, not
    // CERTOPS_JOB_OPERATION_INVALID, so the code path reached the mode check.
    await assert.rejects(
      createCertificateJob({
        workspaceId: "11111111-1111-1111-1111-111111111111",
        operation: "protocol_smoke",
        allowDiagnosticOperation: true,
        mode: "real",
      }),
      (err) => {
        assert.equal(err.code, CERTOPS_JOB_MODE_INVALID);
        return true;
      },
    );
  });
});

describe("protocol_smoke terminal status (always mode: dry_run)", () => {
  it("never allows a dry_run job (protocol_smoke's only mode) to terminate as succeeded", () => {
    assert.throws(
      () => assertModeAllowsTerminalStatus("dry_run", "succeeded"),
      (err) => {
        assert.equal(err.code, CERTOPS_JOB_MODE_TERMINAL_INVALID);
        return true;
      },
    );
  });

  it("allows dry_run_complete and rejected as protocol_smoke terminal outcomes", () => {
    assert.doesNotThrow(() =>
      assertModeAllowsTerminalStatus("dry_run", "dry_run_complete"),
    );
    assert.doesNotThrow(() =>
      assertModeAllowsTerminalStatus("dry_run", "rejected"),
    );
  });
});

// --- diagnostic-bootstrap single-use replay --------------------------------
//
// createDiagnosticBootstrap runs the request-row insert, the agent insert,
// the smoke-job insert, and the audit write inside one transaction on one
// client (see diagnosticBootstrap.js). This mock proves the *shape* of that
// contract at the JS level: a second call with the same requestId must hit
// the unique-violation branch before it can create a second agent/job pair,
// and the caller must see diagnostic_bootstrap_already_consumed, never a
// replayed {agentId, credential, job}.

function createMockDiagnosticBootstrapPool() {
  let requestInsertCount = 0;
  const agentInsertCalls = [];
  const jobCreateCalls = [];
  const queries = [];

  const client = {
    query: async (sql, params) => {
      queries.push(sql);
      if (/^\s*BEGIN\s*$/i.test(sql) || /^\s*COMMIT\s*$/i.test(sql) || /^\s*ROLLBACK\s*$/i.test(sql)) {
        return { rows: [] };
      }
      if (sql.includes("INSERT INTO certops_diagnostic_bootstrap_requests")) {
        requestInsertCount += 1;
        if (requestInsertCount > 1) {
          const error = new Error(
            'duplicate key value violates unique constraint "uq_certops_diagnostic_bootstrap_workspace_request"',
          );
          error.code = "23505";
          error.constraint = "uq_certops_diagnostic_bootstrap_workspace_request";
          throw error;
        }
        return { rows: [{ id: "req-row-1" }] };
      }
      if (sql.includes("INSERT INTO certops_agents")) {
        agentInsertCalls.push(params);
        return {
          rows: [
            {
              id: "agent-row-1",
              agent_id: params[1],
              protocol_version: params[4],
            },
          ],
        };
      }
      if (sql.includes("UPDATE certops_diagnostic_bootstrap_requests")) {
        return { rows: [] };
      }
      throw new Error(`Unexpected query in mock pool: ${sql}`);
    },
    release: () => {},
  };

  const dbPool = {
    connect: async () => client,
  };

  return {
    dbPool,
    agentInsertCalls,
    jobCreateCalls,
    getRequestInsertCount: () => requestInsertCount,
  };
}

describe("diagnostic-bootstrap single-use consumption", () => {
  it("fails a consumed-bootstrap retry with diagnostic_bootstrap_already_consumed, without replaying agent/credential/job", async () => {
    const mock = createMockDiagnosticBootstrapPool();
    const deps = {
      ensureActiveSigningKey: async () => ({
        signingKeyId: "key-1",
        publicKeyPem: "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----",
      }),
      createCertificateJob: async (options) => {
        mock.jobCreateCalls.push(options);
        return {
          id: "job-1",
          operation: "protocol_smoke",
          mode: "dry_run",
          status: "pending",
        };
      },
      writeAudit: async () => {},
    };

    const first = await createDiagnosticBootstrap({
      dbPool: mock.dbPool,
      workspaceId: "22222222-2222-2222-2222-222222222222",
      requestId: "req-abc",
      requestedByUserId: 1,
      deps,
    });

    assert.ok(first.agentId);
    assert.ok(first.credential);
    assert.equal(mock.agentInsertCalls.length, 1);
    assert.equal(mock.jobCreateCalls.length, 1);

    await assert.rejects(
      createDiagnosticBootstrap({
        dbPool: mock.dbPool,
        workspaceId: "22222222-2222-2222-2222-222222222222",
        requestId: "req-abc",
        requestedByUserId: 1,
        deps,
      }),
      (err) => {
        assert.equal(err.code, CERTOPS_DIAGNOSTIC_BOOTSTRAP_ALREADY_CONSUMED);
        return true;
      },
    );

    // The retry must never reach the agent/job insert path at all: the
    // unique violation on the request-row insert is what stops it, before
    // any second credential could be minted.
    assert.equal(mock.agentInsertCalls.length, 1);
    assert.equal(mock.jobCreateCalls.length, 1);
  });

  it("rejects a requestId over 128 characters before touching the database", async () => {
    const mock = createMockDiagnosticBootstrapPool();
    await assert.rejects(
      createDiagnosticBootstrap({
        dbPool: mock.dbPool,
        workspaceId: "22222222-2222-2222-2222-222222222222",
        requestId: "x".repeat(129),
      }),
      (err) => {
        assert.equal(err.code, "CERTOPS_DIAGNOSTIC_BOOTSTRAP_REQUEST_ID_INVALID");
        return true;
      },
    );
    assert.equal(mock.getRequestInsertCount(), 0);
  });
});
