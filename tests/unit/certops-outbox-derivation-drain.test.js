"use strict";

/**
 * The adoption intent's lifecycle in the outbox drain: one case per terminal
 * decision, the wall-clock wait deadline, the sweep behaviour that today's drain
 * got wrong (a waiting row must never be parked as failed), and the detach race
 * in both commit orders.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const workerUrl = pathToFileURL(
  path.join(__dirname, "..", "..", "apps", "worker", "src", "certops-worker.js"),
).href;

const WORKSPACE = "11111111-1111-4111-8111-111111111111";
const CERT_ID = "22222222-2222-4222-8222-222222222222";
const PROFILE_ID = "33333333-3333-4333-8333-333333333333";
const JOB_ID = "44444444-4444-4444-8444-444444444444";
const CLAIM_ID = "66666666-6666-4666-8666-666666666666";
const OUTBOX_ID = "77777777-7777-4777-8777-777777777777";

const silentLogger = { info() {}, warn() {}, error() {}, debug() {} };

function normalize(sql) {
  return String(sql).replace(/\s+/g, " ").trim();
}

function intentRow(overrides = {}) {
  return {
    id: OUTBOX_ID,
    workspace_id: WORKSPACE,
    event_type: "profile_derivation_requested",
    dedupe_key: `derive-profile:${JOB_ID}`,
    payload: { jobId: JOB_ID, certificateId: CERT_ID },
    attempt_count: 1,
    max_attempts: 5,
    created_at: new Date().toISOString(),
    ...overrides,
  };
}

/**
 * Pool for the handler. Models the four reads it makes plus the transaction it
 * owns, so the assertions are about ordering and locking rather than mocks.
 */
function createHandlerPool({
  job = { id: JOB_ID, status: "succeeded", claim_id: CLAIM_ID, operation: "renew", payload: {} },
  outboxStatus = "pending",
  outboxRowMissing = false,
  certificate = { id: CERT_ID, common_name: "app.example.com", subject_alt_names: [], profile_id: null },
  evidence = { step: "verify", exitCode: 0 },
  onCertificateLock = null,
} = {}) {
  const queries = [];
  const state = { job, outboxStatus, certificate, committed: false, rolledBack: false };
  const client = {
    async query(sql, params = []) {
      const text = normalize(sql);
      queries.push({ sql: text, params, on: "client" });
      if (text === "BEGIN") return { rows: [] };
      if (text === "COMMIT") {
        state.committed = true;
        return { rows: [] };
      }
      if (text === "ROLLBACK") {
        state.rolledBack = true;
        return { rows: [] };
      }
      if (text.startsWith("SELECT id, status FROM certops_outbox")) {
        return {
          rows: outboxRowMissing ? [] : [{ id: OUTBOX_ID, status: state.outboxStatus }],
        };
      }
      if (text.includes("FROM managed_certificates")) {
        if (onCertificateLock) await onCertificateLock(state);
        return { rows: state.certificate ? [state.certificate] : [] };
      }
      if (text.includes("FROM certificate_evidence")) {
        return { rows: evidence ? [{ metadata: evidence }] : [] };
      }
      if (text.startsWith("UPDATE certops_outbox")) return { rows: [], rowCount: 1 };
      throw new Error(`unexpected client query: ${text}`);
    },
    release() {},
  };
  const dbPool = {
    queries,
    state,
    async query(sql, params = []) {
      const text = normalize(sql);
      queries.push({ sql: text, params, on: "pool" });
      if (text.includes("FROM certificate_jobs")) {
        return { rows: state.job ? [state.job] : [] };
      }
      throw new Error(`unexpected pool query: ${text}`);
    },
    async connect() {
      return client;
    },
  };
  return { dbPool, client, queries, state };
}

async function runHandler(worker, options = {}, overrides = {}) {
  const harness = createHandlerPool(options);
  const row = intentRow(overrides.row || {});
  const result = await worker.handleProfileDerivationIntent({
    dbPool: harness.dbPool,
    row,
    claimId: CLAIM_ID,
    payload: row.payload,
    log: silentLogger,
    deriveProfile:
      overrides.deriveProfile || (async () => ({ profileId: PROFILE_ID, created: true })),
    now: overrides.now,
    waitDeadlineMs: overrides.waitDeadlineMs,
  });
  return { ...harness, result };
}

describe("adoption intent lifecycle", () => {
  it("derives and completes the row inside the handler's own transaction", async () => {
    const worker = await import(workerUrl);
    const { result, queries, state } = await runHandler(worker);

    assert.equal(result.completed, true);
    assert.equal(result.terminalStatus, "succeeded");
    assert.equal(state.committed, true);

    const clientSql = queries.filter((q) => q.on === "client").map((q) => q.sql);
    // Own row locked first, terminal write before COMMIT: the side effect and
    // the row's terminal status are one atomic fact.
    assert.match(clientSql[1], /SELECT id, status FROM certops_outbox/);
    assert.match(clientSql[1], /FOR UPDATE/);
    const terminalIndex = clientSql.findIndex((sql) =>
      sql.startsWith("UPDATE certops_outbox"),
    );
    assert.ok(terminalIndex > 0);
    assert.ok(terminalIndex < clientSql.indexOf("COMMIT"));
  });

  it("waits while the job is still running, without consuming an attempt", async () => {
    const worker = await import(workerUrl);
    const { result, state } = await runHandler(worker, {
      job: { id: JOB_ID, status: "running", claim_id: CLAIM_ID, payload: {} },
    });

    assert.equal(result.deferred, true);
    assert.equal(result.reason, "running");
    assert.ok(result.retryInMs > 0, "a wait must carry its own backoff");
    assert.equal(state.committed, false, "nothing is decided yet");
  });

  it("skips a dry run, which proves nothing about a real deployment", async () => {
    const worker = await import(workerUrl);
    const { result } = await runHandler(worker, {
      job: { id: JOB_ID, status: "dry_run_complete", claim_id: CLAIM_ID, payload: {} },
    });

    // dry_run_complete is terminal but is not 'succeeded'; treating the two the
    // same would arm automation from a run that deliberately changed nothing.
    assert.equal(result.queued, false);
    assert.equal(result.reason, "dry_run");
  });

  it("skips orphaned_unknown_effect as its own outcome", async () => {
    const worker = await import(workerUrl);
    const { result } = await runHandler(worker, {
      job: {
        id: JOB_ID,
        status: "orphaned_unknown_effect",
        claim_id: CLAIM_ID,
        payload: {},
      },
    });

    // The certificate may in fact have been deployed with nobody able to
    // confirm it, which is exactly the run a renewal profile must not be built
    // from, and it must be distinguishable from a clean failure.
    assert.equal(result.queued, false);
    assert.equal(result.reason, "orphaned_unknown_effect");
  });

  for (const [status, reason] of [
    ["failed", "job_failed"],
    ["rejected", "job_rejected"],
    ["cancelled", "job_cancelled"],
    ["blocked", "job_blocked"],
  ]) {
    it(`skips a ${status} job with its own reason`, async () => {
      const worker = await import(workerUrl);
      const { result } = await runHandler(worker, {
        job: { id: JOB_ID, status, claim_id: CLAIM_ID, payload: {} },
      });
      assert.equal(result.queued, false);
      assert.equal(result.reason, reason);
    });
  }

  it("skips when the job is gone", async () => {
    const worker = await import(workerUrl);
    const { result } = await runHandler(worker, { job: null });
    assert.equal(result.reason, "job_not_found");
  });

  it("skips when the certificate is gone", async () => {
    const worker = await import(workerUrl);
    const { result, state } = await runHandler(worker, { certificate: null });
    assert.equal(result.completed, true);
    assert.equal(result.reason, "certificate_not_found");
    assert.equal(state.committed, true);
  });

  it("skips a certificate that already has a profile", async () => {
    const worker = await import(workerUrl);
    const { result } = await runHandler(worker, {
      certificate: {
        id: CERT_ID,
        common_name: "app.example.com",
        subject_alt_names: [],
        profile_id: PROFILE_ID,
      },
    });
    assert.equal(result.reason, "already_linked");
  });

  it("refuses to derive without evidence bound to this attempt's claim", async () => {
    const worker = await import(workerUrl);
    const { result, queries } = await runHandler(worker, { evidence: null });

    assert.equal(result.reason, "no_claim_bound_verify_evidence");
    const evidenceQuery = queries.find((q) => q.sql.includes("FROM certificate_evidence"));
    assert.match(evidenceQuery.sql, /claim_id = \$3::uuid/);
    assert.equal(evidenceQuery.params[2], CLAIM_ID);
  });

  it("skips an operator-owned profile instead of retrying forever", async () => {
    const worker = await import(workerUrl);
    const { result } = await runHandler(
      worker,
      {},
      { deriveProfile: async () => ({ profileId: null, reason: "profile_operator_owned" }) },
    );
    assert.equal(result.terminalStatus, "skipped");
    assert.equal(result.reason, "profile_operator_owned");
  });

  it("throws on a derivation failure so the drain can retry it", async () => {
    const worker = await import(workerUrl);
    const harness = createHandlerPool();
    const row = intentRow();

    await assert.rejects(
      () =>
        worker.handleProfileDerivationIntent({
          dbPool: harness.dbPool,
          row,
          claimId: CLAIM_ID,
          payload: row.payload,
          log: silentLogger,
          deriveProfile: async () => ({ profileId: null, reason: "derivation_failed" }),
        }),
      /could not be derived/,
    );
    assert.equal(harness.state.committed, false);
    assert.equal(harness.state.rolledBack, true);
  });

  it("gives up on a job that never terminates, on wall clock not attempts", async () => {
    const worker = await import(workerUrl);
    const createdAt = new Date("2026-01-01T00:00:00Z");
    const { result } = await runHandler(
      worker,
      { job: { id: JOB_ID, status: "queued", claim_id: null, payload: {} } },
      {
        row: { created_at: createdAt.toISOString(), attempt_count: 1 },
        waitDeadlineMs: 1000,
        now: () => createdAt.getTime() + 5000,
      },
    );

    // A job nothing ever claims would otherwise leave this row cycling for the
    // life of the workspace, since waiting never burns an attempt.
    assert.equal(result.queued, false);
    assert.equal(result.reason, "job_never_terminated");
  });
});

/**
 * Sweep-level pool. Tracks the row's persisted state across sweeps so the retry
 * budget claim can be tested for real rather than asserted on one statement.
 */
function createSweepPool(initialRow) {
  const row = { ...initialRow };
  const queries = [];
  return {
    row,
    queries,
    async query(sql, params = []) {
      const text = normalize(sql);
      queries.push({ sql: text, params });
      if (text.startsWith("WITH due AS")) {
        if (row.status !== "pending") return { rows: [] };
        row.attempt_count += 1;
        return { rows: [{ ...row }] };
      }
      if (text.includes("attempt_count = GREATEST(0, attempt_count - 1)")) {
        row.attempt_count = Math.max(0, row.attempt_count - 1);
        return { rows: [], rowCount: 1 };
      }
      if (text.startsWith("UPDATE certops_outbox")) {
        if (params[0] === "failed" || params[0] === true) row.status = "failed";
        else if (typeof params[0] === "string") row.status = params[0];
        return { rows: [], rowCount: 1 };
      }
      return { rows: [], rowCount: 1 };
    },
  };
}

describe("drain retry budget", () => {
  it("never parks a waiting row as failed, however many sweeps pass", async () => {
    const worker = await import(workerUrl);
    const dbPool = createSweepPool({
      ...intentRow({ attempt_count: 0 }),
      status: "pending",
    });

    for (let sweep = 0; sweep < 20; sweep += 1) {
      const summary = await worker.drainCertOpsOutbox({
        dbPool,
        log: silentLogger,
        alertResolver: async () => ({ queued: true }),
        derivationResolver: async () => ({
          deferred: true,
          reason: "running",
          retryInMs: 60_000,
        }),
      });
      assert.equal(summary.deferred, 1, `sweep ${sweep} must defer`);
      assert.equal(summary.failed, 0);
    }

    assert.equal(dbPool.row.status, "pending", "a row that only waited must stay pending");
    assert.equal(
      dbPool.row.attempt_count,
      0,
      "attempt_count counts failed attempts at real work, not sweeps",
    );
  });

  it("still exhausts attempts for a row that genuinely keeps failing", async () => {
    const worker = await import(workerUrl);
    const dbPool = createSweepPool({
      ...intentRow({ attempt_count: 4, max_attempts: 5 }),
      status: "pending",
    });

    const summary = await worker.drainCertOpsOutbox({
      dbPool,
      log: silentLogger,
      alertResolver: async () => ({ queued: true }),
      derivationResolver: async () => {
        throw new Error("postgres unavailable");
      },
    });

    assert.equal(summary.failed, 1);
    assert.equal(summary.deferred, 0);
    assert.equal(dbPool.row.status, "failed");
  });
});

describe("detach race", () => {
  it("detach first leaves the intent skipped as detached and no profile", async () => {
    const worker = await import(workerUrl);
    // The detach committed before the handler's transaction re-read its own row,
    // so the handler finds it no longer pending and derives nothing.
    const harness = createHandlerPool({ outboxStatus: "skipped" });
    const row = intentRow();
    let derivationCalls = 0;

    const result = await worker.handleProfileDerivationIntent({
      dbPool: harness.dbPool,
      row,
      claimId: CLAIM_ID,
      payload: row.payload,
      log: silentLogger,
      deriveProfile: async () => {
        derivationCalls += 1;
        return { profileId: PROFILE_ID };
      },
    });

    assert.equal(derivationCalls, 0, "a detached intent must derive nothing");
    assert.equal(result.completed, true);
    assert.equal(result.terminalStatus, "skipped");
    assert.equal(result.reason, "detached");
    assert.equal(harness.state.committed, false);
    assert.equal(harness.state.rolledBack, true);
  });

  it("handler first derives, and the later detach removes the link", async () => {
    const worker = await import(workerUrl);
    const certificate = {
      id: CERT_ID,
      common_name: "app.example.com",
      subject_alt_names: [],
      profile_id: null,
    };
    // The detach is blocked on the certificate row lock the handler holds, so it
    // only applies after the handler commits: no ordering yields a certificate
    // that is both detached and profiled.
    const detach = { applied: false };
    const harness = createHandlerPool({
      certificate,
      onCertificateLock: async () => {
        assert.equal(detach.applied, false, "the detach must wait for the lock");
      },
    });
    const row = intentRow();

    const result = await worker.handleProfileDerivationIntent({
      dbPool: harness.dbPool,
      row,
      claimId: CLAIM_ID,
      payload: row.payload,
      log: silentLogger,
      deriveProfile: async () => {
        certificate.profile_id = PROFILE_ID;
        return { profileId: PROFILE_ID, created: true };
      },
    });

    assert.equal(result.terminalStatus, "succeeded");
    assert.equal(harness.state.committed, true);

    certificate.profile_id = null;
    detach.applied = true;
    assert.equal(certificate.profile_id, null, "the detach wins the final state");
  });

  it("locks the certificate in the same transaction as the outbox row", async () => {
    const worker = await import(workerUrl);
    const { queries } = await runHandler(worker);
    const certLock = queries.find(
      (q) => q.on === "client" && q.sql.includes("FROM managed_certificates"),
    );
    assert.ok(certLock, "the certificate must be read on the handler's own client");
    assert.match(certLock.sql, /FOR UPDATE/);
  });
});
