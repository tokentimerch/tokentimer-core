"use strict";

/**
 * Focused test for scripts/certops-audit-nonce-ledger.cjs. Modeled on
 * tests/unit/certops-job-signing.test.js's in-memory pg-client stand-in:
 * this repo's fast unit tier
 * (`pnpm run test:unit`) runs with no live infra, so the query itself is
 * exercised against a minimal in-memory client that mirrors the exact
 * JOIN/WHERE the script issues against certificate_jobs and
 * certops_consumed_nonces, rather than against a real Postgres.
 *
 * Seeds one clean case (a job whose claimed_by_agent_id matches the
 * issued_to_agent_id on its consumed nonce row) and one anomalous case (a
 * result attributed to a different agent than the nonce was issued to),
 * and asserts the script surfaces exactly the anomalous one.
 */

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  findNonceLedgerAnomalies,
} = require(
  path.resolve(__dirname, "../../scripts/certops-audit-nonce-ledger.cjs"),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";
const AGENT_ISSUED = "22222222-2222-4222-8222-222222222222";
const AGENT_OTHER = "33333333-3333-4333-8333-333333333333";

/**
 * Minimal in-memory stand-in for the pg Pool/client, covering exactly the
 * one read-only query certops-audit-nonce-ledger.cjs issues: a JOIN of
 * certificate_jobs and certops_consumed_nonces on (job_id, workspace_id),
 * filtered to consumed nonces with a non-null agent id on both sides that
 * disagree.
 */
function createMemoryClient({ jobs, nonces }) {
  return {
    jobs,
    nonces,
    async query(sql) {
      const normalized = sql.replace(/\s+/g, " ").trim();
      if (
        !normalized.includes("FROM certificate_jobs") ||
        !normalized.includes("JOIN certops_consumed_nonces")
      ) {
        throw new Error(`memory client: unhandled query: ${normalized}`);
      }

      const rows = [];
      for (const job of jobs) {
        for (const nonce of nonces) {
          if (nonce.job_id !== job.id) continue;
          if (nonce.workspace_id !== job.workspace_id) continue;
          if (nonce.consumed_at === null || nonce.consumed_at === undefined) {
            continue;
          }
          if (job.claimed_by_agent_id === null) continue;
          if (nonce.issued_to_agent_id === null) continue;
          if (job.claimed_by_agent_id === nonce.issued_to_agent_id) continue;

          rows.push({
            job_id: job.id,
            workspace_id: job.workspace_id,
            result_agent_id: job.claimed_by_agent_id,
            issued_to_agent_id: nonce.issued_to_agent_id,
            nonce: nonce.nonce,
            consumed_at: nonce.consumed_at,
            status: job.status,
            completed_at: job.completed_at,
          });
        }
      }
      return { rows };
    },
  };
}

function baseJob(overrides = {}) {
  return {
    id: "job-0000",
    workspace_id: WORKSPACE_A,
    claimed_by_agent_id: AGENT_ISSUED,
    status: "succeeded",
    completed_at: new Date("2026-08-01T00:00:00.000Z"),
    ...overrides,
  };
}

function baseNonce(overrides = {}) {
  return {
    nonce: "clean-nonce-0000000000001",
    job_id: "job-0000",
    workspace_id: WORKSPACE_A,
    issued_to_agent_id: AGENT_ISSUED,
    consumed_at: new Date("2026-08-01T00:00:05.000Z"),
    ...overrides,
  };
}

describe("certops-audit-nonce-ledger findNonceLedgerAnomalies", () => {
  it("surfaces exactly the anomalous job and not the clean one", async () => {
    const cleanJob = baseJob({ id: "job-clean" });
    const cleanNonce = baseNonce({
      nonce: "clean-nonce-0000000000001",
      job_id: "job-clean",
      issued_to_agent_id: AGENT_ISSUED,
    });

    const anomalousJob = baseJob({
      id: "job-anomalous",
      claimed_by_agent_id: AGENT_OTHER,
    });
    const anomalousNonce = baseNonce({
      nonce: "anomalous-nonce-0000000002",
      job_id: "job-anomalous",
      issued_to_agent_id: AGENT_ISSUED,
    });

    const client = createMemoryClient({
      jobs: [cleanJob, anomalousJob],
      nonces: [cleanNonce, anomalousNonce],
    });

    const anomalies = await findNonceLedgerAnomalies(client);

    assert.equal(anomalies.length, 1);
    assert.equal(anomalies[0].job_id, "job-anomalous");
    assert.equal(anomalies[0].result_agent_id, AGENT_OTHER);
    assert.equal(anomalies[0].issued_to_agent_id, AGENT_ISSUED);
    assert.equal(anomalies[0].nonce, "anomalous-nonce-0000000002");
  });

  it("reports no anomalies when every consumed nonce's issued_to_agent_id matches the job's claimed_by_agent_id", async () => {
    const jobA = baseJob({ id: "job-a", claimed_by_agent_id: AGENT_ISSUED });
    const jobB = baseJob({ id: "job-b", claimed_by_agent_id: AGENT_OTHER });
    const nonceA = baseNonce({
      nonce: "nonce-a",
      job_id: "job-a",
      issued_to_agent_id: AGENT_ISSUED,
    });
    const nonceB = baseNonce({
      nonce: "nonce-b",
      job_id: "job-b",
      issued_to_agent_id: AGENT_OTHER,
    });

    const client = createMemoryClient({
      jobs: [jobA, jobB],
      nonces: [nonceA, nonceB],
    });

    const anomalies = await findNonceLedgerAnomalies(client);
    assert.deepEqual(anomalies, []);
  });

  it("does not flag an unconsumed nonce (no result was ever ingested against it)", async () => {
    const job = baseJob({ id: "job-pending", claimed_by_agent_id: AGENT_OTHER });
    const nonce = baseNonce({
      nonce: "pending-nonce",
      job_id: "job-pending",
      issued_to_agent_id: AGENT_ISSUED,
      consumed_at: null,
    });

    const client = createMemoryClient({ jobs: [job], nonces: [nonce] });

    const anomalies = await findNonceLedgerAnomalies(client);
    assert.deepEqual(anomalies, []);
  });

  it("does not flag a nonce ledger row with a null issued_to_agent_id (unattributable, not a mismatch)", async () => {
    const job = baseJob({ id: "job-broadcast", claimed_by_agent_id: AGENT_OTHER });
    const nonce = baseNonce({
      nonce: "broadcast-nonce",
      job_id: "job-broadcast",
      issued_to_agent_id: null,
    });

    const client = createMemoryClient({ jobs: [job], nonces: [nonce] });

    const anomalies = await findNonceLedgerAnomalies(client);
    assert.deepEqual(anomalies, []);
  });
});
