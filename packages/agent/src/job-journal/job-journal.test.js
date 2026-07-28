"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  markSideEffectReached,
  scanUnresolvedJournalEntries,
  hasUnresolvedJournalForJob,
  clearJournalOnTerminal,
  formatUnresolvedJournalReport,
} = require("./index.js");

describe("job-journal", () => {
  it("persists, scans, and clears markers without embedding secrets", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-job-journal-"));
    try {
      const marked = markSideEffectReached({
        stateDir: dir,
        jobId: "job-1",
        attemptId: "attempt-1",
        claimId: "claim-1",
        stage: "deploy",
      });
      assert.equal(marked.created, true);
      assert.equal(hasUnresolvedJournalForJob(dir, "job-1"), true);
      const unresolved = scanUnresolvedJournalEntries(dir);
      assert.equal(unresolved.length, 1);
      assert.doesNotMatch(JSON.stringify(unresolved), /BEGIN [A-Z0-9 ]*PRIVATE KEY/);
      assert.match(formatUnresolvedJournalReport(unresolved), /job-1/);
      assert.equal(
        clearJournalOnTerminal({
          stateDir: dir,
          jobId: "job-1",
          attemptId: "attempt-1",
          status: "failed",
        }).cleared,
        true,
      );
      assert.equal(hasUnresolvedJournalForJob(dir, "job-1"), false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
