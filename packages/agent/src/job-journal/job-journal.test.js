"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  markSideEffectReached,
  recordWindowsCngContainer,
  markWindowsCngContainerReconciled,
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

  describe("recordWindowsCngContainer / markWindowsCngContainerReconciled", () => {
    it("attaches the container name and store onto an already-existing entry", () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-job-journal-"));
      try {
        markSideEffectReached({
          stateDir: dir,
          jobId: "job-1",
          attemptId: "attempt-1",
          stage: "keygen",
        });
        const result = recordWindowsCngContainer({
          stateDir: dir,
          jobId: "job-1",
          attemptId: "attempt-1",
          containerName: "tokentimer-job-1-abcd1234",
          store: "WebHosting",
        });
        assert.notEqual(result, null);
        const [entry] = scanUnresolvedJournalEntries(dir);
        assert.equal(entry.windowsCngContainerName, "tokentimer-job-1-abcd1234");
        assert.equal(entry.windowsCngStore, "WebHosting");
        // stage is untouched: this function enriches, never overwrites,
        // the fields markSideEffectReached itself owns.
        assert.equal(entry.stage, "keygen");
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it("is a no-op (returns null) when no journal entry exists yet for this attempt", () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-job-journal-"));
      try {
        const result = recordWindowsCngContainer({
          stateDir: dir,
          jobId: "job-1",
          attemptId: "attempt-1",
          containerName: "tokentimer-job-1-abcd1234",
        });
        assert.equal(result, null);
        assert.equal(scanUnresolvedJournalEntries(dir).length, 0);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it("rejects a containerName outside the closed alphabet", () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-job-journal-"));
      try {
        markSideEffectReached({ stateDir: dir, jobId: "job-1", attemptId: "attempt-1", stage: "keygen" });
        assert.throws(() =>
          recordWindowsCngContainer({
            stateDir: dir,
            jobId: "job-1",
            attemptId: "attempt-1",
            containerName: "not; safe",
          }),
        );
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it("markWindowsCngContainerReconciled stamps a timestamp without clearing the entry", () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-job-journal-"));
      try {
        markSideEffectReached({ stateDir: dir, jobId: "job-1", attemptId: "attempt-1", stage: "keygen" });
        recordWindowsCngContainer({
          stateDir: dir,
          jobId: "job-1",
          attemptId: "attempt-1",
          containerName: "tokentimer-job-1-abcd1234",
        });
        const result = markWindowsCngContainerReconciled({
          stateDir: dir,
          jobId: "job-1",
          attemptId: "attempt-1",
        });
        assert.notEqual(result, null);
        // Still unresolved: container lifecycle and job-attempt-outcome
        // lifecycle are deliberately separate (see the module's own doc
        // comment on markWindowsCngContainerReconciled).
        assert.equal(hasUnresolvedJournalForJob(dir, "job-1"), true);
        const [entry] = scanUnresolvedJournalEntries(dir);
        assert.equal(typeof entry.windowsCngContainerReconciledAt, "string");
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });
});
