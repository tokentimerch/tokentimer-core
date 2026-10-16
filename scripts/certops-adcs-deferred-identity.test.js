"use strict";
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path");
const subject = require("../tests/e2e/helpers/certops-adcs-deferred-identity");
test("actual deferred readiness accepts omitted immediate-issued ID, never missing poll/current job", () => {
  const row = {
    state: "validation_deferred",
    current_job_id: "owned-job",
    request_id: null,
    next_poll_at: new Date(),
  };
  assert.equal(subject.isDeferredPollReady(row), true);
  assert.equal(
    subject.isDeferredPollReady({ ...row, request_id: undefined }),
    true,
  );
  assert.equal(
    subject.isDeferredPollReady({ ...row, current_job_id: null }),
    false,
  );
  assert.equal(
    subject.isDeferredPollReady({ ...row, next_poll_at: "invalid" }),
    false,
  );
  assert.equal(
    subject.isDeferredPollReady({ ...row, state: "requested" }),
    false,
  );
});
function value() {
  return {
    row: {
      state: "validation_deferred",
      current_job_id: "owned-job",
      request_id: null,
    },
    jobId: "owned-job",
    state: "validation_deferred",
    nativeRequest: { requestId: 42, disposition: 20, subjectRequestCount: 7 },
    journal: {
      kind: "valid",
      journal: {
        state: "validation_deferred",
        jobId: "owned-job",
        ...Object.fromEntries(
          subject.IMMUTABLE.map((name) => [name, `public-${name}`]),
        ),
      },
      artifacts: {
        leafPem: fs.readFileSync(
          path.join(
            __dirname,
            "../packages/agent/src/verify/fixtures/leaf.crt.pem",
          ),
          "utf8",
        ),
      },
    },
  };
}
test("actual immediate-issued omission is accepted only with an independent native RequestId and unchanged recovery artifacts", () => {
  const initial = value(),
    before = subject.observe(initial),
    continued = value();
  continued.jobId = "continuation";
  continued.row.current_job_id = "continuation";
  continued.journal.journal.jobId = "continuation";
  continued.state =
    continued.row.state =
    continued.journal.journal.state =
      "installed";
  assert.ok(subject.verifyRecovery(before, subject.observe(continued)));
  assert.equal(initial.row.request_id, null);
  assert.equal(initial.journal.journal.requestId, undefined);
});
test("missing native ID, mismatched reported ID/current claim or changed durable identity refuse", () => {
  for (const mutate of [
    (v) => {
      delete v.nativeRequest.requestId;
    },
    (v) => {
      v.row.request_id = 43;
    },
    (v) => {
      v.journal.journal.requestId = 43;
    },
    (v) => {
      v.row.current_job_id = "foreign";
    },
    (v) => {
      v.journal.journal.jobId = "foreign";
    },
  ]) {
    const v = value();
    mutate(v);
    assert.throws(() => subject.observe(v));
  }
  const before = subject.observe(value());
  const resubmitted = value();
  resubmitted.nativeRequest.subjectRequestCount++;
  assert.throws(() =>
    subject.verifyRecovery(before, subject.observe(resubmitted)),
  );
  for (const field of subject.IMMUTABLE) {
    const v = value();
    v.journal.journal[field] += "-changed";
    assert.throws(() => subject.verifyRecovery(before, subject.observe(v)));
  }
});
