"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  createJobLogSession,
  withJobConsole,
  mirrorToJobConsole,
  closeInBackground,
  drainJobLogSessions,
  inferStep,
  MAX_BATCH_LINES,
} = require("./index.js");
const { AGENT_PROTOCOL_ERROR_CODES } = require("../protocol");

function ok(body) {
  return {
    status: 200,
    json: { ackThroughSeq: body.lines.at(-1)?.seq || 0, streamDisabled: false },
  };
}

function protocolError(code) {
  const error = new Error("refused");
  error.code = code;
  return error;
}

test("retries a batch with the same seq and sends an empty final after close", async () => {
  const posts = [];
  let failedOnce = false;
  const session = createJobLogSession({
    jobId: "job-1",
    claimId: "claim-1",
    sleep: async () => {},
    now: () => 0,
    post: async (request) => {
      posts.push(request.body);
      if (!failedOnce && request.body.final !== true) {
        failedOnce = true;
        return { status: 503, retryAfterMs: 0, json: {} };
      }
      return {
        status: 200,
        json: {
          ackThroughSeq: request.body.lines.at(-1)?.seq || 0,
          newlyStored: request.body.lines.length,
          duplicateCount: 0,
          serverDroppedCount: 0,
          streamDisabled: false,
        },
      };
    },
  });
  session.logger.step("deploy").info("Deploying certificate");
  await session.flush();
  await session.close();
  const dataPosts = posts.filter((body) => body.final !== true);
  assert.equal(dataPosts.length, 2);
  assert.equal(dataPosts[0].lines[0].seq, dataPosts[1].lines[0].seq);
  assert.equal(dataPosts[0].lines[0].message, "Deploying certificate");
  assert.equal(posts.at(-1).final, true);
  assert.equal(posts.at(-1).lines.length, 0);
  assert.equal("sequence" in posts[0], false);
});

test("splits a batch when the server answers 413", async () => {
  const sizes = [];
  const session = createJobLogSession({
    jobId: "job-1",
    claimId: "claim-2",
    maxBatchBytes: 64 * 1024,
    sleep: async () => {},
    now: () => 0,
    post: async (request) => {
      sizes.push(request.body.lines.length);
      if (request.body.lines.length > 1) return { status: 413, json: {} };
      return {
        status: 200,
        json: { ackThroughSeq: request.body.lines[0]?.seq || 0, streamDisabled: false },
      };
    },
  });
  session.logger.info("one");
  session.logger.info("two");
  await session.flush();
  assert.ok(sizes.includes(2));
  assert.ok(sizes.includes(1));
});

test("never sends more lines than the schema allows in one batch", async () => {
  const bodies = [];
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const session = createJobLogSession({
    jobId: "job-1",
    claimId: "claim-cap",
    sleep: async () => {},
    post: async ({ body }) => {
      await gate;
      bodies.push(body);
      return ok(body);
    },
  });
  for (let i = 0; i < 450; i += 1) session.logger.info(`line ${i}`);
  release();
  await session.close();
  const data = bodies.filter((body) => body.final !== true);
  assert.ok(data.every((body) => body.lines.length <= MAX_BATCH_LINES));
  const seqs = data.flatMap((body) => body.lines.map((line) => line.seq));
  assert.deepEqual(seqs, Array.from({ length: 450 }, (_, i) => i + 1));
});

test("flattens fields to the schema shape before sending", async () => {
  const bodies = [];
  const session = createJobLogSession({
    jobId: "job-1",
    claimId: "claim-fields",
    sleep: async () => {},
    post: async ({ body }) => {
      bodies.push(body);
      return ok(body);
    },
  });
  session.logger.info("with fields", { nested: { a: 1 }, list: [1], host: "web-1", port: 443, tls: true });
  await session.close();
  assert.deepEqual(bodies[0].lines[0].fields, { host: "web-1", port: 443, tls: true });
});

test("drops a batch the server rejects with a client error and keeps streaming", async () => {
  const bodies = [];
  const session = createJobLogSession({
    jobId: "job-1",
    claimId: "claim-400",
    sleep: async () => {},
    post: async ({ body }) => {
      bodies.push(body);
      if (body.lines[0]?.message === "bad") return { status: 422, json: {} };
      return ok(body);
    },
  });
  session.logger.info("bad");
  await session.flush();
  session.logger.info("good");
  await session.close();
  assert.equal(bodies.filter((body) => body.lines[0]?.message === "bad").length, 1);
  const good = bodies.find((body) => body.lines[0]?.message === "good");
  assert.equal(good.droppedBefore, 1);
  assert.equal(bodies.at(-1).final, true);
});

test("does not retry a batch the protocol layer refused locally", async () => {
  let calls = 0;
  const session = createJobLogSession({
    jobId: "job-1",
    claimId: "claim-local",
    sleep: async () => {},
    post: async ({ body }) => {
      calls += 1;
      if (!body.final) throw protocolError(AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE);
      return ok(body);
    },
  });
  session.logger.info("refused");
  await session.flush();
  assert.equal(calls, 1);
});

test("retries network errors", async () => {
  let calls = 0;
  const session = createJobLogSession({
    jobId: "job-1",
    claimId: "claim-net",
    sleep: async () => {},
    post: async ({ body }) => {
      calls += 1;
      if (calls < 3) throw protocolError(AGENT_PROTOCOL_ERROR_CODES.NETWORK_ERROR);
      return ok(body);
    },
  });
  session.logger.info("eventually");
  assert.equal(await session.flush(), true);
  assert.equal(calls, 3);
});

test("stops the stream when the claim is unknown", async () => {
  const bodies = [];
  const session = createJobLogSession({
    jobId: "job-1",
    claimId: "claim-gone",
    sleep: async () => {},
    post: async ({ body }) => {
      bodies.push(body);
      return { status: 409, json: {} };
    },
  });
  session.logger.info("first");
  await session.flush();
  session.logger.info("second");
  await session.close();
  assert.equal(bodies.length, 1);
});

test("close finishes within its budget when the server never accepts", async () => {
  let clock = 0;
  const session = createJobLogSession({
    jobId: "job-1",
    claimId: "claim-slow",
    now: () => clock,
    sleep: async (ms) => { clock += Math.max(ms, 1); },
    post: async () => {
      clock += 100;
      return { status: 503, json: {} };
    },
  });
  for (let i = 0; i < 300; i += 1) session.logger.info(`line ${i}`);
  await session.close();
  assert.ok(clock <= 60_000 + 1_000, `close took ${clock}ms of fake time`);
});

test("mirrors printed job lines without the job prefix", async () => {
  const bodies = [];
  const session = createJobLogSession({
    jobId: "job-7",
    claimId: "claim-mirror",
    sleep: async () => {},
    post: async ({ body }) => {
      bodies.push(body);
      return ok(body);
    },
  });
  withJobConsole(session, () => {
    mirrorToJobConsole("info", "job job-7: verifying deployed certificate at /etc/ssl/a.pem");
    mirrorToJobConsole("info", "job job-7: WARNING: binding precedence differs");
  });
  mirrorToJobConsole("info", "job job-7: outside the job context");
  await session.close();
  const lines = bodies[0].lines;
  assert.equal(lines.length, 2);
  assert.equal(lines[0].message, "verifying deployed certificate at /etc/ssl/a.pem");
  assert.equal(lines[0].step, "verify");
  assert.equal(lines[1].level, "warn");
});

test("infers steps from the leading verb", () => {
  assert.equal(inferStep("deploying certificate to /x", "other"), "deploy");
  assert.equal(inferStep("reloading service nginx", "other"), "reload");
  assert.equal(inferStep("ACME order succeeded", "other"), "acme");
  assert.equal(inferStep("something else", "claim"), "claim");
});

test("background close does not block and shutdown drain is bounded", async () => {
  const session = createJobLogSession({
    jobId: "job-1",
    claimId: "claim-hang",
    post: () => new Promise(() => {}),
  });
  session.logger.info("stuck");
  const started = Date.now();
  closeInBackground(session);
  assert.ok(Date.now() - started < 50);
  await drainJobLogSessions(50);
  assert.ok(Date.now() - started < 1000);
});
