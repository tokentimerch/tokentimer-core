"use strict";
/** Benign loopback transport fixture only; no real agent, API, CA or service. */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const http = require("node:http");
const { setTimeout: delay } = require("node:timers/promises");
const {
  prepareOutputPrivacy,
} = require("../tests/e2e/helpers/certops-windows-output-privacy");
function post(origin, body) {
  return new Promise((resolve, reject) => {
    const request = http.request(
      new URL("/api/v1/certops/agent/jobs/results", origin),
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        agent: false,
      },
      (response) => {
        response.resume();
        response.once("end", () => resolve(response.statusCode));
      },
    );
    request.setTimeout(5000, () =>
      request.destroy(new Error("Owned transport fixture timed out")),
    );
    request.once("error", reject);
    request.end(body);
  });
}
test(
  "owned result barrier holds only exact original result before forwarding and drains without replay",
  { timeout: 15000 },
  async () => {
    const root = fs.mkdtempSync(
      path.join(os.tmpdir(), "certops-result-barrier-"),
    );
    const original = fs.lstatSync(root, { bigint: true });
    const received = [];
    const upstream = http.createServer((request, response) => {
      const chunks = [];
      request.on("data", (chunk) => chunks.push(chunk));
      request.once("end", () => {
        received.push(Buffer.concat(chunks).toString("utf8"));
        response.end("{}");
      });
    });
    let proxy;
    try {
      await new Promise((resolve, reject) => {
        upstream.once("error", reject);
        upstream.listen(0, "127.0.0.1", resolve);
      });
      proxy = await prepareOutputPrivacy(
        root,
        process.execPath,
        [],
        `http://127.0.0.1:${upstream.address().port}`,
      );
      const jobId = "11111111-1111-4111-8111-111111111111",
        claimId = "22222222-2222-4222-8222-222222222222";
      proxy.armResultBarrier(jobId, claimId);
      const evidence = JSON.stringify({
        messageType: "evidence",
        body: { jobId, claimId, evidenceItems: [] },
      });
      assert.equal(await post(proxy.agentUrl, evidence), 200);
      assert.deepEqual(received, [evidence]);
      const foreignClaim = JSON.stringify({
        messageType: "result",
        body: {
          jobId,
          claimId: "33333333-3333-4333-8333-333333333333",
          status: "failed",
        },
      });
      assert.equal(await post(proxy.agentUrl, foreignClaim), 200);
      assert.deepEqual(received, [evidence, foreignClaim]);
      const owned = JSON.stringify({
        messageType: "result",
        body: { jobId, claimId, status: "failed" },
      });
      let settled = false;
      const held = post(proxy.agentUrl, owned).then(
        () => {
          settled = true;
          return "unexpected-response";
        },
        () => {
          settled = true;
          return "closed-without-response";
        },
      );
      const deadline = performance.now() + 3000;
      while (
        proxy.resultBarrierObservation().actualHeldRequests === 0 &&
        performance.now() < deadline
      )
        await delay(10);
      assert.equal(proxy.resultBarrierObservation().actualHeldRequests, 1);
      assert.equal(settled, false);
      assert.deepEqual(received, [evidence, foreignClaim]);
      await proxy.discardHeldResults();
      assert.equal(await held, "closed-without-response");
      assert.equal(proxy.resultBarrierObservation(), null);
      assert.deepEqual(
        received,
        [evidence, foreignClaim],
        "Discarded original result must never be replayed",
      );
    } finally {
      if (proxy) await proxy.close();
      upstream.closeAllConnections();
      await new Promise((resolve) => upstream.close(resolve));
      const current = fs.lstatSync(root, { bigint: true });
      assert.ok(
        current.dev === original.dev &&
          current.ino === original.ino &&
          !current.isSymbolicLink(),
      );
      fs.rmSync(root, { recursive: true });
    }
  },
);
