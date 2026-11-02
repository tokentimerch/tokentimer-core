"use strict";
/** Benign actual loopback transport controls; no agent, CA or qualification. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const crypto = require("node:crypto");
const helper = require("../tests/e2e/helpers/certops-acme-result-outage");
function post(url, path, bytes) {
  return new Promise((resolve, reject) => {
    const request = http.request(
      new URL(path, url),
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(bytes),
          "x-owned-control": "unchanged",
        },
        agent: false,
      },
      (response) => {
        response.resume();
        response.once("end", () => resolve(response.statusCode));
        response.once("error", reject);
      },
    );
    request.once("error", reject);
    request.end(bytes);
  });
}
test("actual loopback result refusal never forwards until restored, then preserves original bytes", async () => {
  const received = [];
  const upstream = http.createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      received.push({
        bytes: Buffer.concat(chunks),
        path: request.url,
        marker: request.headers["x-owned-control"],
      });
      response.writeHead(204).end();
    });
  });
  await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  let gateway;
  try {
    gateway = await helper.startResultOutageGateway({
      upstreamUrl: `http://127.0.0.1:${upstream.address().port}`,
    });
    const jobId = crypto.randomUUID(),
      claimId = crypto.randomUUID();
    gateway.arm(jobId, claimId);
    assert.throws(() => gateway.restoreDelivery());
    const bytes = Buffer.from(
      `{ "messageType" : "result", "body":{"jobId":"${jobId}","claimId":"${claimId}"},"signature":"benign-control-not-a-native-signature" }\n`,
    );
    const endpoint = "/api/v1/certops/agent/jobs/results";
    assert.equal(await post(gateway.agentUrl, endpoint, bytes), 503);
    assert.equal(received.length, 0);
    assert.equal(
      await post(
        gateway.agentUrl,
        endpoint,
        JSON.stringify({
          messageType: "result",
          body: { jobId, claimId: crypto.randomUUID() },
        }),
      ),
      409,
    );
    assert.equal(received.length, 0);
    // Evidence shares the results route in the ACTUAL protocol. It must
    // continue unchanged while the terminal result alone is unavailable.
    const evidence=Buffer.from(JSON.stringify({messageType:'evidence',body:{jobId,claimId,evidenceItems:[]}}));
    assert.equal(await post(gateway.agentUrl,endpoint,evidence),204);
    assert.ok(received.pop().bytes.equals(evidence));
    gateway.restoreDelivery();
    assert.equal(await post(gateway.agentUrl, endpoint, bytes), 204);
    assert.equal(received.length, 1);
    assert.deepEqual(received[0], {
      bytes,
      path: endpoint,
      marker: "unchanged",
    });
    assert.deepEqual(gateway.observation(), {
      refusedResults: 1,
      forwardedResults: 1,
      mismatchedResults: 1,
      deliveryRestored: true,
    });
    assert.equal(
      await post(
        gateway.agentUrl,
        "/api/v1/certops/agent/jobs/results?foreign=1",
        bytes,
      ),
      404,
    );
    assert.equal(
      await post(gateway.agentUrl, endpoint, Buffer.alloc(1048577)),
      413,
    );
    assert.equal(received.length, 1);
  } finally {
    if (gateway) {
      await gateway.close();
      await gateway.close();
      assert.equal(gateway.hasLiveResource(), false);
    }
    await new Promise((resolve, reject) =>
      upstream.close((error) => (error ? reject(error) : resolve())),
    );
  }
});
test("gateway authority is one explicit loopback HTTP endpoint", () => {
  for (const value of [
    "https://127.0.0.1:4000",
    "http://localhost:4000",
    "http://127.0.0.1:4000/foreign",
    "http://user:password@127.0.0.1:4000",
    "http://127.0.0.1:4000/?x=1",
    "http://127.0.0.1:4000/#fragment",
  ])
    assert.throws(() => helper.upstream(value));
  assert.deepEqual(helper.upstream("http://127.0.0.1:4000"), {
    hostname: "127.0.0.1",
    port: 4000,
  });
});
