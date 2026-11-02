const { test } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const {
  getRequestContext,
  attachRequestContext,
  requestCorrelation,
} = require("../../apps/api/utils/request-context");

test("concurrent HTTP requests keep their own correlation through async work", async (t) => {
  const records = [];
  const server = http.createServer((req, res) => {
    requestCorrelation(req, res, async () => {
      await new Promise((resolve) => setTimeout(resolve, Math.random() * 15));
      const record = attachRequestContext({ correlationId: "forged" });
      records.push(record);
      assert.equal(record.correlationId, req.correlationId);
      res.end(record.correlationId);
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}/?token=private`;
  const ids = await Promise.all(Array.from({ length: 20 }, async () => {
    const response = await fetch(url, { headers: { "X-Request-Id": "secret-token" } });
    const id = await response.text();
    assert.equal(response.headers.get("x-request-id"), id);
    assert.match(id, /^[0-9a-f-]{36}$/);
    return id;
  }));
  assert.equal(new Set(ids).size, 20);
  assert.equal(records.length, 20);
  assert.equal(getRequestContext(), undefined);
  assert.deepEqual(attachRequestContext({ message: "background" }), { message: "background" });
});

test("synchronous middleware failures propagate without leaking context", () => {
  assert.throws(() => requestCorrelation({}, { setHeader() {} }, () => {
    assert.ok(getRequestContext().correlationId);
    throw new Error("expected");
  }), /expected/);
  assert.equal(getRequestContext(), undefined);
});
