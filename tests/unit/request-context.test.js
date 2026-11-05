const { test } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { EventEmitter } = require("node:events");
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

for (const event of ["finish", "close"]) {
  test(`background work created by a request loses its ID after response ${event}`, async () => {
    const res = new EventEmitter();
    res.setHeader = () => {};
    const req = {};
    const background = new Promise((resolve) => {
      requestCorrelation(req, res, () => {
        assert.equal(getRequestContext().correlationId, req.correlationId);
        setImmediate(() => resolve(attachRequestContext({ message: "pool event" })));
      });
    });
    // Async resources such as a database socket inherit the context in which
    // they were created, even if their later events are unrelated to the request.
    res.emit(event);
    assert.deepEqual(await background, { message: "pool event" });
  });
}

test("ending one response does not clear another active request", async () => {
  const first = Object.assign(new EventEmitter(), { setHeader() {} });
  const second = Object.assign(new EventEmitter(), { setHeader() {} });
  const req = {};
  let firstResult;
  let secondResult;
  requestCorrelation({}, first, () => {
    firstResult = new Promise((resolve) => setImmediate(() => resolve(getRequestContext())));
  });
  requestCorrelation(req, second, () => {
    secondResult = new Promise((resolve) => setImmediate(() => resolve(getRequestContext())));
  });
  first.emit("finish");
  assert.equal(await firstResult, undefined);
  assert.equal((await secondResult).correlationId, req.correlationId);
  second.emit("finish");
});
