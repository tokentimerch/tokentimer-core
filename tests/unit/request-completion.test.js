const { test } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const {
  requestCorrelation,
  requestCompletionLogger,
} = require("../../apps/api/utils/request-context");

test("routine probe successes are quiet while failures and other requests remain correlated", async (t) => {
  const records = [];
  const logger = {
    info: (message, metadata) => records.push({ message, ...metadata }),
  };
  const logCompletion = requestCompletionLogger(logger);
  const server = http.createServer((req, res) => {
    req.originalUrl = req.url;
    requestCorrelation(req, res, () =>
      logCompletion(req, res, () => {
        const pathname = new URL(req.url, "http://localhost").pathname;
        req.route =
          pathname === "/api/items/123"
            ? { path: "/api/items/:id" }
            : ["/health", "/metrics"].includes(pathname)
              ? { path: pathname }
              : undefined;
        res.statusCode = req.url.includes("notmodified=1")
          ? 304
          : req.url.includes("fail=1")
            ? 503
            : req.method === "POST"
              ? 405
              : pathname === "/missing"
                ? 404
                : 200;
        res.end("ok");
      }),
    );
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  for (const [path, method] of [
    ["/health?token=private", "GET"],
    ["/health", "HEAD"],
    ["/metrics", "GET"],
  ]) {
    const response = await fetch(base + path, { method });
    assert.match(response.headers.get("x-request-id"), /^[0-9a-f-]{36}$/);
  }
  assert.equal(records.length, 0);
  await fetch(base + "/health?fail=1");
  await fetch(base + "/health", { method: "POST" });
  await fetch(base + "/api/items/123?token=private");
  await fetch(base + "/missing?token=private");
  await fetch(base + "/cached?notmodified=1&token=private");
  assert.deepEqual(
    records.map((r) => [r.method, r.statusCode, r.route]),
    [
      ["GET", 503, "/health"],
      ["POST", 405, "/health"],
      ["GET", 200, "/api/items/:id"],
      ["GET", 404, "unmatched"],
      ["GET", 304, "unmatched"],
    ],
  );
  for (const record of records) {
    assert.equal(record.message, "HTTP request completed");
    assert.match(record.correlationId, /^[0-9a-f-]{36}$/);
    assert.doesNotMatch(
      JSON.stringify(record),
      /token=private|\/api\/items\/123/,
    );
  }
});
