"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { validateTarget, runStagedAgentProtocol } = require("../../scripts/staged-agent-protocol.cjs");
const fixture = {
  baseUrl: "http://127.0.0.1:4010", workspaceId: "11111111-1111-4111-8111-111111111111",
  sessionCookie: "synthetic-fixture-cookie", csrfToken: "synthetic-fixture-csrf", disposable: true,
};
test("staged acceptance refuses nonlocal targets and embedded credentials", () => {
  for (const baseUrl of ["https://tokentimer.ch", "http://127.0.0.1.example.test", "http://user:secret@localhost", "http://localhost/path", "http://localhost/?token=secret", "http://localhost/#secret", "file:///tmp/test"]) {
    assert.throws(() => validateTarget({ ...fixture, baseUrl }));
  }
});
test("staged acceptance requires explicit disposable authority and complete owned fixture context", () => {
  for (const patch of [{ disposable: false }, { workspaceId: "" }, { sessionCookie: "" }, { csrfToken: "" }]) {
    assert.throws(() => validateTarget({ ...fixture, ...patch }));
  }
  assert.equal(validateTarget(fixture), "http://127.0.0.1:4010");
  assert.equal(validateTarget({ ...fixture, baseUrl: "http://[::1]:4010" }), "http://[::1]:4010");
});
test("an invalid fixture fails before contacting a service", async () => {
  await assert.rejects(runStagedAgentProtocol({ ...fixture, disposable: false, edition: "core" }), /disposable-stack authorization/);
});

test("staged acceptance never follows an authenticated API redirect", async () => {
  let redirectedRequests = 0;
  let apiRequests = 0;
  const receiver = http.createServer((_request, response) => {
    redirectedRequests += 1;
    response.writeHead(500).end();
  });
  const origin = http.createServer((_request, response) => {
    apiRequests += 1;
    response.writeHead(307, {
      location: `http://127.0.0.1:${receiver.address().port}/unexpected`,
    }).end();
  });
  const listen = (server) => new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const close = (server) => new Promise((resolve) => {
    server.close(resolve);
    server.closeAllConnections();
  });
  try {
    await listen(receiver);
    await listen(origin);
    await assert.rejects(runStagedAgentProtocol({
      ...fixture,
      baseUrl: `http://127.0.0.1:${origin.address().port}`,
      edition: "core",
    }), AggregateError);
    assert.equal(apiRequests, 1);
    assert.equal(redirectedRequests, 0);
  } finally {
    await Promise.all([close(origin), close(receiver)]);
  }
});
