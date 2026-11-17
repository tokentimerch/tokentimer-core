"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { endpoint, pin, createNativeOpenBaoTransport } = require("./native-openbao-transport.cjs");

const scope = { workspaceId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", groupId: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
  materialVersionId: "cccccccc-cccc-cccc-cccc-cccccccccccc", providerVersion: 7 };
test("accepts only explicit protected loopback HTTPS endpoints and an exact pin", () => {
  assert.equal(endpoint("https://127.0.0.1:60806").host, "127.0.0.1:60806");
  for (const address of ["http://127.0.0.1:60806", "https://localhost:60806", "https://example.com:60806",
    "https://127.0.0.1:60806/path", "https://user@127.0.0.1:60806", "https://127.0.0.1:60806#end"]) {
    assert.throws(() => endpoint(address));
  }
  assert.throws(() => pin({ ...scope, providerVersion: "latest" }));
  assert.throws(() => pin({ ...scope, groupId: "../sys" }));
});
test("only the armed version and the separated AppRole operations reach OpenBao", () => {
  const sent = [];
  const proxy = createNativeOpenBaoTransport((req, res) => { sent.push(req); res.statusCode = 200; res.emit("finish"); });
  const hit = (method, url) => {
    const res = new EventEmitter();
    res.writeHead = status => { res.statusCode = status; return res; };
    res.end = () => res.emit("finish");
    proxy.forward({ method, url }, res);
    return res.statusCode;
  };
  const pinned = pin(scope);
  assert.equal(hit("GET", pinned), 403);
  proxy.arm(scope);
  for (const [method, address] of [["GET", pinned.split("?")[0]], ["GET", pinned.replace("7", "8")],
    ["POST", pinned], ["GET", "/v1/sys/health"], ["PUT", "/v1/auth/approle/login"], ["POST", "/v1/auth/token/create"]]) {
    assert.equal(hit(method, address), 403);
  }
  assert.equal(hit("POST", "/v1/auth/approle/login"), 200);
  assert.equal(hit("GET", pinned), 200);
  assert.equal(hit("POST", "/v1/auth/token/renew-self"), 200);
  assert.equal(sent.length, 3);
  assert.deepEqual(proxy.facts(), { exactRead200: 1, renew200: 1 });
  assert.throws(() => proxy.arm(scope));
});
