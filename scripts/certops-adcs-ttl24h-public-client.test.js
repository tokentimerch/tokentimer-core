"use strict";
/** Pure scope/privacy controls, no mocked or actual login qualification. */
const { test } = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), helper = require("./certops-adcs-ttl24h-public-client");
const workspace = "11111111-1111-1111-1111-111111111111";
test("resume API scope refuses redirect-style, foreign-workspace and extra method paths", () => {
  assert.equal(helper.validateRoute(workspace, "/api/csrf-token", "GET"), true); assert.equal(helper.validateRoute(workspace, "/auth/login", "POST"), true); assert.equal(helper.validateRoute(workspace, `/api/v1/workspaces/${workspace}/certops/profiles`, "POST"), true);
  for (const [route, method] of [["https://foreign.example.test/", "GET"], ["//foreign.example.test/", "GET"], ["/api/csrf-token", "POST"], ["/auth/login", "GET"], [`/api/v1/workspaces/${workspace}/certops/../foreign`, "GET"], [`/api/v1/workspaces/${workspace}/certops/profiles?secret=x`, "GET"], ["/api/v1/workspaces/22222222-2222-2222-2222-222222222222/certops/profiles", "POST"], [`/api/v1/workspaces/${workspace}/certops/profiles`, "DELETE"]]) assert.throws(() => helper.validateRoute(workspace, route, method));
});
test("resume client uses real CSRF/login and internal cookies without logging private values", () => {
  const source = fs.readFileSync(path.join(__dirname, "certops-adcs-ttl24h-public-client.js"), "utf8"); assert.ok(source.includes('request("/auth/login", "POST"')); assert.ok(source.includes('request("/api/csrf-token")')); assert.ok(source.includes('redirect: "error"')); assert.ok(source.includes("credential.unprotect")); assert.doesNotMatch(source, /console\.|process\.stdout|process\.stderr|writeFile|appendFile/);
});
test("encoded path normalization cannot escape the original workspace scope", () => {
  for (const suffix of ["%2e%2e/auth", "%2E./auth", "%2fother", "profiles%3fsecret=x", "profiles%23other"]) assert.throws(() => helper.validateRoute(workspace, `/api/v1/workspaces/${workspace}/certops/${suffix}`, "GET"));
});
test("public JSON is consumed within a capped stream and overflow cancels before concatenation", async () => {
  assert.deepEqual(await helper.readBoundedJson(new Response('{"public":true}')), { public: true });
  const exact = JSON.stringify("a".repeat(262142)); assert.equal(Buffer.byteLength(exact), 262144); assert.equal((await helper.readBoundedJson(new Response(exact))).length, 262142);
  let cancelled = false, reads = 0; const body = new ReadableStream({ pull(controller) { reads++; controller.enqueue(new Uint8Array(65536)); }, cancel() { cancelled = true; } }, { highWaterMark: 0 });
  await assert.rejects(helper.readBoundedJson(new Response(body)), /exceeds bounded read/); assert.equal(cancelled, true); assert.equal(reads, 5);
  await assert.rejects(helper.readBoundedJson(new Response('private-sentinel-invalid-json')), error => !error.message.includes("private-sentinel"));
});
