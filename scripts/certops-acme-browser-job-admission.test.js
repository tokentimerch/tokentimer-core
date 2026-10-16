"use strict";
// Pure native-admission request oracles; no browser/API/native execution.
const test = require("node:test"),
  assert = require("node:assert/strict");
const helper = require("../tests/e2e/helpers/certops-acme-browser-job-admission");
const workspaceId = "11111111-1111-4111-8111-111111111111",
  certificateId = "22222222-2222-4222-8222-222222222222",
  key = "33333333-3333-4333-8333-333333333333",
  apiOrigin = "http://127.0.0.1:4000";
test("UI actual job request is origin/route/closed body bound", () => {
  const expectedBody = {
    operation: "renew",
    idempotencyKey: key,
    subjectType: "managed_certificate",
    subjectId: certificateId,
    payload: { reason: "Native browser renewal" },
  };
  helper.validateInput(expectedBody);
  const request = {
    url: `${apiOrigin}/api/v1/workspaces/${workspaceId}/certops/jobs`,
    method: "POST",
    body: expectedBody,
  };
  assert.equal(
    helper.verifyRequest(request, { apiOrigin, workspaceId, expectedBody }),
    true,
  );
  for (const change of [
    { method: "PUT" },
    { url: request.url + "?other=1" },
    { url: request.url.replace(":4000", ":4001") },
    { body: { ...expectedBody, payload: { reason: "changed" } } },
  ])
    assert.throws(() =>
      helper.verifyRequest(
        { ...request, ...change },
        { apiOrigin, workspaceId, expectedBody },
      ),
    );
});
test("renewal refuses unsupported operations, subjects and execution overrides", () => {
  const renew = {
    operation: "renew",
    idempotencyKey: key,
    subjectType: "managed_certificate",
    subjectId: certificateId,
    payload: { reason: "Native browser renewal" },
  };
  for (const change of [
    { operation: "continue-enrollment" },
    { subjectType: "domain" },
    { payload: { reason: "owned", certPath: "/foreign" } },
    { assignedAgentId: certificateId },
  ])
    assert.throws(() => helper.validateInput({ ...renew, ...change }));
  for (const method of ["POST", "PATCH", "PUT", "DELETE"])
    assert.equal(
      helper.isWrite({
        method: () => method,
        url: () =>
          `http://other.invalid/api/v1/workspaces/${certificateId}/certops/settings`,
      }),
      true,
    );
  assert.equal(
    helper.isWrite({
      method: () => "POST",
      url: () => `${apiOrigin}/api/v1/auth/login`,
    }),
    false,
  );
});
test("native lifecycle proof requires two distinct actual jobs, leaves and keys", () => {
  const h = require("../tests/e2e/helpers/certops-acme-browser-lifecycle"),
    p = {
      scope: h.SCOPE,
      jobIds: [workspaceId, key],
      certificateId,
      fingerprints: ["a", "b"].map((v) => v.repeat(64)),
      spkiHashes: ["c", "d"].map((v) => v.repeat(64)),
      ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
    };
  assert.equal(h.verifyProof(p), true);
  for (const flag of h.FLAGS) {
    const wrong = { ...p };
    delete wrong[flag];
    assert.throws(() => h.verifyProof(wrong));
  }
  for (const change of [
    {
      jobIds: [
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
      ],
    },
    { jobIds: [key, key] },
    { fingerprints: ["a".repeat(64), "a".repeat(64)] },
    { spkiHashes: ["c".repeat(64), "c".repeat(64)] },
    { rawKey: "private" },
  ])
    assert.throws(() => h.verifyProof({ ...p, ...change }));
});
test("native lifecycle guard refuses growth and equal-byte foreign file replacement", () => {
  const fs = require("node:fs"),
    path = require("node:path"),
    h = require("../tests/e2e/helpers/certops-acme-browser-lifecycle");
  const directory = fs.mkdtempSync(
      path.resolve(__dirname, "../.build/browser-lifecycle-guard-"),
    ),
    file = path.join(directory, "guard"),
    bytes = Buffer.from("owned public guard");
  try {
    fs.writeFileSync(file, bytes);
    const identity = fs.lstatSync(file, { bigint: true });
    h.readGuard(file, bytes, identity);
    assert.throws(() =>
      h.ownedPath(
        directory + path.sep + "child" + path.sep + ".." + path.sep + "guard",
        directory,
      ),
    );
    fs.appendFileSync(file, "foreign growth");
    assert.throws(() => h.readGuard(file, bytes, identity));
    fs.renameSync(file, path.join(directory, "original"));
    fs.writeFileSync(file, bytes);
    assert.throws(() => h.readGuard(file, bytes, identity));
    assert.ok(fs.readFileSync(file).equals(bytes));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
