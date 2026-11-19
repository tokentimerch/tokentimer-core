"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { labAccess } = require("./lab-access.cjs");

const REPO = "tokentimerch/tokentimer-core";
const MAIN = "refs/heads/main";
const WORKFLOW = REPO + "/.github/workflows/certops-iis-lab-access.yml@" + MAIN;
const AUD = "api://AzureADTokenExchange";
const EXPIRED_AT = "2025-01-01T06:00:00.000Z";
const id = number => `00000000-0000-4000-8000-${String(number).padStart(12, "0")}`;
const jwt = payload => "test." + Buffer.from(JSON.stringify(payload)).toString("base64url") + ".sig";

function fixture({ operation = "read", readStatus = 200, errorCode = "ResourceGroupNotFound",
  wrongOwner = false, wrongRole = false, wrongPrincipal = false, expiresAt = EXPIRED_AT } = {}) {
  const runId = "a".repeat(32);
  const group = "tt-iis-" + runId;
  const scope = `/subscriptions/${id(2)}/resourceGroups/${group}`;
  const mode = operation === "read" ? "verifier" : "cleanup";
  const assertion = jwt({ iss: "https://token.actions.githubusercontent.com", ref: MAIN, aud: AUD, workflow_ref: WORKFLOW,
    sub: `repo:${REPO}:environment:certops-iis-${wrongRole ? "other" : mode}` });
  const token = jwt({ tid: id(1), oid: wrongPrincipal ? id(9) : id(4), appid: id(3) });
  const env = {
    GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: REPO, GITHUB_REF: MAIN, GITHUB_WORKFLOW_REF: WORKFLOW,
    GITHUB_EVENT_NAME: "workflow_dispatch", ACTIONS_ID_TOKEN_REQUEST_URL: "https://issuer.actions.githubusercontent.com/token",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "fixture-only-runner-credential",
    TT_IIS_TENANT_ID: id(1), TT_IIS_SUBSCRIPTION_ID: id(2), TT_IIS_CLIENT_ID: id(3), TT_IIS_PRINCIPAL_ID: id(4),
    TT_IIS_RUN_ID: runId, TT_IIS_CONFIRM_GROUP: group, TT_IIS_EXPIRES_AT: EXPIRED_AT,
  };
  const calls = [];
  const headers = { "x-ms-request-id": id(6) };
  async function fetchImpl(target, options) {
    const url = new URL(target);
    calls.push([url.origin, options.method || "GET"]);
    assert.equal(options.redirect, "error");
    if (url.origin === "https://issuer.actions.githubusercontent.com") {
      assert.equal(url.searchParams.get("audience"), AUD);
      return Response.json({ value: assertion });
    }
    if (url.origin === "https://login.microsoftonline.com") {
      assert.equal(url.pathname, `/${id(1)}/oauth2/v2.0/token`);
      assert.equal(options.body.get("client_assertion"), assertion);
      assert.equal(options.body.get("scope"), "https://management.azure.com/.default");
      return Response.json({ access_token: token });
    }
    assert.equal(url.origin, "https://management.azure.com");
    assert.equal(url.pathname, scope);
    assert.equal(options.headers.authorization, "Bearer " + token);
    if (options.method === "DELETE") return new Response(null, { status: 202, headers });
    if (readStatus !== 200) return Response.json({ error: { code: errorCode } }, { status: readStatus, headers });
    return Response.json({ id: scope, location: "swedencentral", tags: {
      "tt-purpose": "windows-iis-qualification", "tt-run-id": wrongOwner ? "b".repeat(32) : runId,
      "tt-expires-at": expiresAt,
    } }, { headers });
  }
  return { env, fetchImpl, calls, token, scope };
}

test("the same verifier records owned 200 and exact absent 404 without IDs or credentials", async () => {
  const present = fixture();
  const absent = fixture({ readStatus: 404 });
  const before = await labAccess("read", present.env, present.fetchImpl);
  const after = await labAccess("read", absent.env, absent.fetchImpl);
  assert.equal(before.principalSha256, after.principalSha256);
  assert.equal(before.groupSha256, after.groupSha256);
  assert.equal(before.read.state, "owned");
  assert.equal(after.read.state, "absent");
  assert.equal(after.read.status, 404);
  assert.ok(!JSON.stringify(before).includes(present.token));
  assert.ok(!JSON.stringify(before).includes(present.scope));
});

test("wrong workflow, branch, issuer, subject and Azure principal cannot reach ARM", async () => {
  for (const [key, value] of [["GITHUB_REF", "refs/heads/draft"], ["GITHUB_WORKFLOW_REF", WORKFLOW + "-other"],
    ["ACTIONS_ID_TOKEN_REQUEST_URL", "https://actions.githubusercontent.com.other.test/token"]]) {
    const { env, fetchImpl, calls } = fixture();
    await assert.rejects(labAccess("read", { ...env, [key]: value }, fetchImpl));
    assert.deepEqual(calls, []);
  }
  for (const config of [{ wrongRole: true }, { wrongPrincipal: true }]) {
    const { env, fetchImpl, calls } = fixture(config);
    await assert.rejects(labAccess("read", env, fetchImpl));
    assert.ok(!calls.some(([origin]) => origin === "https://management.azure.com"));
  }
});

test("denied requests or other 404 errors cannot be recorded as absence", async () => {
  for (const config of [{ readStatus: 403 }, { readStatus: 404, errorCode: "ResourceNotFound" }]) {
    const { env, fetchImpl } = fixture(config);
    await assert.rejects(labAccess("read", env, fetchImpl));
  }
});

test("checking backup access is read-only and deletion requires confirmation, ownership and the reserved expiry", async () => {
  const check = fixture({ operation: "check-cleanup" });
  delete check.env.TT_IIS_EXPIRES_AT;
  const receipt = await labAccess("check-cleanup", check.env, check.fetchImpl);
  assert.equal(receipt.read.status, 200);
  assert.ok(!check.calls.some(([, method]) => method === "DELETE"));
  const invalid = fixture({ operation: "delete-owned-group" });
  invalid.env.TT_IIS_CONFIRM_GROUP = "unexpected-group";
  await assert.rejects(labAccess("delete-owned-group", invalid.env, invalid.fetchImpl));
  assert.deepEqual(invalid.calls, []);
  const foreign = fixture({ operation: "delete-owned-group", wrongOwner: true });
  await assert.rejects(labAccess("delete-owned-group", foreign.env, foreign.fetchImpl));
  assert.ok(!foreign.calls.some(([, method]) => method === "DELETE"));
  const unarmed = fixture({ operation: "delete-owned-group" });
  delete unarmed.env.TT_IIS_EXPIRES_AT;
  await assert.rejects(labAccess("delete-owned-group", unarmed.env, unarmed.fetchImpl));
  assert.deepEqual(unarmed.calls, []);
  const differentExpiry = fixture({ operation: "delete-owned-group", expiresAt: "2025-01-02T06:00:00.000Z" });
  await assert.rejects(labAccess("delete-owned-group", differentExpiry.env, differentExpiry.fetchImpl));
  assert.ok(!differentExpiry.calls.some(([, method]) => method === "DELETE"));
  const owned = fixture({ operation: "delete-owned-group" });
  const deleted = await labAccess("delete-owned-group", owned.env, owned.fetchImpl);
  assert.deepEqual(owned.calls.filter(([, method]) => method === "DELETE"), [["https://management.azure.com", "DELETE"]]);
  assert.equal(deleted.deletion.status, 202);
  assert.equal(deleted.read.state, "owned");
});
