"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");

const REPOSITORY = "tokentimerch/tokentimer-core";
const MAIN = "refs/heads/main";
const WORKFLOW = REPOSITORY + "/.github/workflows/certops-iis-lab-access.yml@" + MAIN;
const AUDIENCE = "api://AzureADTokenExchange";
const ARM = "https://management.azure.com";
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const OPS = new Set(["read", "check-cleanup", "delete-owned-group"]);

function digest(value) {
  return createHash("sha256").update(value.toLowerCase()).digest("hex");
}

function claims(token) {
  assert.ok(typeof token === "string" && token.length <= 32768);
  const parts = token.split(".");
  assert.equal(parts.length, 3);
  return JSON.parse(Buffer.from(parts[1], "base64url"));
}

async function labAccess(operation, env = process.env, fetchImpl = fetch) {
  assert.ok(OPS.has(operation));
  assert.equal(env.GITHUB_ACTIONS, "true");
  assert.equal(env.GITHUB_REPOSITORY, REPOSITORY);
  assert.equal(env.GITHUB_REF, MAIN);
  assert.equal(env.GITHUB_WORKFLOW_REF, WORKFLOW);
  assert.equal(env.GITHUB_EVENT_NAME, "workflow_dispatch");
  const { TT_IIS_TENANT_ID: tenant, TT_IIS_SUBSCRIPTION_ID: subscription,
    TT_IIS_CLIENT_ID: client, TT_IIS_PRINCIPAL_ID: principal, TT_IIS_RUN_ID: runId } = env;
  for (const value of [tenant, subscription, client, principal]) assert.match(value, UUID);
  assert.match(runId, /^[a-f0-9]{32}$/);
  const group = "tt-iis-" + runId;
  const expiresAt = env.TT_IIS_EXPIRES_AT;
  if (operation === "delete-owned-group") {
    assert.equal(env.TT_IIS_CONFIRM_GROUP, group);
    assert.equal(new Date(expiresAt).toISOString(), expiresAt);
  }
  const subject = `repo:${REPOSITORY}:environment:certops-iis-${operation === "read" ? "verifier" : "cleanup"}`;

  const request = (url, options) => fetchImpl(url, {
    ...options, redirect: "error", signal: AbortSignal.timeout(15000),
  });
  const oidcUrl = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
  assert.ok(oidcUrl.protocol === "https:" && oidcUrl.hostname.endsWith(".actions.githubusercontent.com") &&
    !oidcUrl.username && !oidcUrl.password && !oidcUrl.port && !oidcUrl.hash);
  assert.ok(env.ACTIONS_ID_TOKEN_REQUEST_TOKEN);
  oidcUrl.searchParams.set("audience", AUDIENCE);
  const oidc = await request(oidcUrl, { headers: { authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` } });
  assert.equal(oidc.status, 200);
  const { value: assertion } = await oidc.json();
  const github = claims(assertion);
  assert.equal(github.iss, "https://token.actions.githubusercontent.com");
  assert.equal(github.sub, subject);
  assert.equal(github.aud, AUDIENCE);
  assert.equal(github.ref, MAIN);
  assert.equal(github.workflow_ref, WORKFLOW);

  // Exchange directly so the verifier needs only resourceGroups/read.
  // Azure CLI subscription discovery would require a separate permission.
  const identity = await request(`https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "client_credentials", scope: ARM + "/.default", client_id: client,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion,
    }),
  });
  assert.equal(identity.status, 200);
  const { access_token: token } = await identity.json();
  const azure = claims(token);
  assert.equal(azure.tid?.toLowerCase(), tenant.toLowerCase());
  assert.equal(azure.oid?.toLowerCase(), principal.toLowerCase());
  assert.equal((azure.azp || azure.appid)?.toLowerCase(), client.toLowerCase());

  const resourceId = `/subscriptions/${subscription}/resourceGroups/${group}`;
  const endpoint = ARM + resourceId + "?api-version=2021-04-01";
  const headers = { authorization: `Bearer ${token}` };
  const observed = await request(endpoint, { headers, method: "GET" });
  let state = "owned";
  if (operation === "read" && observed.status === 404) {
    assert.equal((await observed.json()).error?.code, "ResourceGroupNotFound");
    state = "absent";
  } else {
    assert.equal(observed.status, 200);
    const body = await observed.json();
    assert.equal(body.id?.toLowerCase(), resourceId.toLowerCase());
    assert.equal(body.location, "swedencentral");
    assert.equal(body.tags?.["tt-purpose"], "windows-iis-qualification");
    assert.equal(body.tags?.["tt-run-id"], runId);
    if (operation === "delete-owned-group") assert.equal(body.tags["tt-expires-at"], expiresAt);
  }
  const readRequestId = observed.headers.get("x-ms-request-id");
  assert.match(readRequestId, UUID);

  let deletion;
  if (operation === "delete-owned-group") {
    const response = await request(endpoint, { headers, method: "DELETE" });
    assert.ok([200, 202, 204].includes(response.status));
    const requestId = response.headers.get("x-ms-request-id");
    assert.match(requestId, UUID);
    deletion = { status: response.status, requestId };
  }
  return {
    operation, groupSha256: digest(resourceId), principalSha256: digest(tenant + ":" + principal),
    read: { status: observed.status, state, requestId: readRequestId }, deletion,
    observedAt: new Date().toISOString(),
  };
}

if (require.main === module) {
  labAccess(process.argv[2]).then(receipt => {
    process.stdout.write(JSON.stringify(receipt) + "\n");
  }).catch(() => {
    process.stderr.write("The IIS Azure access check did not pass.\n");
    process.exitCode = 1;
  });
}

module.exports = { labAccess };
