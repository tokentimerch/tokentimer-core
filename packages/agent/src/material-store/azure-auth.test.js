"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { credential } = require("./azure");
const { writeProtectedFile } = require("./index");
test("Azure workload federation rereads assertions at renewal and never uses a remote challenge authority", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tt-azure-auth-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, "assertion");
  writeProtectedFile(file, "synthetic-federated-assertion-initial");
  const tenantId = crypto.randomUUID(),
    clientId = crypto.randomUUID(),
    calls = [];
  const token = credential(
    {
      auth: {
        type: "workload-identity",
        tenantId,
        clientId,
        assertionFile: file,
      },
    },
    5000,
    async (url, options) => {
      calls.push({ url, options });
      return {
        status: 200,
        json: {
          access_token: `synthetic-federated-access-token-${calls.length}`,
          expires_in: 3600,
        },
      };
    },
  );
  assert.equal(await token(), "synthetic-federated-access-token-1");
  assert.equal(await token(), "synthetic-federated-access-token-1");
  assert.equal(calls.length, 1);
  writeProtectedFile(file, "synthetic-federated-assertion-rotated");
  assert.equal(await token(true), "synthetic-federated-access-token-2");
  assert.equal(
    calls[1].url.href,
    `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
  );
  const body = new URLSearchParams(calls[1].options.body);
  assert.equal(
    body.get("client_assertion"),
    "synthetic-federated-assertion-rotated",
  );
  assert.equal(body.get("client_id"), clientId);
  assert.equal(body.get("scope"), "https://vault.azure.net/.default");
});
test("Azure managed identity uses only IMDS and renews bounded short-lived tokens", async () => {
  let calls = 0;
  const clientId = crypto.randomUUID();
  const token = credential(
    { auth: { type: "managed-identity", clientId } },
    5000,
    async (url, options) => {
      calls++;
      assert.equal(url.origin, "http://169.254.169.254");
      assert.equal(url.pathname, "/metadata/identity/oauth2/token");
      assert.equal(url.searchParams.get("client_id"), clientId);
      assert.equal(url.searchParams.get("resource"), "https://vault.azure.net");
      assert.equal(options.headers.Metadata, "true");
      return {
        status: 200,
        json: {
          access_token: "synthetic-managed-identity-access-token",
          expires_on: String(Math.floor(Date.now() / 1000) + 60),
        },
      };
    },
  );
  await token();
  await token();
  assert.equal(calls, 2);
  const denied = credential(
    { auth: { type: "managed-identity" } },
    5000,
    async () => ({
      status: 403,
      json: { error_description: "customer-secret-canary" },
    }),
  );
  await assert.rejects(
    denied(),
    (error) =>
      error.code === "material_auth_unavailable" &&
      !error.message.includes("canary"),
  );
});
