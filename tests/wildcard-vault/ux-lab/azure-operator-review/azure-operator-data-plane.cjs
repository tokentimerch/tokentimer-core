"use strict";
const assert = require("node:assert/strict");
const { VERSION, MAX_SECRET_BYTES, CONTENT_TYPE } = require("../../../../packages/agent/src/material-store/azure.js");
const { requestJson } = require("../../../../packages/agent/src/material-store/transport.js");

const VAULT_HOST = /^ttkv[a-f0-9]{20}\.vault\.azure\.net$/;
const OBJECT = /^tt-[a-f0-9]{64}$/;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function createDataPlane({ vaultHost, readToken, deadlineMs, assertLease, journal, grantExactRead }) {
  assert.match(vaultHost || "", VAULT_HOST);
  assert.ok(Number.isSafeInteger(deadlineMs) && deadlineMs > Date.now());
  for (const check of [readToken, assertLease, journal, grantExactRead]) assert.equal(typeof check, "function");
  const origin = "https://" + vaultHost;
  let selected, committed;
  const live = () => assert.ok(Date.now() + 10000 < deadlineMs, "owned vault lease is ending");

  async function send(role, name, suffix, method = "GET", body) {
    live();
    if (name !== selected) throw new Error("Azure object is outside this operator run");
    const url = new URL("/secrets/" + name + suffix, origin);
    url.searchParams.set("api-version", "7.4");
    return requestJson(url, { method, body, timeoutMs: 10000, maxBytes: 128 * 1024,
      headers: { Authorization: "Bearer " + await readToken(role), "Content-Type": "application/json" } });
  }
  async function untilAuthorized(request, expected) {
    for (;;) {
      const response = await request();
      if (expected.includes(response.status)) return response.json;
      assert.equal(response.status, 403, "unexpected real Key Vault readiness response");
      await delay(3000);
    }
  }
  return {
    async recordOwnedObject(name) {
      assert.match(name || "", OBJECT);
      assert.equal(selected, undefined, "this run allows one material object");
      await assertLease();
      await journal({ action: "publication-intent", name });
      selected = name;
      const existing = await untilAuthorized(() => send("issuer", name, "/versions?maxresults=2"), [200, 404]);
      assert.ok(!existing || Array.isArray(existing.value) && existing.value.length === 0 && !existing.nextLink,
        "the planned material object already exists");
    },
    async onlyCommittedVersion(name) {
      const response = await send("issuer", name, "/versions?maxresults=2");
      assert.equal(response.status, 200);
      assert.ok(Array.isArray(response.json?.value) && response.json.value.length === 1 && !response.json.nextLink,
        "exactly one owned Key Vault version expected");
      const id = new URL(response.json.value[0].id);
      const version = id.pathname.split("/").at(-1);
      assert.equal(id.href, origin + "/secrets/" + name + "/" + version);
      assert.match(version, VERSION);
      assert.ok(!committed || committed === version, "the owned version changed after restart");
      committed = version;
      return version;
    },
    async grantConsumer(name) {
      assert.ok(name === selected && VERSION.test(committed || ""));
      await assertLease();
      const ungranted = await send("consumer", name, "/" + committed);
      assert.equal(ungranted.status, 403, "consumer already has access outside this run's exact grant");
      await journal({ action: "consumer-grant-intent", name });
      await grantExactRead(name);
    },
    async proveConsumerAccess(name, version) {
      assert.ok(name === selected && version === committed && VERSION.test(version || ""));
      const response = await untilAuthorized(() => send("consumer", name, "/" + version), [200]);
      assert.equal(response.id, origin + "/secrets/" + name + "/" + version);
      assert.equal(response.contentType, CONTENT_TYPE);
      assert.ok(typeof response.value === "string" && Buffer.byteLength(response.value) <= MAX_SECRET_BYTES);
      const bundle = JSON.parse(response.value);
      assert.ok(typeof bundle.certificatePem === "string");
      await journal({ action: "consumer-denied-put-intent", name });
      const denial = await send("consumer", name, "", "PUT", { value: "disposable-operator-permission-check" });
      assert.equal(denial.status, 403, "owned consumer write was not denied by Key Vault");
      return { certificatePem: bundle.certificatePem, writeStatus: denial.status };
    },
  };
}

module.exports = { createDataPlane };
