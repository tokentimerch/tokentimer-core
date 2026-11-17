"use strict";
// Supporting checks only. Caller supplies protected assertion reader and the
// existing Core requestJson transport; never returns tokens or assertions.
const assert = require("node:assert/strict");
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
async function crossExchange({ issuer, consumer, federationMismatchCodes, readAssertion, requestJson }) {
  for (const role of [issuer, consumer]) {
    assert.match(role?.tenantId || "", UUID); assert.match(role?.clientId || "", UUID);
    assert.ok(typeof role.assertionFile === "string" && role.assertionFile.startsWith("/"));
  }
  assert.notEqual(issuer.clientId.toLowerCase(), consumer.clientId.toLowerCase());
  assert.ok(Array.isArray(federationMismatchCodes) && federationMismatchCodes.length > 0 && federationMismatchCodes.every(Number.isSafeInteger), "reviewed mismatch codes required");
  assert.equal(typeof readAssertion, "function"); assert.equal(typeof requestJson, "function");
  async function exchange(source, target) {
    const assertion = String(await readAssertion(source.assertionFile)).trim();
    assert.match(assertion, /^[A-Za-z0-9_.-]{20,16384}$/);
    const response = await requestJson(new URL(`https://login.microsoftonline.com/${target.tenantId}/oauth2/v2.0/token`), {
      method: "POST", timeoutMs: 10000, maxBytes: 32768,
      headers: {"Content-Type":"application/x-www-form-urlencoded"},
      body: new URLSearchParams({client_id:target.clientId,grant_type:"client_credentials",scope:"https://vault.azure.net/.default",client_assertion:assertion,client_assertion_type:"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}).toString(),
    });
    return response;
  }
  for (const role of [issuer, consumer]) {
    const response = await exchange(role, role);
    assert.equal(response.status, 200, "own-role exchange failed");
    assert.ok(typeof response.json?.access_token === "string" && response.json.access_token.length >= 20, "own-role token absent");
  }
  for (const [source,target] of [[issuer,consumer],[consumer,issuer]]) {
    const response = await exchange(source,target);
    assert.equal(response.status, 400, "cross-role exchange not rejected as federation mismatch");
    assert.equal(response.json?.error, "invalid_client", "cross-role failure not attributable to trust");
    assert.ok(Array.isArray(response.json?.error_codes) && response.json.error_codes.some(code => federationMismatchCodes.includes(code)), "reviewed federation mismatch code absent");
  }
  return { status:"supporting-pass", releaseQualification:"not-established", ownRoleExchanges:2, crossRoleRejected:2 };
}
module.exports = { crossExchange };
