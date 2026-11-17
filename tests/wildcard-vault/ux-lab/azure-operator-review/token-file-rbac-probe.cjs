"use strict";
// Caller supplies the Core Azure credential() getter and requestJson client.
// Probe secret and its enclosing vault must be disposable and already owned.
const assert = require("node:assert/strict");
async function consumerReadWriteProbe({ vaultOrigin, secretName, version, getToken, requestJson, recordOwnedIntent }) {
  const origin = new URL(vaultOrigin);
  assert.equal(origin.protocol, "https:"); assert.match(origin.hostname, /^[a-z0-9-]{3,24}\.vault\.azure\.net$/i);
  assert.equal(origin.username + origin.password + origin.search + origin.hash, "");
  assert.equal(origin.pathname, "/"); assert.ok(!origin.port || origin.port === "443");
  assert.match(secretName || "", /^tt-probe-[a-f0-9]{32}$/);
  assert.match(version || "", /^[a-f0-9]{32}$/);
  for (const fn of [getToken,requestJson,recordOwnedIntent]) assert.equal(typeof fn, "function");
  const base = `/secrets/${secretName}`;
  const url = suffix => { const result = new URL(base + suffix, origin); result.searchParams.set("api-version","7.4"); return result; };
  const headers = async () => ({ Authorization:`Bearer ${await getToken()}`, "Content-Type":"application/json" });
  const read = await requestJson(url(`/${version}`), {method:"GET",timeoutMs:10000,maxBytes:32768,headers:await headers()});
  assert.equal(read.status, 200, "consumer scoped read did not succeed");
  assert.equal(read.json?.id, `${origin.origin}${base}/${version}`, "consumer read did not identify the exact version");
  // An unexpectedly permitted PUT may create a secret version. Register the
  // owned probe before the write so the lab cleanup can remove its whole group.
  await recordOwnedIntent({secretName, kind:"disposable-rbac-probe"});
  const write = await requestJson(url(""), {method:"PUT",timeoutMs:10000,maxBytes:32768,headers:await headers(),body:{value:"non-secret-isolation-probe"}});
  assert.equal(write.status, 403, "consumer write denial not established; owned probe requires cleanup");
  return {status:"supporting-pass",releaseQualification:"not-established",consumerRead:true,consumerWriteDenied:true};
}
module.exports = {consumerReadWriteProbe};
