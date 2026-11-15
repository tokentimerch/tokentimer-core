"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { parseIisSnapshot, provesWildcardAbsent, readAbsenceSnapshot, readStableAbsenceSnapshot } = require("./iis-absence-proof");

const thumb = "AA".repeat(20);
const observation = { locationKind:"iis_binding", siteName:"Default Web Site", port:443, boundAddress:"192.0.2.10", thumbprint:thumb, fingerprintSha256:"b".repeat(64) };
const certificates = [{thumbprint:thumb,fingerprintSha256:observation.fingerprintSha256,hasPrivateKey:true}];
const row = { site:"Default Web Site", binding:"192.0.2.10:443:", flags:0 };
const iis = (...rows) => parseIisSnapshot(JSON.stringify({ sites:["Default Web Site"], items:rows }));
const http = (...selectors) => selectors.map(ipPort => ({ keyedBy:"ipport", ipPort, thumbprint:thumb, storeName:"My" }));

test("a concrete binding and complete native snapshots prove absence only for the same target", () => {
  assert.equal(provesWildcardAbsent(observation, iis(row), http("192.0.2.10:443"),certificates), true);
  assert.equal(provesWildcardAbsent({ ...observation, siteName:"Other" }, iis(row), http("192.0.2.10:443"),certificates), false);
  assert.equal(provesWildcardAbsent({ ...observation, thumbprint:"BB".repeat(20) }, iis(row), http("192.0.2.10:443"),certificates), false);
  assert.equal(provesWildcardAbsent({ ...observation, port:444 }, iis(row), http("192.0.2.10:443"),certificates), false);
});
test("wildcard, SNI, duplicate and missing HTTP.sys bindings never prove absence", () => {
  assert.equal(provesWildcardAbsent(observation, iis(row,{ site:row.site, binding:"*:443:", flags:0 }), http("192.0.2.10:443"),certificates), false);
  assert.equal(provesWildcardAbsent(observation, iis(row), http("192.0.2.10:443","0.0.0.0:443"),certificates), false);
  assert.equal(provesWildcardAbsent(observation, iis(row), http("192.0.2.10:443","[::]:443"),certificates), false);
  assert.equal(provesWildcardAbsent(observation, iis(row), http("192.0.2.10:443","[0:0:0:0:0:0:0:0]:443"),certificates), false);
  assert.equal(provesWildcardAbsent(observation, iis({ ...row, flags:1 }), http("192.0.2.10:443"),certificates), false);
  assert.equal(provesWildcardAbsent(observation, iis(row,row), http("192.0.2.10:443"),certificates), false);
  assert.equal(provesWildcardAbsent(observation, iis(row), [],certificates), false);
  assert.equal(provesWildcardAbsent(observation, iis(row), [...http("192.0.2.10:443"),{keyedBy:"ipport",ipPort:"192.0.2.10:443",thumbprint:"BB".repeat(20)}],certificates), false);
});
test("malformed and partial IIS snapshot is rejected", () => {
  for (const value of [{}, { sites:[row.site], items:[{...row,binding:"broken"}] }, {sites:[],items:[row]}, {sites:[row.site],items:[{...row,flags:null}]}]) {
    assert.throws(() => parseIisSnapshot(JSON.stringify(value)));
  }
});
test("a changed or failed native reading cannot produce a proof", async () => {
  const base = { iis:iis(row), http:http("192.0.2.10:443"), certificates };
  let reads = 0;
  const stable = await readStableAbsenceSnapshot({ read:async () => { reads++; return base; } });
  assert.equal(reads,2);
  assert.equal(provesWildcardAbsent(observation,stable.iis,stable.http,stable.certificates),true);
  reads = 0;
  await assert.rejects(readStableAbsenceSnapshot({ read:async () => ++reads === 1 ? base : { ...base, http:http("192.0.2.10:443","0.0.0.0:443") } }),/changed/);
  await assert.rejects(readStableAbsenceSnapshot({ read:async () => { throw new Error("access denied"); } }),/access denied/);
});
test("native snapshot checks both IIS and strict HTTP.sys and rejects partial output", async () => {
  const nativeIis = JSON.stringify({ sites:[row.site], items:[row] });
  const nativeHttp = JSON.stringify({ items:[{kind:"SslBindingInfo",key:"192.0.2.10:443",values:{SslCertHash:[...Buffer.from(thumb,"hex")],SslCertStoreName:"My"}}] });
  const rawData = [1, 2, 3, 255];
  const fingerprintSha256 = createHash("sha256").update(Buffer.from(rawData)).digest("hex");
  const nativeStore = JSON.stringify({ items:[{thumbprint:thumb,rawData,hasPrivateKey:true}] });
  let storeScript;
  const execFileImpl = (_file,args,_options,callback) => {
    if (args.at(-1).includes("Get-ChildItem -Path")) storeScript = args.at(-1);
    const value = args.at(-1).includes("Get-Website") ? nativeIis : args.at(-1).includes("Get-ChildItem -Path") ? nativeStore : nativeHttp;
    process.nextTick(() => callback(null,value,""));
    return {kill(){}};
  };
  const snapshot = await readAbsenceSnapshot({execFileImpl});
  assert.match(storeScript, /\[int\[\]\]\$_\.RawData/);
  assert.doesNotMatch(storeScript, /SHA256|ComputeHash|BitConverter/);
  assert.deepEqual(snapshot.certificates,[{thumbprint:thumb,fingerprintSha256,hasPrivateKey:true}]);
  assert.equal(provesWildcardAbsent({...observation,fingerprintSha256},snapshot.iis,snapshot.http,snapshot.certificates),true);
  const broken = (_file,args,_options,callback) => {
    const value = args.at(-1).includes("Get-Website") ? nativeIis : JSON.stringify({items:[{kind:"unknown"}]});
    process.nextTick(() => callback(null,value,""));
    return {kill(){}};
  };
  await assert.rejects(readAbsenceSnapshot({execFileImpl:broken}),/HTTP.sys snapshot unavailable/);
});
test("malformed certificate bytes make the whole native snapshot fail closed", async () => {
  const nativeIis = JSON.stringify({ sites:[row.site], items:[row] });
  const nativeHttp = JSON.stringify({ items:[{kind:"SslBindingInfo",key:"192.0.2.10:443",values:{SslCertHash:[...Buffer.from(thumb,"hex")],SslCertStoreName:"My"}}] });
  for (const rawData of [[], [256], [-1], [1.5], ["1"], null]) {
    const execFileImpl = (_file,args,_options,callback) => {
      const value = args.at(-1).includes("Get-Website") ? nativeIis : args.at(-1).includes("Get-ChildItem -Path")
        ? JSON.stringify({items:[{thumbprint:thumb,rawData,hasPrivateKey:true}]}) : nativeHttp;
      process.nextTick(() => callback(null,value,""));
      return {kill(){}};
    };
    await assert.rejects(readAbsenceSnapshot({execFileImpl}),/Invalid certificate store snapshot/);
  }
});
test("cancellation before enumeration never starts a native process", async () => {
  const controller = new AbortController();
  controller.abort();
  let calls = 0;
  await assert.rejects(readAbsenceSnapshot({ signal:controller.signal, execFileImpl:() => { calls++; } }), /IIS snapshot unavailable/);
  assert.equal(calls,0);
});
