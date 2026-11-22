"use strict";
const {test}=require("node:test");
const assert=require("node:assert/strict");
const {runWindowsDiscoveryScan}=require("../../packages/agent/src/index");
const thumb="AA".repeat(20), fingerprint="b".repeat(64);
const item={locationKind:"iis_binding",locationSlot:"Site:18450@::1",siteName:"Site",port:18450,boundAddress:"::1",thumbprint:thumb,fingerprintSha256:fingerprint,storeLocation:"LocalMachine",storeName:"My",keyPresent:true};
const snapshot={iis:[{site:"Site",address:"::1",port:18450,hostname:"",flags:0}],http:[{keyedBy:"ipport",ipPort:"[::1]:18450",thumbprint:thumb,storeName:"My"}],certificates:[{thumbprint:thumb,fingerprintSha256:fingerprint,hasPrivateKey:true}]};
async function scan(observations,read,signal){const reports=[];await runWindowsDiscoveryScan({client:{reportEvidence:async body=>reports.push(...body.evidenceItems)},collect:async()=>observations,readIisProofSnapshot:read,signal});return reports;}
const proof=entry=>entry.metadata.find(field=>field.name==="iisTopologyProof")?.value;
test("attests a strict IIS match using one snapshot per discovery cycle",async()=>{let reads=0;const rows=await scan([item,{...item}],async()=>{reads++;return snapshot});assert.equal(reads,1);assert.deepEqual(rows.map(proof),["v1","v1"])});
test("omits attestation on native errors, wildcard, SNI and CCS",async()=>{
  assert.equal(proof((await scan([item],async()=>{throw Error("access denied")}))[0]),undefined);
  for(const bad of [{...snapshot,iis:[...snapshot.iis,{site:"Site",address:"*",port:18450,hostname:"",flags:0}]},{...snapshot,iis:[{...snapshot.iis[0],flags:1}]},{...snapshot,iis:[{...snapshot.iis[0],flags:2}]}])assert.equal(proof((await scan([item],async()=>bad))[0]),undefined);
  assert.equal(proof((await scan([{...item,sniHost:"sni.example.test"}],async()=>snapshot))[0]),undefined);
});
test("oversized IIS scans skip strict reads and never attest",async()=>{let reads=0;const rows=await scan(Array.from({length:65},(_,i)=>({...item,locationSlot:`Site:${i}`})),async()=>{reads++;return snapshot});assert.equal(reads,0);assert.equal(rows.length,65);assert.ok(rows.every(entry=>proof(entry)===undefined));});
test("SNI candidates do not exhaust the limit for a concrete eligible binding",async()=>{let reads=0;const rows=await scan([item,...Array.from({length:65},(_,i)=>({...item,locationSlot:`sni-${i}`,sniHost:"sni.example.test"}))],async()=>{reads++;return snapshot});assert.equal(reads,1);assert.equal(proof(rows[0]),"v1");assert.ok(rows.slice(1).every(entry=>proof(entry)===undefined));});
test("shutdown during the strict snapshot never emits an attestation",async()=>{const controller=new AbortController();const rows=await scan([item],async({signal})=>{assert.equal(signal,controller.signal);controller.abort();return snapshot},controller.signal);assert.equal(proof(rows[0]),undefined);});
