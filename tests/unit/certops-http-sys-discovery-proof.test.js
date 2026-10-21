"use strict";
// Portable negative oracles for the separately executed native Windows fixture.
// These synthetic records validate strict matching only; no OS mutation/qualification occurs.
const {test}=require("node:test"),assert=require("node:assert/strict");
const {verifyObservations}=require("../../packages/agent/scripts/host/discovery-http-sys-fixture");
function fixture(){const expected=[{kind:"SslBindingInfo",selector:"[::1]:443",address:"::1",port:443,store:"WebHosting",appId:"12345678-1234-1234-1234-123456789abc",thumbprint:"A".repeat(40),fingerprint:"b".repeat(64)}];return {expected,native:[{...expected[0]}],observations:[{locationKind:"http_sys",boundAddress:"::1",port:443,storeName:"WebHosting",storeLocation:"LocalMachine",thumbprint:"A".repeat(40),fingerprintSha256:"b".repeat(64),keyPresent:true,locationSlot:"::1:443"}]};}
test("discovery oracle requires exact native ownership store DER and IPv6 selector facts",()=>{const value=fixture();assert.doesNotThrow(()=>verifyObservations(value.expected,value.native,value.observations));
 for(const mutate of [v=>{v.native[0].appId="foreign";},v=>{v.native[0].thumbprint="C".repeat(40);},v=>{v.native[0].store="My";},v=>{v.observations[0].fingerprintSha256="d".repeat(64);},v=>{v.observations[0].boundAddress="127.0.0.1";},v=>{v.observations[0].locationKind="iis_binding";},v=>{v.observations[0].keyPresent=false;},v=>{v.observations[0].storeName="My";},v=>{v.observations[0].storeLocation="CurrentUser";},v=>{v.observations.push({...v.observations[0]});},v=>{v.native=[];}]){const changed=fixture();mutate(changed);assert.throws(()=>verifyObservations(changed.expected,changed.native,changed.observations));}
});
