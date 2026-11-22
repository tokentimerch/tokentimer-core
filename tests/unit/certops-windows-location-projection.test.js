"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { foldWindowsLocations } = require("../../apps/api/services/certops/windowsLocationProjection");

function fixture() {
  const common={source:"agent_windows",target_agent_id:"agent",target_hostname:"host",target_port:18450,target_sni:null,
    evidence_kind:"service_binding",presence_state:"confirmed_present",fresh:true,authoritative_instance:true,iis_attribution_verified:true,previous_count:0,previous_observations:[]};
  const old={...common,id:"http",target_id:"http-target",location_kind:"http_sys",target_address:null,target_site:null,
    source_ref:"agent/host/http_sys/0:0:0:0:0:0:0:1:18450",target_source_ref:"agent/host/http_sys/0:0:0:0:0:0:0:1:18450",
    deployment_reference:"http-sys://[0:0:0:0:0:0:0:1]:18450",target_reference:"http-sys://[0:0:0:0:0:0:0:1]:18450",captured_at:new Date("2026-01-01T00:00:00Z")};
  const current={...common,id:"iis",target_id:"iis-target",location_kind:"iis_binding",target_address:"::1",target_site:"Site",
    source_ref:"agent/host/iis_binding/Site:18450@::1",target_source_ref:"agent/host/iis_binding/Site:18450@::1",
    deployment_reference:"iis://Site:18450@[::1]",target_reference:"iis://Site:18450@[::1]",captured_at:new Date("2026-01-01T00:01:00Z")};
  const target=row=>({id:row.target_id,agent_id:row.target_agent_id,hostname:row.target_hostname,windows_port:row.target_port,
    windows_sni_host:row.target_sni,location_kind:row.location_kind,deployment_reference:row.target_reference,bound_address:row.target_address});
  return {old,current,targets:[target(old),target(current)]};
}

test("groups a uniquely proved older HTTP.sys observation while retaining its history",()=>{
  const {old,current,targets}=fixture();
  const result=foldWindowsLocations([current,old],targets);
  assert.equal(result.length,1);
  assert.equal(result[0].id,"iis");
  assert.equal(result[0].previous_count,1);
  assert.equal(result[0].previous_observations[0].id,"http");
  assert.equal(result[0].previous_observations[0].deploymentReference,"http-sys://[0:0:0:0:0:0:0:1]:18450");
});

for(const [name,change] of [
  ["an equally recent or newer HTTP.sys observation",f=>{f.old.captured_at=f.current.captured_at;}],
  ["a future IIS timestamp",f=>{f.current.captured_at=new Date(Date.now()+60000);}],
  ["an IIS slot without an authoritative instance",f=>{f.current.authoritative_instance=false;}],
  ["an older agent without IIS attribution evidence",f=>{f.current.iis_attribution_verified=undefined;}],
  ["a malformed IIS attribution marker",f=>{f.current.iis_attribution_verified="true";}],
  ["a missing IIS address",f=>{f.current.target_address=null;}],
  ["an SNI target",f=>{f.current.target_sni="private.example.test";}],
  ["a different agent",f=>{f.current.target_agent_id="other";}],
  ["a different host",f=>{f.current.target_hostname="other";}],
  ["a different port",f=>{f.current.target_port=18451;}],
  ["a different address",f=>{f.current.target_address="::2";}],
  ["an inconsistent source reference",f=>{f.current.target_source_ref="different";}],
  ["a third exact target",f=>{f.targets.push({...f.targets[1],id:"other"});}],
  ["an unknown target address",f=>{f.targets.push({...f.targets[1],id:"other",bound_address:null});}],
  ["an unknown target hostname",f=>{f.targets.push({...f.targets[1],id:"other",hostname:null});}],
  ["an IPv6 wildcard",f=>{f.targets.push({...f.targets[1],id:"other",bound_address:"::"});}],
  ["an SNI binding at the same port",f=>{f.targets.push({...f.targets[1],id:"other",windows_sni_host:"private.example.test"});}],
]) test(`does not group ${name}`,()=>{const f=fixture();change(f);assert.equal(foldWindowsLocations([f.current,f.old],f.targets).length,2);});

test("normalizes the address in the IIS source and reference without rewriting them",()=>{
  const f=fixture(), expanded="0:0:0:0:0:0:0:1";
  f.current.source_ref=`agent/host/iis_binding/Site:18450@${expanded}`;
  f.current.target_source_ref=f.current.source_ref;
  f.current.deployment_reference=`iis://Site:18450@[${expanded}]`;
  f.current.target_reference=f.current.deployment_reference;
  assert.equal(foldWindowsLocations([f.current,f.old],f.targets).length,1);
  assert.ok(f.current.source_ref.endsWith(expanded));
});

test("keeps an IPv4 wildcard distinct from an IPv6 binding",()=>{
  const f=fixture();f.targets.push({...f.targets[1],id:"ipv4",bound_address:"0.0.0.0"});
  assert.equal(foldWindowsLocations([f.current,f.old],f.targets).length,1);
});
