"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {activationDecision,nextActivation,validateActivationPolicy}=require("../../packages/contracts/certops/activation-calendar.cjs");
const {activationDeadline}=require("../../apps/api/services/certops/distributionMaintenance");
const policy={method:"reload",disruptive:true,requiresApproval:true,timezone:"Europe/Berlin",windows:[{days:[0],start:"02:00",end:"03:00"}],blackouts:[],validUntil:null,emergency:null};
const allowed=(value,time)=>activationDecision(value,Date.parse(time)).allowed;
test("IANA calendars handle DST gaps, both repeated hours, end exclusivity and UTC",()=>{
  assert.equal(allowed(policy,"2026-03-29T00:59:00Z"),false);
  assert.equal(allowed(policy,"2026-03-29T01:00:00Z"),false,"The missing 02:00 hour is never manufactured");
  assert.equal(allowed(policy,"2026-10-25T00:30:00Z"),true);
  assert.equal(allowed(policy,"2026-10-25T01:30:00Z"),true);
  assert.equal(allowed(policy,"2026-10-25T02:00:00Z"),false);
  assert.equal(allowed({...policy,timezone:"UTC"},"2026-10-25T02:30:00Z"),true);
});
test("blackouts win over overlapping windows and bounded emergency exceptions",()=>{
  const value={...policy,windows:[...policy.windows,{days:[0],start:"02:20",end:"04:00"}],
    emergency:{start:"2026-10-25T00:00:00Z",end:"2026-10-25T03:00:00Z",reference:"change_248"},
    blackouts:[{start:"2026-10-25T00:25:00Z",end:"2026-10-25T00:35:00Z"}]};
  assert.equal(allowed(value,"2026-10-25T00:30:00Z"),false);
  assert.equal(allowed(value,"2026-10-25T00:40:00Z"),true);
  assert.equal(allowed({...value,validUntil:"2026-10-25T00:35:00Z"},"2026-10-25T00:40:00Z"),false);
});
test("overnight windows retain the originating weekday and missed expiry escalates",()=>{
  const value={...policy,timezone:"America/New_York",windows:[{days:[1],start:"23:30",end:"01:00"}]};
  assert.equal(allowed(value,"2026-10-27T04:30:00Z"),true);
  assert.equal(allowed(value,"2026-10-27T05:00:00Z"),false);
  const next=nextActivation(value,"2026-10-27T03:45:00Z",Date.parse("2026-10-27T03:00:00Z"));
  assert.equal(next.at,"2026-10-27T03:30:00.000Z");
  assert.equal(nextActivation(value,"2026-10-27T03:20:00Z",Date.parse("2026-10-27T03:00:00Z")).reason,"no_window_before_expiry");
});
test("activation classes are explicit and unsafe policies are rejected",()=>{
  assert.throws(()=>validateActivationPolicy({...policy,method:"shell"}));
  assert.throws(()=>validateActivationPolicy({...policy,method:"controlled-restart",disruptive:false}));
  assert.throws(()=>validateActivationPolicy({...policy,timezone:"CET+unknown"}));
  assert.throws(()=>validateActivationPolicy({...policy,windows:[{days:[0],start:"01:00",end:"01:00"}]}));
  assert.equal(activationDecision({...policy,method:"manual"}).reason,"manual_activation_required");
  assert.equal(activationDecision({...policy,windows:[]}).allowed,false);
});
test("maintenance escalation uses the earlier deployed expiry even after source renewal",()=>{
  assert.equal(activationDeadline("2027-01-01T00:00:00Z","2026-11-01T00:00:00Z"),"2026-11-01T00:00:00.000Z");
});
test("forecast preserves short future emergency periods and exact blackout ends between minute boundaries",()=>{
  const future={...policy,timezone:"UTC",windows:[],emergency:{start:"2026-10-27T10:00:10Z",end:"2026-10-27T10:00:20Z",reference:"change_248"}};
  assert.equal(nextActivation(future,"2026-10-27T11:00:00Z",Date.parse("2026-10-27T10:00:05Z")).at,"2026-10-27T10:00:10.000Z");
  const blackout={...future,disruptive:false,emergency:null,blackouts:[{start:"2026-10-27T10:00:00Z",end:"2026-10-27T10:00:20Z"}]};
  assert.equal(nextActivation(blackout,"2026-10-27T10:00:30Z",Date.parse("2026-10-27T10:00:05Z")).at,"2026-10-27T10:00:20.000Z");
});
