"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { refreshState, classifyPreflight, refreshIdempotencyKey, BACKOFF_MS,
  MAX_ATTEMPTS, issuerRefreshStates } = require("../../apps/api/services/certops/adcsPreflightRefresh");
const NOW = Date.parse("2026-11-16T12:00:00Z");
const version = { version: 1, ca_config: "ca.example\\CA", template: "WebServer",
  ca_key_sha256: "ab".repeat(32), confirmed_at: new Date(NOW - 7 * 86400000) };
const verdict = { caConfig: version.ca_config,template: version.template,
  caKeySha256s: [version.ca_key_sha256],templateCheck: "safe",caCheck: "safe" };
function job(overrides = {}) { return { id: "j1",assigned_agent_id: "a1",source: "automation",
  status: "failed",created_at: new Date(NOW - 60000),completed_at: new Date(NOW),...overrides }; }
const safe = (overrides = {}) => job({ status: "succeeded",result_metadata: { preflightVerdict: verdict },...overrides });

describe("automatic AD CS preflight retry policy", () => {
  it("keeps approval indefinitely but expires safe evidence at 24 hours", () => {
    assert.equal(refreshState([safe()],version,NOW).state,"fresh");
    assert.equal(refreshState([safe({created_at: new Date(NOW-86400001)})],version,NOW).state,"required");
    assert.equal(refreshState([],version,NOW).state,"required");
  });
  it("blocks observed unsafe settings and changed pins before considering operational failures", () => {
    for (const [patch,code] of [[{templateCheck:"unsafe"},"ADCS_TEMPLATE_UNSAFE"],
      [{caCheck:"unsafe"},"ADCS_CA_CONFIG_UNSAFE"],[{caKeySha256s:["cd".repeat(32)]},"ADCS_CA_KEY_CHANGED"],
      [{template:"Other"},"CERTOPS_ISSUER_REVALIDATION_REQUIRED"]]) {
      const state=refreshState([safe({result_metadata:{preflightVerdict:{...verdict,...patch}}})],version,NOW);
      assert.equal(state.state,"blocked");assert.equal(state.code,code);
    }
  });
  it("does not accept unreadable results or missing CA certificates as safe", () => {
    for(const patch of [{templateCheck:"unreadable"},{caCheck:"unreadable"},{caKeySha256s:[]}]) {
      assert.equal(refreshState([safe({result_metadata:{preflightVerdict:{...verdict,...patch}}})],version,NOW).state,"retrying");
    }
  });
  it("uses persistent consecutive failures for bounded exponential backoff", () => {
    for(let count=1;count<MAX_ATTEMPTS;count++) {
      const jobs=Array.from({length:count},()=>job());
      const state=refreshState(jobs,version,NOW);
      const wait=BACKOFF_MS*2**(count-1);
      assert.equal(state.nextRefreshAt,new Date(NOW+wait).toISOString());
      assert.equal(state.dispatch,false);
      assert.equal(refreshState(jobs,version,NOW+wait-1).dispatch,false);
      assert.equal(refreshState(jobs,version,NOW+wait).dispatch,true);
    }
    assert.equal(refreshState(Array.from({length:MAX_ATTEMPTS},()=>job()),version,NOW).code,"CERTOPS_PREFLIGHT_RETRIES_EXHAUSTED");
  });
  it("manual checks and safe results reset an exhausted episode", () => {
    const failures=Array.from({length:MAX_ATTEMPTS},()=>job());
    assert.equal(refreshState([job({source:"api"}),...failures],version,NOW).attempts,1);
    assert.equal(refreshState([safe(),...failures],version,NOW).state,"fresh");
    assert.equal(refreshState([job(),safe(),...failures],version,NOW).attempts,1);
  });
  it("a newer unsafe or failed check supersedes an earlier safe check", () => {
    assert.equal(refreshState([job(),safe()],version,NOW).state,"retrying");
    assert.equal(refreshState([safe({result_metadata:{preflightVerdict:{...verdict,caCheck:"unsafe"}}}),safe()],version,NOW).state,"blocked");
  });
  it("does not retry policy refusals or cancellation", () => {
    for(const status of ["blocked","rejected","cancelled"]) {
      assert.equal(refreshState([job({status,error_code:"issuer_not_allowlisted"})],version,NOW).state,"blocked");
    }
    assert.equal(refreshState([job({error_code:"ADCS_TEMPLATE_UNSAFE"})],version,NOW).state,"blocked");
  });
  it("waits for queued, running and human approval jobs; recovers interrupted read-only jobs", () => {
    for(const status of ["pending","claimed","running","pending_approval"]) {
      assert.equal(refreshState([job({status})],version,NOW).dispatch,undefined);
    }
    assert.equal(refreshState([job({status:"orphaned_unknown_effect"})],version,NOW).state,"retrying");
  });
  it("never authorizes a revalidation-required issuer or future evidence", () => {
    assert.equal(refreshState([safe()],{...version,revalidation_required:true},NOW).state,"blocked");
    assert.notEqual(refreshState([safe({created_at:new Date(NOW+1)})],version,NOW).state,"fresh");
  });
  it("does not reuse an earlier issuer version when confirmation timestamps overlap", () => {
    const previous=safe({result_metadata:{preflightVerdict:verdict,preflightContext:{issuerVersion:1,
      caKeySha256:version.ca_key_sha256,confirmedAt:version.confirmed_at}}});
    assert.notEqual(refreshState([previous],{...version,version:2},NOW).state,"fresh");
  });
  it("separates deduplication by workspace, agent, version, approved pin, pair and predecessor", () => {
    const context={workspaceId:"w1",issuerId:"i1",agentId:"a1",version,previousId:"j1"};
    const key=refreshIdempotencyKey(context);
    assert.equal(key,refreshIdempotencyKey({...context}));
    for(const change of [{workspaceId:"w2"},{issuerId:"i2"},{agentId:"a2"},{previousId:"j2"},
      {version:{...version,version:2}},{version:{...version,ca_key_sha256:"cd".repeat(32)}},
      {version:{...version,template:"Other"}}]) assert.notEqual(key,refreshIdempotencyKey({...context,...change}));
  });
  it("projects each agent independently", () => {
    const states=issuerRefreshStates([job({assigned_agent_id:"offline"}),safe()],version,NOW);
    assert.equal(states.find(s=>s.agentId==="offline").state,"retrying");
    assert.equal(states.find(s=>s.agentId==="a1").state,"fresh");
    assert.equal(classifyPreflight(job(),version),null);
  });
});
