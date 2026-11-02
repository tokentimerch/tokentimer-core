/**
 * Regression coverage: unconfigured janitor schedules no provider runners and no-op two-slot provider is excluded.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),{spawnSync}=require("node:child_process");
const {enrolledProviders,assertProducerEnrollment,selectProviders}=require("./certops-dns-cleanup-enrollment");
test("unconfigured janitor schedules no provider runners and no-op two-slot provider is excluded",()=>{assert.deepEqual(selectProviders({mode:"janitor"}),[]);assert.deepEqual(selectProviders({raw:'["acme-dns"]',mode:"janitor"}),[]);assert.deepEqual(selectProviders({raw:'["route53","cloudflare","acme-dns"]',mode:"janitor"}),["cloudflare","route53"]);});
test("manual DNS selection defaults to one explicit enrolled provider and all never means unconfigured providers",()=>{assert.deepEqual(selectProviders({raw:'["cloudflare","route53"]',mode:"qualify",requested:"route53"}),["route53"]);assert.deepEqual(selectProviders({raw:'["route53"]',mode:"qualify",requested:"all"}),["route53"]);assert.throws(()=>selectProviders({mode:"qualify",requested:"all"}));assert.throws(()=>selectProviders({raw:'["cloudflare"]',mode:"qualify",requested:"route53"}));});
test("unknown duplicate malformed and injected cleanup inventories fail closed",()=>{for(const raw of ['{}','null','["cloudflare","cloudflare"]','["attacker"]','["cloudflare\\nforged=true"]','not-json'])assert.throws(()=>enrolledProviders(raw));assert.throws(()=>assertProducerEnrollment("cloudflare",undefined));assert.doesNotThrow(()=>assertProducerEnrollment("cloudflare",'["cloudflare"]'));});
test("un-enrolled direct producer refuses specifically at enrollment before provider configuration",()=>{
 const script="require(process.argv[1]).main().catch(error=>{console.error(error.message);process.exitCode=1;});";
 const result=spawnSync(process.execPath,["-e",script,require.resolve("./certops-dns-provider-host")],{encoding:"utf8",timeout:10000,env:{...process.env,CERTOPS_DNS_PROVIDER:"cloudflare",CERTOPS_DNS_ENROLLED_PROVIDERS_JSON:"[]",CERTOPS_DNS_CREDENTIALS_JSON:"must-not-read-credential"}});
 assert.notEqual(result.status,0);assert.match(result.stderr,/enrolled for independent cleanup before mutation/);assert.equal((result.stdout+result.stderr).includes("must-not-read-credential"),false);
});
