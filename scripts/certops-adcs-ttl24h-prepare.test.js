"use strict";
/** Offline admission and source safety guards, never native preparation proof. */
const { test } = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), { spawnSync } = require("node:child_process");
const ROOT = path.resolve(__dirname, "..");
test("guest bootstrap matches scoped provision parameter and success-marker contract", () => {
  const bootstrap = fs.readFileSync(path.join(ROOT, "infra/certops-adcs/run-ttl24h-prepare.ps1"), "utf8"), provision = fs.readFileSync(path.join(ROOT, "infra/certops-adcs/provision-lab.ps1"), "utf8");
  for (const key of ["AdcsTtl24hCreatedAt", "AdcsTtl24hRunId", "AdcsTtl24hRunAttempt", "AdcsTtl24hNonce"]) { assert.ok(bootstrap.includes("$" + key)); assert.ok(provision.includes(key)); }
  assert.ok(bootstrap.includes("new Date(process.argv[3]).toISOString()")); assert.ok(bootstrap.includes("CERTOPS_STAGE=adcs-ttl24h-prepared")); assert.ok(provision.includes("CERTOPS_STAGE=adcs-ttl24h-prepared"));
});
test("actual preparation entry refuses an unqualified process before reading a lease or touching the host", () => {
  const env = { ...process.env }; for (const name of Object.keys(env)) if (/^CERTOPS_ADCS_(?:DISPOSABLE_LAB|TTL24H)$/i.test(name)) delete env[name];
  const child = spawnSync(process.execPath, ["-e", "require('./tests/e2e/certops-adcs-ttl24h-prepare').prepare('deliberately-absent-lease').then(()=>process.exitCode=2).catch(e=>{process.exitCode=e.code==='ERR_ASSERTION'?0:3;})"], { cwd: ROOT, env, timeout: 30000, windowsHide: true }); assert.ok(!child.error && child.status === 0, "Unqualified preparation must fail its admission assertion before lease I/O or native commands");
});
test("separate source retains default configuration, actual public dispatch and drain-before-fault-restoration", () => {
  const source = fs.readFileSync(path.join(ROOT, "tests/e2e/certops-adcs-ttl24h-prepare.js"), "utf8"), stop = fs.readFileSync(path.join(ROOT, "scripts/certops-adcs-ttl24h-stop-agent.ps1"), "utf8");
  assert.doesNotMatch(source, /validationTimeoutSeconds\s*:|scheduleDueEnrollments|renewalSweep|UPDATE\s|INSERT\s|DELETE\s|\.cleanup\(/i);
  assert.ok(source.includes("drain(); await fault.close()")); assert.ok(source.includes("await successful(installed.jobId)")); assert.ok(source.includes("await fault.install(); const deferred = await enroll()")); assert.ok(source.includes("actualCaRequestCounts"));
  assert.ok(stop.includes("adcs-ttl24h")); assert.ok(stop.includes("Exact service tree did not drain; preserve fixture")); assert.ok(stop.includes("CreationDate -eq $old.CreationDate")); assert.doesNotMatch(stop, /Stop-Process|taskkill|retention24h/);
});
