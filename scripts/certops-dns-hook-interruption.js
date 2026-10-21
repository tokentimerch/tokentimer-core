"use strict";
/** Owned DNS-hook process interruption after a real provider write. This is
 * hook recovery in a disposable resolver fixture, not ACME cancellation or
 * authenticated live-provider qualification. Unknown process custody blocks
 * the owning harness cleanup through its registered retained resource. */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { startOwnedDnsPresent } = require("./certops-dns-owned-server");
const SCOPE = "native-dns-hook-interruption-fresh-cleanup";
const SCENARIO = "dns-routing-owned-cleanup";
const FLAGS = Object.freeze(["realTargetAndSiblingTxtObserved", "interruptedHookLiveBeforeStop", "retainedPidfdStopAndDrainVerified", "freshCleanupProcessVerified", "repeatedCleanupVerified", "distinctNameSiblingPreservedDuringCleanup", "ownedTxtAbsentAfterCleanup"]);
const REQUIRED_SOURCES = Object.freeze(["scripts/certops-dns-hook-interruption.js", "scripts/certops-dns-owned-server.js", "scripts/certops-dns-owned-server.py", "scripts/certops-dns-routing-host.js", "packages/agent/bin/certops-dns-hook.js", "packages/agent/src/dns/hook.js", "packages/agent/src/dns/propagate.js", "packages/agent/src/dns/lockfile.js", "packages/agent/src/dns/providers/pebble-challtestsrv.js"]);
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(Object.keys(p).sort(), ["schemaVersion", "scope", "interruptedExitCode", "cleanupRuns", "liveProviderQualified", "acmeCancellationQualified", "sameNameSiblingQualified", "fullPropagationQualified", ...FLAGS].sort());
  assert.equal(p.schemaVersion, 1); assert.equal(p.scope, SCOPE);
  assert.equal(p.interruptedExitCode, -15); assert.equal(p.cleanupRuns, 2);
  assert.equal(p.liveProviderQualified, false); assert.equal(p.acmeCancellationQualified, false);
  assert.equal(p.sameNameSiblingQualified, false); assert.equal(p.fullPropagationQualified, false);
  for (const flag of FLAGS) assert.equal(p[flag], true, `Missing interruption observation ${flag}`);
  return true;
}
function requireCleanup(result) {
  assert.equal(result.code, 0);
  const events = result.stdout.split(/\r?\n/).filter(line => line.startsWith("{")).map(line => JSON.parse(line)).filter(event => event.event === "dns.propagation");
  assert.equal(events.length, 1);
  assert.equal(events[0].mode, "cleanup"); assert.equal(events[0].ok, true);
  assert.equal(events[0].phase, "cleanup-verify");
  assert.equal(events[0].provider, "pebble-challtestsrv");
  assert.ok(events[0].attempts >= 1);
}
async function qualify({directory, zone, config, hook, txt, records, ownedResolverResources}) {
  const domain = `interruption.${zone}`, value = `certops-interrupt-${crypto.randomBytes(16).toString("hex")}`, sibling = `certops-interrupt-${crypto.randomBytes(16).toString("hex")}`;
  const siblingDomain = `interruption-sibling.${zone}`;
  records.push({domain:siblingDomain,value:sibling}, {domain,value});
  config(); assert.equal((await hook(directory,siblingDomain,sibling)).code, 0);
  assert.deepEqual(await txt(siblingDomain), [sibling]);
  config([zone], ["127.0.0.1:18053"], 30000);
  let resource;
  try {
    resource = await startOwnedDnsPresent(owner => ownedResolverResources.push(owner), {configDir:directory,domain,value});
    const deadline = Date.now() + 10000;
    while (true) {
      resource.assertLive();
      const observed = await txt(domain);
      if (observed.includes(value) && (await txt(siblingDomain)).includes(sibling)) break;
      assert.ok(Date.now() < deadline, "Real interrupted hook TXT write not observed");
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    resource.assertLive();
    const closed = await resource.stop();
    assert.equal(closed.rootExitCode, -15); assert.equal(closed.pidfdSignalUsed, true);
    resource.assertCleanupSafe();
    config();
    for (let i = 0; i < 2; i++) {
      requireCleanup(await hook(directory,domain,value,"cleanup"));
      assert.deepEqual(await txt(domain), []);
      assert.deepEqual(await txt(siblingDomain), [sibling]);
    }
    requireCleanup(await hook(directory,siblingDomain,sibling,"cleanup"));
    assert.deepEqual(await txt(siblingDomain), []);
    const proof = {schemaVersion:1, scope:SCOPE, interruptedExitCode:-15, cleanupRuns:2, liveProviderQualified:false, acmeCancellationQualified:false, sameNameSiblingQualified:false, fullPropagationQualified:false, ...Object.fromEntries(FLAGS.map(flag => [flag,true]))};
    verifyProof(proof); return proof;
  } finally {
    if (resource) { await resource.stop(); resource.assertCleanupSafe(); }
    config();
  }
}
module.exports = {SCOPE, SCENARIO, FLAGS, REQUIRED_SOURCES, verifyProof, requireCleanup, qualify};
