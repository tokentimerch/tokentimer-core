"use strict";
/** Offline public CA-summary and mutation-order controls; no native qualification. */
const { test } = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path");
const h = require("./certops-adcs-ttl24h-contract"), { prepared } = require("./fixtures/certops-adcs-ttl24h.cjs"), finish = require("./certops-adcs-ttl24h-finish");
test("postday pre-CA summary binds both genuine prepared generations without assuming elapsed authority", () => {
  const p = prepared(), now = Date.now(), timing = { finishedAt: new Date(now - 1000).toISOString() }, value = { observedAt: new Date(now).toISOString(), nativeTotalRequestCount: p.caRequestCounts.deferred, nativeRequesterCount: 2, requestIds: [p.predecessor.requestId, p.validation.requestId], fingerprints: [p.predecessor.fingerprint, p.validation.leafFingerprint], caKeySha256: p.preflight.caKeySha256, crlSha256: "a".repeat(64), crlNextUpdate: new Date(now + 2 * h.HOUR).toISOString() };
  finish.verifyPreCa(value, p, timing);
  for (const mutate of [v => v.requestIds.reverse(), v => v.fingerprints.reverse(), v => v.nativeRequesterCount++, v => v.caKeySha256 = "b".repeat(64), v => v.crlNextUpdate = timing.finishedAt, v => v.privateExtra = "sentinel"]) { const bad = structuredClone(value); mutate(bad); assert.throws(() => finish.verifyPreCa(bad, p, timing)); }
});
test("native postday source seals uncertain attempt before mutations and uses actual terminal job semantics", () => {
  const source = fs.readFileSync(path.join(__dirname, "certops-adcs-ttl24h-finish.js"), "utf8");
  assert.ok(source.indexOf("postday-started.json") < source.indexOf("createClient(")); assert.ok(source.indexOf("postday-started.json") < source.indexOf("Start-Service"));
  assert.ok(source.includes("status IN ('pending','pending_approval','approved','claimed','running')")); assert.ok(source.includes('assert.equal(deferred.job_status, "failed")')); assert.ok(source.includes("custody(oldLeaf, prepared.predecessor.containerName)"));
  assert.doesNotMatch(source, /Set-Date|utimes|writeEnrollmentJournal|now:\s*new Date|jobCreator:/);
});
