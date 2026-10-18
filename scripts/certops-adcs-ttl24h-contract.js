"use strict";
/** Draft contracts for a separate real-day AD CS TTL fixture. These validators
 * execute no native action, authorize no Azure lease extension and produce no
 * release qualification. Actual producers/controller/auth remain required. */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { ADCS_PREFLIGHT_MAX_AGE_MS } = require("../packages/contracts/certops/adcs-preflight-freshness.cjs");
const { DEFAULT_VALIDATION_TIMEOUT_SECONDS } = require("../packages/agent/src/issuers/adcs-validation-deadline");
const { HOUR, DAY, INITIAL, MAX, epoch } = require("./certops-retention24h-contract");
const KIND = "certops-native-adcs-ttl24h", TASK_PREFIX = "TokenTimer-AdcsTtl24h-";
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/, HEX = /^[a-f0-9]{64}$/;
const IDENTITIES = ["candidateSha", "runId", "runAttempt", "nonce", "vmResourceId", "vmId", "taskName", "nodeSha256", "keeperSha256"];
const LEASE_KEYS = [...IDENTITIES, "schemaVersion", "kind", "phase", "createdAt", "expiresAt", "hardExpiresAt"];
function exact(value, keys) { assert.ok(value && typeof value === "object" && !Array.isArray(value)); assert.deepEqual(Object.keys(value).sort(), [...keys].sort()); }
function uuid(value) { assert.equal(typeof value, "string"); assert.match(value, UUID); }
function hex(value) { assert.equal(typeof value, "string"); assert.match(value, HEX); }
function request(value) { assert.equal(typeof value, "string"); assert.match(value, /^[1-9][0-9]{0,9}$/); assert.ok(Number(value) <= 0xffffffff); }
function constants() { assert.equal(ADCS_PREFLIGHT_MAX_AGE_MS, DAY); assert.equal(DEFAULT_VALIDATION_TIMEOUT_SECONDS * 1000, DAY); }
function verifyLease(lease) {
  exact(lease, LEASE_KEYS); constants(); assert.equal(lease.schemaVersion, 1); assert.equal(lease.kind, KIND);
  assert.match(lease.candidateSha, /^[a-f0-9]{40}$/); for (const key of ["runId", "runAttempt"]) assert.match(lease[key], /^[1-9][0-9]{0,19}$/);
  for (const key of ["nonce", "nodeSha256", "keeperSha256"]) hex(lease[key]); uuid(lease.vmId);
  assert.equal(lease.taskName, TASK_PREFIX + lease.nonce);
  assert.match(lease.vmResourceId, /^\/subscriptions\/[a-f0-9-]{36}\/resourceGroups\/tt-certops-[1-9][0-9]*-[1-9][0-9]*\/providers\/Microsoft.Compute\/virtualMachines\/windows-agent$/);
  assert.ok(lease.vmResourceId.includes(`/resourceGroups/tt-certops-${lease.runId}-${lease.runAttempt}/`));
  assert.ok(["preparing", "resident-owned"].includes(lease.phase)); const created = epoch(lease.createdAt);
  assert.equal(epoch(lease.hardExpiresAt), created + MAX); assert.equal(epoch(lease.expiresAt), created + (lease.phase === "preparing" ? INITIAL : MAX)); return true;
}
function createLease(owner, createdAt) {
  const lease = { ...Object.fromEntries(IDENTITIES.map(key => [key, owner[key]])), schemaVersion: 1, kind: KIND, phase: "preparing", createdAt, expiresAt: new Date(epoch(createdAt) + INITIAL).toISOString(), hardExpiresAt: new Date(epoch(createdAt) + MAX).toISOString() }; verifyLease(lease); return lease;
}
function verifySources(rows) {
  assert.ok(Array.isArray(rows) && rows.length > 0 && rows.length <= 128); const seen = new Set();
  for (const row of rows) { exact(row, ["file", "sha256"]); assert.match(row.file, /^(?:scripts|tests|packages|apps|infra|\.github)\/[a-zA-Z0-9_./-]+$/); assert.ok(row.file.split("/").every(part => part && part !== "." && part !== "..") && !seen.has(row.file)); seen.add(row.file); hex(row.sha256); }
}
function verifyPreparedReceipt(value) {
  exact(value, ["scope", "lease", "preparedAt", "bootTime", "chainHelperSha256", "configurationSha256", "apiTrust", "caRequestCounts", "run", "workspaceId", "agentRowId", "issuerId", "confirmedAt", "preflight", "validation", "predecessor", "sources"]);
  assert.equal(value.scope, "prepared-real-adcs-ttl24h-not-elapsed-qualified"); verifyLease(value.lease); assert.equal(value.lease.phase, "preparing"); assert.match(value.run, /^[a-f0-9]{10}$/);
  for (const key of ["workspaceId", "agentRowId", "issuerId"]) uuid(value[key]);
  const created = epoch(value.lease.createdAt), prepared = epoch(value.preparedAt), confirmed = epoch(value.confirmedAt);
  assert.ok(prepared >= created && prepared < epoch(value.lease.expiresAt) && confirmed >= created && confirmed <= prepared);
  assert.ok(epoch(value.bootTime) <= prepared, "Actual prepared VM boot must precede its observation");
  hex(value.chainHelperSha256); hex(value.configurationSha256);
  exact(value.apiTrust, ["fileId", "sha256", "fingerprint", "notAfter"]); assert.match(value.apiTrust.fileId, /^[1-9][0-9]{0,19}$/); hex(value.apiTrust.sha256); hex(value.apiTrust.fingerprint); assert.ok(epoch(value.apiTrust.notAfter) > epoch(value.lease.hardExpiresAt) + HOUR, "Original API TLS certificate must cover the hard lease and cleanup margin");
  exact(value.caRequestCounts, ["before", "installed", "deferred"]); for (const count of Object.values(value.caRequestCounts)) assert.ok(Number.isSafeInteger(count) && count >= 0 && count <= 2048); assert.equal(value.caRequestCounts.installed, value.caRequestCounts.before + 1); assert.equal(value.caRequestCounts.deferred, value.caRequestCounts.installed + 1);
  const p = value.preflight;
  exact(p, ["jobId", "createdAt", "completedAt", "cacheUpdatedAt", "cacheFileId", "cacheSha256", "templateCacheUpdatedAt", "templateCacheFileId", "templateCacheSha256", "caKeySha256", "templateOid", "status"]); uuid(p.jobId); assert.equal(p.status, "succeeded");
  assert.ok(epoch(p.createdAt) >= confirmed && epoch(p.completedAt) >= epoch(p.createdAt) && epoch(p.completedAt) <= prepared);
  assert.ok(epoch(p.cacheUpdatedAt) >= epoch(p.createdAt) - 5000 && epoch(p.cacheUpdatedAt) <= epoch(p.completedAt) + 5000); assert.match(p.cacheFileId, /^[1-9][0-9]{0,19}$/); hex(p.cacheSha256); hex(p.caKeySha256); assert.match(p.templateOid, /^\d+(?:\.\d+)+$/);
  assert.ok(epoch(p.templateCacheUpdatedAt) >= epoch(p.createdAt) - 5000 && epoch(p.templateCacheUpdatedAt) <= epoch(p.completedAt) + 5000); assert.match(p.templateCacheFileId, /^[1-9][0-9]{0,19}$/); hex(p.templateCacheSha256);
  const v = value.validation;
  exact(v, ["enrollmentId", "jobId", "requestId", "containerName", "nativeKeyIdentitySha256", "journalUpdatedAt", "deadlineAt", "csrSha256", "csrSpkiSha256", "snapshotSha256", "journalSha256", "leafFingerprint", "state", "configuredTimeoutSeconds"]);
  uuid(v.enrollmentId); uuid(v.jobId); request(v.requestId); assert.equal(v.containerName, `tokentimer-enr-${v.enrollmentId}`); assert.equal(v.state, "validation_deferred"); assert.equal(v.configuredTimeoutSeconds, null, "Default24-hour configuration must remain untouched");
  for (const key of ["csrSha256", "csrSpkiSha256", "snapshotSha256", "journalSha256", "leafFingerprint", "nativeKeyIdentitySha256"]) hex(v[key]);
  const written = epoch(v.journalUpdatedAt), deadline = epoch(v.deadlineAt); assert.ok(written >= created && written <= prepared); assert.ok(Math.abs(deadline - written - DAY) <= 5000, "Production deadline must represent actual default24h, not configured300seconds");
  const c = value.predecessor;
  exact(c, ["enrollmentId", "jobId", "requestId", "containerName", "nativeKeyIdentitySha256", "fingerprint", "spkiSha256", "serialNumber", "notAfter", "domain", "site", "port"]); uuid(c.enrollmentId); uuid(c.jobId); request(c.requestId); assert.equal(c.containerName, `tokentimer-enr-${c.enrollmentId}`); hex(c.fingerprint); hex(c.spkiSha256); hex(c.nativeKeyIdentitySha256); assert.match(c.serialNumber, /^[a-f0-9]{2,128}$/); assert.ok(epoch(c.notAfter) > deadline + HOUR);
  assert.equal(c.domain, `certops-adcs-${value.run}-ttlvalidation.example.test`); assert.equal(c.site, `TTADCS-${value.run}-ttlvalidation`); assert.ok(Number.isInteger(c.port) && c.port > 0 && c.port <= 65535);
  for (const [left, right] of [[c.enrollmentId, v.enrollmentId], [c.jobId, v.jobId], [c.requestId, v.requestId], [c.fingerprint, v.leafFingerprint], [c.spkiSha256, v.csrSpkiSha256]]) assert.notEqual(left, right, "Deferred material must be distinct from the installed control");
  verifySources(value.sources); return true;
}
function verifyResidentTimingReceipt(value, prepared) {
  verifyPreparedReceipt(prepared);
  exact(value, ["scope", "candidateSha", "nonce", "vmId", "processId", "bootTime", "processCreatedAt", "startedAt", "finishedAt", "monotonicElapsedMs", "preDeadlineObservedAt", "keptObservationCount", "maximumObservationGapMs", "preparedSha256"]);
  assert.equal(value.scope, "resident-adcs-ttl24h-timing-only-native-oracles-required");
  for (const key of ["candidateSha", "nonce", "vmId"]) assert.equal(value[key], prepared.lease[key]); hex(value.preparedSha256); assert.equal(value.preparedSha256, preparedDigest(prepared), "Resident receipt must bind exact prepared wire bytes");
  assert.ok(Number.isInteger(value.processId) && value.processId > 0 && value.processId <= 0xffffffff);
  const started = epoch(value.startedAt), finished = epoch(value.finishedAt), observed = epoch(value.preDeadlineObservedAt);
  assert.equal(value.bootTime, prepared.bootTime, "Resident observations must remain on the actual prepared boot"); assert.ok(epoch(value.bootTime) <= epoch(value.processCreatedAt)); assert.ok(epoch(value.processCreatedAt) <= started && epoch(value.processCreatedAt) >= epoch(prepared.preparedAt));
  assert.ok(started >= epoch(prepared.preparedAt) && started - epoch(prepared.preparedAt) <= 600000); assert.ok(started < epoch(prepared.validation.deadlineAt) - 60000);
  assert.ok(Number.isInteger(value.monotonicElapsedMs) && value.monotonicElapsedMs >= DAY && value.monotonicElapsedMs <= DAY + HOUR); assert.ok(Math.abs(finished - started - value.monotonicElapsedMs) <= 5000); assert.ok(finished < epoch(prepared.lease.hardExpiresAt));
  assert.ok(observed >= started + 23 * HOUR && observed < epoch(prepared.validation.deadlineAt) - 60000);
  assert.ok(Number.isInteger(value.keptObservationCount) && value.keptObservationCount >= 24 && value.keptObservationCount <= 26); assert.ok(Number.isInteger(value.maximumObservationGapMs) && value.maximumObservationGapMs > 0 && value.maximumObservationGapMs <= HOUR + 300000);
  for (const timestamp of [prepared.preflight.createdAt, prepared.preflight.cacheUpdatedAt, prepared.preflight.templateCacheUpdatedAt]) assert.ok(finished > epoch(timestamp) + DAY, "Actual API and both local preflight cache observations must be stale"); assert.ok(finished > epoch(prepared.validation.deadlineAt)); return true;
}
function encodePreparedReceipt(value) { verifyPreparedReceipt(value); return Buffer.from(JSON.stringify(value) + "\n", "utf8"); }
function preparedDigest(value) { return crypto.createHash("sha256").update(encodePreparedReceipt(value)).digest("hex"); }
const OBSERVATION_FLAGS = Object.freeze(["soleAgentStoppedAndDrained", "originalCacheAndJournalUnmodified", "predecessorNativeCustodyVerified", "predecessorTrustedTlsVerified", "deferredUnacceptedNativeCustodyVerified"]);
const OBSERVATION_FIELDS = Object.freeze([...IDENTITIES, "preparedSha256", "taskXmlSha256", "processId", "processCreatedAt", "bootTime", "principalSid", "taskState", "nativeVerificationStartedAt", "nativeVerificationFinishedAt", "monotonicElapsedMs", ...OBSERVATION_FLAGS]);
function verifyTaskObservation(value, prepared) {
  verifyPreparedReceipt(prepared); exact(value, OBSERVATION_FIELDS); for (const key of IDENTITIES) assert.equal(value[key], prepared.lease[key]); assert.equal(value.preparedSha256, preparedDigest(prepared)); hex(value.taskXmlSha256); assert.equal(value.principalSid, "S-1-5-18"); assert.equal(value.taskState, "Running"); assert.equal(value.bootTime, prepared.bootTime);
  assert.ok(Number.isInteger(value.processId) && value.processId > 0 && value.processId <= 0xffffffff); assert.ok(typeof value.processCreatedAt === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3,7}Z$/.test(value.processCreatedAt)); const created = Date.parse(value.processCreatedAt); assert.ok(Number.isFinite(created) && created >= epoch(prepared.preparedAt));
  const start = epoch(value.nativeVerificationStartedAt), end = epoch(value.nativeVerificationFinishedAt); assert.ok(start >= created && end >= start && end - start <= 300000 && end < epoch(prepared.lease.expiresAt)); assert.ok(Number.isSafeInteger(value.monotonicElapsedMs) && value.monotonicElapsedMs >= 0 && value.monotonicElapsedMs < INITIAL); for (const flag of OBSERVATION_FLAGS) assert.equal(value[flag], true); return true;
}
function verifyPreparationEnvelope(value) { exact(value, ["schemaVersion", "kind", "prepared", "observed"]); assert.equal(value.schemaVersion, 1); assert.equal(value.kind, KIND); verifyTaskObservation(value.observed, value.prepared); return true; }
function verifyCompletedTaskObservation(value, prepared, original) {
  verifyTaskObservation(original, prepared); exact(value, [...OBSERVATION_FIELDS, "residentTiming"]); assert.equal(value.taskState, "Ready"); for (const key of [...IDENTITIES, "preparedSha256", "taskXmlSha256", "processId", "processCreatedAt", "bootTime", "principalSid", "monotonicElapsedMs"]) assert.equal(value[key], original[key]); for (const flag of OBSERVATION_FLAGS) assert.equal(value[flag], true);
  verifyResidentTimingReceipt(value.residentTiming, prepared); assert.equal(value.residentTiming.processId, original.processId); assert.equal(value.residentTiming.processCreatedAt, new Date(original.processCreatedAt).toISOString()); assert.equal(value.residentTiming.bootTime, original.bootTime);
  const start = epoch(value.nativeVerificationStartedAt), end = epoch(value.nativeVerificationFinishedAt); assert.ok(start >= epoch(value.residentTiming.finishedAt) && end >= start && end - start <= 300000 && end < epoch(prepared.lease.hardExpiresAt)); return true;
}
module.exports = { KIND, TASK_PREFIX, IDENTITIES, LEASE_KEYS, HOUR, DAY, INITIAL, MAX, createLease, verifyLease, verifySources, verifyPreparedReceipt, encodePreparedReceipt, preparedDigest, verifyResidentTimingReceipt, OBSERVATION_FLAGS, OBSERVATION_FIELDS, verifyTaskObservation, verifyPreparationEnvelope, verifyCompletedTaskObservation };
