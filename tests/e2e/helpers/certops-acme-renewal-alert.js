"use strict";
/**
 * Qualification: native renewal proxy refusal
 *
 * In the Ubuntu certbot bulk lane, admit one real public renewal after a genuine
 * certificate already serves. Refuse new-order only on the owned proxy and count only
 * actual observed requests NOT forwarded. Require current-claim failure, one consumed
 * nonce, no additional issuance response and exact predecessor certificate/private
 * key/trusted TLS. This controlled proxy fault cannot stand in for a native CA failure
 * or issuance. Retain the actual outbox/delivery path;
 * CERTOPS_NATIVE_RENEWAL_MAILHOG_URL and CERTOPS_NATIVE_RENEWAL_SMTP_PORT select the
 * disposable mail observer. Shared policy: docs/certops/e2e-qualification.md.
 */
/** Native renewal failure through actual SMTP. The parent owns the disposable
 * API, agent, CA proxy and MailHog. No result, claim, nonce or due date is forged.
 * The fault is an explicitly observed proxy refusal, recorded before forwarding.
 * Production delivery runs in an isolated one-shot Node process. A test-mode
 * email success is simulated and cannot count as the MailHog receipt. */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { spawnSync } = require("node:child_process");
const SCENARIO = "real-acme-native-renewal-failure-smtp";
const SCOPE = "native-renewal-transport-refusal-production-outbox-and-smtp";
const SIDECAR = "qualification-results/acme-renewal-alert-proof.json";
const FIELD = "nativeAcmeRenewalAlert";
const active = new Set(), GUARD = ".native-renewal-alert-active";
function registerOperation(root) {
  const directory = path.resolve(root), file = path.join(directory, GUARD);
  assert.equal(active.has(directory), false);
  active.add(directory);
  const bytes = Buffer.from(JSON.stringify({ scope: SCOPE, nonce: crypto.randomUUID() }));
  const fd = fs.openSync(file, "wx+", 0o600);
  let original;
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); original = fs.fstatSync(fd, { bigint: true }); }
  finally { fs.closeSync(fd); }
  assert.ok(original.isFile() && original.ino > 0n && original.nlink === 1n);
  return { release() {
    const opened = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    try {
      const stat = fs.fstatSync(opened, { bigint: true }), current = fs.lstatSync(file, { bigint: true });
      assert.ok(stat.isFile() && !current.isSymbolicLink() && stat.dev === original.dev && stat.ino === original.ino && current.dev === stat.dev && current.ino === stat.ino && stat.size === BigInt(bytes.length) && stat.nlink === 1n && stat.mtimeNs === original.mtimeNs && stat.ctimeNs === original.ctimeNs);
      const observed = Buffer.alloc(bytes.length + 1);
      const count = fs.readSync(opened, observed, 0, observed.length, 0);
      assert.ok(count === bytes.length && observed.subarray(0, count).equals(bytes));
      fs.unlinkSync(file);
    } finally { fs.closeSync(opened); }
    active.delete(directory);
  } };
}
function assertCleanupSafe(root) {
  const directory = path.resolve(root);
  assert.equal(active.has(directory), false, "Preserve native renewal alert state while outcome is unresolved");
  let present;
  try { present = fs.lstatSync(path.join(directory, GUARD)); }
  catch (error) { if (error.code !== "ENOENT") throw error; }
  assert.equal(present, undefined, "Preserve pending renewal alert ownership receipt");
}
const FLAGS = Object.freeze([
  "actualPublicRenewal", "actualCurrentClaimFailed", "actualNonceConsumed",
  "actualNativeClientReachedFault", "faultRequestsNotForwarded",
  "noAdditionalCaIssuance", "originalServingPairPreserved",
  "independentTrustedTlsPreserved", "actualProductionOutboxDrained",
  "actualProductionDeliveryWorker", "independentNewSmtpReceipt",
  "exactAlertJobLineage", "singleSuccessfulEmailDelivery", "outboxReplayDeduplicated",
  "ownershipGuardReleased",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-acme-renewal-alert.js",
  "tests/e2e/helpers/certops-acme-transparent-proxy.js",
  "tests/e2e/acme-real-journey.js", "apps/api/services/certops/jobs.js",
  "apps/api/services/certops/agentDispatch.js", "apps/api/services/certops/outbox.js",
  "apps/api/services/certops/renewalFailureAlerts.js",
  "apps/api/services/certops/renewalAlertPolicy.js",
  "apps/api/src/shared/contactGroups.js",
  "apps/api/src/shared/retiredCertificateAlerts.js",
  "apps/api/src/shared/replaceAssetContactGroups.js",
  "apps/worker/src/certops-worker.js", "apps/worker/src/delivery-worker.js",
  "apps/worker/src/db.js", "apps/worker/src/notify/email.js",
  "apps/worker/src/shared/contactGroups.js", "apps/worker/src/shared/retiredCertificateAlerts.js",
  "deploy/compose/docker-compose.test.yml", "packages/agent/src/index.js",
  "scripts/certops-acme-certificate-outbox-report.js",
  "scripts/certops-acme-renewal-alert-report.js",
  "scripts/certops_acme_renewal_alert_proof.py",
  "scripts/test-support/acme-renewal-alert-proof.cjs",
  "tests/e2e/helpers/certops-acme-certificate-outbox.js",
  "packages/agent/src/acme/index.js", "packages/agent/src/acme/command.js",
]);
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const digest = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
function verifyProof(value) {
  assert.ok(value && typeof value === "object");
  assert.deepEqual(Object.keys(value).sort(), ["scope", "jobId", "claimId", "certificateId", "alertId", "faultRequestCount", "servingFingerprint", ...FLAGS].sort());
  assert.equal(value.scope, SCOPE);
  for (const key of ["jobId", "claimId", "certificateId"]) assert.match(value[key], UUID);
  assert.match(value.alertId, /^[1-9][0-9]*$/);
  assert.ok(Number.isSafeInteger(value.faultRequestCount) && value.faultRequestCount > 0);
  assert.match(value.servingFingerprint, /^[A-F0-9]{2}(?::[A-F0-9]{2}){31}$/);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
function productionDeliveryEnv(base, smtp) {
  assert.ok(base && typeof base === "object" && !Array.isArray(base));
  assert.ok(Number.isSafeInteger(smtp) && smtp >= 1025 && smtp <= 65535);
  const env = {
    ...base,
    NODE_ENV: "production",
    SMTP_HOST: "127.0.0.1",
    SMTP_PORT: String(smtp),
    SMTP_SECURE: "false",
    SMTP_REQUIRE_TLS: "false",
    SMTP_USER: "",
    SMTP_PASS: "",
    SMTP_USERS: "",
    SMTP_PASSWORDS: "",
    FROM_EMAIL: "qualification@localhost.local",
    FROM_EMAIL_NAME: "Owned qualification",
  };
  assert.equal(env.NODE_ENV, "production");
  assert.equal(env.SMTP_HOST, "127.0.0.1");
  assert.equal(env.SMTP_PORT, String(smtp));
  return env;
}
function independentReceipt({ nodeEnv, deliveryStatus, messages }) {
  assert.equal(typeof nodeEnv, "string");
  assert.equal(deliveryStatus, "sent");
  assert.ok(Array.isArray(messages) && messages.length <= 1000);
  return nodeEnv === "production" && messages.length === 1;
}
function localEndpoint(raw) {
  const url = new URL(raw);
  assert.equal(url.protocol, "http:");
  assert.ok(["127.0.0.1", "localhost"].includes(url.hostname));
  assert.equal(url.username + url.password + url.search + url.hash, "");
  return url;
}
function verifyAgainstOutbox(proof, previous) {
  verifyProof(proof);
  require("./certops-acme-certificate-outbox").verifyProof(previous);
  assert.equal(proof.certificateId, previous.certificateId);
  assert.equal(proof.servingFingerprint.replaceAll(":", "").toLowerCase(), previous.fingerprints[1]);
  assert.notEqual(proof.jobId.toLowerCase(), previous.jobId.toLowerCase());
  assert.notEqual(proof.claimId.toLowerCase(), previous.claimId.toLowerCase());
  return true;
}
function messageText(message) {
  let count = 0;
  const walk = (part, depth) => {
    assert.ok(depth <= 4 && ++count <= 32);
    const body = part?.Body || "";
    assert.equal(typeof body, "string");
    assert.ok(Buffer.byteLength(body) <= 1024 * 1024);
    const encoding = String(part?.Headers?.["Content-Transfer-Encoding"]?.[0] || "").toLowerCase();
    let text = body;
    if (encoding === "base64") text = Buffer.from(body, "base64").toString("utf8");
    if (encoding === "quoted-printable") text = body.replace(/=\r?\n/g, "").replace(/=([0-9a-f]{2})/gi, (_all, hex) => String.fromCharCode(parseInt(hex, 16)));
    assert.ok(!part?.Parts || Array.isArray(part.Parts));
    return text + (part?.Parts || []).map(item => walk(item, depth + 1)).join("\n");
  };
  return walk(message.Content, 0) + walk(message.MIME, 0);
}
function matchingMessages(body, { recipient, previous, jobId }) {
  assert.ok(body && Array.isArray(body.items) && body.items.length <= 1000);
  assert.equal(body.start, 0);
  assert.equal(body.total, body.items.length, "A truncated inbox cannot prove absence of duplicate mail");
  assert.equal(body.count, body.items.length);
  assert.match(jobId, UUID);
  return body.items.filter(message => {
    assert.equal(typeof message.ID, "string");
    return !previous.has(message.ID) &&
      (message.Content?.Headers?.To || []).some(to => {
        const text = String(to).trim();
        const address = text.match(/^[^<>]*<([^<>]+)>$/)?.[1] || text;
        return address.toLowerCase() === recipient.toLowerCase();
      }) &&
      (message.Content?.Headers?.Subject || []).some(subject => {
        const decoded = String(subject).replace(/=\?utf-8\?B\?([^?]+)\?=/gi, (_all, b64) => Buffer.from(b64, "base64").toString("utf8"));
        return decoded.includes("Certificate renewal failed");
      }) && messageText(message).includes(jobId);
  });
}
async function qualify(c) {
  assert.equal(process.platform, "linux");
  assert.equal(c.acmeKind, "certbot");
  assert.equal(process.env.CERTOPS_REAL_ACME_EAB || "none", "none");
  const mail = localEndpoint(process.env.CERTOPS_NATIVE_RENEWAL_MAILHOG_URL || "http://127.0.0.1:8025");
  const smtp = Number(process.env.CERTOPS_NATIVE_RENEWAL_SMTP_PORT || "1025");
  assert.ok(Number.isSafeInteger(smtp) && smtp >= 1025 && smtp <= 65535);
  const readMail = async () => {
    const response = await fetch(new URL("/api/v2/messages?limit=1000&start=0", mail), { redirect: "error", signal: AbortSignal.timeout(10000) });
    assert.equal(response.status, 200);
    const reader = response.body.getReader(), chunks = [];
    let bytes = 0, completed = false;
    try {
      for (;;) {
        const next = await reader.read();
        if (next.done) { completed = true; break; }
        bytes += next.value.byteLength;
        assert.ok(bytes <= 4 * 1024 * 1024, "Owned MailHog response exceeds bounded observation");
        chunks.push(next.value);
      }
    } finally { if (!completed) await reader.cancel(); reader.releaseLock(); }
    const raw = Buffer.concat(chunks).toString("utf8");
    const result = JSON.parse(raw);
    assert.ok(Array.isArray(result.items) && result.items.length <= 1000);
    assert.equal(result.start, 0);
    assert.equal(result.count, result.items.length);
    assert.equal(result.total, result.items.length);
    return result;
  };
  const previous = new Set((await readMail()).items.map(item => item.ID));
  const operation = registerOperation(c.workDir);
  const recipient = `native-renewal-${crypto.randomUUID()}@example.test`;
  const api = `/api/v1/workspaces/${c.workspaceId}`;
  const contact = await c.publicSession.request(`${api}/contacts`, "POST", { first_name: "Owned native renewal", last_name: "SMTP receipt", details: { email: recipient } });
  assert.equal(contact.status, 201);
  const configured = await c.publicSession.request(`${api}/alert-settings`, "PUT", {
    email_alerts_enabled: true, alert_thresholds: [7, 1, 0],
    delivery_window_start: "00:00", delivery_window_end: "23:59", delivery_window_tz: "UTC",
    contact_groups: [{ id: "owned-native-renewal", name: "Owned native renewal", email_contact_ids: [contact.body.id] }],
    default_contact_group_id: "owned-native-renewal",
  });
  assert.equal(configured.status, 200);
  const original = [c.certPath, c.keyPath].map(file => digest(fs.readFileSync(file)));
  const leaf = new crypto.X509Certificate(fs.readFileSync(c.certPath));
  const base = require("../../../scripts/certops-acme-bulk-report");
  const previousProof = require("../../../scripts/certops-acme-certificate-outbox-report").readProof(base.SCOPE, base.MAIN, c.repoRoot);
  assert.equal(previousProof.certificateId, c.certificateId);
  assert.equal(previousProof.fingerprints[1], digest(leaf.raw));
  assert.equal(await c.servedFingerprint(), leaf.fingerprint256);
  const before = c.proxy.snapshot();
  let jobId, job;
  c.proxy.setFailure("new-order");
  try {
    const response = await c.publicSession.request(`${api}/certops/jobs`, "POST", { operation: "renew", subjectType: "managed_certificate", subjectId: c.certificateId, idempotencyKey: crypto.randomUUID() });
    assert.equal(response.status, 201);
    jobId = response.body.job.id;
    assert.match(jobId, UUID);
    c.ownedJobIds.push(jobId);
    await c.waitUntil(async () => {
      assert.equal(c.agent.exitCode, null);
      assert.equal(c.agent.signalCode, null);
      job = (await c.pool.query("SELECT j.status,j.operation,j.mode,j.subject_id,j.claim_id,j.claimed_by_agent_id,j.attempt_count,a.agent_id FROM certificate_jobs j JOIN certops_agents a ON a.workspace_id=j.workspace_id AND a.id=j.claimed_by_agent_id WHERE j.workspace_id=$1 AND j.id=$2", [c.workspaceId, jobId])).rows[0];
      assert.ok(!["succeeded", "cancelled", "dry_run_complete", "rejected"].includes(job?.status));
      return job?.status === "failed";
    });
  } finally { c.proxy.setFailure(null); }
  assert.equal(job.operation, "renew");
  assert.equal(job.mode, "real");
  assert.equal(job.subject_id, c.certificateId);
  assert.equal(job.agent_id, c.agentId);
  assert.equal(job.attempt_count, 1);
  assert.match(job.claim_id, UUID);
  const nonce = (await c.pool.query("SELECT count(*)::int count FROM certops_consumed_nonces WHERE workspace_id=$1 AND job_id=$2 AND issued_to_agent_id=$3 AND consumed_at IS NOT NULL", [c.workspaceId, jobId, job.claimed_by_agent_id])).rows[0];
  assert.equal(nonce.count, 1);
  const after = c.proxy.snapshot();
  assert.equal(after.transportFailed, false);
  const refused = after.perStage["new-order"].refused - before.perStage["new-order"].refused;
  assert.ok(refused > 0);
  assert.equal(after.perStage["new-order"].forwarded, before.perStage["new-order"].forwarded);
  assert.equal(after.issuedResponses, before.issuedResponses);
  assert.deepEqual([c.certPath, c.keyPath].map(file => digest(fs.readFileSync(file))), original);
  assert.equal(await c.servedFingerprint(), leaf.fingerprint256);
  await c.verifyDnsCleanup();
  const pending = (await c.pool.query("SELECT id FROM certops_outbox WHERE workspace_id=$1 AND event_type='renewal_alert_requested' AND payload->>'jobId'=$2", [c.workspaceId, jobId])).rows;
  assert.equal(pending.length, 1);
  const { drainCertOpsOutbox } = await import(pathToFileURL(path.join(c.repoRoot, "apps/worker/src/certops-worker.js")).href);
  await drainCertOpsOutbox({ dbPool: c.pool, env: process.env });
  const alertKey = `cert_renewal_failed:${jobId}`;
  const token = (await c.pool.query("SELECT token_id FROM managed_certificates WHERE workspace_id=$1 AND id=$2", [c.workspaceId, c.certificateId])).rows[0];
  assert.ok(Number.isSafeInteger(token?.token_id) && token.token_id > 0, "Actual native inventory must provide the alert token");
  const alerts = async () => (await c.pool.query("SELECT id::text,status,token_id FROM alert_queue WHERE alert_key=$1", [alertKey])).rows;
  const queued = await alerts();
  assert.equal(queued.length, 1);
  assert.equal(queued[0].token_id, token.token_id);
  const due = (await c.pool.query("SELECT aq.id::text,t.workspace_id FROM alert_queue aq JOIN tokens t ON t.id=aq.token_id WHERE aq.status IN ('pending','partial','failed') AND aq.due_date<=CURRENT_DATE AND (aq.next_attempt_at IS NULL OR aq.next_attempt_at<=NOW()) ORDER BY aq.id LIMIT 501")).rows;
  assert.equal(due.length, 1, "Delivery must not adopt unrelated pending fixture work");
  assert.equal(due[0].id, queued[0].id);
  assert.equal(due[0].workspace_id, c.workspaceId);
  assert.equal(independentReceipt({ nodeEnv: "test", deliveryStatus: "sent", messages: [] }), false);
  const childEnv = productionDeliveryEnv(process.env, smtp);
  const delivered = spawnSync(process.execPath, ["src/delivery-worker.js"], {
    cwd: path.join(c.repoRoot, "apps/worker"), stdio: "ignore", windowsHide: true, timeout: 90000,
    env: childEnv,
  });
  assert.equal(delivered.error, undefined, "Production delivery worker must drain normally");
  assert.equal(delivered.signal, null);
  assert.equal(delivered.status, 0);
  assert.equal((await alerts())[0].status, "sent");
  assert.equal((await c.pool.query("SELECT count(*)::int count FROM alert_delivery_log WHERE alert_queue_id=$1 AND channel='email' AND status='success'", [queued[0].id])).rows[0].count, 1);
  await c.waitUntil(async () => matchingMessages(await readMail(), { recipient, previous, jobId }).length === 1, 30000);
  const messages = matchingMessages(await readMail(), { recipient, previous, jobId });
  assert.equal(independentReceipt({ nodeEnv: "test", deliveryStatus: "sent", messages }), false, "Test-mode simulated delivery must not count as the SMTP receipt");
  assert.equal(independentReceipt({ nodeEnv: childEnv.NODE_ENV, deliveryStatus: "sent", messages }), true);
  await drainCertOpsOutbox({ dbPool: c.pool, env: process.env });
  assert.equal((await alerts()).length, 1);
  const replayed = matchingMessages(await readMail(), { recipient, previous, jobId });
  assert.equal(independentReceipt({ nodeEnv: "test", deliveryStatus: "sent", messages: replayed }), false);
  assert.equal(independentReceipt({ nodeEnv: childEnv.NODE_ENV, deliveryStatus: "sent", messages: replayed }), true);
  assert.deepEqual([c.certPath, c.keyPath].map(file => digest(fs.readFileSync(file))), original);
  assert.equal(await c.servedFingerprint(), leaf.fingerprint256);
  const proof = { scope: SCOPE, jobId, claimId: job.claim_id, certificateId: c.certificateId, alertId: queued[0].id, faultRequestCount: refused, servingFingerprint: leaf.fingerprint256, ...Object.fromEntries(FLAGS.map(flag => [flag, true])) };
  verifyAgainstOutbox(proof, previousProof);
  operation.release();
  return proof;
}
module.exports = { SCENARIO, SCOPE, SIDECAR, FIELD, FLAGS, REQUIRED_SOURCES, verifyProof, verifyAgainstOutbox, productionDeliveryEnv, independentReceipt, localEndpoint, matchingMessages, qualify, registerOperation, assertCleanupSafe };
