"use strict";
// Run only against a disposable Core API and database. Public fixtures are read from
// CSR_TEST_FIXTURES; a private key is read solely for the rejection request.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createHash, randomUUID } = require("node:crypto");
const { execFileSync } = require("node:child_process");
const request = require("supertest");
const bcrypt = require("bcryptjs");
const { pool } = require("../../apps/api/db/database");
const { parsePublicCertificateMaterial } = require("../../apps/api/services/certops/parser");
const { bridgeEndpointCertificateObservation } = require("../../apps/api/services/certops/monitorBridge");
const { containsPrivateKeyMaterial } = require("../../apps/api/utils/secretMaterial");
const api = process.env.CSR_TEST_API || "http://127.0.0.1:4000";
const dir = process.env.CSR_TEST_FIXTURES || path.join(process.env.TEMP || "/tmp", "tt-csr-245-manual-20260929");
const evidence = { at: new Date().toISOString(), api, checks: [], workflows: {}, certificates: {} };
let ws, uid, agent, csrf;
const file = (name, extension) => fs.readFileSync(path.join(dir, `${name}.${extension}`), "utf8");
const csr = name => file(name, "csr.pem");
const cert = (name, variant = "same") => file(name, `${variant}.crt.pem`);
const leaf = (name, variant) => parsePublicCertificateMaterial(cert(name, variant))[0];
const q = async (sql, values = []) => (await pool.query(sql, values)).rows;
function ok(name, actual, expected) {
  assert.deepEqual(actual, expected, name);
  evidence.checks.push({ name, actual });
  console.log(`PASS ${name}: ${JSON.stringify(actual)}`);
}
async function login(email, password) {
  const a = request.agent(api);
  const token = (await a.get("/api/csrf-token")).body.csrfToken;
  const res = await a.post("/auth/login").set("X-CSRF-Token", token).send({ email, password });
  assert.equal(res.status, 200, `login ${email}`);
  return { agent: a, csrf: token };
}
function route(id, operation) {
  return `/api/v1/workspaces/${ws}/certops/csrs${id ? `/${id}` : ""}${operation ? `/${operation}` : ""}`;
}
function apiCall(method, url, body, session = { agent, csrf }) {
  const req = session.agent[method](url).set("X-CSRF-Token", session.csrf);
  return body === undefined ? req : req.send(body);
}
async function create(name, target, existingCertificateId) {
  const body = { csrPem: csr(name), ...(typeof target === "string" ? { targetId: target } : { target }), ...(existingCertificateId ? { existingCertificateId } : {}) };
  const res = await apiCall("post", route(), body);
  assert.equal(res.status, 201, `create ${name}: ${JSON.stringify(res.body)}`);
  evidence.workflows[name] = res.body.id;
  return res.body;
}
const get = async flow => {
  const response = await apiCall("get", route(flow.id));
  assert.equal(response.status, 200, `get ${flow.id}: ${response.status} ${JSON.stringify(response.body)}`);
  return response.body;
};
const signed = (flow, name, variant) => apiCall("post", route(flow.id, "signed-certificate"), { certificatePem: cert(name, variant) });
const act = (flow, operation) => apiCall("post", route(flow.id, operation), {});
const managed = async id => (await q("SELECT id,status,fingerprint_sha256,not_after,token_id,profile_id,public_metadata FROM managed_certificates WHERE id=$1", [id]))[0];
const instanceCount = async id => (await q("SELECT count(*)::int AS n FROM certificate_instances WHERE target_id=$1", [id]))[0].n;
async function addCertificate(name, status = "active") {
  const c = leaf(name);
  const id = (await q(`INSERT INTO managed_certificates (workspace_id,status,source,name,certificate_pem,fingerprint_sha256,spki_fingerprint_sha256,not_after,public_metadata)
    VALUES ($1,$2,'api',$3,$4,$5,$6,$7,'{"manual_case":"245"}') RETURNING id`,
  [ws, status, name, c.certificatePem, c.fingerprintSha256, c.spkiFingerprintSha256, c.notAfter]))[0].id;
  evidence.certificates[name] = id;
  return id;
}
async function monitor(name) {
  const host = `${name}-${randomUUID().slice(0, 8)}.example.test`;
  const tokenId = (await q("INSERT INTO tokens (workspace_id,user_id,created_by,name,expiration,type,category) VALUES ($1,$2,$2,$3,'2030-01-01','ssl_cert','cert') RETURNING id", [ws, uid, `CSR ${name} monitor`]))[0].id;
  const monitorId = (await q("INSERT INTO domain_monitors (workspace_id,url,token_id,created_by) VALUES ($1,$2,$3,$4) RETURNING id", [ws, `https://${host}`, tokenId, uid]))[0].id;
  const targetId = (await q("INSERT INTO certificate_targets (workspace_id,domain_monitor_id,token_id,name,target_type,source,source_ref,hostname,url) VALUES ($1,$2,$3,$4,'endpoint','endpoint_monitor',$6,$4,$5) RETURNING id", [ws, monitorId, tokenId, host, `https://${host}`, monitorId]))[0].id;
  return { host, tokenId, monitorId, targetId };
}
async function observe(mon, name, variant = "changed") {
  const c = leaf(name, variant);
  const r = await bridgeEndpointCertificateObservation({ dbPool: pool, env: { CERTOPS_ENABLED: "true" }, workspaceId: ws,
    domainMonitorId: mon.monitorId, tokenId: mon.tokenId, hostname: mon.host, url: `https://${mon.host}`,
    source: "endpoint_monitor", certificate: { issuer: c.issuer, subject: c.subject, serialNumber: c.serialNumber,
      fingerprintSha256: c.fingerprintSha256, notAfter: c.notAfter, certificatePem: c.certificatePem,
      subjectAltNames: c.subjectAltNames } });
  ok(`${name} real observation`, { skipped: r.skipped, target: r.target.id, instance: Boolean(r.instance?.id) },
    { skipped: false, target: mon.targetId, instance: true });
  return r;
}
function digest(pem) { return createHash("sha256").update(Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, ""), "base64")).digest("hex"); }
async function run() {
  assert.equal(api, "http://127.0.0.1:4000", "Requires disposable local API");
  assert.match(process.env.CSR_TEST_HAPPY_ID || "", /^[0-9a-f-]{36}$/i,
    "Set CSR_TEST_HAPPY_ID to the dashboard-created workflow in the disposable workspace");
  const email = process.env.ADMIN_EMAIL || "csr-admin@example.test";
  ({ agent, csrf } = await login(email, process.env.ADMIN_PASSWORD || "CsrManualTest123!"));
  uid = (await q("SELECT id FROM users WHERE email=$1", [email]))[0].id;
  ws = process.env.CSR_TEST_WORKSPACE || (await q("SELECT workspace_id FROM workspace_memberships WHERE user_id=$1 ORDER BY (role='admin') DESC LIMIT 1", [uid]))[0].workspace_id;
  evidence.workspaceId = ws;
  ok("migration 56 present", (await q("SELECT to_regclass('certificate_csr_workflows') AS name"))[0].name, "certificate_csr_workflows");

  // 1. The first request was created through the dashboard.
  const happy = await get({ id: process.env.CSR_TEST_HAPPY_ID });
  evidence.workflows.happy = happy.id;
  if (happy.status === "pending_signature") {
  ok("dashboard CSR pending", happy.status, "pending_signature");
  ok("CSR export DER digest", digest(happy.csrPem), digest(csr("happy")));
  ok("CSR digest stored", happy.csrDerSha256, digest(csr("happy")));
  ok("same target same CSR idempotent", (await create("happy", happy.targetId)).id, happy.id);
  const other = await create("happy-other", happy.targetId);
  ok("same key different CSR distinct", { distinct: other.id !== happy.id, sameSpki: other.spkiFingerprintSha256 === happy.spkiFingerprintSha256 }, { distinct: true, sameSpki: true });
  const imported = await signed(happy, "happy");
  ok("new signed import", { http: imported.status, state: imported.body.status }, { http: 200, state: "signed_pending_install" });
  const provisional = await managed(imported.body.managedCertificateId);
  ok("new provisional certificate", { status: provisional.status, token: provisional.token_id }, { status: "provisioning", token: null });
  ok("no pending instance", await instanceCount(happy.targetId), 0);
  const confirm = await act(happy, "confirm-installation");
  ok("manual attestation", { http: confirm.status, state: confirm.body.status, method: confirm.body.confirmationMethod, actor: confirm.body.confirmedBy, observed: confirm.body.observedInstanceId },
    { http: 200, state: "completed", method: "manual", actor: uid, observed: null });
  ok("no fabricated instance", await instanceCount(happy.targetId), 0);
  const active = await managed(imported.body.managedCertificateId);
  ok("activation after attestation", { status: active.status, linkedToken: Boolean(active.token_id) }, { status: "active", linkedToken: true });
  const tokenExpiry = (await q("SELECT expiration FROM tokens WHERE id=$1", [active.token_id]))[0].expiration;
  ok("token signed expiry", String(tokenExpiry).slice(0, 10), new Date(leaf("happy").notAfter).toISOString().slice(0, 10));
  ok("completed cannot cancel", (await act(happy, "cancel")).status, 409);
  } else {
    ok("resumed happy workflow", happy.status, "completed");
    ok("resumed happy has no instance", await instanceCount(happy.targetId), 0);
  }

  // 2. Rotation preserves A until installation.
  if (!(await q("SELECT 1 FROM certificate_csr_workflows WHERE workspace_id=$1 AND csr_der_sha256=$2 AND status='completed'", [ws, digest(csr("rotation-new"))])).length) {
  const a = await addCertificate("rotation-old"), baseline = await managed(a);
  const rotation = await create("rotation-new", { name: "Manual rotation host", type: "host" }, a);
  const rotImport = await signed(rotation, "rotation-new");
  ok("rotation signed import", { http: rotImport.status, certificate: rotImport.body.managedCertificateId }, { http: 200, certificate: a });
  const before = await managed(a);
  ok("rotation baseline retained", { fp: before.fingerprint_sha256, expiry: before.not_after.toISOString(), token: before.token_id, profile: before.profile_id, metadata: before.public_metadata },
    { fp: baseline.fingerprint_sha256, expiry: baseline.not_after.toISOString(), token: baseline.token_id, profile: baseline.profile_id, metadata: baseline.public_metadata });
  ok("rotation no pending instance", await instanceCount(rotation.targetId), 0);
  ok("rotation manual completion", (await act(rotation, "confirm-installation")).body.status, "completed");
  ok("rotation promoted same identity", (await managed(a)).fingerprint_sha256, leaf("rotation-new").fingerprintSha256);
  ok("rotation still no instance", await instanceCount(rotation.targetId), 0);
  } else ok("resumed rotation workflow", true, true);

  // 3-4. Name review on both sides of a normal monitor observation.
  if (!(await q("SELECT 1 FROM certificate_csr_workflows WHERE workspace_id=$1 AND csr_der_sha256=$2 AND identity_conflict_at IS NOT NULL", [ws, digest(csr("late-new"))])).length) {
  for (const [name, ackFirst] of [["obs-after", true], ["obs-before", false]]) {
    const mon = await monitor(name), flow = await create(name, mon.targetId);
    const imported = await signed(flow, name, "changed");
    ok(`${name} changed names`, { http: imported.status, additions: imported.body.nameAdditions.length > 0, namesChanged: imported.body.namesChanged }, { http: 200, additions: true, namesChanged: true });
    ok(`${name} manual blocked`, (await act(flow, "confirm-installation")).status, 409);
    if (ackFirst) ok(`${name} ack first`, (await act(flow, "acknowledge-names")).status, 200);
    const observed = await observe(mon, name);
    const current = await get(flow);
    ok(`${name} links factual instance`, current.observedInstanceId, observed.instance.id);
    if (ackFirst) ok(`${name} completes after observation`, current.status, "completed");
    else {
      ok(`${name} pending before review`, current.status, "signed_pending_install");
      ok(`${name} completes from prior observation`, (await act(flow, "acknowledge-names")).body.status, "completed");
    }
    ok(`${name} no manual attestation`, (await get(flow)).confirmedAt, null);
  }

  // 5-8. Known identity, retired identity, collisions, SPKI and custody.
  const knownId = await addCertificate("known"), known = await create("known", { name: "Known host", type: "host" });
  ok("known nonterminal reuse", (await signed(known, "known")).body.managedCertificateId, knownId);
  await q("UPDATE managed_certificates SET status='revoked' WHERE id=$1", [knownId]);
  const retired = await create("known", { name: "Retired known host", type: "host" });
  ok("retired fingerprint conflict", (await signed(retired, "known")).status, 409);
  ok("retired remains retired", (await managed(knownId)).status, "revoked");
  const collisionA = await addCertificate("late-old");
  await addCertificate("spki");
  const collision = await create("spki", { name: "A B import conflict", type: "host" }, collisionA);
  ok("A B signed import conflict", (await signed(collision, "spki")).status, 409);
  ok("A B no rebinding", (await get(collision)).managedCertificateId, null);
  ok("A unchanged", (await managed(collisionA)).fingerprint_sha256, leaf("late-old").fingerprintSha256);
  const mismatch = await create("cancel", { name: "SPKI mismatch host", type: "host" });
  ok("SPKI mismatch", (await signed(mismatch, "spki")).status, 422);
  ok("SPKI mismatch no leaf", (await get(mismatch)).signedLeafPem, null);
  const lateMon = await monitor("late-new"), late = await create("late-new", lateMon.targetId, collisionA);
  ok("late signed import", (await signed(late, "late-new", "changed")).status, 200);
  const lateObs = await observe(lateMon, "late-new");
  const lateCurrent = await get(late);
  ok("late B conflict visible", { owner: lateCurrent.identityConflict?.observedCertificateId, instance: lateCurrent.identityConflict?.observedInstanceId, state: lateCurrent.status },
    { owner: lateObs.managedCertificate.id, instance: lateObs.instance.id, state: "signed_pending_install" });
  ok("late names can be acknowledged", (await act(late, "acknowledge-names")).status, 200);
  ok("late manual conflict", (await act(late, "confirm-installation")).status, 409);
  ok("late A unchanged", (await managed(collisionA)).fingerprint_sha256, leaf("late-old").fingerprintSha256);
  } else ok("resumed observation and collision scenarios", true, true);
  const privatePem = file("happy", "key.pem"), refusedTarget = "Private rejection target";
  const refused = await apiCall("post", route(), { csrPem: `${csr("happy")}\n${privatePem}`, target: { name: refusedTarget, type: "host" } });
  ok("private CSR rejected", refused.status, 422);
  ok("private response contains no key", refused.text.includes(privatePem), false);
  ok("private target absent", (await q("SELECT count(*)::int AS n FROM certificate_targets WHERE workspace_id=$1 AND name=$2", [ws, refusedTarget]))[0].n, 0);
  const otherId = (await q("SELECT id FROM certificate_csr_workflows WHERE workspace_id=$1 AND csr_der_sha256=$2 LIMIT 1", [ws, digest(csr("happy-other"))]))[0].id;
  ok("private cert rejected", (await apiCall("post", route(otherId, "signed-certificate"), { certificatePem: privatePem })).status, 422);

  // 9. Viewer and foreign workspace sessions, cancellation and import replay.
  const pass = "CsrManualRole123!", hash = await bcrypt.hash(pass, 10);
  const viewerEmail = `csr-viewer-${randomUUID()}@example.test`, managerEmail = `csr-manager-${randomUUID()}@example.test`;
  const viewerId = (await q("INSERT INTO users (email,display_name,password_hash,email_verified) VALUES ($1,'CSR Viewer',$2,true) RETURNING id", [viewerEmail, hash]))[0].id;
  const managerId = (await q("INSERT INTO users (email,display_name,password_hash,email_verified) VALUES ($1,'CSR Other Manager',$2,true) RETURNING id", [managerEmail, hash]))[0].id;
  await q("INSERT INTO workspace_memberships (user_id,workspace_id,role,invited_by) VALUES ($1,$2,'viewer',$3)", [viewerId, ws, uid]);
  const otherWs = (await q("INSERT INTO workspaces (id,name,created_by) VALUES ($1,'CSR other workspace',$2) RETURNING id", [randomUUID(), managerId]))[0].id;
  await q("INSERT INTO workspace_memberships (user_id,workspace_id,role,invited_by) VALUES ($1,$2,'workspace_manager',$1)", [managerId, otherWs]);
  const viewer = await login(viewerEmail, pass), manager = await login(managerEmail, pass);
  for (const [kind, session] of [["viewer", viewer], ["other workspace", manager]]) {
    for (const [operation, method, url, body] of [["list", "get", route()], ["export", "get", route(happy.id)], ["mutate", "post", route(happy.id, "cancel"), {}]]) {
      const code = (await apiCall(method, url, body, session)).status;
      ok(`${kind} ${operation} denied`, code === 403 || code === 404, true);
    }
  }
  const cancel = await create("cancel", { name: "Cancellation host", type: "host" });
  ok("cancel pending", (await act(cancel, "cancel")).status, 200);
  ok("cancel audited", (await q("SELECT count(*)::int AS n FROM audit_events WHERE action='CERTOPS_CSR_CANCELLED' AND metadata->>'workflow_id'=$1", [cancel.id]))[0].n, 1);
  ok("cancel blocks import", (await signed(cancel, "cancel")).status, 409);
  ok("cancel blocks completion", (await act(cancel, "confirm-installation")).status, 409);
  const knownId = (await q("SELECT id FROM certificate_csr_workflows WHERE workspace_id=$1 AND csr_der_sha256=$2 AND status='signed_pending_install' LIMIT 1", [ws, digest(csr("known"))]))[0].id;
  ok("same signed import replay", (await signed({ id: knownId }, "known")).status, 200);
  ok("different signed import conflict", (await signed({ id: knownId }, "known", "changed")).status, 409);

  // 10. Failed audit insert must roll back a create. Conflict audit is best effort.
  if (!(await q("SELECT 1 FROM certificate_csr_workflows WHERE workspace_id=$1 AND csr_der_sha256=$2 AND identity_conflict_at IS NOT NULL", [ws, digest(csr("audit-late"))])).length) {
  await q(`CREATE OR REPLACE FUNCTION csr_245_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF NEW.action = 'CERTOPS_CSR_IMPORTED' THEN RAISE EXCEPTION 'CSR manual audit failure'; END IF;
    RETURN NEW; END $$`);
  await q("CREATE TRIGGER csr_245_fail_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION csr_245_fail_audit()");
  try {
    const name = `Audit rollback target ${randomUUID().slice(0, 8)}`;
    ok("audit failure response", (await apiCall("post", route(), { csrPem: csr("rotation-old"), target: { name, type: "host" } })).status, 500);
    ok("audit failure target rollback", (await q("SELECT count(*)::int AS n FROM certificate_targets WHERE workspace_id=$1 AND name=$2", [ws, name]))[0].n, 0);
    ok("audit failure workflow rollback", (await q("SELECT count(*)::int AS n FROM certificate_csr_workflows w JOIN certificate_targets t ON t.id=w.target_id WHERE w.workspace_id=$1 AND w.csr_der_sha256=$2 AND t.name=$3", [ws, digest(csr("rotation-old")), name]))[0].n, 0);
    await q(`CREATE OR REPLACE FUNCTION csr_245_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
      IF NEW.action = 'CERTOPS_CSR_OBSERVED_IDENTITY_CONFLICT' THEN RAISE EXCEPTION 'CSR manual conflict audit failure'; END IF;
      RETURN NEW; END $$`);
    const collisionA = (await q("SELECT id FROM managed_certificates WHERE workspace_id=$1 AND name='late-old' LIMIT 1", [ws]))[0].id;
    const mon = await monitor("audit-late"), flow = await create("audit-late", mon.targetId, collisionA);
    ok("audit conflict signed", (await signed(flow, "audit-late", "changed")).status, 200);
    const observation = await observe(mon, "audit-late");
    const current = await get(flow);
    ok("audit failure observation persists", current.identityConflict?.observedInstanceId, observation.instance.id);
    ok("audit failure conflict remains pending", current.status, "signed_pending_install");
  } finally {
    await q("DROP TRIGGER IF EXISTS csr_245_fail_audit ON audit_events");
    await q("DROP FUNCTION IF EXISTS csr_245_fail_audit()");
  }
  } else ok("resumed audit failure scenarios", true, true);

  // Complete the active-identity preservation check with a real linked token,
  // contact, profile, alert row, and older observed instance.
  if (!(await q("SELECT 1 FROM certificate_targets WHERE workspace_id=$1 AND name='Rotation preservation host'", [ws])).length) {
    const identityId = (await q("SELECT managed_certificate_id FROM certificate_csr_workflows WHERE id=$1", [happy.id]))[0].managed_certificate_id;
    const identity = await managed(identityId);
    const profileId = (await q("INSERT INTO certificate_profiles (workspace_id,name,source) VALUES ($1,$2,'manual') RETURNING id", [ws, `CSR preservation ${randomUUID().slice(0, 8)}`]))[0].id;
    await q("UPDATE managed_certificates SET profile_id=$2 WHERE id=$1", [identityId, profileId]);
    await q("UPDATE tokens SET contacts='ops@example.test' WHERE id=$1", [identity.token_id]);
    const alertId = (await q("INSERT INTO alert_queue (user_id,token_id,alert_key,threshold_days,due_date) VALUES ($1,$2,$3,30,'2030-01-01') RETURNING id", [uid, identity.token_id, `csr-preserve:${randomUUID()}`]))[0].id;
    const oldTarget = (await q("INSERT INTO certificate_targets (workspace_id,name,target_type,source) VALUES ($1,$2,'host','manual') RETURNING id", [ws, `CSR old deployment ${randomUUID().slice(0, 8)}`]))[0].id;
    const oldInstance = (await q("INSERT INTO certificate_instances (workspace_id,managed_certificate_id,target_id,source,observed_fingerprint_sha256,observed_at) VALUES ($1,$2,$3,'manual',$4,NOW()) RETURNING id", [ws, identityId, oldTarget, identity.fingerprint_sha256]))[0].id;
    const baseline = { certificate: await managed(identityId), token: (await q("SELECT id,expiration,contacts FROM tokens WHERE id=$1", [identity.token_id]))[0],
      alerts: (await q("SELECT count(*)::int AS n FROM alert_queue WHERE token_id=$1", [identity.token_id]))[0].n,
      instances: (await q("SELECT count(*)::int AS n FROM certificate_instances WHERE managed_certificate_id=$1", [identityId]))[0].n };
    const flow = await create("rotation-old", { name: "Rotation preservation host", type: "host" }, identityId);
    ok("preservation signed import", (await signed(flow, "rotation-old")).status, 200);
    const preInstall = { certificate: await managed(identityId), token: (await q("SELECT id,expiration,contacts FROM tokens WHERE id=$1", [identity.token_id]))[0],
      alerts: (await q("SELECT count(*)::int AS n FROM alert_queue WHERE token_id=$1", [identity.token_id]))[0].n,
      instances: (await q("SELECT count(*)::int AS n FROM certificate_instances WHERE managed_certificate_id=$1", [identityId]))[0].n };
    ok("active identity token contacts profile alerts and instances unchanged before install", preInstall, baseline);
    ok("preservation manual confirmation", (await act(flow, "confirm-installation")).body.status, "completed");
    const advanced = await managed(identityId);
    ok("preservation identity and profile", { id: advanced.id, profile: advanced.profile_id }, { id: identityId, profile: profileId });
    ok("preservation linked token and contacts", (await q("SELECT id,contacts FROM tokens WHERE id=$1", [advanced.token_id]))[0], { id: identity.token_id, contacts: "ops@example.test" });
    ok("preservation old instance", (await q("SELECT id FROM certificate_instances WHERE id=$1 AND managed_certificate_id=$2", [oldInstance, identityId]))[0].id, oldInstance);
    ok("preservation alert record", (await q("SELECT id FROM alert_queue WHERE id=$1 AND token_id=$2", [alertId, identity.token_id]))[0].id, alertId);
    ok("preservation new signed expiry", (await q("SELECT expiration::text AS expiration FROM tokens WHERE id=$1", [identity.token_id]))[0].expiration, new Date(leaf("rotation-old").notAfter).toISOString().slice(0, 10));
  } else {
    ok("resumed preservation scenario", true, true);
    const identityId = (await q("SELECT managed_certificate_id FROM certificate_csr_workflows WHERE id=$1", [happy.id]))[0].managed_certificate_id;
    const linked = await managed(identityId);
    ok("preservation new signed expiry", (await q("SELECT expiration::text AS expiration FROM tokens WHERE id=$1", [linked.token_id]))[0].expiration, new Date(leaf("rotation-old").notAfter).toISOString().slice(0, 10));
  }

  // Database scan uses the same content detector as the production boundary.
  const csrRows = await q("SELECT csr_pem,signed_leaf_pem,signed_chain_pem FROM certificate_csr_workflows WHERE workspace_id=$1", [ws]);
  const certRows = await q("SELECT certificate_pem,public_metadata FROM managed_certificates WHERE workspace_id=$1", [ws]);
  const audits = await q("SELECT metadata FROM audit_events WHERE workspace_id=$1 AND action LIKE 'CERTOPS_CSR_%'", [ws]);
  ok("CSR rows public only", csrRows.some(row => containsPrivateKeyMaterial(row)), false);
  ok("certificate rows public only", certRows.some(row => containsPrivateKeyMaterial(row)), false);
  ok("CSR audit rows public only", audits.some(row => containsPrivateKeyMaterial(row)), false);
  const keyLine = file("happy", "key.pem").split(/\r?\n/).find(line => /^[A-Za-z0-9+/]{64}$/.test(line));
  assert.ok(keyLine, "local key fingerprint line available for custody scan");
  const changedPaths = execFileSync("git", ["status", "--porcelain", "-uall"], { encoding: "utf8" })
    .split(/\r?\n/).filter(Boolean).map(line => line.slice(3));
  const leakedFiles = changedPaths.filter(relative => {
    const absolute = path.resolve(__dirname, "../..", relative);
    return fs.existsSync(absolute) && fs.statSync(absolute).isFile() && fs.readFileSync(absolute).includes(keyLine);
  });
  ok("no operator key in changed control-plane files", leakedFiles, []);
  evidence.counts = { workflows: csrRows.length, certificates: certRows.length, auditRows: audits.length,
    observedInstances: (await q("SELECT count(*)::int AS n FROM certificate_instances WHERE workspace_id=$1", [ws]))[0].n };
}
run().then(() => {
  fs.writeFileSync(path.join(dir, "evidence.json"), JSON.stringify(evidence, null, 2));
  console.log(`COMPLETE ${evidence.checks.length} checks`);
}).catch(error => {
  evidence.failure = { message: error.message, stack: error.stack };
  fs.writeFileSync(path.join(dir, "evidence.json"), JSON.stringify(evidence, null, 2));
  console.error(`FAILED ${error.stack}`);
  process.exitCode = 1;
}).finally(() => pool.end());
