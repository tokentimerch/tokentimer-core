"use strict";
/* Authenticated public admission for the installed Windows ACME journey.
 * Only owned user/membership prerequisites use SQL. Anonymous and viewer
 * refusals precede authorized manager POST admission and idempotent replay; job/source/
 * requester/Windows target derivation are independently read from PostgreSQL.
 * No service-layer issuance call or seeded job can satisfy this producer.
 */
const assert = require("node:assert/strict"),
  crypto = require("node:crypto");
function buildPublicWindowsIssue({
  workspaceId,
  keyProfile,
  domain,
  site,
  port,
  caEndpoint,
  idempotencyKey = crypto.randomUUID(),
}) {
  assert.match(workspaceId, /^[a-f0-9-]{36}$/);
  assert.match(idempotencyKey, /^[a-f0-9-]{36}$/);
  return {
    route: `/api/v1/workspaces/${workspaceId}/certops/jobs`,
    body: {
      operation: "issue",
      idempotencyKey,
      payload: {
        ...keyProfile,
        sans: [domain],
        target: {
          type: "windows-iis",
          reference: domain,
          store: "My",
          binding: { site, port, sniHost: domain },
        },
        commandRef: "qualification-acmesh",
        caEndpoint,
        acmeKind: "acme.sh",
        dnsProvider: "pebble-challtestsrv",
        dnsZone: "example.test",
      },
    },
  };
}
function verifyPublicIssuanceFacts(facts) {
  for (const field of [
    "anonymousAdmissionRefused",
    "viewerAdmissionRefused",
    "authorizedAdmissionCreated",
    "idempotentSameJob",
    "publicRequesterPreserved",
    "serverDerivedOsStoreKeyMode",
    "publicPayloadPreserved",
    "nativeJobSucceeded",
    "nativeCngIisTrustedTlsVerified",
    "ownedActorCleanup",
  ])
    assert.equal(facts[field], true, field);
  assert.ok([401, 403].includes(facts.anonymousStatus));
  assert.equal(facts.viewerStatus, 403);
  assert.equal(facts.createStatus, 201);
  assert.equal(facts.replayStatus, 201);
  assert.equal(facts.authorizedRole, "workspace_manager");
  assert.equal(facts.source, "api");
  assert.equal(facts.mode, "real");
  return true;
}
async function admitPublicWindowsIssue({
  baseUrl,
  pool,
  workspaceId,
  session,
  input,
  ownedJobs,
}) {
  const { route, body } = input;
  const jobs = async () =>
    (
      await pool.query(
        "SELECT id,source,mode,requested_by_user_id,payload,subject_id FROM certificate_jobs WHERE workspace_id=$1 AND idempotency_key=$2",
        [workspaceId, body.idempotencyKey],
      )
    ).rows;
  const admissionState = async () =>
    (
      await pool.query(
        "SELECT (SELECT COUNT(*)::int FROM certificate_jobs WHERE workspace_id=$1) AS jobs,(SELECT COUNT(*)::int FROM managed_certificates WHERE workspace_id=$1 AND source='agent_issuance') AS issued",
        [workspaceId],
      )
    ).rows[0];
  const beforeDenied = await admissionState();
  assert.deepEqual(await jobs(), []);
  const anonymous = await fetch(new URL(route, baseUrl), {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30000),
  });
  assert.ok(
    [401, 403].includes(anonymous.status),
    "Anonymous public issuance must be refused",
  );
  await anonymous.arrayBuffer();
  assert.deepEqual(await jobs(), []);
  assert.deepEqual(
    await admissionState(),
    beforeDenied,
    "Anonymous refusal must create no job or issuance identity",
  );
  // A new run-owned real login receives an explicit fixture membership. The
  // route must enforce that role; no protected job/certificate state is seeded.
  await pool.query(
    "INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'viewer')",
    [workspaceId, session.userId],
  );
  const viewer = await session.request(route, "POST", body);
  assert.equal(viewer.status, 403);
  assert.equal(viewer.body.code, "INSUFFICIENT_ROLE");
  assert.deepEqual(await jobs(), []);
  assert.deepEqual(
    await admissionState(),
    beforeDenied,
    "Viewer refusal must create no job or issuance identity",
  );
  await pool.query(
    "UPDATE workspace_memberships SET role='workspace_manager' WHERE workspace_id=$1 AND user_id=$2",
    [workspaceId, session.userId],
  );
  const created = await session.request(route, "POST", body);
  assert.equal(created.status, 201);
  const job = created.body.job;
  assert.ok(job.id && job.subjectId);
  ownedJobs.push(job.id);
  assert.equal(job.source, "api");
  assert.equal(String(job.requestedByUserId), String(session.userId));
  assert.notEqual(
    job.status,
    "pending_approval",
    "Fresh workspace's public admission must preserve its default approval policy",
  );
  const replay = await session.request(route, "POST", body);
  assert.equal(replay.status, 201);
  assert.equal(replay.body.job.id, job.id);
  assert.equal(replay.body.job.subjectId, job.subjectId);
  const rows = await jobs();
  assert.equal(rows.length, 1);
  const stored = rows[0];
  assert.equal(stored.id, job.id);
  assert.equal(stored.source, "api");
  assert.equal(stored.mode, "real");
  assert.equal(String(stored.requested_by_user_id), String(session.userId));
  assert.equal(stored.subject_id, job.subjectId);
  assert.equal(stored.payload.keyMode, "os-store-managed");
  assert.equal(stored.payload.certificateId, job.subjectId);
  for (const [name, value] of Object.entries(body.payload))
    assert.deepEqual(
      stored.payload[name],
      value,
      `Public Windows payload derivation changed ${name}`,
    );
  assert.equal(stored.payload.certPath, undefined);
  return {
    job,
    facts: {
      anonymousAdmissionRefused: true,
      viewerAdmissionRefused: true,
      authorizedAdmissionCreated: true,
      authorizedRole: "workspace_manager",
      idempotentSameJob: true,
      publicRequesterPreserved: true,
      serverDerivedOsStoreKeyMode: true,
      publicPayloadPreserved: true,
      anonymousStatus: anonymous.status,
      viewerStatus: viewer.status,
      createStatus: created.status,
      replayStatus: replay.status,
      source: stored.source,
      mode: stored.mode,
    },
  };
}
module.exports = {
  buildPublicWindowsIssue,
  admitPublicWindowsIssue,
  verifyPublicIssuanceFacts,
};
