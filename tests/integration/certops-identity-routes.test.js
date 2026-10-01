"use strict";

const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { request, TestUtils } = require("./setup");
const BASE = process.env.TEST_API_URL || "http://localhost:4000";
const A = "a3".repeat(32),
  B = "b3".repeat(32);
const SOURCE_REF = "file:///private/certops/source.pem";
const DEPLOYMENT_REF = "file:///private/certops/deployment.pem";
const KEY_REF = "vault://private/certops/key";
const PRIVATE_KEY =
  "-----BEGIN PRIVATE KEY-----\nZmFrZS1wcml2YXRlLWtleQ==\n-----END PRIVATE KEY-----";

describe("CertOps identity HTTP authorization and admission", function () {
  this.timeout(90000);
  let owner,
    manager,
    viewer,
    outsider,
    ws,
    otherWs,
    mc,
    identityId,
    firstPeriod;
  const people = [];
  async function person() {
    const user = await TestUtils.createVerifiedTestUser();
    const session = await TestUtils.loginTestUser(
      user.email,
      "SecureTest123!@#",
    );
    const workspaces = await request(BASE)
      .get("/api/v1/workspaces?limit=50&offset=0")
      .set("Cookie", session.cookie)
      .expect(200);
    const result = {
      user,
      cookie: session.cookie,
      workspaceId: workspaces.body.items[0].id,
    };
    people.push(result);
    return result;
  }
  async function source(fingerprint, sourceRef) {
    return (
      await TestUtils.execQuery(
        `INSERT INTO managed_certificates(workspace_id,source,source_ref,
      fingerprint_sha256,common_name,key_mode,key_reference) VALUES($1,'agent_filesystem',$2,$3,
        'Identity route certificate','external-unknown',$4) RETURNING id`,
        [ws, sourceRef, fingerprint, KEY_REF],
      )
    ).rows[0].id;
  }
  const path = (suffix, workspaceId = ws) =>
    `/api/v1/workspaces/${workspaceId}/certops/${suffix}`;
  const post = (suffix, who, body = {}, workspaceId = ws) =>
    request(BASE)
      .post(path(suffix, workspaceId))
      .set("Cookie", who.cookie)
      .send(body);
  before(async () => {
    owner = await person();
    manager = await person();
    viewer = await person();
    outsider = await person();
    ws = owner.workspaceId;
    otherWs = outsider.workspaceId;
    await TestUtils.execQuery(
      `INSERT INTO workspace_memberships(user_id,workspace_id,role,invited_by)
      VALUES($1,$2,'workspace_manager',$3),($4,$2,'viewer',$3)`,
      [manager.user.id, ws, owner.user.id, viewer.user.id],
    );
    mc = await source(A, SOURCE_REF);
    identityId = (
      await TestUtils.execQuery(
        "SELECT id FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2",
        [ws, A],
      )
    ).rows[0].id;
    firstPeriod = (
      await TestUtils.execQuery(
        "SELECT id FROM certops_management_periods WHERE managed_certificate_id=$1",
        [mc],
      )
    ).rows[0].id;
    const target = (
      await TestUtils.execQuery(
        "INSERT INTO certificate_targets(workspace_id,name,target_type) VALUES($1,'Route test host','host') RETURNING id",
        [ws],
      )
    ).rows[0].id;
    await TestUtils.execQuery(
      `INSERT INTO certificate_instances(workspace_id,managed_certificate_id,target_id,
      source,source_ref,observed_fingerprint_sha256,observed_at,location_kind,deployment_reference)
      VALUES($1,$2,$3,'agent_filesystem',$4,$5,NOW(),'filesystem',$6)`,
      [ws, mc, target, SOURCE_REF, A, DEPLOYMENT_REF],
    );
  });
  after(async () => {
    for (const who of people)
      await TestUtils.cleanupTestUser(who.user.email, who.cookie);
  });
  it("exposes source and location history to a manager", async () => {
    const res = await request(BASE)
      .get(path(`certificate-identities/${identityId}`))
      .set("Cookie", manager.cookie)
      .expect(200);
    assert.equal(res.body.certificate.identityId, identityId);
    assert.equal(res.body.certificate.keyReference, KEY_REF);
    assert.equal(res.body.certificate.sources[0].sourceRef, SOURCE_REF);
    assert.equal(
      res.body.certificate.locations[0].deploymentReference,
      DEPLOYMENT_REF,
    );
  });
  it("redacts sensitive source, key and deployment references from viewer list and detail", async () => {
    for (const suffix of [
      "certificate-identities",
      `certificate-identities/${identityId}`,
    ]) {
      const res = await request(BASE)
        .get(path(suffix))
        .set("Cookie", viewer.cookie)
        .expect(200);
      for (const value of [SOURCE_REF, DEPLOYMENT_REF, KEY_REF])
        assert(!res.text.includes(value));
      const item = res.body.certificate || res.body.items[0];
      assert.equal(item.keyReference, undefined);
      assert.equal(item.sources[0].sourceRef, undefined);
      assert.equal(item.locations[0].deploymentReference, undefined);
      assert.equal(item.sourceCount, 1);
      assert.equal(item.locationCount, 1);
    }
  });
  it("rejects every management/lifecycle write from viewers", async () => {
    await post(`management-periods/${firstPeriod}/stop`, viewer).expect(403);
    await post(`sources/${mc}/readd`, viewer, {
      renewalProfileId: null,
      automationEnabled: false,
    }).expect(403);
    await post(`certificate-identities/${identityId}/retire`, viewer, {
      status: "revoked",
      reason: "Forbidden",
      expectedFingerprintSha256: A,
    }).expect(403);
    assert.equal(
      (
        await TestUtils.execQuery(
          "SELECT ended_at FROM certops_management_periods WHERE id=$1",
          [firstPeriod],
        )
      ).rows[0].ended_at,
      null,
    );
  });
  it("isolates reads and all writes from a different workspace even with forged body workspace IDs", async () => {
    await request(BASE)
      .get(path("certificate-identities"))
      .set("Cookie", outsider.cookie)
      .expect(403);
    await request(BASE)
      .get(path(`certificate-identities/${identityId}`, otherWs))
      .set("Cookie", outsider.cookie)
      .expect(404);
    const fake = { workspaceId: ws, workspace_id: ws };
    await post(
      `management-periods/${firstPeriod}/stop`,
      outsider,
      fake,
      otherWs,
    ).expect(404);
    await post(
      `sources/${mc}/readd`,
      outsider,
      { ...fake, renewalProfileId: null, automationEnabled: false },
      otherWs,
    ).expect(404);
    await post(
      `certificate-identities/${identityId}/retire`,
      outsider,
      {
        ...fake,
        status: "revoked",
        reason: "Wrong workspace",
        expectedFingerprintSha256: A,
      },
      otherWs,
    ).expect(404);
    await post(
      `certificates/${mc}/retire`,
      outsider,
      {
        status: "revoked",
        reason: "Wrong workspace",
        expectedFingerprintSha256: A,
      },
      otherWs,
    ).expect(404);
  });
  it("rejects key material on identity retirement, stop and re-add without echoing it", async () => {
    for (const [suffix, body] of [
      [
        `certificate-identities/${identityId}/retire`,
        {
          status: "revoked",
          expectedFingerprintSha256: A,
          reason: PRIVATE_KEY,
        },
      ],
      [`management-periods/${firstPeriod}/stop`, { secret: PRIVATE_KEY }],
      [
        `sources/${mc}/readd`,
        {
          renewalProfileId: null,
          automationEnabled: false,
          secret: PRIVATE_KEY,
        },
      ],
    ]) {
      const res = await post(suffix, owner, body).expect(422);
      assert.equal(res.body.code, "PRIVATE_KEY_MATERIAL_REJECTED");
      assert(!res.text.includes("BEGIN PRIVATE KEY"));
    }
  });
  it("requires the exact fingerprint precondition on the legacy source retirement route", async () => {
    await post(`certificates/${mc}/retire`, owner, {
      status: "revoked",
      reason: "No fingerprint",
    }).expect(428);
    await post(`certificates/${mc}/retire`, owner, {
      status: "revoked",
      reason: "Stale identity",
      expectedFingerprintSha256: B,
    }).expect(412);
    assert.equal(
      (
        await TestUtils.execQuery(
          "SELECT lifecycle_status FROM certops_certificate_identities WHERE id=$1",
          [identityId],
        )
      ).rows[0].lifecycle_status,
      "active",
    );
  });
  it("manager stop is idempotent and explicit re-add creates a different period", async () => {
    await post(`management-periods/${firstPeriod}/stop`, manager).expect(200);
    await post(`management-periods/${firstPeriod}/stop`, manager).expect(200);
    const res = await post(`sources/${mc}/readd`, manager, {
      renewalProfileId: null,
      automationEnabled: false,
    }).expect(201);
    assert.notEqual(res.body.periodId, firstPeriod);
    const periods = (
      await TestUtils.execQuery(
        "SELECT id,ended_at FROM certops_management_periods WHERE managed_certificate_id=$1",
        [mc],
      )
    ).rows;
    assert.equal(periods.length, 2);
    assert(periods.find((p) => p.id === firstPeriod).ended_at);
    assert.equal(
      periods.find((p) => p.id === res.body.periodId).ended_at,
      null,
    );
    assert.equal(
      (
        await TestUtils.execQuery(
          "SELECT lifecycle_status FROM certops_certificate_identities WHERE id=$1",
          [identityId],
        )
      ).rows[0].lifecycle_status,
      "active",
    );
  });
  it("rejects invalid UUID configuration, filters and sorting with client errors", async () => {
    await post(`sources/${mc}/readd`, owner, {
      renewalProfileId: "bad-id",
      automationEnabled: true,
    }).expect(400);
    await request(BASE)
      .get(path("certificate-identities/not-a-uuid"))
      .set("Cookie", owner.cookie)
      .expect(404);
    for (const query of [
      { sort: "not-a-sort" },
      { direction: "sideways", sort: "name" },
      { status: "deleted" },
      { source: "anywhere" },
      { unmanaged: "maybe" },
    ]) {
      await request(BASE)
        .get(path("certificate-identities"))
        .query(query)
        .set("Cookie", owner.cookie)
        .expect(400);
    }
  });
  it("route re-add cannot bypass mandatory quota admission", async () => {
    const current = (
      await TestUtils.execQuery(
        "SELECT id FROM certops_management_periods WHERE managed_certificate_id=$1 AND ended_at IS NULL",
        [mc],
      )
    ).rows[0].id;
    await post(`management-periods/${current}/stop`, owner).expect(200);
    await TestUtils.execQuery(
      "UPDATE workspaces SET certops_managed_identity_limit=1 WHERE id=$1",
      [ws],
    );
    await source(B, `file:///private/${randomUUID()}.pem`);
    const res = await post(`sources/${mc}/readd`, owner, {
      renewalProfileId: null,
      automationEnabled: false,
    }).expect(409);
    assert.equal(res.body.code, "CERTOPS_MANAGED_CERT_LIMIT");
    assert.equal(
      (
        await TestUtils.execQuery(
          "SELECT COUNT(*)::int n FROM certops_management_periods WHERE managed_certificate_id=$1 AND ended_at IS NULL",
          [mc],
        )
      ).rows[0].n,
      0,
    );
  });
});
