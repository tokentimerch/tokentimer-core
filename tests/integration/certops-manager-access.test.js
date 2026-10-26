"use strict";

const crypto = require("node:crypto");
const { expect, request, TestUtils } = require("./setup");
const base = process.env.TEST_API_URL || "http://localhost:4000";

describe("CertOps workspace-manager access (real API and database)", function () {
  this.timeout(60000);
  let owner;
  let actor;
  const workspaceId = crypto.randomUUID();
  const api = `/api/v1/workspaces/${workspaceId}/certops`;

  before(async () => {
    owner = await TestUtils.createAuthenticatedUser();
    actor = await TestUtils.createAuthenticatedUser();
    await TestUtils.execQuery(
      "INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'Certificate manager access',$2,'oss')",
      [workspaceId, owner.id],
    );
    await TestUtils.execQuery(
      "INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'workspace_manager')",
      [workspaceId, actor.id],
    );
  });

  after(async () => {
    const ids = [owner?.id, actor?.id].filter(Boolean);
    if (!ids.length) return;
    await TestUtils.execQuery(
      "DELETE FROM audit_events WHERE actor_user_id=ANY($1::int[]) OR subject_user_id=ANY($1::int[]) OR workspace_id IN (SELECT id FROM workspaces WHERE created_by=ANY($1::int[]))",
      [ids],
    );
    await TestUtils.execQuery(
      "DELETE FROM workspaces WHERE created_by=ANY($1::int[])",
      [ids],
    );
    await TestUtils.execQuery("DELETE FROM users WHERE id=ANY($1::int[])", [
      ids,
    ]);
  });

  const call = (method, path, body) => {
    const req = request(base)[method](path).set("Cookie", actor.cookie);
    return body === undefined ? req : req.send(body);
  };

  it("lets a non-owner manager configure an issuer and create/edit its renewal profile", async () => {
    const capabilities = await call(
      "get",
      `/api/v1/workspaces/${workspaceId}/onboarding/capabilities`,
    );
    expect(capabilities.status).to.equal(200);
    expect(
      capabilities.body.items.find((item) => item.id === "certops.adcs")
        .authorized,
    ).to.equal(true);
    const created = await call("post", `${api}/issuers`, {
      kind: "adcs",
      name: "Managed issuing CA",
    });
    expect(created.status, JSON.stringify(created.body)).to.equal(201);
    const issuerId = created.body.issuer.id;
    expect((await call("get", `${api}/issuers`)).status).to.equal(200);
    // The actual CA check is a separate native qualification. Seed its confirmed
    // result here so this API test cannot dispatch any operation to a real host.
    await TestUtils.execQuery(
      "INSERT INTO certificate_issuer_versions(workspace_id,issuer_id,version,ca_config,template,transport,ca_key_sha256,confirmed_at) VALUES($1,$2,1,$3,'WebServer','dcom',$4,NOW())",
      [workspaceId, issuerId, "ca.example.test\\Issuing CA", "ab".repeat(32)],
    );
    await TestUtils.execQuery(
      "UPDATE certificate_issuers SET current_version=1,revalidation_required=false WHERE id=$1",
      [issuerId],
    );
    const profile = await call("post", `${api}/profiles`, {
      name: "Manager renewal",
      issuerId,
      target: {
        type: "windows-iis",
        reference: "app.example.test",
        store: "My",
        binding: {
          site: "Manager site",
          port: 443,
          sniHost: "app.example.test",
        },
      },
      keyAlgorithm: "rsa",
      keySize: 2048,
    });
    expect(profile.status, JSON.stringify(profile.body)).to.equal(201);
    const edited = await call("patch", `${api}/profiles/${profile.body.id}`, {
      renewBeforeDays: 21,
    });
    expect(edited.status, JSON.stringify(edited.body)).to.equal(200);
    expect(edited.body.renewBeforeDays).to.equal(21);
    const acmeProfile = await TestUtils.execQuery(
      `INSERT INTO certificate_profiles(workspace_id,name,status,source,source_ref,renew_before_days,key_mode,public_metadata,created_by)
       VALUES($1,'ACME manager profile','active','manual',$2,30,'os-store-managed',$3::jsonb,$4) RETURNING id`,
      [
        workspaceId,
        `manager-acme:${crypto.randomUUID()}`,
        JSON.stringify({
          renewalProfile: {
            schemaVersion: 1,
            profileName: "ACME manager profile",
            sanPolicy: {
              mode: "exact",
              sans: ["app.example.test"],
              allowWildcards: false,
            },
            keyAlgorithm: "ecdsa",
            keySize: 256,
            keyRotationPolicy: { rotateOnRenew: true },
            preferredChain: null,
            ca: {
              endpoint: "https://acme-v02.api.letsencrypt.org/directory",
              accountRef: "le-prod",
              eabRef: null,
            },
            acme: { kind: "certbot", commandRef: "issue.dns" },
            dns: { provider: "route53", zone: "example.test" },
            deploymentTargets: [
              {
                type: "domain",
                reference: "app.example.test",
                certPath: "/etc/ssl/certs/app.pem",
                reloadService: "nginx",
                owner: "root",
              },
            ],
            target: {
              type: "domain",
              reference: "app.example.test",
              certPath: "/etc/ssl/certs/app.pem",
            },
            verification: { host: null, port: null, requireMatch: false },
          },
        }),
        actor.id,
      ],
    );
    const acmeEdit = await call(
      "patch",
      `${api}/profiles/${acmeProfile.rows[0].id}`,
      { renewBeforeDays: 14 },
    );
    expect(acmeEdit.status, JSON.stringify(acmeEdit.body)).to.equal(200);
    expect(acmeEdit.body.renewBeforeDays).to.equal(14);
    const jobs = await TestUtils.execQuery(
      "SELECT COUNT(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1",
      [workspaceId],
    );
    expect(jobs.rows[0].count).to.equal(0);
  });

  it("admits manager enrollment operations while preserving validation and missing-resource checks", async () => {
    for (const [action, body] of [
      ["cancel", {}],
      ["abandon", {}],
      ["reconcile", { requestId: 1 }],
      [
        "recover",
        {
          orphanedJobId: crypto.randomUUID(),
          acknowledgeUnknownEffect: true,
          reason: "Disposable role test",
        },
      ],
      ["retry-installation", {}],
    ]) {
      const result = await call(
        "post",
        `${api}/enrollments/${crypto.randomUUID()}/${action}`,
        body,
      );
      expect(
        [400, 404],
        `${action}: ${JSON.stringify(result.body)}`,
      ).to.include(result.status);
      expect(result.body.code).to.match(/^CERTOPS_/);
    }
    const repair = await call(
      "post",
      `${api}/certificates/${crypto.randomUUID()}/renewal-profile/repair`,
      {},
    );
    expect(repair.status, JSON.stringify(repair.body)).to.equal(404);
    expect(repair.body.code).to.match(/^CERTOPS_/);
  });

  it("denies viewers and missing membership on the same public endpoints", async () => {
    await TestUtils.execQuery(
      "UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2",
      [workspaceId, actor.id],
    );
    for (const [method, path, body] of [
      ["get", `${api}/issuers`],
      ["post", `${api}/issuers`, { kind: "adcs", name: "Forbidden issuer" }],
      ["post", `${api}/profiles`, {}],
      [
        "post",
        `${api}/certificates/${crypto.randomUUID()}/renewal-profile/repair`,
        {},
      ],
      ...[
        "cancel",
        "abandon",
        "reconcile",
        "recover",
        "retry-installation",
      ].map((action) => [
        "post",
        `${api}/enrollments/${crypto.randomUUID()}/${action}`,
        {},
      ]),
    ])
      expect((await call(method, path, body)).status, path).to.equal(403);
    await TestUtils.execQuery(
      "DELETE FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2",
      [workspaceId, actor.id],
    );
    expect((await call("get", `${api}/issuers`)).status).to.equal(403);
  });
});
