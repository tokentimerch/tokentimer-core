"use strict";
/** Supported manager/viewer boundary, not admin demotion or mounted-role polling.
 * Real public role changes act only on run-owned non-owner identities. Native
 * enrollment/job/audit/key/TLS observations remain independent and unchanged. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  tls = require("node:tls");
const { isDeepStrictEqual } = require("node:util");
const { createApiFixture } = require("./certops-api-fixture");
const session = require("./certops-adcs-browser-session");
const {
  readEnrollmentJournal,
} = require("../../../packages/agent/src/issuers/adcs-enrollment");
const REQUIRED_SCENARIOS = Object.freeze([
  "adcs-real-browser-manager-viewer-admin-boundary",
  "adcs-real-browser-role-boundary-preserves-native-uncertain-state",
]);
const REQUIRED_SOURCES = Object.freeze([
  ...new Set([
    ...session.REQUIRED_SOURCES,
    "tests/e2e/helpers/certops-adcs-browser-admin-boundary.js",
    "tests/e2e/helpers/certops-adcs-native-cleanup-guard.js",
    "tests/e2e/helpers/certops-api-fixture.js",
    "apps/dashboard/src/pages/certops/CertOpsAdcs.jsx",
    "apps/dashboard/src/components/certops/useCertOps.js",
    "apps/api/routes/workspaces.js",
    "apps/api/services/workspace.js",
    "apps/api/services/rbac.js",
    "apps/api/routes/certops-enrollments.js",
    "apps/api/services/certops/certificateEnrollments.js",
    "packages/agent/src/issuers/adcs-enrollment-journal.js",
    "infra/certops-adcs/owned-request-observation.ps1",
    "infra/certops-adcs/owned-issued-request.ps1",
  ]),
]);
const FLAGS = Object.freeze([
  "distinctOwnedNonownerActors",
  "noGlobalAdminBypassAssumed",
  "publicManagerViewerManagerTransitions",
  "managerAndViewerUiDenied",
  "bothRolesReconcileAndAbandonForbidden",
  "publicOwnerAdminPatchDemotionRefused",
  "exactOwnerAdminUnchanged",
  "actualUncertainEnrollmentAndJobsUnchanged",
  "nativeCaAndUnacceptedKeyUnchanged",
  "servingNativeCustodyAndTrustedTlsUnchanged",
  "targetCertOpsAuditUnchanged",
  "exactMembershipAudits",
  "managerMembershipRestored",
  "browserAndTrustDrained",
]);
const SCOPE =
  "public-manager-viewer-adcs-admin-boundary-not-mounted-admin-withdrawal";
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
function verifyProof(value) {
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      "enrollmentId",
      "forbiddenMutations",
      "roleChanges",
      "adminDemotions",
      "mountedAdminWithdrawalQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.scope, SCOPE);
  assert.match(value.enrollmentId, UUID);
  assert.equal(value.forbiddenMutations, 4);
  assert.equal(value.roleChanges, 2);
  assert.equal(value.adminDemotions, 0);
  assert.equal(value.mountedAdminWithdrawalQualified, false);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
function verifyRoleObservations(value) {
  assert.deepEqual(value.roles, [
    "workspace_manager",
    "viewer",
    "workspace_manager",
  ]);
  assert.deepEqual(value.forbiddenStatuses, [403, 403, 403, 403]);
  assert.equal(value.adminDemotionStatus, 403);
  assert.equal(value.ownerRole, "admin");
  assert.equal(value.actorGlobalAdmin, false);
  assert.equal(value.controllerGlobalAdmin, false);
  return true;
}
async function qualifyAdminRoleBoundary(context, enrollmentId) {
  const {
      gate,
      fixture,
      baseUrl,
      configDir,
      command,
      ps,
      renewalFixture,
      tlsAuthority,
      ownedApiFixtures,
    } = context,
    root = path.resolve(__dirname, "../../..");
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.match(enrollmentId, UUID);
  assert.ok(Array.isArray(ownedApiFixtures));
  assert.equal(renewalFixture.item.id, "rsa2048");
  assert.match(
    renewalFixture.item.domain,
    /^certops-adcs-[a-f0-9]{10}-rsa2048\.example\.test$/,
  );
  assert.match(renewalFixture.site, /^TTADCS-[a-f0-9]{10}-rsa2048$/);
  assert.ok(
    Number.isInteger(renewalFixture.port) &&
      renewalFixture.port > 1024 &&
      renewalFixture.port < 65536,
  );
  const actor = await createApiFixture(baseUrl);
  ownedApiFixtures.push(actor);
  const controller = await createApiFixture(baseUrl);
  ownedApiFixtures.push(controller);
  assert.notEqual(String(actor.userId), String(controller.userId));
  assert.notEqual(String(actor.userId), String(fixture.userId));
  assert.notEqual(String(controller.userId), String(fixture.userId));
  const query = (sql, args = []) => fixture.pool.query(sql, args),
    api = `/api/v1/workspaces/${fixture.workspaceId}/certops`,
    member = `/api/v1/workspaces/${fixture.workspaceId}/members/${actor.userId}`;
  const owner = (
    await query("SELECT created_by FROM workspaces WHERE id=$1", [
      fixture.workspaceId,
    ])
  ).rows[0];
  assert.equal(String(owner.created_by), String(fixture.userId));
  const users = (
    await query("SELECT id,is_admin FROM users WHERE id=ANY($1::int[])", [
      [actor.userId, controller.userId],
    ])
  ).rows;
  assert.equal(users.length, 2);
  assert.ok(users.every((row) => row.is_admin === false));
  // Prerequisite memberships are scoped to newly owned users. Admin grants and
  // PATCH demotion of an existing admin is intentionally refused by that route.
  assert.equal(
    (
      await query(
        "SELECT user_id FROM workspace_memberships WHERE workspace_id=$1 AND user_id=ANY($2::int[])",
        [fixture.workspaceId, [actor.userId, controller.userId]],
      )
    ).rows.length,
    0,
  );
  await query(
    "INSERT INTO workspace_memberships(workspace_id,user_id,role,invited_by) VALUES($1,$2,'workspace_manager',$4),($1,$3,'admin',$4)",
    [fixture.workspaceId, actor.userId, controller.userId, fixture.userId],
  );
  const memberships = async () =>
    (
      await query(
        "SELECT workspace_id,user_id,role FROM workspace_memberships WHERE user_id=ANY($1::int[]) ORDER BY workspace_id,user_id",
        [[actor.userId, controller.userId]],
      )
    ).rows;
  const membershipsBefore = await memberships();
  const role = async () => {
    const response = await actor.request(
      `/api/v1/workspaces/${fixture.workspaceId}`,
    );
    assert.equal(response.status, 200);
    return response.body.role;
  };
  const current = (
    await query(
      "SELECT * FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",
      [fixture.workspaceId, enrollmentId],
    )
  ).rows[0];
  assert.equal(current.state, "submission_uncertain");
  assert.ok(current.certificate_id);
  const journal = readEnrollmentJournal(configDir, enrollmentId);
  assert.equal(journal.kind, "valid");
  assert.equal(journal.journal.state, "submission_uncertain");
  const container = journal.journal.containerName;
  assert.match(
    container,
    /^tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/,
  );
  const target = current.deploy_target;
  assert.match(
    target.reference,
    /^certops-adcs-[a-f0-9]{10}-uncertain\.example\.test$/,
  );
  const nativeKey = () =>
    ps(
      `$k=[Security.Cryptography.CngKey]::Open('${container}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey);$sha=[Security.Cryptography.SHA256]::Create();try{if($k.KeyName-ne'${container}'-or!$k.IsMachineKey-or$k.ExportPolicy-ne[Security.Cryptography.CngExportPolicies]::None){throw 'Owned uncertain custody changed'};[Convert]::ToBase64String($sha.ComputeHash($k.Export([Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob)))}finally{$sha.Dispose();$k.Dispose()}`,
    );
  const ca = () => {
    const value = JSON.parse(
      command("powershell.exe", [
        "-NoProfile",
        "-NonInteractive",
        "-File",
        path.join(root, "infra/certops-adcs/owned-request-observation.ps1"),
        "-CommonName",
        target.reference,
        "-Discover",
      ]),
    );
    assert.equal(value.subjectRequestCount, 0);
    return value.subjectRequestCount;
  };
  const peer = () =>
    new Promise((resolve, reject) => {
      const socket = tls.connect(
        {
          host: "127.0.0.1",
          port: renewalFixture.port,
          servername: renewalFixture.item.domain,
          ca: tlsAuthority(renewalFixture.authority),
          rejectUnauthorized: true,
        },
        () => {
          try {
            assert.equal(socket.authorized, true);
            resolve(
              new crypto.X509Certificate(socket.getPeerCertificate().raw),
            );
          } catch (error) {
            reject(error);
          } finally {
            socket.destroy();
          }
        },
      );
      socket.once("error", reject);
      socket.setTimeout(10000, () =>
        socket.destroy(new Error("Admin boundary trusted TLS timed out")),
      );
    });
  const initialPeer = await peer(),
    servingThumb = initialPeer.fingerprint.replace(/:/g, "").toUpperCase();
  const servingCustody = () =>
    ps(
      `$c=Get-Item 'Cert:\\LocalMachine\\My\\${servingThumb}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if(!$k-or!$k.Key.IsMachineKey-or$k.Key.ExportPolicy-ne[Security.Cryptography.CngExportPolicies]::None){throw 'Serving protected custody changed'};@{container=$k.Key.KeyName;machine=$k.Key.IsMachineKey;der=[Convert]::ToBase64String($c.RawData)}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`,
    );
  const snapshot = async () => ({
    enrollment: (
      await query(
        "SELECT * FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",
        [fixture.workspaceId, enrollmentId],
      )
    ).rows,
    jobs: (
      await query(
        "SELECT * FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 ORDER BY id",
        [fixture.workspaceId, String(current.certificate_id)],
      )
    ).rows,
    audits: (
      await query(
        "SELECT id,action,metadata FROM audit_events WHERE workspace_id=$1 AND metadata->>'enrollmentId'=$2 ORDER BY id",
        [fixture.workspaceId, enrollmentId],
      )
    ).rows,
    journal: readEnrollmentJournal(configDir, enrollmentId),
    key: nativeKey(),
    ca: ca(),
    serving: servingCustody(),
    binding: ps(
      `Import-Module WebAdministration;$b=@(Get-WebBinding -Name '${renewalFixture.site}' -Protocol https|Where-Object bindingInformation -eq '*:${renewalFixture.port}:${renewalFixture.item.domain}');$h=@(Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object {[string]$_.GetValue('HostnamePort') -ieq '${renewalFixture.item.domain}:${renewalFixture.port}'});if($b.Count-ne 1-or$h.Count-ne 1){throw 'Exact serving binding required'};@{store=[string]$b[0].certificateStoreName;flags=[int]$b[0].sslFlags;httpStore=[string]$h[0].GetValue('SslCertStoreName');hash=[BitConverter]::ToString([byte[]]$h[0].GetValue('SslCertHash')).Replace('-','')}|ConvertTo-Json -Compress`,
    ),
    peer: (await peer()).fingerprint256,
  });
  const before = await snapshot();
  assert.equal(before.peer, initialPeer.fingerprint256);
  const servingBinding = JSON.parse(before.binding);
  assert.equal(servingBinding.store, "My");
  assert.equal(servingBinding.httpStore, "My");
  assert.equal(servingBinding.hash, servingThumb);
  assert.equal(servingBinding.flags, 1);
  const actualRequest = JSON.parse(
    command("powershell.exe", [
      "-NoProfile",
      "-NonInteractive",
      "-File",
      path.join(root, "infra/certops-adcs/owned-issued-request.ps1"),
      "-CommonName",
      renewalFixture.item.domain,
      "-FingerprintSha256",
      initialPeer.fingerprint256.replace(/:/g, "").toLowerCase(),
    ]),
  );
  assert.equal(actualRequest.disposition, 20);
  assert.match(String(actualRequest.requestId), /^[1-9][0-9]{0,9}$/);
  assert.ok(Number(actualRequest.requestId) <= 0xffffffff);
  gate.report.fixtureSources ??= [];
  for (const file of REQUIRED_SOURCES) {
    const sha256 = crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.join(root, file)))
        .digest("hex"),
      prior = gate.report.fixtureSources.find((row) => row.file === file);
    if (prior) assert.equal(prior.sha256, sha256);
    else gate.report.fixtureSources.push({ file, sha256 });
  }
  const observations = {
    roles: [],
    forbiddenStatuses: [],
    actorGlobalAdmin: false,
    controllerGlobalAdmin: false,
  };
  let changed = false,
    primary;
  try {
    await gate.scenario(
      REQUIRED_SCENARIOS[0],
      async () => {
        observations.roles.push(await role());
        const demotion = await controller.request(
          `/api/v1/workspaces/${fixture.workspaceId}/members/${fixture.userId}`,
          "PATCH",
          { role: "viewer" },
        );
        observations.adminDemotionStatus = demotion.status;
        assert.equal(demotion.status, 403);
        assert.equal(
          demotion.body.error,
          "Workspace admin role cannot be changed here",
        );
        await session.withOwnedAdcsBrowserPage(
          {
            ...context,
            fixture: { ...actor, workspaceId: fixture.workspaceId },
          },
          async (page) => {
            const denied = page.getByText(
              "AD CS issuer management is limited to workspace admins",
              { exact: true },
            );
            await denied.waitFor();
            const forbidden = async () => {
              assert.equal(
                await page
                  .getByRole("button", {
                    name: /^(Reconcile |Abandon |Confirm abandon )/,
                  })
                  .count(),
                0,
              );
              for (const action of ["reconcile", "abandon"]) {
                const response = await actor.request(
                  `${api}/enrollments/${enrollmentId}/${action}`,
                  "POST",
                  action === "reconcile"
                    ? { requestId: Number(actualRequest.requestId) }
                    : {},
                );
                observations.forbiddenStatuses.push(response.status);
                assert.equal(response.status, 403);
                assert.ok(response.body?.error==="Forbidden: insufficient role","Expected authoritative workspace role refusal");
              }
              await denied.waitFor();
            };
            await forbidden();
            changed = true;
            assert.equal(
              (await controller.request(member, "PATCH", { role: "viewer" }))
                .status,
              200,
            );
            observations.roles.push(await role());
            await forbidden();
            assert.equal(
              (
                await controller.request(member, "PATCH", {
                  role: "workspace_manager",
                })
              ).status,
              200,
            );
            changed = false;
            observations.roles.push(await role());
            await denied.waitFor();
          },
        );
        observations.ownerRole = (
          await fixture.request(`/api/v1/workspaces/${fixture.workspaceId}`)
        ).body.role;
        verifyRoleObservations(observations);
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "real separate non-owner manager/viewer UI remains admin-restricted, public manager→viewer→manager transitions, four actual forbidden operations and public admin-demotion refusal",
      },
    );
  } catch (error) {
    primary = error;
  } finally {
    try {
      if (changed) {
        assert.equal(
          (
            await controller.request(member, "PATCH", {
              role: "workspace_manager",
            })
          ).status,
          200,
        );
      }
      assert.equal(await role(), "workspace_manager");
      assert.ok(
        isDeepStrictEqual(await memberships(), membershipsBefore),
        "Owned actor memberships changed after restoration",
      );
    } catch (error) {
      throw new AggregateError(
        [...(primary ? [primary] : []), error],
        "Owned role boundary restoration incomplete",
      );
    }
  }
  if (primary) throw primary;
  await gate.scenario(
    REQUIRED_SCENARIOS[1],
    async () => {
      assert.ok(
        isDeepStrictEqual(await snapshot(), before),
        "Restricted role operations changed actual uncertain enrollment, jobs, journal, audit, CA/key or trusted TLS",
      );
      const audits = (
        await query(
          "SELECT actor_user_id,subject_user_id,metadata FROM audit_events WHERE workspace_id=$1 AND action='MEMBER_ROLE_CHANGED' AND subject_user_id=$2 ORDER BY id",
          [fixture.workspaceId, actor.userId],
        )
      ).rows;
      assert.equal(audits.length, 2);
      assert.ok(
        audits.every(
          (row) => String(row.actor_user_id) === String(controller.userId),
        ),
      );
      assert.deepEqual(audits.map((row) => row.metadata.role).sort(), [
        "viewer",
        "workspace_manager",
      ]);
      const value = {
        scope: SCOPE,
        enrollmentId,
        forbiddenMutations: 4,
        roleChanges: 2,
        adminDemotions: 0,
        mountedAdminWithdrawalQualified: false,
        ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
      };
      verifyProof(value);
      gate.report.nativeBrowserAdminBoundary = value;
    },
    {
      evidenceLevel: "real-host",
      oracle:
        "exact native uncertain CNG/CA/journal/enrollment/jobs/target-audit and serving protected TLS remain unchanged; only two attributable membership audits and exact original memberships restored",
    },
  );
  return gate.report.nativeBrowserAdminBoundary;
}
module.exports = {
  REQUIRED_SCENARIOS,
  REQUIRED_SOURCES,
  FLAGS,
  SCOPE,
  verifyProof,
  verifyRoleObservations,
  qualifyAdminRoleBoundary,
};
