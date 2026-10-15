"use strict";
/** Real public refusal on an installed Windows fixture. Multi-target profiles
 * cannot be introduced through these APIs: target paths are immutable and
 * manual renewal accepts only a reason override. No signed execution is claimed. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { isDeepStrictEqual } = require("node:util");
const installed = require("./certops-windows-installed-paths"),
  controls = require("./certops-windows-service-controls"),
  activeControls = require("./certops-windows-active-service-controls");
const SCOPE = "public-immutable-windows-multi-target-admission-refusal",
  SCENARIO = "windows-public-multi-target-admission-refusal";
const FLAGS = Object.freeze([
  "publicProfileTargetEditRefused",
  "publicRenewalSnapshotOverrideRefused",
  "storedProfileUnchanged",
  "noJobAllocated",
  "sameInstalledSystemProcesses",
  "nativeInventoryAndCustodyUnchanged",
  "trustedTlsUnchanged",
  "credentialAndPinUnchanged",
  "actualAcmeAndDnsUnchanged",
  "ownedAdmissionGuardCleared",
]);
const REQUIRED_SOURCES = Object.freeze([
  ...new Set([
    "tests/e2e/helpers/certops-windows-multi-target-admission-refusal.js",
    ...activeControls.REQUIRED_SOURCES,
    "apps/api/routes/certops.js",
    "apps/api/services/certops/renewalProfileAdmin.js",
    "apps/api/services/certops/renewalProfile.js",
    "apps/api/services/certops/jobs.js",
  ]),
]);
const GUARD = ".installed-multi-target-admission-active.json",
  active = new Set();
function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      "profilePatchStatus",
      "renewOverrideStatus",
      "signedJobExecutionQualified",
      "multiTargetDeploymentQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.scope, SCOPE);
  assert.equal(value.profilePatchStatus, 422);
  assert.equal(value.renewOverrideStatus, 400);
  assert.equal(value.signedJobExecutionQualified, false);
  assert.equal(value.multiTargetDeploymentQualified, false);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
function assertCleanupSafe(root) {
  assert.ok(
    !active.has(root) && !fs.existsSync(path.join(root, GUARD)),
    "Preserve unresolved public target-admission state",
  );
}
function proposedTargets(profile) {
  assert.equal(profile?.target?.type, "windows-iis");
  assert.equal(profile.target.store, "My");
  assert.ok(
    Array.isArray(profile.deploymentTargets) &&
      profile.deploymentTargets.length === 1,
  );
  const first = structuredClone(profile.target);
  assert.ok(
    Number.isSafeInteger(first.binding.port) &&
      first.binding.port >= 1 &&
      first.binding.port <= 65535,
  );
  const second = structuredClone(first);
  second.binding.port =
    first.binding.port === 65535 ? 1 : first.binding.port + 1;
  return [first, second];
}
async function qualify(c) {
  assert.equal(process.platform, "win32");
  const {
    receipt,
    configDir,
    ps,
    pool,
    workspaceId,
    certificateId,
    profileId,
    publicSession,
    dnsRequestCount,
    acmeReceiptDirectory,
    ownedJobs,
  } = c;
  installed.assertOwnedRoot(receipt);
  assert.equal(receipt.historicalSupportingOnly, false);
  assertCleanupSafe(receipt.root);
  const guard = path.join(receipt.root, GUARD),
    bytes = crypto.randomBytes(32);
  active.add(receipt.root);
  fs.writeFileSync(guard, bytes, { flag: "wx", mode: 0o600 });
  const guardId = fs.lstatSync(guard, { bigint: true });
  const state = async () => ({
    profile: (
      await pool.query(
        "SELECT id,name,status,issuer_id,renew_before_days,description,key_mode,source,source_ref,public_metadata FROM certificate_profiles WHERE workspace_id=$1 AND id=$2",
        [workspaceId, profileId],
      )
    ).rows,
    jobs: (
      await pool.query(
        "SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 ORDER BY id",
        [workspaceId, String(certificateId)],
      )
    ).rows,
  });
  const agents = (
    await pool.query(
      "SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
      [workspaceId, c.agentId],
    )
  ).rows;
  assert.equal(agents.length, 1, "Exact installed agent row required");
  assert.match(agents[0].id, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  const before = await state();
  assert.equal(before.profile.length, 1);
  const profile = before.profile[0].public_metadata.renewalProfile,
    targets = proposedTargets(profile);
  const expected = {
    host: path.join(receipt.root, "app/bin/tokentimer-agent-host-amd64.exe"),
    node: process.execPath,
    entry: path.join(receipt.root, "app/bin/tokentimer-agent.js"),
    config: configDir,
  };
  const observe = () => {
    installed.assertOwnedRoot(receipt);
    const value = JSON.parse(ps(installed.observationScript()));
    installed.validateObservation(value, expected);
    return value;
  };
  const acmeFiles = () => {
    const dir = fs.lstatSync(acmeReceiptDirectory);
    assert.ok(dir.isDirectory() && !dir.isSymbolicLink());
    const names = fs.readdirSync(acmeReceiptDirectory).sort();
    assert.ok(names.length > 0 && names.length <= 1000);
    return names.map((name) => {
      const file = path.join(acmeReceiptDirectory, name),
        stat = fs.lstatSync(file);
      assert.ok(
        stat.isFile() && !stat.isSymbolicLink() && stat.size <= 1048576,
      );
      return {
        name,
        sha256: crypto
          .createHash("sha256")
          .update(fs.readFileSync(file))
          .digest("hex"),
      };
    });
  };
  const snapshot = () => ({
    processes: observe(),
    custody: JSON.parse(ps(controls.custodyScript(c))),
    certificates: ps(
      "@(Get-ChildItem Cert:\\LocalMachine\\My|Sort-Object Thumbprint|ForEach-Object{@{thumb=$_.Thumbprint;der=[Convert]::ToBase64String($_.RawData)}})|ConvertTo-Json -Depth 4 -Compress",
    ),
    keys: ps(
      "$p=Join-Path $env:ProgramData 'Microsoft\\Crypto\\Keys';@(Get-ChildItem -LiteralPath $p -Force -File -ErrorAction Stop|Sort-Object Name|ForEach-Object{@{name=$_.Name;length=$_.Length;write=$_.LastWriteTimeUtc.Ticks}})|ConvertTo-Json -Depth 4 -Compress",
    ),
    protected: ["config.json", "credential", "signing-key-pin.json"].map(
      (name) =>
        crypto
          .createHash("sha256")
          .update(fs.readFileSync(path.join(configDir, name)))
          .digest("hex"),
    ),
    acme: acmeFiles(),
    dns: dnsRequestCount(),
  });
  const original = snapshot();
  await activeControls.trustedBoundLeaf(c);
  const edit = await publicSession.request(
    `/api/v1/workspaces/${workspaceId}/certops/profiles/${profileId}`,
    "PATCH",
    { renewalProfile: { deploymentTargets: targets } },
  );
  assert.equal(edit.status, 422);
  assert.equal(edit.body.code, "CERTOPS_PROFILE_FIELD_IMMUTABLE");
  const renew = await publicSession.request(
    `/api/v1/workspaces/${workspaceId}/certops/jobs`,
    "POST",
    {
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: certificateId,
      assignedAgentId: agents[0].id,
      idempotencyKey: `multi-target-admission-${crypto.randomUUID()}`,
      payload: { renewalProfile: { ...profile, deploymentTargets: targets } },
    },
  );
  // Register any unexpectedly admitted job before refusing broad parent cleanup.
  if (renew.body?.job?.id) ownedJobs.push(renew.body.job.id);
  assert.equal(renew.status, 400);
  assert.equal(renew.body.code, "CERTOPS_RENEWAL_OVERRIDE_INVALID");
  assert.ok(
    isDeepStrictEqual(await state(), before),
    "Rejected multi-target admission changed profile or jobs",
  );
  assert.ok(
    isDeepStrictEqual(snapshot(), original),
    "Rejected multi-target admission changed native state or ACME/DNS",
  );
  await activeControls.trustedBoundLeaf(c);
  installed.assertOwnedRoot(receipt);
  const current = fs.lstatSync(guard, { bigint: true });
  assert.ok(
    current.dev === guardId.dev &&
      current.ino === guardId.ino &&
      fs.readFileSync(guard).equals(bytes),
    "Public admission ownership receipt changed",
  );
  fs.unlinkSync(guard);
  active.delete(receipt.root);
  const proof = {
    scope: SCOPE,
    profilePatchStatus: 422,
    renewOverrideStatus: 400,
    signedJobExecutionQualified: false,
    multiTargetDeploymentQualified: false,
    ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
  };
  verifyProof(proof);
  return proof;
}
module.exports = {
  SCOPE,
  SCENARIO,
  FLAGS,
  REQUIRED_SOURCES,
  GUARD,
  verifyProof,
  assertCleanupSafe,
  proposedTargets,
  qualify,
};
