"use strict";
/** Public contract/adversarial controls only; no native work or real API runs. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const h = require("../tests/e2e/helpers/certops-windows-multi-target-admission-refusal");
function proof() {
  return {
    scope: h.SCOPE,
    profilePatchStatus: 422,
    renewOverrideStatus: 400,
    signedJobExecutionQualified: false,
    multiTargetDeploymentQualified: false,
    ...Object.fromEntries(h.FLAGS.map((x) => [x, true])),
  };
}
test("public multi-target refusal never qualifies signed executor or multi-target support", () => {
  h.verifyProof(proof());
  for (const key of Object.keys(proof())) {
    const bad = proof();
    delete bad[key];
    assert.throws(() => h.verifyProof(bad));
  }
  for (const flag of h.FLAGS) {
    const bad = proof();
    bad[flag] = false;
    assert.throws(() => h.verifyProof(bad));
  }
  for (const patch of [
    { signedJobExecutionQualified: true },
    { multiTargetDeploymentQualified: true },
    { scope: "installed-agent-public-multi-target-iis-renewal-refusal" },
    { renewOverrideStatus: 422 },
    { nativePrivate: "secret" },
  ])
    assert.throws(() => h.verifyProof({ ...proof(), ...patch }));
});
test("actual public service contracts reject immutable target edit and manual snapshot override", () => {
  const admin = require("../apps/api/services/certops/renewalProfileAdmin"),
    profile = require("../apps/api/services/certops/renewalProfile");
  const target = {
      type: "windows-iis",
      reference: "owned.example.test",
      store: "My",
      binding: { site: "owned", port: 443, sniHost: "owned.example.test" },
    },
    original = { target, deploymentTargets: [target] };
  const before = structuredClone(original),
    targets = h.proposedTargets(original);
  assert.equal(targets.length, 2);
  assert.notEqual(targets[0].binding.port, targets[1].binding.port);
  assert.deepEqual(original, before);
  assert.throws(
    () =>
      admin.applyRenewalProfilePatch(original, { deploymentTargets: targets }),
    (error) => error.code === "CERTOPS_PROFILE_FIELD_IMMUTABLE",
  );
  assert.throws(
    () =>
      profile.validateRenewalManualOverrides({
        renewalProfile: { ...original, deploymentTargets: targets },
      }),
    (error) => error.code === "CERTOPS_RENEWAL_OVERRIDE_INVALID",
  );
  assert.deepEqual(original, before);
});
test("unknown public admission outcome preserves durable ownership", () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-multi-admission-proof-"),
  );
  try {
    h.assertCleanupSafe(root);
    fs.writeFileSync(path.join(root, h.GUARD), "public-only");
    assert.throws(() => h.assertCleanupSafe(root));
    fs.unlinkSync(path.join(root, h.GUARD));
    h.assertCleanupSafe(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("reporter requires bounded refusal sidecars in all Windows key-profile scopes", () => {
  const reporter = require("./certops-stack-reporter"),
    root = fs.mkdtempSync(
      path.join(os.tmpdir(), "certops-multi-admission-reporter-"),
    ),
    dir = path.join(root, "qualification-results");
  fs.mkdirSync(dir);
  const name =
    "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence";
  try {
    for (const profile of [
      "rsa-2048",
      "rsa-3072",
      "rsa-4096",
      "ec-p256",
      "ec-p384",
    ]) {
      const scope = "real-agent-windows-acme-iis/" + profile,
        file = path.join(dir, `windows-multi-target-admission-${profile}.json`);
      assert.throws(() =>
        reporter.multiTargetAdmissionProof(scope, name, root),
      );
      fs.writeFileSync(file, JSON.stringify(proof()));
      assert.deepEqual(
        reporter.multiTargetAdmissionProof(scope, name, root),
        proof(),
      );
      fs.writeFileSync(
        file,
        JSON.stringify({ ...proof(), signedJobExecutionQualified: true }),
      );
      assert.throws(() =>
        reporter.multiTargetAdmissionProof(scope, name, root),
      );
      fs.writeFileSync(file, " ".repeat(16385));
      assert.throws(() =>
        reporter.multiTargetAdmissionProof(scope, name, root),
      );
    }
    assert.equal(
      reporter.multiTargetAdmissionProof(
        "real-agent-acme-filesystem",
        name,
        root,
      ),
      undefined,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
