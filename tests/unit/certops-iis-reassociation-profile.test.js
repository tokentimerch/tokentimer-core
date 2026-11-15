"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { profileForExplicitIisReassociation } = require("../../apps/api/services/certops/windowsStoreReassociation");

function profile() {
  return { target: { type: "windows-iis", reference: "app.example", store: "My",
    binding: { site: "Default Web Site", port: 443, sniHost: null } },
  deploymentTargets: [{ type: "windows-iis", reference: "app.example", store: "My",
    binding: { site: "Default Web Site", port: 443, sniHost: null } }] };
}

test("explicit IIS reassociation updates both targets without mutating the source profile", () => {
  const original = profile();
  const updated = profileForExplicitIisReassociation(original, "192.0.2.10");
  assert.equal(updated.target.binding.address, "192.0.2.10");
  assert.equal(updated.deploymentTargets[0].binding.address, "192.0.2.10");
  assert.equal(original.target.binding.address, undefined);
  assert.equal(profileForExplicitIisReassociation({ target: original.target }, "2001:db8::1").target.binding.address, "2001:db8::1");
});

test("explicit IIS reassociation rejects ambiguous targets and non-concrete addresses", () => {
  for (const address of ["*", "0.0.0.0", "::", "fe80::1%3", "example.com"]) {
    assert.throws(() => profileForExplicitIisReassociation(profile(), address), { code: "CERTOPS_WINDOWS_REASSOCIATION_REFUSED" });
  }
  const duplicate = profile();
  duplicate.deploymentTargets.push(structuredClone(duplicate.deploymentTargets[0]));
  assert.throws(() => profileForExplicitIisReassociation(duplicate, "192.0.2.10"), { code: "CERTOPS_WINDOWS_REASSOCIATION_REFUSED" });
  const mismatched = profile();
  mismatched.deploymentTargets[0].binding.port = 444;
  assert.throws(() => profileForExplicitIisReassociation(mismatched, "192.0.2.10"), { code: "CERTOPS_WINDOWS_REASSOCIATION_REFUSED" });
  const sni = profile();
  sni.target.binding.sniHost = "app.example";
  assert.throws(() => profileForExplicitIisReassociation(sni, "192.0.2.10"), { code: "CERTOPS_WINDOWS_REASSOCIATION_REFUSED" });
});
