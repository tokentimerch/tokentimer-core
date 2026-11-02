"use strict";
// Public wire admission must agree with the API and the agent's legacy-payload
// defense. This test creates no native keys, certificates or CA requests.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { validateSignedJob } = require("../../packages/contracts/certops/validate-signed-job.cjs");
test("Windows CNG renewal wire refuses explicit reuse while Linux false and Windows omission remain valid", () => {
  const job = { schemaVersion: 1, jobId: "11111111-1111-4111-8111-111111111111", workspaceId: "22222222-2222-4222-8222-222222222222", agentId: "33333333-3333-4333-8333-333333333333", certificateId: "cert-1", action: "renew", keyMode: "os-store-managed", target: { type: "windows-iis", reference: "app.example.com", store: "My", binding: { site: "Default Web Site", port: 443 } }, requestedAt: "2026-10-14T00:00:00.000Z" };
  for (const mode of ["real", "dry_run"]) {
    assert.equal(validateSignedJob({ ...job, mode }).valid, true);
    assert.equal(validateSignedJob({ ...job, mode, keyRotation: true }).valid, true);
    assert.equal(validateSignedJob({ ...job, mode, keyRotation: false }).valid, false);
    assert.equal(validateSignedJob({ ...job, mode, keyMode: "agent-local", target: { type: "domain", reference: "/etc/nginx/cert.pem" }, keyRotation: false }).valid, true);
  }
});
