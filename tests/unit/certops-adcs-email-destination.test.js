"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const workspaceId = "11111111-1111-4111-8111-111111111111";
const issuerId = "22222222-2222-4222-8222-222222222222";
test("AD CS emails construct an internal issuer destination in HTML and text", async () => {
  const { buildOperationalIncidentEmail } =
    await import("../../apps/worker/src/notify/email.js");
  const email = buildOperationalIncidentEmail({
    category: "certops",
    type: "adcs_preflight_blocked",
    workspaceId,
    title: "Renewal blocked",
    message: "Restore the simulated CA",
    metadata: {
      issuerId,
      href: "https://evil.invalid/",
      workspace_id: "untrusted",
    },
  });
  const url = new URL(
    "/certops/renewals",
    process.env.APP_URL || "http://localhost:5173",
  );
  url.search = new URLSearchParams({
    workspace: workspaceId,
    action: "check-adcs-issuer",
    issuerId,
  });
  assert.ok(email.text.includes(url.href));
  assert.ok(email.html.includes(url.href.replaceAll("&", "&amp;")));
  assert.ok(!email.html.includes("evil.invalid"));
  assert.ok(!email.text.includes("untrusted"));
});
test("other incidents cannot opt into an AD CS link using metadata alone", async () => {
  const { buildOperationalIncidentEmail } =
    await import("../../apps/worker/src/notify/email.js");
  for (const args of [
    { category: "delivery", type: "adcs_preflight_blocked", workspaceId },
    { category: "certops", type: "other", workspaceId },
    {
      category: "certops",
      type: "adcs_preflight_blocked",
      workspaceId: "https://evil.invalid",
    },
  ]) {
    const email = buildOperationalIncidentEmail({
      ...args,
      title: "Blocked",
      metadata: { issuerId, href: "https://evil.invalid" },
    });
    assert.ok(email.html.includes("/control-center"));
    assert.ok(!email.html.includes("/certops/renewals"));
  }
});
