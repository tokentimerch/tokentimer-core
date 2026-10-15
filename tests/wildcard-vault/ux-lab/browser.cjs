"use strict";
// Real Chromium, real authenticated dashboard and live API. No route mocks.
const assert = require("node:assert/strict");
async function inspect({
  state,
  owner,
  base,
  matrix,
  root,
  label = "converged",
}) {
  const { chromium } = require("playwright");
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  try {
    await context.addCookies(
      [...owner.jar].map(([name, value]) => ({
        name,
        value,
        url: base,
        httpOnly: true,
        sameSite: "Lax",
      })),
    );
    const page = await context.newPage();
    const failures = [];
    page.on("pageerror", () => failures.push("dashboard runtime error"));
    const loaded = page.waitForResponse(
      (r) =>
        r.url().includes(`/distribution-groups/${state.groupId}/consumers`) &&
        r.status() === 200,
    );
    await page.goto(base + "/certops/renewals?workspace=" + state.workspaceId);
    await page.getByText("Certificate distribution", { exact: true }).waitFor();
    await page.getByLabel("Distribution group").selectOption(state.groupId);
    await loaded;
    const rows = await matrix();
    for (const b of state.bindings) {
      const actual = rows.find((r) => r.binding_id === b.id);
      assert.ok(actual);
      const row = page
        .getByRole("row")
        .filter({ has: page.getByRole("cell", { name: b.id, exact: true }) });
      await row.waitFor();
      const text = await row.innerText();
      assert.ok(
        text.includes(actual.desired_material_version_id || "Not assigned"),
      );
      assert.ok(
        text.includes(actual.observed_material_version_id || "Not observed"),
      );
      assert.ok(
        text.includes(
          actual.converged ? "Verified and current" : "Needs verification",
        ),
      );
      if (actual.latest_deployment?.stage)
        assert.ok(
          text.includes(
            actual.latest_deployment.failureCode ||
              actual.latest_deployment.stage,
          ),
        );
      if (actual.latest_deployment?.jobId)
        assert.ok(
          (
            await row
              .getByRole("link", { name: "View job" })
              .getAttribute("href")
          ).includes(actual.latest_deployment.jobId),
        );
    }
    assert.deepEqual(failures, []);
    // Screenshots only include public distribution state, never local sessions.
    await page
      .getByText("Certificate distribution", { exact: true })
      .scrollIntoViewIfNeeded();
    await page.screenshot({
      path: require("node:path").join(root, `distribution-${label}.png`),
    });
    state.browserObservations ||= [];
    state.browserObservations.push({
      label,
      bindings: rows.map((r) => ({
        id: r.binding_id,
        converged: r.converged,
        stage: r.latest_deployment?.stage || null,
      })),
    });
  } finally {
    await context.close();
    await browser.close();
  }
}
module.exports = { inspect };
