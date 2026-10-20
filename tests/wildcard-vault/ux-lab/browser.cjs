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
    // Distribution is shown per certificate: open the one this group is registered to.
    await page.goto(base + "/certops/certificates?workspace=" + state.workspaceId);
    if (label === "workspace-paused")
      await page.getByText("Certificate operations are paused for this workspace", { exact: true }).waitFor();
    // Two registrations can share a common name; the row's certificate id is unambiguous.
    const certificateRow = page.locator(`tr[data-certificate-id="${state.certificateId}"]`);
    await certificateRow.waitFor();
    const loaded = page.waitForResponse(
      (r) =>
        r.url().includes(`/distribution-groups/${state.groupId}/consumers`) &&
        r.status() === 200,
    );
    await certificateRow.getByRole("button", { name: /^Open certificate deployments:/ }).click();
    await loaded;
    const dialog = page.getByRole("dialog");
    const table = dialog.getByRole("table", { name: "Certificate deployment consumers" });
    await table.waitFor();
    const rows = await matrix();
    for (const b of state.bindings) {
      const actual = rows.find((r) => r.binding_id === b.id);
      assert.ok(actual);
      // Each destination row owns an expandable panel keyed by its binding id.
      const toggle = table.locator(`button[aria-controls="consumer-${b.id}"]`);
      await toggle.waitFor();
      const row = toggle.locator("xpath=ancestor::tr[1]");
      const status = (await row.locator("td").nth(2).innerText()).trim();
      assert.equal(
        status === "Verified",
        Boolean(actual.converged),
        `Consumer ${b.name} shows "${status}" but the API reports converged=${actual.converged}`,
      );
      if ((await toggle.getAttribute("aria-expanded")) !== "true") await toggle.click();
      const text = await dialog.locator(`[id="consumer-${b.id}"]`).evaluate((node) => node.textContent);
      assert.ok(text.includes(actual.desired_material_version_id || "Not assigned"));
      assert.ok(text.includes(actual.observed_material_version_id || "Never confirmed"));
      if (actual.latest_deployment?.stage)
        assert.ok(
          text.includes(actual.latest_deployment.failureCode || actual.latest_deployment.stage),
        );
      if (actual.latest_deployment?.jobId)
        assert.ok(
          (
            await dialog
              .locator(`[id="consumer-${b.id}"]`)
              .getByRole("link", { name: "View job and evidence" })
              .getAttribute("href")
          ).includes(actual.latest_deployment.jobId),
        );
    }
    assert.deepEqual(failures, []);
    // Screenshots only include public distribution state, never local sessions.
    await table.scrollIntoViewIfNeeded();
    await page.screenshot({
      path: require("node:path").join(root, `distribution-${label}.png`),
    });    state.browserObservations ||= [];
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
async function viewerRefused({ state, viewer, base }) {
  const browser = await require("playwright").chromium.launch({ headless: true });
  const context = await browser.newContext();
  try {
    await context.addCookies([...viewer.jar].map(([name, value]) => ({ name, value, url: base, httpOnly: true, sameSite: "Lax" })));
    const page = await context.newPage();
    let successfulDistributionResponses = 0;
    page.on("response", response => {
      if (response.url().includes("/certops/distribution-groups") && response.status() === 200) successfulDistributionResponses++;
    });
    await page.goto(base + "/certops/renewals?workspace=" + state.workspaceId);
    await page.waitForURL(url => url.pathname === "/dashboard");
    assert.equal(await page.getByRole("table", { name: "Certificate deployment consumers" }).count(), 0);
    assert.equal(await page.getByRole("button", { name: /^Open certificate deployments:/ }).count(), 0);
    assert.equal(successfulDistributionResponses, 0);
    state.browserObservations ||= [];
    state.browserObservations.push({ label: "viewer-refused", distributionRendered: false, successfulDistributionResponses });
  } finally { await context.close(); await browser.close(); }
}
module.exports = { inspect, viewerRefused };
