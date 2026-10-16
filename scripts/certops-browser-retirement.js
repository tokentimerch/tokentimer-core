/** Real Chromium retirement filters and factual observation details.
 * Invoked by the manual dashboard qualification lane against disposable API/PG.
 * Actual public retirement and trusted TLS rescans are independent UI oracles;
 * this verifies browser lifecycle visibility, not certificate removal or CA revocation. */
"use strict";
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const { chromium } = require("playwright"),
  { spawnSync } = require("node:child_process");
const {
    createApiFixture,
  } = require("../tests/e2e/helpers/certops-api-fixture"),
  {
    createRetirementItems,
  } = require("../tests/e2e/helpers/certops-browser-retirement-fixture"),
  { createHostGate } = require("../packages/agent/scripts/host-gate");
const scenarios = [
  "browser-retirement-active-observed-control",
  "browser-retirement-public-retire-and-real-rescan",
  "browser-retirement-default-hidden",
  "browser-retirement-show-retired",
  "browser-retirement-explicit-status-filter",
  "browser-retirement-factual-detail-no-renewal",
  "browser-retirement-owned-cleanup",
];
const requiredSources = [
  "scripts/certops-browser-retirement.js",
  "tests/e2e/helpers/certops-browser-retirement-fixture.js",
  "tests/e2e/helpers/certops-api-fixture.js",
];
async function main() {
  const api = process.env.CERTOPS_CSR_API_URL,
    ui = process.env.CERTOPS_BROWSER_URL;
  assert.ok(api && ui);
  const fixture = await createApiFixture(api);
  let browser,
    tlsFixture,
    ready = false,
    primary,
    page;
  const hash = (file) => ({
    file,
    sha256: crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.resolve(__dirname, "..", file)))
      .digest("hex"),
  });
  const gate = createHostGate({
    suite: "browser-retirement-visibility",
    strict: true,
    evidenceLevel: "e2e",
    reportPath: process.env.CERTOPS_BROWSER_RETIREMENT_REPORT,
    fixtureSource: hash(requiredSources[0]),
    requiredCapabilities: ["browser", "api", "postgres", "openssl"],
    probeCapabilities: async () => {
      let available = false;
      try {
        browser = await chromium.launch({ headless: true });
        available = true;
      } catch {}
      return {
        browser: { available },
        api: { available: (await fetch(api)).ok },
        postgres: {
          available: (await fixture.pool.query("SELECT 1")).rowCount === 1,
        },
        openssl: { available: spawnSync("openssl", ["version"]).status === 0 },
      };
    },
  });
  gate.report.fixtureSources = requiredSources.map(hash);
  gate.report.artifactQualification =
    process.env.GITHUB_ACTIONS === "true"
      ? "workflow-checkout-source"
      : "local-worktree-source-baseline-sha-only";
  const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops`,
    url = new URL(`/certops/certificates?workspace=${fixture.workspaceId}`, ui)
      .href;
  const row = (item) =>
    page.locator(`[data-certificate-identity-id="${item.identityId}"]`);
  async function go() {
    const loaded = page.waitForResponse((response) => {
      const parsed = new URL(response.url());
      return (
        parsed.pathname === `${prefix}/certificate-identities` &&
        parsed.searchParams.get("excludeRetired") === "true" &&
        response.status() === 200
      );
    });
    await page.goto(url);
    await loaded;
    await page
      .getByRole("checkbox", { name: /Show retired/ })
      .waitFor({ state: "attached" });
  }
  try {
    await gate.preflight();
    ready = true;
    tlsFixture = await createRetirementItems(fixture);
    const context = await browser.newContext();
    page = await context.newPage();
    page.setDefaultTimeout(30000);
    await page.goto(new URL("/login", ui).href);
    await page.getByLabel("Email", { exact: true }).fill(fixture.email);
    await page.getByLabel("Password", { exact: true }).fill(fixture.password);
    await page.getByRole("button", { name: "Sign In", exact: true }).click();
    await page.waitForURL((value) => !value.pathname.includes("login"));
    await gate.scenario(scenarios[0], async () => {
      await go();
      for (const item of tlsFixture.items) {
        await row(item).waitFor();
        assert.equal(await item.peer(), item.fingerprint);
        assert.ok(await item.capture());
      }
    });
    await gate.scenario(scenarios[1], async () => {
      for (const item of tlsFixture.items) {
        if (item.status === "decommissioned") await item.removeMonitor();
        const response = await fixture.request(
          `${prefix}/certificate-identities/${item.identityId}/retire`,
          "POST",
          {
            status: item.status,
            expectedFingerprintSha256: item.fingerprint,
            reason: "Browser qualification lifecycle",
            acknowledgeUncertainty: true,
          },
        );
        assert.equal(response.status, 200);
        item.retired = await item.snapshot();
        assert.equal(item.retired.identity.lifecycle_status, item.status);
        assert.equal(item.retired.audits.length, 1);
        if (item.status === "decommissioned") await item.recreateMonitor();
        const before = await item.capture();
        assert.ok(before);
        await item.rescan();
        assert.ok(new Date(await item.capture()) > new Date(before));
        const after = await item.snapshot();
        assert.deepEqual(after.identity, item.retired.identity);
        assert.deepEqual(after.audits, item.retired.audits);
        assert.ok(
          after.tokens.every(
            (token) => token.cert_lifecycle_status === item.status,
          ),
        );
        item.retired = after;
        const detail = await fixture.request(
          `${prefix}/certificate-identities/${item.identityId}`,
        );
        assert.equal(detail.status, 200);
        assert.equal(detail.body.certificate.stillObserved, true);
      }
    });
    await gate.scenario(scenarios[2], async () => {
      await go();
      await page
        .getByText("No certificates in view", { exact: true })
        .waitFor();
      for (const item of tlsFixture.items) {
        assert.equal(await row(item).count(), 0);
      }
      const response = await fixture.request(
        `${prefix}/certificate-identities?excludeRetired=true`,
      );
      assert.equal(response.status, 200);
      assert.equal(response.body.items.length, 0);
    });
    await gate.scenario(scenarios[3], async () => {
      await page
        .getByRole("checkbox", { name: /Show retired/ })
        .locator("..")
        .click();
      for (const item of tlsFixture.items) {
        await row(item).waitFor();
        assert.match(
          await row(item).innerText(),
          new RegExp(
            item.status === "revoked" ? "Revoked" : "Decommissioned",
            "i",
          ),
        );
        assert.match(await row(item).innerText(), /Still observed/i);
      }
      await page.reload();
      for (const item of tlsFixture.items) await row(item).waitFor();
    });
    await gate.scenario(scenarios[4], async () => {
      await go();
      for (const item of tlsFixture.items) {
        await page
          .getByRole("combobox", { name: "Filter by certificate status" })
          .selectOption(item.status);
        await row(item).waitFor();
        await page.waitForFunction(
          (other) =>
            !document.querySelector(
              `[data-certificate-identity-id="${other}"]`,
            ),
          tlsFixture.items.find((value) => value !== item).identityId,
        );
        assert.equal(
          await page
            .getByRole("checkbox", { name: /Show retired/ })
            .isChecked(),
          false,
        );
        const result = await fixture.request(
          `${prefix}/certificate-identities?status=${item.status}`,
        );
        assert.deepEqual(
          result.body.items.map((value) => value.identityId),
          [item.identityId],
        );
      }
    });
    await gate.scenario(scenarios[5], async () => {
      for (const item of tlsFixture.items) {
        await page
          .getByRole("combobox", { name: "Filter by certificate status" })
          .selectOption(item.status);
        await row(item).waitFor();
        assert.equal(
          await row(item)
            .getByRole("button", { name: /Set up renewal|Detach|Add new CSR/ })
            .count(),
          0,
        );
        await row(item)
          .getByRole("button", { name: "Details", exact: true })
          .click();
        const dialog = page.getByRole("dialog");
        await dialog
          .getByRole("table", { name: "Observed locations" })
          .waitFor();
        assert.match(await dialog.innerText(), /TLS endpoint/);
        assert.match(await dialog.innerText(), /Service use/);
        assert.match(await dialog.innerText(), /Observed/);
        assert.match(
          await dialog.innerText(),
          new RegExp(
            item.status === "revoked" ? "Revoked" : "Decommissioned",
            "i",
          ),
        );
        assert.equal(
          await dialog
            .getByRole("button", { name: /Renew now|Set up renewal/ })
            .count(),
          0,
        );
        assert.deepEqual(await item.snapshot(), item.retired);
        await page.keyboard.press("Escape");
        await dialog.waitFor({ state: "hidden" });
      }
      assert.equal(
        (
          await fixture.pool.query(
            "SELECT count(*)::int AS n FROM certificate_jobs WHERE workspace_id=$1",
            [fixture.workspaceId],
          )
        ).rows[0].n,
        0,
      );
    });
  } catch (error) {
    primary = error;
  } finally {
    const cleanup = async () => {
      const failures = [];
      for (const action of [
        async () => {
          if (browser) await browser.close();
        },
        async () => {
          if (tlsFixture) await tlsFixture.cleanup();
        },
        () => fixture.cleanup(),
      ]) {
        try {
          await action();
        } catch (error) {
          failures.push(error);
        }
      }
      if (failures.length)
        throw new AggregateError(
          failures,
          "Owned retirement browser cleanup failed",
        );
    };
    try {
      if (ready) {
        await gate.scenario(scenarios[6], cleanup);
        await gate.finish({ requiredScenarios: scenarios });
      } else await cleanup();
    } catch (error) {
      primary = primary
        ? new AggregateError(
            [primary, error],
            "Browser retirement qualification and cleanup failed",
          )
        : error;
    }
  }
  if (primary) throw primary;
  return gate.report;
}
if (require.main === module)
  main().catch(() => {
    console.error(
      "Browser retirement qualification failed; inspect bounded report",
    );
    process.exitCode = 1;
  });
module.exports = { main, scenarios, requiredSources };
