/** Real Chromium audit filtering over genuine public certificate retirements.
 * Run in the manual dashboard qualification lane with disposable API/PostgreSQL.
 * Exact authenticated response IDs and independently ordered persisted events
 * are the oracle; no audit/event/observation rows are fabricated. Reports contain
 * named outcomes and source hashes, never cookies, keys, raw rows or screenshots. */
"use strict";
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { spawnSync } = require("node:child_process"),
  { chromium } = require("playwright");
const {
    createApiFixture,
  } = require("../tests/e2e/helpers/certops-api-fixture"),
  {
    createAuditRetirements,
  } = require("../tests/e2e/helpers/certops-browser-audit-fixture"),
  { createHostGate } = require("../packages/agent/scripts/host-gate");
const scenarios = [
  "browser-audit-genuine-retirement-attribution",
  "browser-audit-literal-search-decoy",
  "browser-audit-action-filter",
  "browser-audit-stable-pagination",
  "browser-audit-workspace-isolation",
  "browser-audit-owned-cleanup",
];
const requiredSources = [
  "scripts/certops-browser-audit.js",
  "tests/e2e/helpers/certops-browser-audit-fixture.js",
  "tests/e2e/helpers/certops-api-fixture.js",
  "apps/dashboard/src/pages/Audit.jsx",
  "apps/api/routes/usage.js",
  "apps/api/services/certops/certificateIdentity.js",
];
async function main() {
  const api = process.env.CERTOPS_CSR_API_URL,
    ui = process.env.CERTOPS_BROWSER_URL;
  assert.ok(api && ui);
  let browser,
    fixture,
    foreign,
    page,
    ready = false,
    primary,
    items,
    foreignItem;
  const hash = (file) => ({
    file,
    sha256: crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.resolve(__dirname, "..", file)))
      .digest("hex"),
  });
  const gate = createHostGate({
    suite: "browser-certificate-audit",
    strict: true,
    evidenceLevel: "e2e",
    reportPath: process.env.CERTOPS_BROWSER_AUDIT_REPORT,
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
  const marker = `audit-${crypto.randomUUID()}-%_`,
    decoy = marker.replace("%_", "XY");
  let route;
  const responseFor = (query, action, offset = 0) =>
    page.waitForResponse((response) => {
      const url = new URL(response.url());
      return (
        url.pathname === route &&
        url.searchParams.get("query") === query &&
        (url.searchParams.get("action") || "") === action &&
        Number(url.searchParams.get("offset") || 0) === offset &&
        response.status() === 200
      );
    });
  async function rowsEqual(expected) {
    const table = page.getByRole("table"),
      rows = table.locator("tbody tr");
    await page.waitForFunction(
      ({ reasons }) => {
        const rows = [...document.querySelectorAll("table tbody tr")];
        return (
          rows.length === reasons.length &&
          rows.every((row, index) => row.textContent.includes(reasons[index]))
        );
      },
      { reasons: expected.map((item) => item.reason) },
    );
    assert.equal(await rows.count(), expected.length);
    for (let index = 0; index < expected.length; index++) {
      const text = await rows.nth(index).innerText();
      assert.ok(text.includes(expected[index].reason));
      assert.ok(text.includes(expected[index].fingerprint));
      assert.ok(text.includes("Certificate API fixture"));
    }
  }
  async function search(value, action = "CERTOPS_CERTIFICATE_RETIRED") {
    const loaded = responseFor(value, action);
    await page.getByPlaceholder("Search action or metadata...").fill(value);
    const response = await loaded;
    return response.json();
  }
  try {
    fixture = await createApiFixture(api);
    foreign = await createApiFixture(api);
    route = `/api/v1/workspaces/${fixture.workspaceId}/audit-events`;
    await gate.preflight();
    ready = true;
    const context = await browser.newContext({
      viewport: { width: 1500, height: 1100 },
    });
    page = await context.newPage();
    page.setDefaultTimeout(30000);
    await gate.scenario(scenarios[0], async () => {
      items = await createAuditRetirements(fixture, [
        ...Array.from(
          { length: 11 },
          (_, index) => `${marker} item-${String(index).padStart(2, "0")}`,
        ),
        `${decoy} decoy`,
      ]);
      [foreignItem] = await createAuditRetirements(foreign, [
        `${marker} foreign`,
      ]);
      assert.equal(
        new Set(
          items.map((item) => new Date(item.event.occurred_at).toISOString()),
        ).size,
        items.length,
      );
      await page.goto(new URL("/login", ui).href);
      await page.getByLabel("Email", { exact: true }).fill(fixture.email);
      await page.getByLabel("Password", { exact: true }).fill(fixture.password);
      await page.getByRole("button", { name: "Sign In", exact: true }).click();
      await page.waitForURL((url) => !url.pathname.includes("login"));
      const loaded = responseFor(marker, "");
      await page.goto(
        new URL(
          `/audit?workspace=${fixture.workspaceId}&q=${encodeURIComponent(marker)}`,
          ui,
        ).href,
      );
      const response = await loaded;
      const data = await response.json();
      assert.equal(data.length, 11);
      assert.ok(
        data.every(
          (row) =>
            row.workspace_id === fixture.workspaceId &&
            row.actor_user_id === fixture.userId,
        ),
      );
    });
    await gate.scenario(scenarios[1], async () => {
      const loaded = responseFor(marker, "CERTOPS_CERTIFICATE_RETIRED");
      await page
        .getByTitle("Filter by specific action type")
        .selectOption("CERTOPS_CERTIFICATE_RETIRED");
      const data = await (await loaded).json();
      const ordered = items
        .filter((item) => item.reason.includes(marker))
        .sort(
          (a, b) =>
            new Date(b.event.occurred_at) - new Date(a.event.occurred_at),
        );
      assert.deepEqual(
        data.map((row) => row.id),
        ordered.map((item) => item.event.id),
      );
      await rowsEqual(ordered.slice(0, 10));
      const all = await search(decoy);
      assert.deepEqual(
        all.map((row) => row.id),
        [items[11].event.id],
      );
      await rowsEqual([items[11]]);
      await search(marker);
      await rowsEqual(ordered.slice(0, 10));
    });
    await gate.scenario(scenarios[2], async () => {
      const loaded = responseFor(marker, "CERTOPS_CERTIFICATE_IMPORTED");
      await page
        .getByTitle("Filter by specific action type")
        .selectOption("CERTOPS_CERTIFICATE_IMPORTED");
      assert.deepEqual(await (await loaded).json(), []);
      await page.getByText("No audit events found.", { exact: true }).waitFor();
      const back = responseFor(marker, "CERTOPS_CERTIFICATE_RETIRED");
      await page
        .getByTitle("Filter by specific action type")
        .selectOption("CERTOPS_CERTIFICATE_RETIRED");
      await back;
    });
    await gate.scenario(scenarios[3], async () => {
      const persisted = (
        await fixture.pool.query(
          "SELECT id FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_CERTIFICATE_RETIRED' AND position($2 in metadata->>'reason')>0 ORDER BY occurred_at DESC",
          [fixture.workspaceId, marker],
        )
      ).rows.map((row) => row.id);
      const expected = persisted.map((id) =>
        items.find((item) => item.event.id === id),
      );
      assert.equal(expected.length, 11);
      await rowsEqual(expected.slice(0, 10));
      const loaded = responseFor(marker, "CERTOPS_CERTIFICATE_RETIRED", 10);
      await page
        .getByRole("button", { name: "Next audit page", exact: true })
        .click();
      assert.deepEqual(
        (await (await loaded).json()).map((row) => row.id),
        persisted.slice(10),
      );
      await rowsEqual(expected.slice(10));
      assert.equal(
        await page
          .getByRole("button", { name: "Next audit page", exact: true })
          .isDisabled(),
        true,
      );
      const previous = responseFor(marker, "CERTOPS_CERTIFICATE_RETIRED", 0);
      await page
        .getByRole("button", { name: "Previous audit page", exact: true })
        .click();
      assert.deepEqual(
        (await (await previous).json()).map((row) => row.id),
        persisted,
      );
      await rowsEqual(expected.slice(0, 10));
    });
    await gate.scenario(scenarios[4], async () => {
      const forbidden = await fixture.request(
        `/api/v1/workspaces/${foreign.workspaceId}/audit-events?query=${encodeURIComponent(marker)}`,
      );
      assert.equal(forbidden.status, 403);
      const data = await fixture.request(
        `${route}?query=${encodeURIComponent(marker)}&action=CERTOPS_CERTIFICATE_RETIRED&limit=100`,
      );
      assert.equal(data.status, 200);
      assert.equal(data.body.length, 11);
      assert.ok(!data.body.some((row) => row.id === foreignItem.event.id));
      assert.ok(
        !(await page.getByRole("table").innerText()).includes(
          foreignItem.reason,
        ),
      );
      const result = await context.request.get(
        new URL(
          `/api/v1/workspaces/${foreign.workspaceId}/audit-events?query=${encodeURIComponent(marker)}`,
          api,
        ).href,
      );
      assert.equal(result.status(), 403);
    });
  } catch (error) {
    primary = error;
  } finally {
    const cleanup = async () => {
      const errors = [];
      for (const action of [
        async () => {
          if (browser) await browser.close();
        },
        async () => {
          if (foreign) await foreign.cleanup();
        },
        async () => {
          if (fixture) await fixture.cleanup();
        },
      ])
        try {
          await action();
        } catch (error) {
          errors.push(error);
        }
      if (errors.length)
        throw new AggregateError(errors, "Owned audit browser cleanup failed");
    };
    try {
      if (ready) {
        await gate.scenario(scenarios[5], cleanup);
        await gate.finish({ requiredScenarios: scenarios });
      } else await cleanup();
    } catch (error) {
      primary = primary
        ? new AggregateError(
            [primary, error],
            "Browser audit and cleanup failed",
          )
        : error;
    }
  }
  if (primary) throw primary;
  return gate.report;
}
if (require.main === module)
  main().catch(() => {
    console.error("Browser audit qualification failed; inspect bounded report");
    process.exitCode = 1;
  });
module.exports = { main, scenarios, requiredSources };
