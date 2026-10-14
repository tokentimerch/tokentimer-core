/**
 * Exercise the real dashboard console against authenticated API/PostgreSQL fixtures.
 * The browser workflow invokes this after the main UI suite. Diagnostic lines come
 * from a registered protocol agent, not an installed native process. Real offline
 * transport and membership changes test reconnection and live authorization boundaries.
 */
"use strict";
const assert = require("node:assert/strict"), crypto = require("node:crypto"), fs = require("node:fs");
const { chromium } = require("playwright");
const { createApiFixture } = require("../tests/e2e/helpers/certops-api-fixture");
const { createRegisteredAgent } = require("../tests/e2e/helpers/certops-registered-agent");
const { createHostGate } = require("../packages/agent/scripts/host-gate");
const scenarios = ["browser-console-authorized-redaction", "browser-console-offline-reconnect", "browser-console-viewer-status-only", "browser-console-authority-withdrawal", "browser-console-owned-cleanup"];
async function until(check) { const end = Date.now() + 30000; while (Date.now() < end) { if (await check()) return; await new Promise(resolve => setTimeout(resolve, 200)); } throw new Error("Browser console condition did not settle"); }
async function main() {
  const api = process.env.CERTOPS_CSR_API_URL, ui = process.env.CERTOPS_BROWSER_URL;
  assert.ok(api && ui); const fixtures = []; let browser, ready = false, primary;
  const gate = createHostGate({ suite: "browser-agent-console", strict: true, evidenceLevel: "e2e", reportPath: process.env.CERTOPS_BROWSER_CONSOLE_REPORT || "qualification-results/browser-console.json", requiredCapabilities: ["browser", "api", "postgres"], fixtureSource: { file: "scripts/certops-browser-console.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: async () => { let available = false; try { browser = await chromium.launch({ headless: true }); available = true; } catch {} return { browser: { available }, api: { available: (await fetch(api)).ok }, postgres: { available: fixtures.length > 0 } }; } });
  gate.report.executionScope = "Actual browser/API/PostgreSQL with registered protocol diagnostic lines and seeded membership prerequisites; no installed native agent or certificate operation";
  try {
    fixtures.push(await createApiFixture(api)); const fixture = fixtures[0];
    assert.equal(await gate.preflight(), true); ready = true;
    const context = await browser.newContext(), page = await context.newPage(); page.setDefaultTimeout(30000);
    gate.report.loginHttpStatuses = []; gate.report.browserNetworkFailures = 0;
    page.on("response", response => { if (new URL(response.url()).pathname.includes("auth") && gate.report.loginHttpStatuses.length < 16) gate.report.loginHttpStatuses.push(response.status()); });
    page.on("requestfailed", () => { gate.report.browserNetworkFailures++; });
    async function login(target, identity) { gate.report.browserStage = "login-navigation"; await target.goto(new URL("/login", ui).href); gate.report.browserStage = "login-email"; await target.getByLabel("Email", { exact: true }).fill(identity.email); await target.getByLabel("Password", { exact: true }).fill(identity.password); gate.report.browserStage = "login-submit"; await target.getByRole("button", { name: "Sign In", exact: true }).click(); gate.report.browserStage = "login-redirect"; await target.waitForURL(url => !url.pathname.includes("login")); }
    const agent = await createRegisteredAgent(fixture, api, ["job-log-stream-v1"]), claimed = await agent.claimNoop();
    const route = `/api/v1/workspaces/${fixture.workspaceId}/certops/jobs/${claimed.jobId}/agent-log`;
    const marker = "Public console diagnostic " + crypto.randomUUID(); const secret = crypto.randomBytes(24).toString("hex");
    const line = (seq, message) => ({ seq, ts: new Date().toISOString(), level: "info", step: "verify", message });
    async function send(seq, message) { const result = await agent.machine(`jobs/${claimed.jobId}/logs`, "log", { jobId: claimed.jobId, claimId: claimed.claimId, final: false, firstSeq: seq, lines: [line(seq, message)] }); assert.equal(result.status, 200); }
    const consoleBox = page.getByTestId("agent-shell-console"); let polls = 0, statusOnlyPolls = 0;
    page.on("response", async response => { if (new URL(response.url()).pathname === route) { polls++; try { const value = await response.json(); if (value.linesVisible === false) statusOnlyPolls++; } catch {} } });
    const jobsUrl = new URL("/certops/jobs", ui); jobsUrl.searchParams.set("workspace", fixture.workspaceId);
    await gate.scenario(scenarios[0], async () => {
      gate.report.browserStage = "console-login"; await login(page, fixture);
      gate.report.browserStage = "console-upload"; await send(1, marker + " initial"); await send(2, "password=" + secret);
      gate.report.browserStage = "console-jobs-navigation"; await page.goto(jobsUrl.href); gate.report.browserStage = "console-expand"; await page.locator('[aria-expanded="false"]').filter({ hasText: "No-op" }).first().click();
      gate.report.browserStage = "console-lines"; await consoleBox.waitFor(); await until(async () => (await consoleBox.innerText()).includes(marker + " initial"));
      assert.equal((await consoleBox.innerText()).includes(secret), false); assert.equal(await consoleBox.locator("[data-shell-line]").count(), 2); assert.equal((await fixture.request(route)).body.linesVisible, true);
      assert.equal((await fixture.pool.query("SELECT count(*)::int AS n FROM certops_agent_job_log WHERE job_id=$1", [claimed.jobId])).rows[0].n, 2);
    });
    await gate.scenario(scenarios[1], async () => {
      gate.report.browserStage = "console-offline"; await context.setOffline(true);
      try { await until(async () => (await consoleBox.innerText()).includes("Reconnecting")); await send(3, marker + " after reconnect"); }
      finally { await context.setOffline(false); }
      await until(async () => (await consoleBox.innerText()).includes(marker + " after reconnect"));
      assert.equal(await consoleBox.locator('[data-shell-line]').filter({ hasText: marker + " initial" }).count(), 1);
      assert.equal(await consoleBox.locator('[data-shell-line]').filter({ hasText: marker + " after reconnect" }).count(), 1);
    }, { oracle: "Actual browser offline network failure followed by resumed cursor polling renders a newly persisted line once without duplicate history" });
    await gate.scenario(scenarios[2], async () => {
      gate.report.browserStage = "console-viewer"; const viewer = await createApiFixture(api); fixtures.push(viewer);
      await fixture.pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'viewer')", [fixture.workspaceId, viewer.userId]);
      const viewerContext = await browser.newContext(), viewerPage = await viewerContext.newPage();
      try { await login(viewerPage, viewer); await viewerPage.goto(jobsUrl.href); await viewerPage.waitForURL(url => url.pathname === "/dashboard");
        assert.equal(await viewerPage.getByTestId("agent-shell-console").count(), 0);
        const result = await viewerContext.request.get(new URL(route, api).href); assert.equal(result.status(), 200); const body = await result.json();
        assert.equal(body.linesVisible, false); assert.deepEqual(body.items, []); assert.equal(body.jobStatus, "claimed"); assert.ok(body.streams.length > 0);
      } finally { await viewerContext.close(); }
    }, { oracle: "Real viewer login is denied the manager-only console route; its actual browser session can read stream status but receives no line text" });
    await gate.scenario(scenarios[3], async () => {
      gate.report.browserStage = "console-authority-withdrawal"; const before = statusOnlyPolls;
      try { await fixture.pool.query("UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2", [fixture.workspaceId, fixture.userId]);
        await send(4, marker + " restricted append"); await until(() => statusOnlyPolls > before);
        await until(async () => !(await consoleBox.innerText()).includes(marker));
        assert.equal(await consoleBox.locator('[data-shell-line]').count(), 0);
        assert.ok((await consoleBox.innerText()).includes("manager access"));
        assert.equal((await fixture.pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [claimed.jobId])).rows[0].status, "claimed");
      } finally { await fixture.pool.query("UPDATE workspace_memberships SET role='admin' WHERE workspace_id=$1 AND user_id=$2", [fixture.workspaceId, fixture.userId]); }
      gate.report.consolePrivacy = { authenticatedPolling: polls > 0, authoritativeStatusOnlyObserved: statusOnlyPolls > 0, cachedTextWithdrawn: true, noNativeExecutionClaim: true };
    });
  } catch (error) { primary = error; throw error; }
  finally { const cleanup = async () => { const failures = []; try { if (browser) await browser.close(); } catch (error) { failures.push(error); } for (const fixture of fixtures.reverse()) { try { await fixture.cleanup(); } catch (error) { failures.push(error); } } if (failures.length) throw new AggregateError(failures, "Owned browser console cleanup failed"); };
    try { if (ready) { await gate.scenario(scenarios[4], cleanup); await gate.finish({ requiredScenarios: scenarios }); } else await cleanup(); }
    catch (error) { if (primary) throw new AggregateError([primary, error], "Browser console qualification and cleanup failed"); throw error; }
  }
}
if (require.main === module) main().catch(() => { console.error("Browser console qualification failed; inspect bounded report"); process.exitCode = 1; });
module.exports = { main, scenarios };
