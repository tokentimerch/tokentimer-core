"use strict";
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path");
const { chromium } = require("playwright");
const { guard, dir, database } = require("./common.cjs");
async function main() {
  const state = guard(),
    db = database(),
    browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({
      viewport: { width: 1440, height: 1100 },
    });
    const csrf = await (
      await context.request.get("http://localhost:55471/api/csrf-token")
    ).json();
    const login = await context.request.post(
      "http://localhost:55471/auth/login",
      {
        headers: { "x-csrf-token": csrf.csrfToken },
        data: { email: state.email, password: state.password },
      },
    );
    assert.equal(login.status(), 200);
    const page = await context.newPage(),
      critical = state.scenarios.find((s) => s.name === "critical"),
      success = state.scenarios.find((s) => s.name === "success");
    const href = (name) =>
      `http://localhost:55174/certops/renewals?${new URLSearchParams({ workspace: state.workspaceId, action: "check-adcs-issuer", issuerId: name.issuerId })}`;
    const inbox = await (
      await fetch("http://localhost:18025/api/v2/messages?limit=100")
    ).json();
    const decode = (value) =>
      value
        .replace(/=\r?\n/g, "")
        .replace(/=([0-9a-f]{2})/gi, (_, h) =>
          String.fromCharCode(parseInt(h, 16)),
        );
    const message = inbox.items.find((item) =>
      decode(item.Content.Body).includes(critical.issuerId),
    );
    assert.ok(message, "Critical incident must have an actual SMTP message");
    const emailUrl = decode(message.Content.Body)
      .match(/http:\/\/localhost:55174\/certops\/renewals\?[^\s<>\"]+/)?.[0]
      .replaceAll("&amp;", "&");
    assert.ok(emailUrl);
    assert.equal(
      new URL(emailUrl).searchParams.get("issuerId"),
      critical.issuerId,
    );
    await page.goto(emailUrl, {
      waitUntil: "networkidle",
      timeout: 90000,
    });
    await page
      .getByText("SIMULATED critical", { exact: true })
      .first()
      .waitFor({ timeout: 30000 });
    assert.ok(page.url().includes("/certops/renewals"));
    await page.screenshot({
      path: path.join(dir, "browser-critical.png"),
      fullPage: true,
    });
    await page
      .getByRole("button", { name: "Check again", exact: true })
      .click();
    await page
      .getByRole("combobox", { name: "Agent for SIMULATED critical" })
      .selectOption(critical.agent.rowId);
    await page
      .getByRole("button", {
        name: "Run check for SIMULATED critical",
        exact: true,
      })
      .click();
    await page
      .getByText(/Preflight queued/)
      .first()
      .waitFor({ timeout: 30000 });
    await page.screenshot({
      path: path.join(dir, "browser-manual.png"),
      fullPage: true,
    });
    const job = (
      await db.query(
        "SELECT source,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND operation='adcs-preflight' ORDER BY preflight_seq DESC NULLS LAST LIMIT 1",
        [state.workspaceId, critical.issuerId],
      )
    ).rows[0];
    assert.equal(job.source, "api");
    assert.equal(job.result_metadata.preflightContext.issuerVersion, 1);
    await page.goto(href(success), {
      waitUntil: "networkidle",
      timeout: 90000,
    });
    await page
      .getByText("SIMULATED success", { exact: true })
      .first()
      .waitFor();
    await page.screenshot({
      path: path.join(dir, "browser-renewed.png"),
      fullPage: true,
    });
    await page.goto("http://localhost:18025", {
      waitUntil: "networkidle",
      timeout: 30000,
    });
    await page
      .getByText("AD CS automatic renewal needs attention")
      .first()
      .waitFor();
    await page.screenshot({
      path: path.join(dir, "browser-mailbox.png"),
      fullPage: true,
    });
    fs.writeFileSync(
      path.join(dir, "browser-verification.json"),
      JSON.stringify(
        {
          candidate: require("node:child_process")
            .execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" })
            .trim(),
          passed: true,
          realApi: true,
          realDashboard: true,
          realSmtpCatcher: true,
          native: false,
          manualServerOwnedContext: true,
          workspaceId: state.workspaceId,
        },
        null,
        2,
      ),
    );
    console.log(
      "PASS actual dashboard, issuer action, manual recheck, renewed scenario and SMTP mailbox",
    );
  } finally {
    await browser.close();
    await db.end();
  }
}
main().catch((error) => {
  console.error(error.stack);
  process.exitCode = 1;
});
