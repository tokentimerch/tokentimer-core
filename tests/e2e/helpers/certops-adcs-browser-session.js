"use strict";
/** Exact pinned native browser session for supported AD CS UI actions. It owns
 * one retained BrowserServer and a temporary public API trust receipt. No raw
 * trace, storage state, credentials or native private configuration is emitted. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const {
  createOwnedBrowserResource,
} = require("./certops-adcs-browser-journey");
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-adcs-browser-session.js",
  "tests/e2e/helpers/certops-adcs-browser-journey.js",
  "infra/certops-adcs/browser-api-trust.ps1",
  "infra/certops-adcs/browser-windows-tools.ps1",
  "package.json",
  "pnpm-lock.yaml",
]);
function releaseBrowserResource(base) {
  let released = false;
  return {
    hasLiveChild: () => !released && base.hasLiveChild(),
    hasOwnershipReceipt: () => !released && base.hasOwnershipReceipt(),
    async close() {
      if (released) return;
      await base.close();
      released = true;
    },
  };
}
async function withOwnedAdcsBrowserPage(
  { fixture, workDir, command, ownedBrowserResources },
  action,
) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.equal(process.env.CERTOPS_ADCS_BROWSER, "1");
  assert.equal(typeof action, "function");
  assert.ok(Array.isArray(ownedBrowserResources));
  const root = path.resolve(__dirname, "../../.."),
    origin = "https://10.64.0.6",
    runtime = JSON.parse(
      fs.readFileSync("C:\\ttqualification\\browser-runtime.json", "utf8"),
    );
  assert.equal(runtime.candidateSha, process.env.GITHUB_SHA);
  const pin = require(path.join(root, "package.json")).devDependencies
    .playwright;
  assert.equal(runtime.playwrightVersion, pin);
  assert.equal(
    runtime.bootstrapSourceSha256,
    crypto
      .createHash("sha256")
      .update(
        fs.readFileSync(
          path.join(root, "infra/certops-adcs/browser-windows-tools.ps1"),
        ),
      )
      .digest("hex"),
  );
  assert.equal(runtime.browserCache, "C:\\ttqualification\\browser-cache");
  process.env.PLAYWRIGHT_BROWSERS_PATH = runtime.browserCache;
  assert.equal(require("playwright/package.json").version, pin);
  const { chromium } = require("playwright"),
    receipt = path.join(workDir, "browser-api-trust.json"),
    trustScript = path.join(root, "infra/certops-adcs/browser-api-trust.ps1");
  assert.equal(fs.existsSync(receipt), false);
  let server,
    primary,
    result,
    stage = "browser-prerequisites";
  const base = createOwnedBrowserResource({
      getServer: () => server,
      receipt,
      removeTrust: () =>
        command("powershell.exe", [
          "-NoProfile",
          "-NonInteractive",
          "-File",
          trustScript,
          "-Mode",
          "Remove",
          "-Receipt",
          receipt,
        ]),
    }),
    resource = releaseBrowserResource(base);
  ownedBrowserResources.push(resource);
  try {
    command("powershell.exe", [
      "-NoProfile",
      "-NonInteractive",
      "-File",
      trustScript,
      "-Mode",
      "Add",
      "-Receipt",
      receipt,
    ]);
    server = await chromium.launchServer({ headless: true, host: "127.0.0.1" });
    const browser = await chromium.connect(server.wsEndpoint(), {
        timeout: 30000,
      }),
      context = await browser.newContext({ ignoreHTTPSErrors: false }),
      page = await context.newPage();
    page.setDefaultTimeout(90000);
    stage = "browser-login";
    await page.goto(origin + "/login");
    await page.getByLabel("Email", { exact: true }).fill(fixture.email);
    await page.getByLabel("Password", { exact: true }).fill(fixture.password);
    await page.getByRole("button", { name: "Sign In", exact: true }).click();
    await page.waitForURL((url) => !url.pathname.includes("login"));
    const destination = new URL("/certops/renewals", origin);
    destination.searchParams.set("workspace", fixture.workspaceId);
    await page.goto(destination.href);
    const section = page.locator(
      'button[aria-controls="certops-adcs-section"]',
    );
    await section.waitFor();
    if ((await section.getAttribute("aria-expanded")) !== "true")
      await section.click();
    stage = "supported-enrollment-action";
    result = await action(page, { origin });
  } catch {
    primary = new Error(`Native AD CS browser session failed at ${stage}`);
  } finally {
    try {
      await resource.close();
    } catch (error) {
      throw new AggregateError(
        [...(primary ? [primary] : []), error],
        "AD CS browser ownership cleanup incomplete",
      );
    }
  }
  if (primary) throw primary;
  return result;
}
module.exports = {
  REQUIRED_SOURCES,
  releaseBrowserResource,
  withOwnedAdcsBrowserPage,
};
