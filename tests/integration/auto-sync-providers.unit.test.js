const { expect } = require("chai");
const path = require("path");
const { pathToFileURL } = require("url");

async function importFresh(relativePath) {
  const abs = path.join(__dirname, "..", "..", relativePath);
  const href = `${pathToFileURL(abs).href}?t=${Date.now()}-${Math.random()}`;
  return import(href);
}

describe("auto-sync-providers (core)", () => {
  const envKeys = ["TT_MODE", "AUTO_SYNC_PROVIDERS"];

  afterEach(() => {
    for (const key of envKeys) delete process.env[key];
  });

  it("allows github and gitlab only", async () => {
    const mod = await importFresh("apps/worker/src/auto-sync-providers.js");
    expect(mod.CORE_AUTO_SYNC_PROVIDERS).to.deep.equal(["github", "gitlab"]);
    expect(mod.isAutoSyncProviderAllowed("github")).to.equal(true);
    expect(mod.isAutoSyncProviderAllowed("gitlab")).to.equal(true);
    expect(mod.isAutoSyncProviderAllowed("aws")).to.equal(false);
    expect(mod.isAutoSyncProviderAllowed("vault")).to.equal(false);
  });

  it("ignores TT_MODE=enterprise env override", async () => {
    process.env.TT_MODE = "enterprise";
    const mod = await importFresh("apps/worker/src/auto-sync-providers.js");
    expect(mod.isAutoSyncProviderAllowed("aws")).to.equal(false);
  });

  it("ignores AUTO_SYNC_PROVIDERS env override", async () => {
    process.env.AUTO_SYNC_PROVIDERS = "aws,vault,github";
    const mod = await importFresh("apps/worker/src/auto-sync-providers.js");
    expect(mod.isAutoSyncProviderAllowed("aws")).to.equal(false);
    expect(mod.isAutoSyncProviderAllowed("vault")).to.equal(false);
    expect(mod.isAutoSyncProviderAllowed("github")).to.equal(true);
  });
});
