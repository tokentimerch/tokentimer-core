/**
 * Qualification: enrolled live DNS provider fixtures
 *
 * Use trusted-main manual certops-dns-provider-qualification.yml for one explicitly
 * enrolled adapter or all enrolled adapters (max two jobs). Configure matching
 * certops-dns-<provider> and unattended certops-dns-cleanup-<provider> environments:
 * CERTOPS_DNS_CREDENTIALS_JSON, CERTOPS_DNS_ZONE, CERTOPS_DNS_RESOLVERS_JSON. Restrict
 * credentials to dedicated fixture operations, require trusted main, and keep the
 * cleanup environment free of human approval. These are configuration prerequisites, not
 * an independent IAM audit. Set CERTOPS_DNS_ENROLLED_PROVIDERS_JSON only after cleanup
 * works; absence means none, and drain owned records before unenrollment. Reserve
 * _acme-challenge.certops-qualification.<zone>; preflight refuses foreign TXT values.
 * acme-dns requires its own account and the exact CNAME; never share a production
 * account. Resolvers must actually reach that zone/CNAME. Two native Node processes use
 * production solvers/shared-host locks for fresh TXT, coexistence, selective removal and
 * complete owned cleanup; an independent native resolver measures propagation. No
 * provider transport/replies are replaced. Require GITHUB_ACTIONS/github-hosted
 * provenance and CERTOPS_DNS_DEDICATED_FIXTURE=1. Write atomic receipts before uncertain
 * mutation. Always retry exact-value cleanup; the hourly certops-dns-fixture-janitor.yml
 * uses the separate cleanup identity and the same per-provider concurrency group to
 * remove only valid fixture values older than two hours. Keep foreign values. acme-dns
 * rotates two slots, has no deletion, reports not-applicable-two-slot-provider and gets
 * no deletion janitor. Credentials stay in environment/memory, never argv, receipts or
 * artifacts. Publish only sanitized outcomes, not DNS values, raw errors or HTTP bodies.
 * This integration lane does not qualify CA/EAB issuance, all provider fault branches,
 * uncertain committed-mutation recovery or multi-host RRset coordination; it creates no
 * VM lab.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";
/**
 * Qualifies one explicitly configured isolated DNS provider zone using production solvers and
 * independent TXT resolution. Invoked by the protected manual provider workflow (or its janitor
 * mode); credentials stay in process environment and cleanup is restricted to reserved owned values.
 */
// Protected disposable DNS fixture only. No CA issuance or provider replies are simulated.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { Resolver } = require("node:dns/promises");
const { spawn } = require("node:child_process");
const { createDnsSolver, listSupportedDnsProviders } = require("../packages/agent/src/dns");
const { createPolicyEngine, loadPolicyConfig } = require("../packages/agent/src/policy");
const { createHostGate } = require("../packages/agent/scripts/host-gate");
const providers = listSupportedDnsProviders().filter((name) => name !== "pebble-challtestsrv");
const scenarios = ["dns-provider-present", "dns-provider-coexist", "dns-provider-owned-cleanup", "dns-provider-cleanup"];
const valuePattern = /^certops-qualification-([0-9]{13})-([a-f0-9]{32})$/;
function configuration() {
  assert.equal(process.env.GITHUB_ACTIONS, "true"); assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted"); assert.equal(process.env.CERTOPS_DNS_DEDICATED_FIXTURE, "1");
  const provider = process.env.CERTOPS_DNS_PROVIDER; assert.ok(providers.includes(provider));
  const zone = String(process.env.CERTOPS_DNS_ZONE || "").toLowerCase().replace(/\.$/, "");
  assert.match(zone, /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/);
  const recordName = `_acme-challenge.certops-qualification.${zone}`;
  const credentials = JSON.parse(process.env.CERTOPS_DNS_CREDENTIALS_JSON || "null");
  assert.ok(credentials && typeof credentials === "object" && !Array.isArray(credentials));
  const solver = createDnsSolver({ provider, credentials, timeoutMs: 30000 });
  const engine = createPolicyEngine(loadPolicyConfig({ allowedDnsProviders: [provider], allowedDnsZones: [zone] }));
  assert.equal(engine.checkDnsProvider(provider).allowed, true); assert.equal(engine.checkDnsZone(zone).allowed, true);
  const servers = JSON.parse(process.env.CERTOPS_DNS_RESOLVERS_JSON || "[]"); assert.ok(Array.isArray(servers) && servers.length > 0 && servers.every((value) => typeof value === "string"));
  const resolver = new Resolver({ timeout: 5000, tries: 1 }); resolver.setServers(servers);
  async function txt() {
    try { return (await resolver.resolveTxt(recordName)).map((chunks) => chunks.join("")); }
    catch (error) { if (["ENODATA", "ENOTFOUND"].includes(error.code)) return []; throw error; }
  }
  async function wait(predicate) {
    const deadline = Date.now() + 300000;
    while (Date.now() < deadline) { if (predicate(await txt())) return; await new Promise((resolve) => setTimeout(resolve, 2000)); }
    throw new Error("Independent native TXT observation exceeded its deadline");
  }
  return { provider, zone, recordName, solver, txt, wait };
}
async function cleanupValues(config, values) {
  const errors = [];
  for (const txtValue of values) {
    try {
      assert.match(txtValue, valuePattern);
      const result = await config.solver.cleanupChallenge({ zone: config.zone, recordName: config.recordName, txtValue });
      assert.equal(result.ok, true, "Owned DNS value cleanup failed; provider output withheld");
      if (config.solver.capabilities.cleanupVerifiable) await config.wait((observed) => !observed.includes(txtValue));
    } catch (error) { errors.push(error); }
  }
  assert.equal(errors.length, 0, "One or more owned DNS values could not be cleaned up");
}
async function cleanupReceipt(file) {
  const config = configuration();
  const receipt = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(receipt.schemaVersion, 1); assert.equal(receipt.provider, config.provider); assert.equal(receipt.recordName, config.recordName);
  assert.ok(Array.isArray(receipt.values) && receipt.values.length <= 2);
  await cleanupValues(config, receipt.values); fs.rmSync(file, { force: true });
}
async function janitor() {
  const config = configuration();
  if (!config.solver.capabilities.cleanupVerifiable) { console.log("DNS cleanup is not applicable to the two-slot provider"); return; }
  const stale = staleValues(await config.txt());
  await cleanupValues(config, stale);
  console.log("Owned stale DNS values cleaned up");
}
function staleValues(values, now = Date.now()) {
  assert.ok(Array.isArray(values) && values.every((value) => typeof value === "string"));
  assert.ok(Number.isSafeInteger(now) && now > 0);
  const cutoff = now - 2 * 60 * 60 * 1000;
  return [...new Set(values)].filter((value) => { const match = value.match(valuePattern); return match && Number(match[1]) < cutoff; });
}
async function present(value) {
  require("./certops-dns-cleanup-enrollment").assertProducerEnrollment(process.env.CERTOPS_DNS_PROVIDER,process.env.CERTOPS_DNS_ENROLLED_PROVIDERS_JSON);
  assert.match(value, valuePattern);
  const config = configuration();
  const result = await config.solver.presentChallenge({ zone: config.zone, recordName: config.recordName, txtValue: value });
  assert.equal(result.ok, true, "Actual provider operation failed; output withheld");
}
async function main() {
  require("./certops-dns-cleanup-enrollment").assertProducerEnrollment(process.env.CERTOPS_DNS_PROVIDER,process.env.CERTOPS_DNS_ENROLLED_PROVIDERS_JSON);
  const config = configuration();
  const values = [0, 1].map(() => `certops-qualification-${Date.now()}-${crypto.randomBytes(16).toString("hex")}`);
  const receiptFile = path.resolve("qualification-results/dns-provider-receipt.json"); fs.mkdirSync(path.dirname(receiptFile), { recursive: true });
  assert.equal(fs.existsSync(receiptFile), false, "Existing cleanup receipt must be handled before another run");
  const receipt = { schemaVersion: 1, provider: config.provider, recordName: config.recordName, values: [] };
  const save = () => { const temporary = `${receiptFile}.${process.pid}.tmp`; fs.writeFileSync(temporary, JSON.stringify(receipt), { mode: 0o600 }); fs.renameSync(temporary, receiptFile); };
  const gate = createHostGate({ suite: "dns-provider-host", strict: true, evidenceLevel: "integration", requiredCapabilities: ["provider-credentials-configured", "native-txt-resolver", "independent-cleanup-enrolled"], fixtureSource: { file: "scripts/certops-dns-provider-host.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: async () => {
    const observed = await config.txt(); assert.ok(observed.every((value) => valuePattern.test(value)), "Dedicated DNS label contains unowned values; refusing mutation");
    return { "provider-credentials-configured": { available: true }, "native-txt-resolver": { available: true }, "independent-cleanup-enrolled": {available: require("./certops-dns-cleanup-enrollment").enrolledProviders(process.env.CERTOPS_DNS_ENROLLED_PROVIDERS_JSON).includes(config.provider)} };
  } });
  gate.report.fixtureSources=[{file:"scripts/certops-dns-cleanup-enrollment.js",sha256:crypto.createHash("sha256").update(fs.readFileSync(require.resolve("./certops-dns-cleanup-enrollment"))).digest("hex")}];
  gate.report.qualificationEnvironment.dnsProvider = config.solver.provider;
  gate.report.cleanupDisposition = config.solver.capabilities.cleanupVerifiable ? "value-deletion-required" : "not-applicable-two-slot-provider";
  let failure, ready = false, cleanup = "failed";
  const children = [];
  try {
    await gate.preflight(); ready = true;
    await gate.scenario(scenarios[0], async () => {
      receipt.values.push(...values); save();
      const outcomes = await Promise.allSettled(values.map((value) => new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [__filename, "--present", value], { stdio: "ignore" }); children.push(child);
        const timeout = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("Actual provider process exceeded deadline")); }, 180000);
        child.once("error", (error) => { clearTimeout(timeout); reject(error); });
        child.once("exit", (code) => { clearTimeout(timeout); if (code === 0) resolve(); else reject(new Error("Actual provider process failed; output withheld")); });
      })));
      assert.ok(outcomes.every((outcome) => outcome.status === "fulfilled"), "Concurrent native provider processes must both complete successfully");
      await config.wait((observed) => observed.includes(values[0]));
    });
    await gate.scenario(scenarios[1], async () => {
      await config.wait((observed) => values.every((value) => observed.includes(value)));
    });
    await gate.scenario(scenarios[2], async () => {
      await cleanupValues(config, [values[0]]);
      if (config.solver.capabilities.cleanupVerifiable) await config.wait((observed) => !observed.includes(values[0]) && observed.includes(values[1]));
      else {
        assert.equal(config.provider, "acme-dns"); await config.wait((observed) => values.every((value) => observed.includes(value)));
      }
    });
  } catch (error) { failure = error; }
  finally {
    const clean = async () => {
      const stopped = await Promise.allSettled(children.map(async (child) => {
        if (child.pid && child.exitCode === null && child.signalCode === null) {
          child.kill("SIGKILL");
          await Promise.race([new Promise((resolve) => child.once("exit", resolve)), new Promise((resolve) => setTimeout(resolve, 5000))]);
          assert.ok(child.exitCode !== null || child.signalCode !== null, "Owned provider process still active before cleanup");
        }
      }));
      assert.ok(stopped.every((outcome) => outcome.status === "fulfilled"), "All owned DNS processes must stop before recovery");
      await cleanupValues(config, receipt.values); fs.rmSync(receiptFile, { force: true });
    };
    try { if (ready) await gate.scenario(scenarios[3], clean); else await clean(); cleanup = "passed"; } catch (error) { failure ||= error; }
    try { await gate.finish({ requiredScenarios: scenarios, cleanup: { status: cleanup, summary: gate.report.cleanupDisposition } }); } catch (error) { failure ||= error; }
  }
  if (failure) throw failure;
}
module.exports = { main, scenarios, providers, valuePattern, staleValues };
if (require.main === module) (process.argv[2] === "--cleanup" ? cleanupReceipt(process.argv[3]) : process.argv[2] === "--janitor" ? janitor() : process.argv[2] === "--present" ? present(process.argv[3]) : main()).catch(() => { console.error("Real DNS provider qualification or cleanup failed; provider responses and credentials withheld"); process.exitCode = 1; });
