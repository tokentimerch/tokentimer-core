"use strict";
/**
 * Exercises production DNS solvers under deterministic upstream faults. The manual DNS error
 * workflow invokes this harness; fixed-endpoint providers use explicitly injected responses,
 * while configurable adapters use owned loopback HTTP/UDP. No live provider account is qualified.
 */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const http = require("node:http"), dgram = require("node:dgram"), net = require("node:net");
const { spawnSync } = require("node:child_process");
const { createHostGate } = require("../packages/agent/scripts/host-gate");
const { createDnsSolver, listSupportedDnsProviders, CONFLICT_MAX_ATTEMPTS } = require("../packages/agent/src/dns");
const inventory = require("../docs/certops/dns-provider-errors.json");
const root = path.resolve(__dirname, "..");
const challenge = { zone: "fixture.invalid", recordName: "_acme-challenge.fixture.invalid", txtValue: "owned-public-challenge" };
function fingerprint(file) { return crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex"); }
function isOAuthFixtureEndpoint(endpoint, provider, credential) {
  let url; try { url = new URL(endpoint); } catch { return false; }
  if (url.protocol !== "https:" || url.username || url.password || url.port || url.search || url.hash) return false;
  if (provider === "azure-dns") return url.hostname === "login.microsoftonline.com" && url.pathname === `/${encodeURIComponent(credential.tenantId)}/oauth2/v2.0/token`;
  return provider === "google-cloud-dns" && url.hostname === "oauth2.googleapis.com" && url.pathname === "/token";
}
function credentials(privateKey, url) {
  return {
    cloudflare: { apiToken: "fixture-cf-sensitive", zoneId: "owned-zone" },
    route53: { accessKeyId: "fixture-access-id", secretAccessKey: "fixture-aws-sensitive", hostedZoneId: "OWNEDZONE" },
    "azure-dns": { tenantId: "fixture-tenant", clientId: "fixture-client", clientSecret: "fixture-azure-sensitive", subscriptionId: "fixture-subscription", resourceGroup: "fixture-group" },
    "google-cloud-dns": { client_email: "fixture@fixture.invalid", private_key: privateKey, project_id: "fixture-project", managedZone: "owned-zone" },
    "acme-dns": { baseUrl: url, username: "fixture-user", password: "fixture-acmedns-sensitive", subdomain: "owned-subdomain", allowInsecureLocalHttp: true },
    ovhcloud: { applicationKey: "fixture-application", applicationSecret: "fixture-ovh-sensitive", consumerKey: "fixture-consumer-sensitive" },
    hetzner: { apiToken: "fixture-hetzner-sensitive" },
    infomaniak: { apiToken: "fixture-infomaniak-sensitive" },
    exoscale: { apiKey: "fixture-exo-key", apiSecret: "fixture-exo-sensitive" },
    powerdns: { apiUrl: url, apiKey: "fixture-powerdns-sensitive", allowInsecureLocalHttp: true },
  };
}
async function run() {
  assert.deepEqual(listSupportedDnsProviders().filter(provider => provider !== "pebble-challtestsrv").sort(), inventory.providers.map(item => item.provider).sort());
  assert.equal(CONFLICT_MAX_ATTEMPTS, inventory.retryAttempts);
  let mode, httpCalls = 0, ready = false, primary, udpMode = "unsigned";
  const server = http.createServer((request, response) => { httpCalls++; request.resume(); response.writeHead(mode.status, { "content-type": "application/json" }); response.end(mode.body); });
  const udp = dgram.createSocket("udp4");
  udp.on("message", (message, peer) => { if (udpMode === "timeout") return; const reply = Buffer.alloc(udpMode === "malformed" ? 3 : 12); message.copy(reply, 0, 0, 2); if (reply.length >= 12) reply.writeUInt16BE(0x8005, 2); udp.send(reply, peer.port, peer.address); });
  const gate = createHostGate({ suite: "dns-provider-errors", strict: true, evidenceLevel: "integration", reportPath: process.env.CERTOPS_DNS_ERRORS_REPORT || "qualification-results/dns-provider-errors.json", requiredCapabilities: ["provider-fixtures", "loopback-sockets"], fixtureSource: { file: "scripts/certops-dns-provider-errors.js", sha256: fingerprint("scripts/certops-dns-provider-errors.js") }, probeCapabilities: () => ({ "provider-fixtures": { available: true }, "loopback-sockets": { available: Boolean(server.listening) && Boolean(udp.address().port) } }) });
  gate.report.executionScope = "Production DNS solvers: existing named adapter contract fixtures, injected fixed-provider HTTP faults, real owned loopback HTTP for PowerDNS/acme-dns and UDP TSIG refusal/timeout. Virtual backoff only; no external provider or live-zone qualification.";
  gate.report.fixtureSources = [...inventory.providers, ...inventory.sharedContracts].map(item => ({ file: item.file, sha256: fingerprint(item.file) }));
  gate.report.dnsAdapterCases = [];
  try {
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    await new Promise((resolve, reject) => { udp.once("error", reject); udp.bind(0, "127.0.0.1", resolve); });
    assert.equal(await gate.preflight(), true); ready = true;
    const url = `http://127.0.0.1:${server.address().port}`;
    const privateKey = crypto.generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } }).privateKey;
    const configs = credentials(privateKey, url);
    for (const definition of [...inventory.providers, ...inventory.sharedContracts]) {
      await gate.scenario(definition.scenario || `dns-errors-${definition.provider}-contract-inventory`, () => {
        const child = spawnSync(process.execPath, ["--test", "--test-reporter=./scripts/certops-stack-reporter.js", definition.file], { cwd: root, env: { ...process.env, CERTOPS_REPORT_SCOPE: "dns-provider-contract-fixtures" }, encoding: "utf8", timeout: 60000, maxBuffer: 5 * 1024 * 1024, windowsHide: true });
        assert.equal(child.status, 0, "Adapter contract child must complete successfully");
        const events = child.stdout.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
        assert.equal(events.some(event => event.type === "test:fail" || event.skip || event.todo), false, "Adapter contract files cannot hide skipped or failed cases");
        for (const name of definition.requiredTests) {
          const matches = events.filter(event => event.name === name && event.fixtureSource?.file === definition.file);
          assert.equal(matches.length, 1, "Mandatory adapter contract must execute once");
          assert.equal(matches[0].type, "test:pass"); assert.equal(Boolean(matches[0].skip || matches[0].todo), false);
          assert.equal(matches[0].fixtureSource.sha256, fingerprint(definition.file));
          gate.report.dnsAdapterCases.push({ file: definition.file, name, status: "passed" });
        }
      }, { evidenceLevel: "unit", oracle: "Actual named production adapter test file; every committed test must execute once without skip or failure, child output is discarded" });
      if (!definition.provider) continue;
      if (definition.provider === "rfc2136") continue;
      const provider = definition.provider, credential = configs[provider];
      const sensitive = Object.entries(credential).filter(([key]) => /secret|token|private_key|password|consumerKey|apiKey/i.test(key)).map(([, value]) => value);
      for (const [label, status] of [["auth-401", 401], ["permission-403", 403], ["conflict-409", 409], ["precondition-412", 412], ["throttle-429", 429], ["transient-503", 503], ["network-refusal", null], ["secret-redaction", 403]]) {
        const realHttp = ["powerdns", "acme-dns"].includes(provider) && status !== null;
        await gate.scenario(`dns-errors-${provider}-${label}`, async () => {
          let calls = 0; const sleeps = []; const beforeHttp = httpCalls;
          mode = { status: status || 503, body: label === "secret-redaction" ? sensitive.join(" ") + " BEGIN PRIVATE KEY " : "bounded fixture fault" };
          const fetchImpl = realHttp ? global.fetch : () => { calls++; if (status === null) return Promise.reject(new Error("Owned transport refusal " + sensitive[0])); return Promise.resolve({ status, text: () => Promise.resolve(mode.body) }); };
          const solver = createDnsSolver({ provider, credentials: credential, fetchImpl, useFileLock: false, sleep: delay => { sleeps.push(delay); return Promise.resolve(); }, timeoutMs: 500 });
          const result = await solver.presentChallenge(challenge);
          assert.equal(result.ok, false); assert.equal(result.provider, provider);
          const attempts = realHttp ? httpCalls - beforeHttp : calls;
          const retry = [409, 412, 429].includes(status);
          assert.equal(attempts, retry ? inventory.retryAttempts : 1); assert.equal(sleeps.length, retry ? inventory.retryAttempts - 1 : 0);
          if (status !== null) assert.equal(result.statusCode, status);
          assert.equal(typeof result.detail, "string"); assert.ok(result.detail.length <= 1024);
          for (const secret of sensitive) assert.equal(result.detail.includes(secret), false);
          assert.equal(result.detail.includes("BEGIN PRIVATE KEY"), false);
        }, { evidenceLevel: realHttp ? "integration" : "unit", oracle: realHttp ? "Actual owned loopback HTTP response; production adapter and shared retry/redaction execute intact, only retry waits are virtual" : "Injected upstream transport fault; real production adapter signing/auth construction, terminal classification, retry bound and redaction; virtual backoff" });
      }
      await gate.scenario(`dns-errors-${provider}-${provider === "acme-dns" ? "status-only-ack" : "malformed-lookup"}`, async () => {
        const realHttp = ["powerdns", "acme-dns"].includes(provider);
        mode = { status: 200, body: "not-json-or-xml" };
        const config = { ...credential }; if (provider === "cloudflare") delete config.zoneId; if (provider === "route53") delete config.hostedZoneId;
        const solver = createDnsSolver({ provider, credentials: config, useFileLock: false, fetchImpl: realHttp ? global.fetch : () => Promise.resolve({ status: 200, text: () => Promise.resolve(mode.body) }) });
        const result = await solver[provider === "ovhcloud" ? "cleanupChallenge" : "presentChallenge"](challenge);
        // acme-dns deliberately acknowledges by HTTP status; it requires no
        // JSON response schema and has no value deletion API.
        assert.equal(result.ok, provider === "acme-dns"); assert.equal(result.provider, provider);
      }, { evidenceLevel: ["powerdns", "acme-dns"].includes(provider) ? "integration" : "unit", oracle: provider === "acme-dns" ? "Actual loopback HTTP status-only acknowledgment; no JSON-body validation or delete capability claim" : "Malformed zone/token/record lookup cannot become a successful operation; OVH tests cleanup listing rather than its body-independent create acknowledgment" });
      if (["azure-dns", "google-cloud-dns"].includes(provider)) await gate.scenario(`dns-errors-${provider}-oauth-credential-redaction`, async () => {
        const token = "generated-private-oauth-fixture";
        for (const network of [false, true]) {
          const fetchImpl = (endpoint) => {
            if (isOAuthFixtureEndpoint(endpoint, provider, credential)) return Promise.resolve({ status: 200, text: () => Promise.resolve(JSON.stringify({ access_token: token })) });
            if (network) return Promise.reject(new Error("Upstream reflected " + token));
            return Promise.resolve({ status: 403, text: () => Promise.resolve("Upstream reflected " + token) });
          };
          const result = await createDnsSolver({ provider, credentials: credential, fetchImpl, useFileLock: false }).presentChallenge(challenge);
          assert.equal(result.ok, false); assert.equal(result.detail.includes(token), false);
        }
      }, { evidenceLevel: "unit", oracle: "Real generated OAuth credential flow with reflected opaque bearer in failed HTTP response and transport exception; successful token parsing preserved" });
      if (provider === "google-cloud-dns") await gate.scenario("dns-errors-google-cloud-dns-assertion-redaction", async () => {
        let assertion;
        const fetchImpl = (_endpoint, options) => { assertion = new URLSearchParams(options.body).get("assertion"); return Promise.resolve({ status: 403, text: () => Promise.resolve(assertion) }); };
        const result = await createDnsSolver({ provider, credentials: credential, fetchImpl, useFileLock: false }).presentChallenge(challenge);
        assert.equal(result.ok, false); assert.ok(assertion); assert.equal(result.detail.includes(assertion), false);
      }, { evidenceLevel: "unit", oracle: "Actual locally RS256-signed OAuth assertion reflected by upstream fixture is removed from operational evidence" });
    }
    for (const [id, behavior] of [["dns-errors-rfc2136-loopback-unsigned", "unsigned"], ["dns-errors-rfc2136-loopback-timeout", "timeout"], ["dns-errors-rfc2136-loopback-malformed", "malformed"]]) await gate.scenario(id, async () => {
      udpMode = behavior;
      const solver = createDnsSolver({ provider: "rfc2136", credentials: { server: "127.0.0.1", port: udp.address().port, keyName: "fixture-key", keySecretBase64: crypto.randomBytes(32).toString("base64") }, useFileLock: false, timeoutMs: 100 });
      const result = await solver.presentChallenge(challenge); assert.equal(result.ok, false); assert.equal(result.provider, "rfc2136"); assert.ok(result.detail.length <= 1024);
    }, { evidenceLevel: "integration", oracle: "Actual UDP exchange with owned loopback responder; unsigned response refused or real timer expires without DNS mutation" });
  } catch (error) { primary = error; throw error; }
  finally {
    const cleanup = async () => {
      const port = server.address()?.port;
      if (server.listening) await new Promise((resolve, reject) => { server.close(error => error ? reject(error) : resolve()); server.closeAllConnections(); });
      await new Promise(resolve => { try { udp.close(resolve); } catch { resolve(); } });
      if (port) await new Promise((resolve, reject) => { const socket = net.connect({ host: "127.0.0.1", port }); socket.once("connect", () => { socket.destroy(); reject(new Error("Owned HTTP listener survived cleanup")); }); socket.once("error", resolve); });
    };
    try { if (ready) { await gate.scenario("dns-errors-owned-cleanup", cleanup, { evidenceLevel: "integration" }); await gate.finish({ requiredScenarios: inventory.requiredScenarios }); } else await cleanup(); }
    catch (error) { if (primary) throw new AggregateError([primary, error], "DNS adapter fixture and owned cleanup failed"); throw error; }
  }
}
if (require.main === module) run().catch(() => { console.error("DNS provider error qualification failed; inspect bounded report"); process.exitCode = 1; });
module.exports = { run, isOAuthFixtureEndpoint };
