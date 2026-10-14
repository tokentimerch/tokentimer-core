/**
 * Own a local Pebble CA/challenge server around the real agent/API ACME journey.
 * certops-real-acme.yml supplies isolated dependencies; this file checks fixed loopback
 * ports, trusts only the generated fixture CA, runs the selected client journey and
 * verifies its report. Public CA interoperability requires separate provider qualification. */
"use strict";
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const net = require("node:net");
const dgram = require("node:dgram");
const { spawn, spawnSync } = require("node:child_process");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { verify } = require("./certops-stack-report");
const required = require("../tests/e2e/agent-protocol-required-tests.json").requiredTests;
const journey = "real ACME: agent discovers public files registers claims issues renews deploys and persists independently verified certificate evidence";
async function portAvailable(port) {
  await new Promise((resolve, reject) => { const server = net.createServer(); server.once("error", reject); server.listen(port, "127.0.0.1", () => server.close(resolve)); });
}
async function udpAvailable(port) {
  await new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    socket.once("error", (error) => { socket.close(); reject(error); });
    socket.bind(port, "127.0.0.1", () => socket.close(resolve));
  });
}
function probeHttpsReady(endpoint, ca) {
  const url = new URL(endpoint);
  assert.equal(url.protocol, "https:");
  assert.ok(["127.0.0.1", "localhost", "[::1]"].includes(url.hostname), "Fixture readiness is loopback-only");
  assert.ok(Buffer.isBuffer(ca) && ca.length > 0, "The owned fixture's public TLS certificate is required");
  return new Promise((resolve) => {
    const request = https.get(url, { ca, rejectUnauthorized: true, timeout: 1000 }, (response) => { response.resume(); resolve(response.statusCode === 200); });
    request.on("error", () => resolve(false)); request.on("timeout", () => request.destroy());
  });
}
async function ready(url, ca) {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    const ok = await probeHttpsReady(url, ca);
    if (ok) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("Disposable Pebble fixture did not become ready");
}
async function withPebble(run) {
  assert.equal(typeof run, "function");
  for (const port of [14000, 15000, 8053, 8055]) await portAvailable(port);
  await udpAvailable(8053);
  assert.equal(spawnSync("openssl", ["version"]).status, 0, "Missing OpenSSL prerequisite");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "certops-pebble-"));
  const children = [];
  const eabRequired = process.env.CERTOPS_REAL_ACME_EAB === "required";
  let primaryError;
  try {
    const cert = path.join(directory, "localhost.pem"); const key = path.join(directory, "localhost.key");
    assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], { stdio: "ignore" }).status, 0);
    const config = path.join(directory, "pebble.json");
    const eab = { eabKid: `qualification-${crypto.randomBytes(12).toString("hex")}`, eabHmacKey: crypto.randomBytes(32).toString("base64url") };
    const eabFile = path.join(directory, "eab-account.json");
    if (eabRequired) fs.writeFileSync(eabFile, JSON.stringify(eab), { mode: 0o600 });
    fs.writeFileSync(config, JSON.stringify({ pebble: { listenAddress: "127.0.0.1:14000", managementListenAddress: "127.0.0.1:15000", certificate: cert, privateKey: key, httpPort: 5002, tlsPort: 5001, ocspResponderURL: "", externalAccountBindingRequired: eabRequired, ...(eabRequired ? { externalAccountMACKeys: { [eab.eabKid]: eab.eabHmacKey } } : {}), profiles: { default: { description: "Qualification short-lived certificate", validityPeriod: 518400 } } } }), { mode: 0o600 });
    children.push(spawn("pebble-challtestsrv", ["-management", "127.0.0.1:8055", "-dns01", "127.0.0.1:8053", "-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", "", "-defaultIPv6", ""], { stdio: "ignore" }));
    children.push(spawn("pebble", ["-config", config, "-strict", "-dnsserver", "127.0.0.1:8053"], { stdio: "ignore", env: { ...process.env, PEBBLE_VA_NOSLEEP: "1", PEBBLE_AUTHZREUSE: "0", PEBBLE_VA_ALWAYS_VALID: "0" } }));
    for (const child of children) child.on("error", () => {});
    await ready("https://127.0.0.1:14000/dir", fs.readFileSync(cert));
    const actualDirectory = await new Promise((resolve, reject) => {
      const request = https.get("https://127.0.0.1:14000/dir", { ca: fs.readFileSync(cert), timeout: 10000 }, (response) => {
        if (response.statusCode !== 200) { response.resume(); reject(new Error("Actual fixture ACME directory unavailable")); return; }
        const chunks = []; let size = 0;
        response.on("data", (chunk) => { size += chunk.length; if (size > 65536) response.destroy(new Error("ACME directory exceeds qualification bound")); else chunks.push(chunk); });
        response.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); } catch { reject(new Error("Actual fixture ACME directory is malformed")); } });
        response.on("error", reject);
      });
      request.on("error", reject); request.on("timeout", () => request.destroy(new Error("Actual fixture ACME directory timed out")));
    });
    assert.equal(actualDirectory.meta?.externalAccountRequired === true, eabRequired, "Actual CA must independently advertise the selected EAB requirement");
    const issuerRoot = await new Promise((resolve, reject) => {
      const request = https.get("https://127.0.0.1:15000/roots/0", { ca: fs.readFileSync(cert), timeout: 10000 }, (response) => {
        if (response.statusCode !== 200) { response.resume(); reject(new Error("Public fixture issuer root unavailable")); return; }
        const chunks = []; let size = 0;
        response.on("data", (chunk) => { size += chunk.length; if (size > 65536) response.destroy(new Error("Public root response exceeds bound")); else chunks.push(chunk); });
        response.on("end", () => resolve(Buffer.concat(chunks))); response.on("error", reject);
      });
      request.on("error", reject); request.on("timeout", () => request.destroy(new Error("Public root retrieval timed out")));
    });
    assert.equal(new (require("node:crypto").X509Certificate)(issuerRoot).ca, true);
    const rootPath = path.join(directory, "issuer-root.pem"); fs.writeFileSync(rootPath, issuerRoot);
    return await run({ CERTOPS_PEBBLE_DIRECTORY: "https://127.0.0.1:14000/dir", CERTOPS_PEBBLE_DNS_API: "http://127.0.0.1:8055", CERTOPS_PEBBLE_DNS_RESOLVER: "127.0.0.1:8053", CERTOPS_PEBBLE_ISSUER_ROOT: rootPath, CERTOPS_PEBBLE_HTTPS_CERT: cert, ...(eabRequired ? { CERTOPS_PEBBLE_EAB_FILE: eabFile } : {}) });
  } catch(error) { primaryError=error;throw error; } finally {
    const exited=child=>child.exitCode !== null || child.signalCode !== null;
    const awaitExit=child=>new Promise((resolve,reject)=>{
      if(exited(child)){resolve();return;}
      const done=()=>{clearTimeout(timer);resolve();};
      const timer=setTimeout(()=>{child.removeListener("exit",done);reject(new Error("Owned Pebble fixture process did not terminate"));},2000);
      child.once("exit",done);
    });
    const stopped=await Promise.allSettled(children.map(async(child)=>{
      if(!child.pid || exited(child))return;
      child.kill("SIGTERM");
      try{await awaitExit(child);}catch{if(!exited(child))child.kill("SIGKILL");await awaitExit(child);}
      assert.ok(exited(child),"Owned Pebble fixture process remains alive");
    }));
    const errors=stopped.filter(result=>result.status === "rejected").map(result=>result.reason);
    try{fs.rmSync(directory,{recursive:true,force:true});}catch(error){errors.push(error);}
    if(errors.length)throw new AggregateError([...(primaryError?[primaryError]:[]),...errors],"Owned Pebble fixture or journey cleanup failed");
  }
}
module.exports = { withPebble, probeHttpsReady };
async function main() {
  assert.equal(process.env.CERTOPS_PROTOCOL_DISPOSABLE_STACK, "1", "Real ACME requires an explicitly disposable database");
  assert.equal(process.platform, "linux", "initial real ACME lane requires Linux");
  const client = process.env.CERTOPS_REAL_ACME_CLIENT || "certbot";
  const eab = process.env.CERTOPS_REAL_ACME_EAB || "none"; assert.ok(["none", "required"].includes(eab));
  const surface = process.env.CERTOPS_REAL_ACME_SURFACE || "ubuntu-host"; assert.ok(["ubuntu-host", "alpine-container"].includes(surface));
  if (surface === "alpine-container") {
    assert.equal(eab, "none", "Alpine account modes require distinct committed scope definitions");
    assert.ok(fs.existsSync("/.dockerenv"), "Alpine foreground evidence requires the actual container surface");
    assert.match(fs.readFileSync("/etc/os-release", "utf8"), /^ID=alpine$/m);
    assert.equal(process.report.getReport().header.glibcVersionRuntime, undefined);
    assert.ok(fs.existsSync("/lib/ld-musl-x86_64.so.1"), "Native musl loader required");
  }
  assert.ok(["certbot", "acme.sh"].includes(client));
  assert.equal(spawnSync(client === "certbot" ? "certbot" : "bash", client === "certbot" ? ["--version"] : [process.env.CERTOPS_LINUX_ACMESH, "--version"]).status, 0, "Missing actual ACME client prerequisite");
  const scope = surface === "alpine-container" ? `real-agent-alpine-${client === "certbot" ? "certbot" : "acmesh"}` : `real-agent-${client === "certbot" ? "acme" : "acmesh"}${eab === "required" ? "-eab" : ""}-filesystem`;
  await withPebble(async (fixtureEnv) => {
    fs.mkdirSync("qualification-results", { recursive: true });
    const report = "qualification-results/real-acme.jsonl";
    const result = spawnSync(process.execPath, ["--test", "--test-reporter=./scripts/certops-stack-reporter.js", `--test-reporter-destination=${report}`, "tests/e2e/certops-agent-e2e.test.js"], { stdio: "inherit", timeout: 840000, env: { ...process.env, ...fixtureEnv, CERTOPS_CSR_DISPOSABLE_STACK: "1", CERTOPS_REAL_ACME_CLIENT: client, CERTOPS_E2E_REQUIRED: "1", CERTOPS_REAL_ACME_REQUIRED: "1", CERTOPS_REPORT_SCOPE: scope } });
    assert.equal(result.status, 0, "real agent/API/ACME suite failed");
    const events = fs.readFileSync(report, "utf8");
    const helper = require("../tests/e2e/helpers/certops-acme-key-reuse");
    const native = events.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line)).filter(event => event.name === journey);
    assert.equal(native.length, 1); helper.verifyProof(native[0].nativeAcmeKeyReuse); assert.equal(native[0].nativeAcmeKeyReuse.client, client);
    console.log(JSON.stringify(verify(events, [...required, journey, helper.scenarioName], "certops-agent-e2e.test.js", scope)));
  });
}
if (require.main === module) main().catch((error) => { console.error(error.message); process.exitCode = 1; });
