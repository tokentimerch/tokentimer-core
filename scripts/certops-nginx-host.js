"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const net = require("node:net");
const tls = require("node:tls");
const crypto = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");
const { deployCertificateAndKey } = require("../packages/agent/src/deploy");
const { reloadService } = require("../packages/agent/src/reload");
const { createPolicyEngine, loadPolicyConfig } = require("../packages/agent/src/policy");
const { createHostGate } = require("../packages/agent/scripts/host-gate");
const scenarios = ["nginx-initial-trusted-tls", "nginx-production-reload-cutover", "nginx-invalid-config-refusal", "nginx-missing-command-refusal", "nginx-cleanup"];
const scenariosFor = (service) => scenarios.map((id) => id.replace(/^nginx-/, `${service}-`));
function native(file, args) {
  const result = spawnSync(file, args, { encoding: "utf8", timeout: 30000, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(result.status, 0, `${path.basename(file)} failed; raw output withheld`); return result;
}
async function main() {
  assert.equal(process.platform, "linux"); assert.equal(process.env.GITHUB_ACTIONS, "true"); assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted"); assert.equal(process.env.CERTOPS_RELOAD_DISPOSABLE_HOST, "1");
  const service = process.env.CERTOPS_RELOAD_SERVICE || "nginx"; assert.ok(["nginx", "apache", "haproxy"].includes(service));
  const requiredScenarios = scenariosFor(service);
  const binary = service === "apache" ? "apache2" : service;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `certops-${service}-`));
  const gate = createHostGate({ suite: `${service}-host`, strict: true, requiredCapabilities: [`native-${service}`, "openssl-chain-oracle"], fixtureSource: { file: "scripts/certops-nginx-host.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => {
    const runtime = native(binary, ["-v"]), openssl = native("openssl", ["version"]);
    return { [`native-${service}`]: { available: runtime.status === 0, evidence: `${runtime.stdout}${runtime.stderr}`.trim() }, "openssl-chain-oracle": { available: openssl.status === 0, evidence: openssl.stdout.trim() } };
  } });
  gate.report.qualificationEnvironment.distributionVersion = fs.readFileSync("/etc/os-release", "utf8").match(/^VERSION_ID="?([^"\n]+)/m)?.[1];
  let child, fixturePort, failure, ready = false, cleanup = "failed";
  try {
    await gate.preflight(); ready = true;
    const ca = path.join(root, "ca.crt"), caKey = path.join(root, "ca.key");
    native("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", caKey, "-out", ca, "-days", "2", "-subj", `/CN=Nginx-CA-${crypto.randomUUID()}`, "-addext", "basicConstraints=critical,CA:TRUE"]);
    const ext = path.join(root, "leaf.ext"); fs.writeFileSync(ext, "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:certops-nginx.invalid\n");
    function fixture(name) {
      const privateKeyPath = path.join(root, `${name}.key`), csr = path.join(root, `${name}.csr`), cert = path.join(root, `${name}.crt`);
      native("openssl", ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", privateKeyPath, "-out", csr, "-subj", "/CN=certops-nginx.invalid"]);
      native("openssl", ["x509", "-req", "-in", csr, "-CA", ca, "-CAkey", caKey, "-set_serial", `0x${crypto.randomUUID().replaceAll("-", "")}`, "-days", "2", "-extfile", ext, "-out", cert]);
      return { privateKeyPath, certificatePem: fs.readFileSync(cert, "utf8"), retainPrivateKeyStaging: true };
    }
    const first = fixture("first"), second = fixture("second");
    const port = await new Promise((resolve, reject) => { const listener = net.createServer(); listener.on("error", reject); listener.listen(0, "127.0.0.1", () => { const value = listener.address().port; listener.close(() => resolve(value)); }); });
    fixturePort = port;
    const config = path.join(root, `${service}.conf`);
    const target = { type: "domain", reference: "certops-nginx.invalid", certPath: path.join(root, "served.crt"), keyPath: path.join(root, service === "haproxy" ? "served.crt.key" : "served.key"), backupDir: path.join(root, "backups") }; fs.mkdirSync(target.backupDir);
    let configText, startArgv, validateArgv, reloadArgv;
    if (service === "nginx") {
      configText = `worker_processes 1;\npid "${path.join(root, "nginx.pid")}";\nerror_log "${path.join(root, "error.log")}";\nevents { worker_connections 64; }\nhttp { access_log off; server { listen 127.0.0.1:${port} ssl; server_name certops-nginx.invalid; ssl_certificate "${target.certPath}"; ssl_certificate_key "${target.keyPath}"; location / { return 200 'qualification'; } } }\n`;
      const argv = ["-c", config, "-p", root]; startArgv = ["-g", "daemon off;", ...argv]; validateArgv = [binary, "-t", ...argv]; reloadArgv = () => [binary, "-s", "reload", ...argv];
    } else if (service === "apache") {
      assert.notEqual(process.getuid(), 0, "Apache fixture runs under the actual non-root runner identity");
      const modules = "/usr/lib/apache2/modules";
      configText = `ServerRoot "${root}"\nPidFile "${path.join(root, "apache.pid")}"\nServerName certops-nginx.invalid\nListen 127.0.0.1:${port}\nErrorLog "${path.join(root, "error.log")}"\nLoadModule mpm_event_module ${modules}/mod_mpm_event.so\nLoadModule authz_core_module ${modules}/mod_authz_core.so\nLoadModule socache_shmcb_module ${modules}/mod_socache_shmcb.so\nLoadModule ssl_module ${modules}/mod_ssl.so\nUser #${process.getuid()}\nGroup #${process.getgid()}\nStartServers 1\nThreadsPerChild 4\nMinSpareThreads 1\nMaxSpareThreads 4\nMaxRequestWorkers 4\nSSLSessionCache "shmcb:${path.join(root, "ssl-cache")}(512000)"\n<VirtualHost 127.0.0.1:${port}>\nServerName certops-nginx.invalid\nSSLEngine on\nSSLCertificateFile "${target.certPath}"\nSSLCertificateKeyFile "${target.keyPath}"\n</VirtualHost>\n`;
      startArgv = ["-DFOREGROUND", "-f", config]; validateArgv = [binary, "-t", "-f", config]; reloadArgv = () => [binary, "-k", "graceful", "-f", config];
    } else {
      configText = `global\n  maxconn 32\n  pidfile ${path.join(root, "haproxy.pid")}\n  ssl-load-extra-files key\ndefaults\n  mode http\n  timeout connect 5s\n  timeout client 5s\n  timeout server 5s\nfrontend owned\n  bind 127.0.0.1:${port} ssl crt ${target.certPath}\n  http-request return status 200 content-type text/plain string qualification\n`;
      startArgv = ["-W", "-db", "-f", config]; validateArgv = [binary, "-c", "-f", config]; reloadArgv = () => ["/usr/bin/kill", "-USR2", String(child.pid)];
    }
    fs.writeFileSync(config, configText);
    const engine = createPolicyEngine(loadPolicyConfig({ allowedPaths: [root] }));
    const profiles = () => {
      assert.ok(child?.pid && child.exitCode === null && child.signalCode === null, "Owned server master must still be running before reload");
      assert.ok(fs.readFileSync(`/proc/${child.pid}/cmdline`, "utf8").includes(config), "Reload target must retain this fixture's exact native configuration");
      const commandPolicy = createPolicyEngine(loadPolicyConfig({ allowedCommands: { validate: { argv: validateArgv }, reload: { argv: reloadArgv() } } }));
      return { validateArgv: commandPolicy.checkCommandRef("validate").argv, reloadArgv: commandPolicy.checkCommandRef("reload").argv };
    };
    async function observe() {
      return new Promise((resolve, reject) => {
        const socket = tls.connect({ host: "127.0.0.1", port, servername: target.reference, ca: fs.readFileSync(ca), rejectUnauthorized: true }, () => { const value = socket.getPeerCertificate().fingerprint256; socket.end(); resolve(value); });
        socket.setTimeout(5000, () => socket.destroy(new Error("Native nginx TLS observation timed out"))); socket.on("error", reject);
      });
    }
    async function waitFingerprint(expected) {
      const deadline = Date.now() + 30000;
      while (Date.now() < deadline) {
        assert.equal(child.exitCode, null, "Owned nginx exited unexpectedly");
        try { if (await observe() === expected) return; } catch { /* Bounded startup/cutover polling. */ }
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
      throw new Error("Native nginx did not serve the required trusted leaf");
    }
    const firstFingerprint = new crypto.X509Certificate(first.certificatePem).fingerprint256;
    const secondFingerprint = new crypto.X509Certificate(second.certificatePem).fingerprint256;
    await gate.scenario(requiredScenarios[0], async () => {
      const result = await deployCertificateAndKey({ target, ...first, checkPath: engine.checkPath }); assert.equal(result.deployed, true);
      child = spawn(binary, startArgv, { stdio: "ignore", detached: true }); child.on("error", () => {});
      await waitFingerprint(firstFingerprint);
    });
    await gate.scenario(requiredScenarios[1], async () => {
      const result = await deployCertificateAndKey({ target, ...second, checkPath: engine.checkPath }); assert.equal(result.deployed, true);
      assert.equal(await observe(), firstFingerprint, "File replacement must not pretend the consuming server already reloaded");
      const reloaded = await reloadService({ service, commandProfiles: profiles() }); assert.equal(reloaded.reloaded, true);
      await waitFingerprint(secondFingerprint); assert.notEqual(firstFingerprint, secondFingerprint);
    });
    await gate.scenario(requiredScenarios[2], async () => {
      fs.appendFileSync(config, "certops_unknown_directive on;\n");
      try {
        const result = await reloadService({ service, commandProfiles: profiles() }); assert.equal(result.reloaded, false); assert.equal(result.stage, "validate");
        assert.equal(await observe(), secondFingerprint);
      } finally { fs.writeFileSync(config, configText); }
    });
    await gate.scenario(requiredScenarios[3], async () => {
      const result = await reloadService({ service, commandProfiles: { ...profiles(), reloadArgv: [path.join(root, "missing-reload-command")] } });
      assert.equal(result.reloaded, false); assert.equal(result.stage, "reload"); assert.equal(await observe(), secondFingerprint);
    });
  } catch (error) { failure = error; }
  finally {
    const clean = async () => {
      const errors = [];
      try {
        if (child?.pid) {
          const members = () => fs.readdirSync("/proc").filter((entry) => /^\d+$/.test(entry)).flatMap((entry) => {
            try {
              const stat = fs.readFileSync(`/proc/${entry}/stat`, "utf8");
              const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
              if (Number(fields[2]) !== child.pid) return [];
              assert.equal(fs.readFileSync(`/proc/${entry}/comm`, "utf8").trim(), binary, "Unexpected process in owned server group; refusing signal");
              return [entry];
            } catch (error) { if (["ENOENT", "ESRCH"].includes(error.code)) return []; throw error; }
          });
          const signal = (value) => { if (members().length) { try { process.kill(-child.pid, value); } catch (error) { if (error.code !== "ESRCH") throw error; } } };
          const waitEmpty = async () => {
            const deadline = Date.now() + 5000;
            while (members().length && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 100));
            return members().length === 0;
          };
          signal(service === "nginx" ? "SIGQUIT" : "SIGTERM");
          if (!await waitEmpty()) { signal("SIGKILL"); assert.equal(await waitEmpty(), true, "Owned nginx worker group remains"); }
          const exitDeadline = Date.now() + 2000;
          while (child.exitCode === null && child.signalCode === null && Date.now() < exitDeadline) await new Promise((resolve) => setTimeout(resolve, 50));
          assert.ok(child.exitCode !== null || child.signalCode !== null, "Owned nginx master cleanup did not complete");
        }
        if (fixturePort !== undefined) {
          await new Promise((resolve, reject) => {
            const listener = net.createServer(); listener.on("error", reject);
            listener.listen(fixturePort, "127.0.0.1", () => listener.close(resolve));
          });
        }
      } catch (error) { errors.push(error); }
      try {
        assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir())); assert.ok(path.basename(root).startsWith(`certops-${service}-`));
        fs.rmSync(root, { recursive: true, force: true }); assert.equal(fs.existsSync(root), false);
      } catch (error) { errors.push(error); }
      assert.equal(errors.length, 0, "Owned nginx fixture cleanup failed");
    };
    try { if (ready) await gate.scenario(requiredScenarios[4], clean); else await clean(); cleanup = "passed"; } catch (error) { failure ||= error; }
    try { await gate.finish({ requiredScenarios, cleanup: { status: cleanup } }); } catch (error) { failure ||= error; }
  }
  if (failure) throw failure;
}
module.exports = { main, scenarios, scenariosFor };
if (require.main === module) main().catch(() => { console.error("Native consuming-server qualification failed; inspect sanitized named report"); process.exitCode = 1; });
