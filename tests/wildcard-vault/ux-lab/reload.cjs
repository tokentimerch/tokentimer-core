"use strict";
const fs = require("node:fs"),
  { spawnSync } = require("node:child_process"),
  tls = require("node:tls"),
  crypto = require("node:crypto");
const [name, action] = process.argv.slice(2),
  dir = "/lab/" + name;
if (
  !["nginx", "haproxy"].includes(name) ||
  !["validate", "reload"].includes(action)
)
  process.exit(2);
const config = dir + "/service.conf";
if (action === "reload") {
  fs.appendFileSync(dir + "/reload-events.jsonl", JSON.stringify({ event: "start", at: Date.now() }) + "\n", { mode: 0o600 });
  process.on("exit", (code) => fs.appendFileSync(dir + "/reload-events.jsonl", JSON.stringify({ event: "end", at: Date.now(), code }) + "\n", { mode: 0o600 }));
  // Customer-only barrier allows the API test to prove actual overlapping
  // service-hook processes without changing agent clocks, leases or receipts.
  const until = Date.now() + 20000;
  while (fs.existsSync(dir + "/hold-reload") && Date.now() < until)
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
  if (fs.existsSync(dir + "/hold-reload")) process.exit(3);
}
// Customer-side fault only: fail before signaling the listener, after the
// product agent has installed the requested pair and recorded uncertainty.
if (action === "reload" && fs.existsSync(dir + "/fail-reload")) process.exit(1);

async function finish(status) {
  if (status !== 0 || action !== "reload") process.exit(status);
  // A reload signal can return before the replacement worker serves TLS.
  // Customer hooks must wait for readiness; the agent still verifies it itself.
  const expected = new crypto.X509Certificate(
    fs.readFileSync(dir + "/cert.pem"),
  ).fingerprint256;
  // Agent command children intentionally receive a restricted environment.
  // Read the customer's approved probe instead of relying on a lab env var.
  const bindings = JSON.parse(fs.readFileSync(dir + "/config.json", "utf8")).materialBindings;
  const servername = Object.values(bindings || {})[0]?.probes?.[0]?.sni;
  if (typeof servername !== "string" || !servername) process.exit(2);
  const deadline = Date.now() + 15000;
  let readySince = null;
  while (Date.now() < deadline) {
    const ready = await new Promise((resolve) => {
      const socket = tls.connect({
        host: "127.0.0.1",
        port: name === "nginx" ? 8443 : 9443,
        servername,
        ca: fs.readFileSync("/lab/issuer-root.pem"),
        rejectUnauthorized: true,
      });
      const timer = setTimeout(() => socket.destroy(), 1000);
      socket.once("secureConnect", () => {
        const matches = socket.getPeerCertificate().fingerprint256 === expected;
        clearTimeout(timer);
        socket.destroy();
        resolve(matches);
      });
      socket.once("error", () => {
        clearTimeout(timer);
        resolve(false);
      });
      socket.once("close", () => {
        clearTimeout(timer);
        resolve(false);
      });
    });
    // During a graceful reload old and new workers can briefly accept in
    // parallel. One lucky new-worker handshake does not establish readiness.
    if (ready) {
      readySince ??= Date.now();
      if (Date.now() - readySince >= 1000) process.exit(0);
    } else readySince = null;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  console.error(
    "Reload did not serve the installed certificate before its deadline",
  );
  process.exit(1);
}

if (name === "nginx") {
  fs.writeFileSync(
    config,
    `pid ${dir}/service.pid; error_log ${dir}/service.log; events {} http { client_body_temp_path ${dir}/client-body; proxy_temp_path ${dir}/proxy-temp; fastcgi_temp_path ${dir}/fastcgi-temp; uwsgi_temp_path ${dir}/uwsgi-temp; scgi_temp_path ${dir}/scgi-temp; access_log off; server { listen 8443 ssl; ssl_certificate ${dir}/cert.pem; ssl_certificate_key ${dir}/key.pem; return 200 'Wildcard UX lab nginx'; } }`,
  );
  let args = ["-p", dir, "-c", config, "-t"];
  const pid = fs.existsSync(dir + "/service.pid")
    ? fs.readFileSync(dir + "/service.pid", "utf8").trim()
    : "";
  if (action === "reload")
    args = [
      "-p",
      dir,
      "-c",
      config,
      ...(/^\d+$/.test(pid) ? ["-s", "reload"] : []),
    ];
  const r = spawnSync("nginx", args, { stdio: "inherit" });
  finish(r.status ?? 1).catch(() => process.exit(1));
} else {
  // HAProxy's PEM bundle is an explicit customer-owned reload action.
  fs.writeFileSync(
    dir + "/haproxy.pem",
    fs.readFileSync(dir + "/cert.pem", "utf8") +
      "\n" +
      fs.readFileSync(dir + "/key.pem", "utf8"),
    { mode: 0o600 },
  );
  fs.writeFileSync(
    config,
    `global\n  daemon\n  pidfile ${dir}/service.pid\n  maxconn 32\ndefaults\n  mode tcp\n  timeout connect 2s\n  timeout client 2s\n  timeout server 2s\nfrontend lab\n  bind 0.0.0.0:9443 ssl crt ${dir}/haproxy.pem\n`,
  );
  const args =
    action === "validate"
      ? ["-c", "-f", config]
      : [
          "-f",
          config,
          ...(fs.existsSync(dir + "/service.pid")
            ? ["-sf", fs.readFileSync(dir + "/service.pid", "utf8").trim()]
            : []),
        ];
  const r = spawnSync("haproxy", args, { stdio: "inherit" });
  finish(r.status ?? 1).catch(() => process.exit(1));
}
