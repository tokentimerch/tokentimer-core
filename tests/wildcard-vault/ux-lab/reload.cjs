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

async function finish(status) {
  if (status !== 0 || action !== "reload") process.exit(status);
  // A reload signal can return before the replacement worker serves TLS.
  // Customer hooks must wait for readiness; the agent still verifies it itself.
  const expected = new crypto.X509Certificate(
    fs.readFileSync(dir + "/cert.pem"),
  ).fingerprint256;
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    const ready = await new Promise((resolve) => {
      const socket = tls.connect({
        host: "127.0.0.1",
        port: name === "nginx" ? 8443 : 9443,
        servername: name + ".wildcard.test",
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
    if (ready) process.exit(0);
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
    `pid ${dir}/service.pid; error_log ${dir}/service.log; events {} http { access_log off; server { listen 8443 ssl; ssl_certificate ${dir}/cert.pem; ssl_certificate_key ${dir}/key.pem; return 200 'Wildcard UX lab nginx'; } }`,
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
