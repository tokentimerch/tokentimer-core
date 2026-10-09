"use strict";
const fs = require("node:fs"),
  { spawnSync } = require("node:child_process");
const [name, action] = process.argv.slice(2),
  dir = "/lab/" + name;
if (
  !["nginx", "haproxy"].includes(name) ||
  !["validate", "reload"].includes(action)
)
  process.exit(2);
const config = dir + "/service.conf";
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
  process.exit(r.status ?? 1);
}
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
process.exit(r.status ?? 1);
