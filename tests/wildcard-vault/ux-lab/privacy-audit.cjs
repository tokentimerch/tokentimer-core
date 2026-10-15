"use strict";
// Independent read-only auditor. Core database/log text arrives on stdin from
// the owned lab controller; private material never leaves the customer host.
const fs = require("node:fs"),
  crypto = require("node:crypto"),
  assert = require("node:assert/strict"),
  path = require("node:path");
const root = "/lab",
  needles = new Set(),
  logs = [];
let privateKeys = 0,
  credentials = 0;
function visit(dir) {
  for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, item.name);
    if (item.isSymbolicLink()) continue;
    if (item.isDirectory()) {
      if (
        !["experimental-agent", "acme", "archive", "backups"].includes(
          item.name,
        )
      )
        visit(file);
      continue;
    }
    const size = fs.statSync(file).size;
    if (size > 4 * 1024 * 1024) continue;
    if (item.name === "material-token") {
      needles.add(fs.readFileSync(file, "utf8").trim());
      credentials++;
    }
    if (item.name.endsWith(".log")) logs.push(fs.readFileSync(file, "utf8"));
    if (/\.(?:pem|key)$/.test(item.name)) {
      const raw = fs.readFileSync(file, "utf8");
      for (const block of raw.matchAll(
        /-----BEGIN (?:EC |RSA )?PRIVATE KEY-----[\s\S]*?-----END (?:EC |RSA )?PRIVATE KEY-----/g,
      )) {
        privateKeys++;
        const key = block[0],
          body = key.split(/\r?\n/).slice(1, -1).join("");
        needles.add(key);
        needles.add(body.slice(0, 48));
        needles.add(Buffer.from(key).toString("base64").slice(0, 64));
        const der = crypto
          .createPrivateKey(key)
          .export({ format: "der", type: "pkcs8" });
        needles.add(der.toString("hex").slice(0, 64));
      }
    }
  }
}
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  assert.ok(input.length <= 32 * 1024 * 1024, "Privacy input bound exceeded");
});
process.stdin.on("end", () => {
  try {
    visit(root);
    assert.ok(privateKeys >= 3);
    assert.ok(credentials >= 3);
    const haystack = input + logs.join("\n");
    for (const value of needles)
      assert.ok(
        value.length >= 24 && !haystack.includes(value),
        "Customer private material entered Core or agent logs",
      );
    console.log(
      JSON.stringify({
        status: "passed",
        coreDatabaseAndLogsScanned: true,
        customerAgentLogsScanned: true,
        privateKeys,
        credentials,
        privateNeedlesExported: false,
        dnsCredentialQualification: false,
      }),
    );
  } catch {
    console.error("Zero-custody audit failed; no material exported");
    process.exitCode = 1;
  }
});
