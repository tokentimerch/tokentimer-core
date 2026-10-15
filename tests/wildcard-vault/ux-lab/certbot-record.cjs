"use strict";
// Customer-local public CSR evidence. Never records a key, token or credential.
const fs = require("node:fs"),
  crypto = require("node:crypto"),
  { spawnSync } = require("node:child_process");
const args = process.argv.slice(2),
  i = args.indexOf("--csr");
if (i >= 0) {
  const pub = spawnSync(
    "openssl",
    ["req", "-in", args[i + 1], "-pubkey", "-noout"],
    { encoding: "utf8" },
  );
  if (pub.status !== 0) process.exit(2);
  const publicKeySha256 = crypto
    .createHash("sha256")
    .update(
      crypto
        .createPublicKey(pub.stdout)
        .export({ type: "spki", format: "der" }),
    )
    .digest("hex");
  fs.appendFileSync(
    "/lab/orders.jsonl",
    JSON.stringify({ at: new Date().toISOString(), publicKeySha256 }) + "\n",
    { mode: 0o600 },
  );
}
const r = spawnSync("certbot", args, { stdio: "inherit" });
process.exit(r.status ?? 1);
