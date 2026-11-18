"use strict";
// Customer-local public CSR evidence. Never records a key, token or credential.
const fs = require("node:fs"),
  crypto = require("node:crypto"),
  { spawnSync } = require("node:child_process");
const args = process.argv.slice(2),
  i = args.indexOf("--csr");
let publicKeySha256;
if (i >= 0) {
  const pub = spawnSync(
    "openssl",
    ["req", "-in", args[i + 1], "-pubkey", "-noout"],
    { encoding: "utf8" },
  );
  if (pub.status !== 0) process.exit(2);
  publicKeySha256 = crypto
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
const dir = args.indexOf("--server");
if (r.status === 0 && i >= 0 && dir >= 0 &&
    args[dir + 1] === "https://ca.wildcard.test:8200/v1/pki/roles/operator/acme/directory") {
  const { issuedCertificate } = require("./azure-operator-review/openbao-operator-observer.cjs");
  const certificate = flag => {
    const index = args.indexOf(flag);
    if (index < 0 || !args[index + 1].startsWith("/lab/")) throw new Error("Owned certificate artifact required");
    return fs.readFileSync(args[index + 1], "utf8");
  };
  const facts = issuedCertificate(certificate("--cert-path"), certificate("--chain-path"),
    fs.readFileSync("/lab/issuer-root.pem", "utf8"));
  fs.appendFileSync("/lab/acme-issued.jsonl", JSON.stringify({ publicKeySha256, ...facts }) + "\n", { mode: 0o600 });
}
process.exit(r.status ?? 1);
