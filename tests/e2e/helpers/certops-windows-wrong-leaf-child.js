"use strict";
/** Disposable native command-profile fault: return an already genuinely CA-issued
 * owned leaf for a different freshly generated CNG CSR. Only public material is
 * copied; the installed production executor must refuse before acceptance. */
const fs = require("node:fs"),
  path = require("node:path"),
  assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
function main() {
  assert.equal(process.platform, "win32");
  const [recipePath, ...args] = process.argv.slice(2);
  const recipe = JSON.parse(fs.readFileSync(recipePath, "utf8"));
  assert.match(recipe.certificateId, /^[a-f0-9-]{36}$/);
  const value = (flag) => {
    const i = args.indexOf(flag);
    assert.ok(i >= 0);
    return args[i + 1];
  };
  const csr = value("--csr");
  assert.ok(
    path.resolve(csr).startsWith(path.resolve(recipe.workDir) + path.sep),
  );
  const csrPem = fs.readFileSync(csr, "utf8");
  assert.ok(Buffer.byteLength(csrPem) < 65536);
  const prefix = `tokentimer-${recipe.certificateId}-`;
  const listing = spawnSync(
    "certutil.exe",
    ["-csp", "Microsoft Software Key Storage Provider", "-key"],
    { encoding: "utf8", timeout: 20000, windowsHide: true },
  );
  assert.equal(listing.status, 0);
  const containers = listing.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(
      (line) =>
        line.startsWith(prefix) &&
        /^[a-f0-9]{8}$/.test(line.slice(prefix.length)),
    );
  assert.ok(containers.length > 0);
  const leaf = fs.readFileSync(recipe.leafPath);
  for (const flag of ["--cert-file", "--fullchain-file"]) {
    const file = value(flag);
    assert.ok(
      path.resolve(file).startsWith(path.resolve(recipe.workDir) + path.sep),
    );
    fs.writeFileSync(file, leaf, { flag: "wx", mode: 0o600 });
  }
  fs.writeFileSync(
    recipe.receiptPath,
    JSON.stringify({
      csrPem,
      containers,
      returnedLeafSha256: require("node:crypto")
        .createHash("sha256")
        .update(leaf)
        .digest("hex"),
    }),
    { flag: "wx", mode: 0o600 },
  );
}
if (require.main === module) {
  try {
    main();
  } catch {
    process.exitCode = 1;
  }
}
module.exports = { main };
