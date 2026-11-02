"use strict";
/** Mandatory-only child for the separate manual native certificate/rotation
 * campaign. No skip path or base journey is used; partial facts are not saved. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path");
async function main() {
  assert.equal(process.env.CERTOPS_CERTIFICATE_SIGNING_DISPOSABLE_STACK, "1");
  assert.equal(process.env.CERTOPS_CSR_DISPOSABLE_STACK, "1");
  const root = path.resolve(__dirname, "../..");
  const report = path.join(
    root,
    "qualification-results/certificate-signing-facts.json",
  );
  assert.equal(fs.existsSync(report), false, "Refuse stale native facts");
  const proof =
    await require("./helpers/certops-acme-certificate-signing").qualify({
      baseUrl: process.env.CERTOPS_CERTIFICATE_SIGNING_API_URL,
      repoRoot: root,
    });
  fs.writeFileSync(report, JSON.stringify(proof), { flag: "wx", mode: 0o600 });
}
if (require.main === module)
  main().catch(() => {
    console.error(
      "Isolated native certificate signing qualification failed; private ownership preserved where unresolved",
    );
    process.exitCode = 1;
  });
module.exports = { main };
