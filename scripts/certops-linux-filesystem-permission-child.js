"use strict";
/** Child of the disposable Linux DAC fixture. Input travels through stdin; no
 * private key bytes, result error strings or host paths enter its public output.
 * Calls the unmodified production filesystem deployer with actual OS permissions. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { deployCertificateAndKey } = require("../packages/agent/src/deploy");
const {
  createPolicyEngine,
  loadPolicyConfig,
} = require("../packages/agent/src/policy");
async function main() {
  assert.equal(process.platform, "linux");
  const bytes = fs.readFileSync(0);
  assert.ok(bytes.length > 0 && bytes.length <= 262144);
  const input = JSON.parse(bytes.toString("utf8"));
  assert.ok(process.getuid() > 0 && process.geteuid() > 0);
  assert.equal(process.getuid(), input.uid);
  assert.equal(process.getgid(), input.gid);
  assert.equal(process.getegid(), input.gid);
  const effective = fs
    .readFileSync("/proc/self/status", "utf8")
    .match(/^CapEff:\s*([a-f0-9]+)$/im)?.[1];
  assert.ok(effective && BigInt(`0x${effective}`) === 0n);
  let osDenied = false;
  if (input.expectDenied) {
    try {
      const fd = fs.openSync(input.probe, "wx", 0o600);
      fs.closeSync(fd);
    } catch (error) {
      assert.equal(error.code, "EACCES");
      osDenied = true;
    }
    assert.equal(
      osDenied,
      true,
      "Actual nonroot write must fail before deployment",
    );
  }
  const checkPath = createPolicyEngine(
    loadPolicyConfig({
      allowedPaths: [
        path.dirname(input.deployment.target.certPath),
        input.deployment.target.backupDir,
        path.dirname(input.deployment.privateKeyPath),
      ],
    }),
  ).checkPath;
  const result = await deployCertificateAndKey({
    ...input.deployment,
    checkPath,
    retainPrivateKeyStaging: true,
  });
  let deployedChainVerified = false;
  if (result.deployed === true) {
    const verified = spawnSync(
      "openssl",
      [
        "verify",
        "-CAfile",
        input.deployment.target.chainPath,
        "-verify_hostname",
        input.deployment.target.reference,
        input.deployment.target.certPath,
      ],
      { encoding: "utf8", timeout: 30000, maxBuffer: 8192 },
    );
    assert.ifError(verified.error);
    assert.equal(
      verified.status,
      0,
      "Native deployed-chain verification failed; raw output withheld",
    );
    deployedChainVerified = true;
  }
  process.stdout.write(
    JSON.stringify({
      schemaVersion: 1,
      uid: process.getuid(),
      gid: process.getgid(),
      effectiveCapabilitiesZero: true,
      osDenied,
      deployedChainVerified,
      deployed: result.deployed,
      skipped: result.skipped,
      stage: result.stage || null,
      backupRefusal:
        result.deployed === false &&
        result.skipped === false &&
        result.stage === "backup" &&
        /EACCES/.test(result.error || ""),
    }),
  );
}
if (require.main === module)
  main().catch(() => {
    process.stderr.write("Owned Linux DAC child refused\n");
    process.exitCode = 1;
  });
module.exports = { main };
