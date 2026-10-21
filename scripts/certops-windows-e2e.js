/*
 * Qualification notes: windows-real-journey
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Run node scripts/certops-windows-e2e.js only on disposable elevated Windows with
 * CERTOPS_WINDOWS_BASH/CERTOPS_WINDOWS_ACMESH,loopback native PostgreSQL migrations,pinned
 * Pebble2.8.0/acme.sh3.1.2/DNS and checked candidate native helpers. certops-windows-e2e.yml uses
 * trusted main: windows_server=all,key_profile=all yields10Server2022/2025
 * RSA2048/3072/4096,ECP256/P384 cells,max2 concurrent; defaultsRSA2048 is partial. SYSTEM bounded
 * ScheduledTask owns launcher/exit receipt,restrictive ACL config/DNS creds and process-scoped git
 * trust. Poll2s,heartbeat/discovery5s preserve real machine-token policy. Use original candidate
 * pack/checksum/architecture/install CLI with only root selector redirected; independent native
 * CNG/HTTP.sys/trustedTLS and claim evidence bind genuine public issue/renewal. Actual
 * anonymous/viewer refusal,manager issue idempotency/source=api/requester/os-store-managed facts are
 * required; fixture SQL only provisions actors. Privacy sidecar windows-output-privacy-<profile>.json
 * delegates unchanged real ACME after random stdout/stderr sentinels; require genuine success marker
 * and no leakage in upload observer/DB/SCM,not child-line streaming. Native execution pending,not
 * browser/domain AD CS or signed asset provenance. historical_upgrade=true adds2RSA2048 Server
 * source-migration slots from signed v0.17.2 commit6c902405c7b5d229e2f47b4d5436d780e91c5e17,compiled
 * solely historical helpers+original JS/installer. Preserve real
 * noop,identity/config/credential/pin/operator fixture key/IIS/TLS and report
 * windows-source-upgrade.json provenance=historical-source-build; false means partial matrix.
 * Published v0.17.3 SHA256ec74ed8e1026b7a76b50e0ddc843ee8dc42d1283923ff01be11603069f94c6bb lacks both
 * service-host executables: published-baseline preflight must remain blocked,never add current
 * binaries/rebuild-source substitution. Exact release/asset IDs,size,URL,digest required; not
 * executable signature. Candidate reapply/restart plus real ACL copy refusal/structurally valid
 * wrong-protocol health rollback preserve service bytes/credential; original uninstall preserves
 * operator state. Retirement86 requiresSCMexit0/norespawn5configured recovery intervals. WERDumpType0
 * is custom dump,not suppression: optional unique benign-copy wer_probe first observes+deletes real
 * dump then experimental debugger,never touches real node.exe sink or claims product containment.
 * Between jobs malformed-config/missing-agentId-with-credential startups drain,retain identity/key/TLS
 * and repair with heartbeat. Crash next actual automation at DNS/CNG journal boundary kills only owned
 * tree; this baseline deliberately changes only owned lease deadline/short offline input,therefore
 * does not claim real elapsed lease. Default-clock elapsed lanes separate. API logs need persisted
 * issuance rows/no bootstrap/privatePEM. Replacement CLI registration uses fresh state: retired
 * identity409 preserves token/no credential/log leak;fresh identity heartbeats without migrating
 * automation/custody. Parent owns precise service/site/bindings/cert/key receipts/new trust
 * anchors/jobs/temp cleanup; protocol fixture owns workspace/registration/bootstrap. Upload only
 * sanitized execution/candidate digest/provenance facts,never state/logs/credentials/dumps/raw
 * inventories.
 */
"use strict";
/* Windows journey producer invoked by the trusted manual Windows workflow. Starts only owned
 * Pebble processes and forwards the candidate environment to the public protocol/API suite;
 * reports installed-agent evidence separately from temporary CA fixture startup.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const { spawnSync } = require("node:child_process");
const { withPebble } = require("./certops-real-acme");
const { verify } = require("./certops-stack-report");
const required = require("../tests/e2e/agent-protocol-required-tests.json").requiredTests;
const journey = "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence";
async function main() {
  assert.equal(process.platform, "win32");
  const keyProfile = process.env.CERTOPS_WINDOWS_KEY_PROFILE || "rsa-2048";
  assert.ok(["rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384"].includes(keyProfile));
  const scope = `real-agent-windows-acme-iis/${keyProfile}`;
  fs.mkdirSync("qualification-results", { recursive: true });
  await withPebble(async (fixtureEnv) => {
    const report = `qualification-results/windows-real-${keyProfile}.jsonl`;
    const result = spawnSync(process.execPath, ["--test", "--test-reporter=./scripts/certops-stack-reporter.js", `--test-reporter-destination=${report}`, "tests/e2e/certops-agent-e2e.test.js"], { stdio: "inherit", timeout: 2040000, env: { ...process.env, ...fixtureEnv, CERTOPS_E2E_REQUIRED: "1", CERTOPS_REAL_WINDOWS_REQUIRED: "1", CERTOPS_CSR_DISPOSABLE_STACK: "1", CERTOPS_REPORT_SCOPE: scope } });
    assert.equal(result.status, 0, "Windows installed-agent journey failed");
    const adoption = JSON.parse(fs.readFileSync(`qualification-results/windows-adoption-${keyProfile}.json`, "utf8"));
    assert.equal(adoption.suite, "windows-adoption-retention-real");
    const adoptionResult = require("./certops-qualification-report").verifyReport(adoption, require("../tests/e2e/windows-adoption-retention-journey").requiredScenarios);
    assert.deepEqual(adoptionResult, [], JSON.stringify(adoptionResult));
    const privacy=JSON.parse(fs.readFileSync(`qualification-results/windows-output-privacy-${keyProfile}.json`,"utf8"));
    assert.deepEqual(require("./certops-qualification-report").verifyReport(privacy),[]);
    require("../tests/e2e/helpers/certops-windows-output-privacy").verifyPrivacyReport(privacy);
    const wrongSpki = JSON.parse(fs.readFileSync(`qualification-results/windows-wrong-spki-${keyProfile}.json`, "utf8"));
    assert.equal(wrongSpki.suite, "windows-acme-wrong-spki");
    assert.deepEqual(require("./certops-qualification-report").verifyReport(wrongSpki), []);
    require("../tests/e2e/helpers/certops-windows-wrong-leaf").verifyProof(wrongSpki.nativeWrongSpki);
    const twoRenewals=JSON.parse(fs.readFileSync(`qualification-results/windows-two-renewals-${keyProfile}.json`,"utf8"));
    assert.equal(twoRenewals.suite,"windows-two-unattended-renewals");
    assert.deepEqual(require("./certops-qualification-report").verifyReport(twoRenewals),[]);
    require("../tests/e2e/helpers/certops-windows-two-renewals").verifyProof(twoRenewals.nativeTwoRenewals);
    const dryRun = JSON.parse(fs.readFileSync("qualification-results/windows-certificate-dry-run.json", "utf8"));
    assert.equal(dryRun.suite, "windows-certificate-dry-run");
    assert.deepEqual(require("./certops-qualification-report").verifyReport(dryRun), []);
    require("../tests/e2e/helpers/certops-windows-certificate-dry-run").verifyProof(dryRun.nativeCertificateDryRun);
    if (keyProfile === "rsa-2048") {
      const renameRefusal=JSON.parse(fs.readFileSync("qualification-results/windows-first-rename-refusal.json","utf8"));
      assert.equal(renameRefusal.suite,"windows-installer-first-rename-refusal");
      assert.deepEqual(require("./certops-qualification-report").verifyReport(renameRefusal),[]);
      require("../tests/e2e/helpers/certops-windows-rename-refusal").verifyProof(renameRefusal.nativeRenameRefusal);
      const secondRename=JSON.parse(fs.readFileSync("qualification-results/windows-second-rename-activation.json","utf8"));
      assert.equal(secondRename.suite,"windows-activation-second-rename");
      assert.deepEqual(require("./certops-qualification-report").verifyReport(secondRename),[]);
      require("../tests/e2e/helpers/certops-windows-second-rename").verifyProof(secondRename.nativeSecondRename);
    }
    if (process.env.CERTOPS_WINDOWS_HISTORICAL_PACKAGE) {
      const upgrade=JSON.parse(fs.readFileSync("qualification-results/historical-supporting-rsa-2048/windows-source-upgrade.json","utf8"));
      assert.deepEqual(require("./certops-qualification-report").verifyReport(upgrade),[]);
      require("../tests/e2e/helpers/certops-windows-source-upgrade").verifySourceUpgradeReport(upgrade);
    }
    verify(fs.readFileSync(report, "utf8"), [...required, require("../tests/e2e/helpers/certops-windows-signing-pin-refusal").SCENARIO, require("../tests/e2e/helpers/certops-windows-installed-verify-rollback").SCENARIO, require("../tests/e2e/helpers/certops-windows-multi-target-admission-refusal").SCENARIO, require("../tests/e2e/helpers/certops-windows-active-service-controls").SCENARIO, require("../tests/e2e/helpers/certops-windows-credential-refusal").SCENARIO, require("../tests/e2e/helpers/certops-windows-retention-config").SCENARIO, require("../tests/e2e/helpers/certops-windows-public-retirement").SCENARIO, require("../tests/e2e/helpers/certops-windows-config-encoding").SCENARIO, require("../tests/e2e/helpers/certops-windows-service-controls").SCENARIO, journey], "certops-agent-e2e.test.js", scope);
    verify(fs.readFileSync(report, "utf8"), [...required, require("../tests/e2e/helpers/certops-windows-signing-pin-refusal").SCENARIO, require("../tests/e2e/helpers/certops-windows-installed-verify-rollback").SCENARIO, require("../tests/e2e/helpers/certops-windows-multi-target-admission-refusal").SCENARIO, require("../tests/e2e/helpers/certops-windows-active-service-controls").SCENARIO, require("../tests/e2e/helpers/certops-windows-installed-weak-acl").SCENARIO, require("../tests/e2e/helpers/certops-windows-retention-config").SCENARIO, require("../tests/e2e/helpers/certops-windows-public-retirement").SCENARIO, require("../tests/e2e/helpers/certops-windows-config-encoding").SCENARIO, require("../tests/e2e/helpers/certops-windows-service-controls").SCENARIO, journey], "certops-agent-e2e.test.js", scope);
    verify(fs.readFileSync(report, "utf8"), [...required, require("../tests/e2e/helpers/certops-windows-signing-pin-refusal").SCENARIO, require("../tests/e2e/helpers/certops-windows-installed-verify-rollback").SCENARIO, require("../tests/e2e/helpers/certops-windows-multi-target-admission-refusal").SCENARIO, require("../tests/e2e/helpers/certops-windows-active-service-controls").SCENARIO, require("../tests/e2e/helpers/certops-windows-source-junction").SCENARIO, require("../tests/e2e/helpers/certops-windows-retention-config").SCENARIO, require("../tests/e2e/helpers/certops-windows-public-retirement").SCENARIO, require("../tests/e2e/helpers/certops-windows-config-encoding").SCENARIO, require("../tests/e2e/helpers/certops-windows-service-controls").SCENARIO, journey], "certops-agent-e2e.test.js", scope);
    const journeyEvent=fs.readFileSync(report,"utf8").split(/\r?\n/).filter(Boolean).map(line=>JSON.parse(line)).find(event=>event.name===journey);
    require("../tests/e2e/helpers/certops-windows-public-issuance").verifyPublicIssuanceFacts(journeyEvent.windowsPublicIssuance);
    require("../tests/e2e/helpers/certops-windows-installed-verify-rollback").verifyProof(journeyEvent.nativeInstalledVerifyRollback);
    require("../tests/e2e/helpers/certops-windows-installed-paths").verifyProof(journeyEvent.nativeInstalledPaths);
    require("../tests/e2e/helpers/certops-windows-multi-target-admission-refusal").verifyProof(journeyEvent.nativeWindowsMultiTargetAdmission);
    require("../tests/e2e/helpers/certops-windows-active-service-controls").verifyProof(journeyEvent.nativeInstalledActiveServiceControls);
    require("../tests/e2e/helpers/certops-windows-service-controls").verifyProof(journeyEvent.nativeInstalledServiceControls);
    require("../tests/e2e/helpers/certops-windows-config-encoding").verifyProof(journeyEvent.nativeInstalledConfigEncoding);
    require("../tests/e2e/helpers/certops-windows-public-retirement").verifyProof(journeyEvent.nativeInstalledPublicRetirement);
    require("../tests/e2e/helpers/certops-windows-retention-config").verifyProof(journeyEvent.nativeInstalledRetentionConfig);
    require("../tests/e2e/helpers/certops-windows-signing-pin-refusal").verifyProof(journeyEvent.nativeInstalledSigningPinRefusal);
    require("../tests/e2e/helpers/certops-windows-credential-refusal").verifyProof(journeyEvent.nativeInstalledCredentialRefusal);
    require("../tests/e2e/helpers/certops-windows-installed-iis-refusal").verifyProof(journeyEvent.nativeInstalledIisRefusal);
    require("../tests/e2e/helpers/certops-windows-key-reuse-refusal").verifyProof(journeyEvent.nativeWindowsKeyReuseRefusal);
    console.log("Windows installed-agent qualification report verified");
  });
}
if (require.main === module) main().catch((error) => { console.error(error.message); process.exitCode = 1; });
module.exports = { main };
