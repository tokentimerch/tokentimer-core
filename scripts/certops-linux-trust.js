"use strict";
// Native executor qualification; signed dispatch and control-plane authorization
// are separate suites. No filesystem, platform or command implementations are mocked.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { X509Certificate, createHash, randomUUID } = require("node:crypto");
const { receiptFinalizeRecovery } = require("./certops-linux-trust-receipt-fault");
const independentRoots = require("./certops-linux-trust-independent-roots");
const trust = require("../packages/agent/src/trust-store");
const { executeTrustJob } = require("../packages/agent/src");
const { loadPolicyConfig, createPolicyEngine } = require("../packages/agent/src/policy");
const { createHostGate } = require("../packages/agent/scripts/host-gate");
const scenarios = ["linux-trust-root-derived", "linux-trust-intermediate-derived", "linux-trust-restart-replay", "linux-trust-preexisting-protected", "linux-trust-invalid-anchor", "linux-trust-refresh-recovery", "linux-trust-corrupt-receipt", "linux-trust-owned-revoke", "linux-trust-cleanup", "linux-trust-renewal-policy-refusal", "linux-trust-receipt-finalize-recovery", independentRoots.SCENARIO];
function native(file, args, expectedSuccess = true) {
  const result = spawnSync(file, args, { encoding: "utf8", timeout: 120000, maxBuffer: 2 * 1024 * 1024 });
  if (expectedSuccess) assert.equal(result.status, 0, `${path.basename(file)} failed; raw output withheld`);
  return result;
}
function guard() {
  assert.equal(process.platform, "linux");
  assert.equal(process.getuid(), 0);
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.equal(process.env.CERTOPS_LINUX_TRUST_DISPOSABLE_HOST, "1");
}
async function replay(file) {
  guard();
  const input = JSON.parse(fs.readFileSync(file, "utf8"));
  const result = await trust.distributeTrust(input);
  assert.equal(result.failureCategory, null);
  assert.equal(result.outcome, "preexisting");
  assert.equal(result.receipt.state, "finalized");
  assert.equal(result.mutationPerformed, false);
}
async function main() {
  guard();
  const release = fs.readFileSync("/etc/os-release", "utf8");
  const field = (name) => release.match(new RegExp(`^${name}="?([^"\\n]+)`, "m"))?.[1];
  const family = field("ID") === "almalinux" ? "rhel" : "debian";
  assert.ok(family === "rhel" || field("ID") === "ubuntu", "Only qualified distribution families allowed");
  const containerObserved = fs.existsSync("/.dockerenv") || fs.existsSync("/run/.containerenv");
  assert.equal(containerObserved, family === "rhel", "Distribution must run on its declared qualification surface");
  const anchorsDir = family === "rhel" ? "/etc/pki/ca-trust/source/anchors" : "/usr/local/share/ca-certificates";
  const update = () => native(family === "rhel" ? "update-ca-trust" : "update-ca-certificates", family === "rhel" ? ["extract"] : ["--fresh"]);
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-trust-"));
  fs.chmodSync(workDir, 0o700);
  const receiptDir = path.join(workDir, "receipts");
  const ownedPaths = new Set();
  const ownedAnchors = [];
  const refreshCommand = family === "rhel" ? "update-ca-trust" : "update-ca-certificates";
  const refreshExecutable = (process.env.PATH || "").split(path.delimiter).some((directory) => {
    try { fs.accessSync(path.join(directory, refreshCommand), fs.constants.X_OK); return true; } catch { return false; }
  });
  const gate = createHostGate({ suite: "linux-trust-host", strict: true, requiredCapabilities: ["native-linux-trust-refresh", "openssl-chain-oracle"], fixtureSource: { file: "scripts/certops-linux-trust.js", sha256: createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: async () => ({ "native-linux-trust-refresh": { available: fs.existsSync(anchorsDir) && refreshExecutable }, "openssl-chain-oracle": { available: native("openssl", ["version"]).status === 0 } }) });
  gate.report.qualificationEnvironment = { osFamily: "linux", osVersion: field("VERSION_ID"), distribution: field("ID"), measurement: "native", executionSurface: containerObserved ? "disposable-container" : "disposable-vm" };
  gate.report.fixtureSources=independentRoots.REQUIRED_SOURCES.map(file=>({file,sha256:createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"..",file))).digest("hex")}));
  function openssl(args) { return native("openssl", args); }
  function cert(name, issuer) {
    const key = path.join(workDir, `${name}.key`), csr = path.join(workDir, `${name}.csr`), pem = path.join(workDir, `${name}.crt`);
    openssl(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", `/CN=CertOps-${randomUUID()}`]);
    const ext = path.join(workDir, `${name}.ext`);
    fs.writeFileSync(ext, name === "leaf" ? "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:certops-trust.invalid\n" : "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n");
    openssl(["x509", "-req", "-in", csr, ...(issuer ? ["-CA", issuer.pem, "-CAkey", issuer.key] : ["-signkey", key]), "-set_serial", `0x${randomUUID().replaceAll("-", "")}`, "-days", "2", "-extfile", ext, "-out", pem]);
    return { key, pem, text: fs.readFileSync(pem, "utf8"), fingerprint: new X509Certificate(fs.readFileSync(pem)).fingerprint256.replaceAll(":", "").toLowerCase() };
  }
  function job(certificate, anchorType, action = "distribute-trust") {
    return { schemaVersion: 1, jobId: randomUUID(), workspaceId: randomUUID(), agentId: randomUUID(), trustAnchorId: randomUUID(), action, anchorType, fingerprintSha256: certificate.fingerprint, ...(action === "distribute-trust" ? { pem: certificate.text } : {}), mode: "real", requestedAt: new Date().toISOString(), transitionGeneration: 1 };
  }
  const seams = family === "debian" ? { freshUpdateCommandArgv: ["update-ca-certificates", "--fresh"] } : {};
  const sourcePath = (certificate) => path.join(anchorsDir, `tokentimer-${certificate.fingerprint}.${family === "debian" ? "crt" : "pem"}`);
  const input = (payload) => ({ job: payload, family, receiptDir, workDir, seams });
  const verify = (certificate, extra = []) => openssl(["verify", ...extra, certificate.pem]);
  let failure, ready = false, cleanup = "failed";
  try {
    await gate.preflight(); ready = true;
    const root = cert("root"), intermediate = cert("intermediate", root), leaf = cert("leaf", intermediate), preexisting = cert("preexisting");
    const originalRootJob = job(root, "root");
    assert.notEqual(native("openssl", ["verify", root.pem], false).status, 0, "Fresh random root must not already be trusted");
    await gate.scenario("linux-trust-renewal-policy-refusal", async () => {
      const before = fs.readdirSync(anchorsDir).sort();
      const policyEngine = createPolicyEngine(loadPolicyConfig({ allowedCommands: { "qualification-renewal": { argv: ["/bin/true"] } } }));
      for (const action of ["distribute-trust", "revoke-trust"]) {
        const payload = job(root, "root", action);
        const result = await executeTrustJob({ job: payload, jobId: payload.jobId, action, jobMode: "real", policyEngine, executionContext: { keysDir: path.join(workDir, "keys") } });
        assert.equal(result.status, "rejected"); assert.equal(result.rejectionReason, "command_not_allowlisted");
        assert.equal(fs.existsSync(sourcePath(root)), false);
        assert.deepEqual(fs.readdirSync(anchorsDir).sort(), before);
        assert.equal(fs.existsSync(path.join(workDir, "trust-receipts")), false);
        assert.notEqual(native("openssl", ["verify", root.pem], false).status, 0);
      }
    }, { oracle: "Actual native-platform agent executor refuses both trust mutations with renewal-only local command policy; independent OS anchor inventory and default trust remain unchanged" });
    await gate.scenario(scenarios[0], async () => {
      assert.equal(fs.existsSync(sourcePath(root)), false); ownedPaths.add(sourcePath(root));
      ownedAnchors.push(root);
      const result = await trust.distributeTrust(input(originalRootJob));
      assert.equal(result.failureCategory, null); assert.equal(result.outcome, "installed"); assert.equal(result.receipt.state, "finalized");
      verify(root); verify(leaf, ["-untrusted", intermediate.pem]);
    });
    await gate.scenario(scenarios[1], async () => {
      assert.equal(fs.existsSync(sourcePath(intermediate)), false); ownedPaths.add(sourcePath(intermediate));
      ownedAnchors.push(intermediate);
      const result = await trust.distributeTrust(input(job(intermediate, "intermediate")));
      assert.equal(result.failureCategory, null); assert.equal(result.outcome, "installed");
      verify(leaf); // No explicit -CAfile or -untrusted: derived OS store must supply both anchors.
    });
    await gate.scenario(scenarios[2], async () => {
      const file = path.join(workDir, "replay.json"); fs.writeFileSync(file, JSON.stringify(input(originalRootJob)), { mode: 0o600 });
      native(process.execPath, [__filename, "--replay", file]);
      const files = fs.readdirSync(receiptDir); assert.equal(files.length, 2);
      for (const entry of files) assert.equal(fs.statSync(path.join(receiptDir, entry)).mode & 0o777, 0o600);
    });
    await gate.scenario(scenarios[3], async () => {
      const file = path.join(anchorsDir, `certops-preexisting-${randomUUID()}.${family === "debian" ? "crt" : "pem"}`);
      assert.equal(fs.existsSync(file), false); ownedPaths.add(file); fs.writeFileSync(file, preexisting.text, { flag: "wx" }); update(); verify(preexisting);
      ownedAnchors.push(preexisting);
      const result = await trust.distributeTrust(input(job(preexisting, "root")));
      assert.equal(result.outcome, "preexisting"); assert.equal(result.receipt.state, "missing");
      const revoked = await trust.revokeTrust(input(job(preexisting, "root", "revoke-trust")));
      assert.equal(revoked.failureCategory, "receipt_missing"); assert.equal(revoked.mutationPerformed, false); verify(preexisting); assert.ok(fs.existsSync(file));
    });
    await gate.scenario(scenarios[4], async () => {
      const wrong = job(root, "root"); wrong.fingerprintSha256 = "0".repeat(64);
      const mismatch = await trust.distributeTrust(input(wrong)); assert.ok(mismatch.failureCategory); assert.equal(mismatch.mutationAttempted, false);
      const notCa = await trust.distributeTrust(input(job(leaf, "root"))); assert.ok(notCa.failureCategory); assert.equal(notCa.mutationAttempted, false);
      assert.equal(fs.readdirSync(receiptDir).length, 2); assert.equal(fs.existsSync(sourcePath(leaf)), false);
    });
    await gate.scenario(scenarios[5], async () => {
      const retryRoot = cert("retry-root"); assert.equal(fs.existsSync(sourcePath(retryRoot)), false); ownedPaths.add(sourcePath(retryRoot));
      ownedAnchors.push(retryRoot);
      const payload = job(retryRoot, "root");
      const failed = await trust.distributeTrust({ ...input(payload), seams: { ...seams, updateCommandArgv: [path.join(workDir, "missing-refresh-command")] } });
      assert.equal(failed.failureCategory, "os_mutation_failed"); assert.equal(failed.receipt.state, "intent_written");
      assert.notEqual(native("openssl", ["verify", retryRoot.pem], false).status, 0, "Source anchor file alone must not imply trust");
      const recovered = await trust.distributeTrust(input({ ...payload, jobId: randomUUID() }));
      assert.equal(recovered.failureCategory, null); assert.equal(recovered.receipt.state, "finalized"); verify(retryRoot);
      const removed = await trust.revokeTrust(input(job(retryRoot, "root", "revoke-trust")));
      assert.equal(removed.failureCategory, null); assert.equal(removed.outcome, "removed");
    });
    await gate.scenario(scenarios[6], async () => {
      const receipt = require("../packages/agent/src/trust-store/receipt");
      const store = family === "rhel" ? "rhel-ca-trust" : "debian-ca-certificates";
      const file = path.join(receiptDir, `${receipt.receiptId(store, root.fingerprint)}.json`);
      const original = fs.readFileSync(file);
      try {
        fs.writeFileSync(file, "{corrupt local receipt", { mode: 0o600 });
        const refused = await trust.revokeTrust(input(job(root, "root", "revoke-trust")));
        assert.equal(refused.failureCategory, "receipt_corrupt"); assert.equal(refused.mutationAttempted, false); verify(root);
      } finally { fs.writeFileSync(file, original, { mode: 0o600 }); }
    });
    await gate.scenario("linux-trust-receipt-finalize-recovery", async () => {
      const certificate = cert("receipt-finalize-root");
      assert.equal(fs.existsSync(sourcePath(certificate)), false); ownedPaths.add(sourcePath(certificate)); ownedAnchors.push(certificate);
      await receiptFinalizeRecovery({ family, receiptDir, certificate, payload: job(certificate, "root"), input, job, verify, sourcePath });
      assert.notEqual(native("openssl", ["verify", certificate.pem], false).status, 0);
    }, { oracle: "Actual native OS refresh succeeds, then an owned receipt path directory collision forces truthful finalize failure; pending ownership refuses revoke, redistribute repairs and real revoke removes derived trust" });
    await gate.scenario(independentRoots.SCENARIO, async () => {
      gate.report.nativeIndependentTrustRoots=await independentRoots.qualifyIndependentRoots({family,workDir,receiptDir,input,job,sourcePath,ownedPaths,ownedAnchors,native});
    }, {oracle:"Two real independent CA/leaf pairs have default native trust; selective owned revocation preserves sibling receipt, source and derived trust before final owned removal"});
    await gate.scenario(scenarios[7], async () => {
      for (const [certificate, type] of [[intermediate, "intermediate"], [root, "root"]]) {
        const result = await trust.revokeTrust(input(job(certificate, type, "revoke-trust")));
        assert.equal(result.failureCategory, null); assert.equal(result.outcome, "removed"); assert.equal(fs.existsSync(sourcePath(certificate)), false);
      }
      assert.notEqual(native("openssl", ["verify", leaf.pem], false).status, 0); verify(preexisting);
    });
  } catch (error) { failure = error; }
  finally {
    try {
      const clean = async () => {
        independentRoots.assertCleanupSafe(workDir);
        const errors = [];
        for (const file of ownedPaths) { try { assert.equal(path.dirname(file), anchorsDir); fs.rmSync(file, { force: true }); } catch (error) { errors.push(error); } }
        try { update(); } catch (error) { errors.push(error); }
        for (const file of ownedPaths) if (fs.existsSync(file)) errors.push(new Error("Owned anchor remains"));
        for (const certificate of ownedAnchors) {
          try {
            new X509Certificate(fs.readFileSync(certificate.pem));
            const observed = native("openssl", ["verify", certificate.pem], false);
            assert.ok(Number.isInteger(observed.status) && observed.status !== 0 && !observed.error, "Derived OS trust must no longer accept the removed fixture anchor");
          } catch (error) { errors.push(error); }
        }
        // Preserve original CA files and durable receipts if native removal or
        // derived-store verification is uncertain; diagnostics need that state.
        assert.equal(errors.length, 0, "Owned trust fixture cleanup failed; preserve fixture state");
        fs.rmSync(workDir, { recursive: true, force: true });
      };
      if (ready) await gate.scenario(scenarios[8], clean); else await clean();
      cleanup = "passed";
    } catch (error) { failure ||= error; }
    try { await gate.finish({ requiredScenarios: scenarios, cleanup: { status: cleanup } }); } catch (error) { failure ||= error; }
  }
  if (failure) throw failure;
}
module.exports = { main, scenarios };
if (require.main === module) (process.argv[2] === "--replay" ? replay(process.argv[3]) : main()).catch(() => { console.error("Native Linux trust qualification failed; inspect named sanitized report"); process.exitCode = 1; });
