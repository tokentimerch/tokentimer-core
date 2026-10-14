"use strict";
/** Offline public-certificate and benign file controls; no native TTL qualification. */
const { test } = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), os = require("node:os"), path = require("node:path"), crypto = require("node:crypto");
const helper = require("../tests/e2e/helpers/certops-adcs-ttl24h-capture");
const { readCertificateTemplateOid } = require("../packages/agent/src/issuers/der-extensions");
const contract = require("./certops-adcs-ttl24h-contract");
test("Windows PowerShell gets an isolated copied module environment", () => {
  const input = { PSModulePath: "pwsh7", pSmOdUlEpAtH: "another", CERTOPS_ADCS_OFFICER_PASSWORD: "owned-test-sentinel", KEEP: "yes" };
  const actual = helper.nativeCommandEnvironment("powershell.exe", input); assert.equal(Object.keys(actual).some(key => key.toLowerCase() === "psmodulepath"), false); assert.ok(actual.CERTOPS_ADCS_OFFICER_PASSWORD === input.CERTOPS_ADCS_OFFICER_PASSWORD); assert.equal(actual.KEEP, "yes"); assert.equal(input.PSModulePath, "pwsh7"); assert.deepEqual(helper.nativeCommandEnvironment("node.exe", input), input);
});
test("native observer emits only exact purpose-scoped ownership and refuses foreign paths", () => {
  const uuid = "11111111-1111-1111-1111-111111111111", nonce = "a".repeat(64);
  const lease = contract.createLease({ candidateSha: "b".repeat(40), runId: "123", runAttempt: "1", nonce, vmResourceId: `/subscriptions/${uuid}/resourceGroups/tt-certops-123-1/providers/Microsoft.Compute/virtualMachines/windows-agent`, vmId: uuid, taskName: contract.TASK_PREFIX + nonce, nodeSha256: "c".repeat(64), keeperSha256: "d".repeat(64) }, "2026-10-15T12:00:00.000Z");
  const input = { lease, stateDir: `C:\\ttqualification\\adcs-ttl24h\\${nonce}\\agent`, controlContainer: `tokentimer-enr-${uuid}`, deferredContainer: "tokentimer-enr-22222222-2222-2222-2222-222222222222", thumbprint: "A".repeat(40), domain: "certops-adcs-123456abcd-ttlvalidation.example.test", site: "TTADCS-123456abcd-ttlvalidation", port: 8960 };
  const script = helper.nativeScript(input); assert.ok(script.includes("KeyIdentity")); assert.ok(script.includes(lease.vmResourceId)); assert.doesNotMatch(script, /Set-|Remove-|New-|Start-|Stop-/);
  for (const patch of [{ stateDir: "C:\\foreign" }, { site: "foreign" }, { thumbprint: "invalid" }, { port: 0 }]) assert.throws(() => helper.nativeScript({ ...input, ...patch }));
  if (process.platform === "win32") {
    const encoded = Buffer.from(script).toString("base64"), parser = `$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'));$t=$null;$e=$null;$null=[Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e);if($e.Count){exit 1}`;
    const result = require("node:child_process").spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", parser], { timeout: 30000, windowsHide: true }); assert.ok(!result.error && result.status === 0, "Generated observer PowerShell AST must parse; observer is never executed");
  }
});
test("observer validates an actual static public CA signature, template and SPKI", () => {
  const root = path.resolve(__dirname, "../packages/agent/reference/adcs-cmc/testdata");
  const leaf = new crypto.X509Certificate(fs.readFileSync(path.join(root, "issued.cer"))), ca = new crypto.X509Certificate(fs.readFileSync(path.join(root, "ca.cer")));
  const domain = leaf.subject.replace(/^CN=/, ""), journal = { templateOid: readCertificateTemplateOid(leaf.raw), csrSpkiSha256: crypto.createHash("sha256").update(leaf.publicKey.export({ type: "spki", format: "der" })).digest("hex") };
  const input = { certificateB64: leaf.raw.toString("base64"), ca, journal, domain };
  assert.equal(helper.publicLeaf(input).fingerprint256, leaf.fingerprint256);
  for (const patch of [{ domain: "wrong.example.test" }, { ca: leaf }, { journal: { ...journal, csrSpkiSha256: "0".repeat(64) } }, { journal: { ...journal, templateOid: "1.2.3.4" } }]) assert.throws(() => helper.publicLeaf({ ...input, ...patch }));
});
test("read-only file observation records actual bounded bytes and refuses invalid file kinds", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tt-ttl-capture-")), file = path.join(root, "public.json");
  try {
    fs.writeFileSync(file, '{"public":true}\n'); const result = helper.readFile(file);
    assert.equal(result.sha256, crypto.createHash("sha256").update(result.bytes).digest("hex")); assert.match(result.fileId, /^\d+$/); assert.equal(result.bytes.toString(), '{"public":true}\n');
    assert.throws(() => helper.readFile(root)); fs.writeFileSync(file, ""); assert.throws(() => helper.readFile(file)); fs.writeFileSync(file, Buffer.alloc(262145)); assert.throws(() => helper.readFile(file));
  } finally { if (fs.existsSync(file)) fs.unlinkSync(file); fs.rmdirSync(root); }
});
test("capture remains a read-only observer with no fabricated execution proof", () => {
  const source = fs.readFileSync(path.resolve(__dirname, "../tests/e2e/helpers/certops-adcs-ttl24h-capture.js"), "utf8");
  assert.doesNotMatch(source, /(?:INSERT\s+INTO|UPDATE\s+certificate|DELETE\s+FROM|Set-Acl|New-SelfSignedCertificate|Start-Service|Stop-Service)/i);
  assert.ok(source.includes("configuredTimeoutSeconds: null")); assert.ok(source.includes("inspectMachineKeySurvivors")); assert.ok(source.includes("contract.verifyPreparedReceipt(result)")); assert.equal(typeof helper.verifyProof, "undefined");
});
