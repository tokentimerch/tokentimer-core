"use strict";
/**
 * Qualification notes: explicit response file barrier support
 *
 * Explicit Windows supporting run (no credentials/network/product mutation):
 *   $env:CERTOPS_RESPONSE_BARRIER_SUPPORT = '1'
 *   node scripts/certops-response-barrier-support.js
 * Three cases first-write zero-length issued.cer/chain.p7b/submit-response.rsp placeholders, never
 * CA response material. Arm acknowledged level-1 input+all output oplocks before authorized child
 * read; bind retained PID/creation/executable/script hash/parent. Observe input then selected
 * output break, unchanged identities/empty lengths; terminate exact retained writer handle, prove
 * absence/input+guard hashes before releasing output holders. All 36 flags/graceful holder+
 * active-guard/registered-worker/drained private receipts required; nativeAdcsQualified and
 * sourceAcquisitionRaceQualified false. Unknown reader/receipt/live child/missed break preserves
 * root; timeout uses owned cancellation, never kill holder to force pass. Ordinary Windows CI also
 * exercises the actual barriers with a restrictive parent execution policy. Selected trusted Windows
 * 2022/2025 or manual windows/all runs support, no ADCS matrix slot. Microsoft level-1 oplock
 * needs ACK; directory FSCTL_REQUEST_OPLOCK notifications are advisory. Real client creates fresh
 * CSR just before launch: reliable actual input-barrier acquisition remains unimplemented, polling
 * not proof. Future real timing must bind client/SYSTEM/requester/CSR/RequestId/leaf and drain
 * producers before placeholder removal; no journal/date/response substitution. Deliberate same-CSR
 * ambiguity remains separate even after real response-loss timing becomes proven.
 *
 * Shared setup, evidence and cleanup policy: .github/maintainers/certops/e2e-qualification.md.
 */
/** Controlled proof and cleanup refusal checks only. Native supporting execution
 * is a separate explicit command and never runs from these tooling regressions. */
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), os = require("node:os"), crypto = require("node:crypto");
const helper = require("./certops-response-barrier-support");
const { spawnSync, spawn } = require("node:child_process");
const caseProof = outputIndex => ({ outputIndex, ...Object.fromEntries(helper.flags.map(flag => [flag, true])) });
test("supporting barrier cannot become native AD CS or source-acquisition qualification", () => {
  const make = () => ({ scope: helper.scope, nativeAdcsQualified: false, sourceAcquisitionRaceQualified: false, cases: [0, 1, 2].map(caseProof) });
  assert.equal(helper.verifyProof(make()), true);
  for (const flag of helper.flags) for (const wrong of [false, 1, null, "true"]) { const value = make(); value.cases[0][flag] = wrong; assert.throws(() => helper.verifyProof(value)); }
  for (const mutate of [value => value.nativeAdcsQualified = true, value => value.sourceAcquisitionRaceQualified = true, value => value.cases.pop(), value => value.cases[1] = value.cases[0], value => value.cases[0].privateReceipt = "unexpected"]) { const value = make(); mutate(value); assert.throws(() => helper.verifyProof(value)); }
});
test("active, changed and undrained supporting receipts preserve the owned directory", () => {
  const root = path.join(os.tmpdir(), `certops-response-barrier-support-${crypto.randomUUID()}`), token = crypto.randomBytes(16).toString("hex"); fs.mkdirSync(root); fs.writeFileSync(path.join(root, ".owner"), token);
  const exited = spawnSync(process.execPath, ["-e", ""], { windowsHide: true }); assert.equal(exited.status, 0);
  fs.writeFileSync(path.join(root, "request.req"), "public controlled input"); const names = ["issued.cer", "chain.p7b", "submit-response.rsp"]; for (const name of names) fs.writeFileSync(path.join(root, name), "");
  const guard = { token, root, scope: "supporting-temporary-file-barriers-not-certreq", rootIdentity: helper.nativeFileIdentity(root), inputIdentity: helper.nativeFileIdentity(path.join(root, "request.req")), inputHash: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, "request.req"))).digest("hex"), driverPid: exited.pid, outputStates: names.map(name => `${helper.nativeFileIdentity(path.join(root, name))}:0:0:32`) }, guardFile = path.join(root, ".active-guard.json"), drainedFile = path.join(root, ".drained.json");
  const writeDrained = () => fs.writeFileSync(drainedFile, JSON.stringify({ token, root, guardHash: crypto.createHash("sha256").update(fs.readFileSync(guardFile)).digest("hex"), guardIdentity: helper.nativeFileIdentity(guardFile), workerPid: exited.pid, workerCreated: "2026-10-14T00:00:00.000Z", childExited: true, childPidAbsent: true, holdersReleasedAfterDrain: true }));
  try {
    assert.throws(() => helper.assertCleanupSafe(root, token)); fs.writeFileSync(guardFile, JSON.stringify(guard)); assert.throws(() => helper.assertCleanupSafe(root, token));
    writeDrained(); assert.equal(helper.assertCleanupSafe(root, token), true);
    const aliasParent = fs.mkdtempSync(path.join(os.tmpdir(), "certops-response-barrier-temp-alias-")), alias = path.join(aliasParent, "temporary");
    const temporaryEnv = Object.fromEntries(["TEMP", "TMP", "TMPDIR"].map(name => [name, process.env[name]]));
    try {
      fs.symlinkSync(fs.realpathSync.native(os.tmpdir()), alias, process.platform === "win32" ? "junction" : "dir");
      process.env.TEMP = process.env.TMP = process.env.TMPDIR = alias;
      assert.equal(helper.assertCleanupSafe(root, token), true, "Canonical owned root remains valid when TEMP is an alias");
      assert.throws(() => helper.assertCleanupSafe(path.join(alias, path.basename(root)), token), "Aliased guard paths remain forbidden");
    } finally {
      for (const [name, value] of Object.entries(temporaryEnv)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; }
      if (fs.existsSync(alias)) fs.unlinkSync(alias); fs.rmdirSync(aliasParent);
    }
    for (const field of ["childExited", "childPidAbsent", "holdersReleasedAfterDrain"]) { writeDrained(); const value = JSON.parse(fs.readFileSync(drainedFile)); value[field] = false; fs.writeFileSync(drainedFile, JSON.stringify(value)); assert.throws(() => helper.assertCleanupSafe(root, token)); }
    writeDrained(); { const value = JSON.parse(fs.readFileSync(drainedFile)); value.workerPid = process.pid; fs.writeFileSync(drainedFile, JSON.stringify(value)); assert.throws(() => helper.assertCleanupSafe(root, token)); }
    writeDrained(); fs.writeFileSync(path.join(root, "issued.cer"), "unwanted output"); assert.throws(() => helper.assertCleanupSafe(root, token)); fs.truncateSync(path.join(root, "issued.cer"), 0);
    fs.writeFileSync(path.join(root, "request.req"), "changed public input"); assert.throws(() => helper.assertCleanupSafe(root, token)); fs.writeFileSync(path.join(root, "request.req"), "public controlled input");
    fs.writeFileSync(guardFile, JSON.stringify({ ...guard, rootIdentity: "00000000:0000000000000000" })); writeDrained(); assert.throws(() => helper.assertCleanupSafe(root, token)); fs.writeFileSync(guardFile, JSON.stringify(guard));
    writeDrained(); const saved = path.join(root, ".saved-guard.json"), bytes = fs.readFileSync(guardFile); assert.equal(path.dirname(saved), root);
    fs.renameSync(guardFile, saved);
    try { fs.writeFileSync(guardFile, bytes); assert.throws(() => helper.assertCleanupSafe(root, token), "A byte-identical replacement receipt has a different file identity"); }
    finally { fs.rmSync(guardFile); fs.renameSync(saved, guardFile); }
    writeDrained(); fs.appendFileSync(guardFile, " "); assert.throws(() => helper.assertCleanupSafe(root, token)); assert.equal(fs.existsSync(root), true);
    fs.writeFileSync(path.join(root, ".owner"), "foreign"); assert.throws(() => helper.assertCleanupSafe(root, token));
  } finally { assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir())); for (const name of [".owner", ".active-guard.json", ".drained.json", "request.req", ...names]) fs.rmSync(path.join(root, name), { force: true }); fs.rmdirSync(root); }
});

test("both actual receipt publishers hide incomplete bytes until atomic publication", { timeout: 30000 }, async () => {
  // Extract only the real Receipt function: this runs benign IO, no native
  // holder, process custody, certificate operation or qualification scenario.
  for (const source of ["certops-response-barrier-driver.ps1", "certops-response-barrier-worker.ps1"]) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-receipt-publication-"));
    const wrapper = path.join(root, "publisher.ps1"), marker = path.join(root, "writer-open"), release = path.join(root, "release"), receipt = path.join(root, ".worker-ready.json");
    fs.writeFileSync(wrapper, `param([string]$Source,[string]$Output)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Receipt source parse failed'}
$function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Receipt'},$false)
if(-not $function){throw 'Receipt function missing'}
$rootPath=[IO.Path]::GetFullPath($Output)
. ([scriptblock]::Create($function.Extent.Text))
$breakpoint=Set-PSBreakpoint -Variable stream -Mode Write -Action {
  [IO.File]::WriteAllText((Join-Path $rootPath 'writer-open'),'public-ready')
  $until=[DateTime]::UtcNow.AddSeconds(8)
  while(-not(Test-Path -LiteralPath (Join-Path $rootPath 'release'))){if([DateTime]::UtcNow -ge $until){throw 'Controlled publication release missing'};Start-Sleep -Milliseconds 10}
}
try{Receipt '.worker-ready.json' @{publicSentinel='complete-receipt'}}finally{Remove-PSBreakpoint $breakpoint}
`);
    const child = spawn(process.platform === "win32" ? "powershell.exe" : "pwsh", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", wrapper, "-Source", path.join(__dirname, source), "-Output", root], { windowsHide: true, timeout: 12000, stdio: ["ignore", "pipe", "pipe"] });
    let output = ""; for (const stream of [child.stdout, child.stderr]) stream.on("data", bytes => { output = (output + bytes.toString()).slice(-4096); });
    const closed = new Promise(resolve => { child.once("error", error => resolve({ error })); child.once("close", code => resolve({ code })); });
    try {
      const until = Date.now() + 10000;
      while (!fs.existsSync(marker) && child.exitCode === null && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 10));
      assert.equal(fs.existsSync(marker), true, `${source}: controlled publisher did not pause`);
      const premature = fs.existsSync(receipt);
      fs.writeFileSync(release, "public-release");
      const result = await closed; assert.equal(result.error, undefined); assert.equal(result.code, 0, output);
      assert.equal(premature, false, `${source}: empty receipt became visible before write completion`);
      assert.deepEqual(JSON.parse(fs.readFileSync(receipt, "utf8")), { publicSentinel: "complete-receipt" });
      assert.equal(fs.existsSync(receipt + ".tmp"), false);
    } finally {
      if (!fs.existsSync(release)) fs.writeFileSync(release, "public-release");
      await closed;
      assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
      for (const name of fs.readdirSync(root)) { const file = path.join(root, name); assert.equal(fs.lstatSync(file).isFile(), true); fs.unlinkSync(file); }
      fs.rmdirSync(root);
    }
  }
});
