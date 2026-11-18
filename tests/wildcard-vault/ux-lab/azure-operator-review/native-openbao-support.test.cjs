"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const { retain } = require("./native-openbao-support.cjs");
const { CAPABILITIES } = require("../../../../scripts/certops-azure-keyvault-package.cjs");
const { candidate, report } = require("../../../../scripts/test-support/final-package-evidence.cjs");

test("OpenBao CA preparation resolves one Node executable when PATH contains multiple applications", t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tt-openbao-launch-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const windows = process.platform === "win32";
  const locations = ["node first", "node second"].map(name => {
    const folder = path.join(directory, name);
    fs.mkdirSync(folder);
    fs.writeFileSync(path.join(folder, windows ? "node.cmd" : "node"), windows ? "@exit /b 0\r\n" : "#!/bin/sh\nexit 0\n",
      { mode: 0o700 });
    return folder;
  });
  const env = { ...process.env };
  const pathKey = Object.keys(env).find(key => key.toUpperCase() === "PATH") || "PATH";
  env[pathKey] = [...locations, env[pathKey]].join(path.delimiter);
  const result = spawnSync("pwsh", ["-NoProfile", "-Command", [
    "$ErrorActionPreference = 'Stop'",
    "$commands = @(Get-Command node -CommandType Application)",
    "if ($commands.Count -lt 2) { throw 'Expected multiple Node applications' }",
    "$runner = [System.Management.Automation.Language.Parser]::ParseFile($env:TT_TEST_OPENBAO_RUNNER, [ref]$null, [ref]$null)",
    "$assignment = $runner.Find({ param($ast) $ast -is [System.Management.Automation.Language.AssignmentStatementAst] -and $ast.Left.VariablePath.UserPath -eq 'nodeExecutable' }, $true)",
    ". ([scriptblock]::Create($assignment.Extent.Text))",
    "if ($nodeExecutable -isnot [string] -or $nodeExecutable -cne $commands[0].Source -or $nodeExecutable -cne $env:TT_TEST_NODE_FIRST) { throw 'OpenBao requires one executable from the first PATH location' }",
  ].join("\n")], {
    env: {
      ...env,
      TT_TEST_OPENBAO_RUNNER: path.join(__dirname, "run.ps1"),
      TT_TEST_NODE_FIRST: path.join(locations[0], windows ? "node.cmd" : "node"),
    },
    encoding: "utf8", timeout: 10000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
});

function fixture(t) {
  const outputDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "tt-openbao-close-"));
  t.after(() => fs.rmSync(outputDirectory, { recursive: true, force: true }));
  const project = "tt-wildcard-ux-qual-123", sourceSha = "a".repeat(40), runId = "444";
  const candidateSha = "b".repeat(40), input = candidate(t, candidateSha);
  const identity = { candidateSha, artifactId: "789", runId: "456",
    packageSha256: input.digest, packageVersion: "0.20.0", capabilities: CAPABILITIES };
  const stage = path.join(outputDirectory, "agent-package");
  fs.mkdirSync(path.join(stage, "artifacts"), { recursive: true });
  for (const [name, bytes] of input.entries) fs.writeFileSync(path.join(stage, "artifacts", name), bytes);
  fs.writeFileSync(path.join(stage, "harness-input.json"), JSON.stringify({ packageArtifact: identity }));
  const teardownReceipt = path.join(outputDirectory, "teardown.json");
  fs.writeFileSync(teardownReceipt, JSON.stringify({ project }));
  const observation = path.join(outputDirectory, "native-openbao-observation.json");
  const native = report("openbao-operator-http-real-ca", sourceSha, runId, identity, input.files).nativeService;
  fs.writeFileSync(observation, JSON.stringify({ sourceSha, runId, packageArtifact: identity, nativeService: native,
    nativeOpenBaoFacts: { installed: { leafSha256: "c".repeat(64), chainSha256: "d".repeat(64) },
      provider: { exactRead200: 1, renew200: 1 } } }));
  return { parameters: { outputDirectory, teardownReceipt, project, sourceSha, runId }, observation,
    output: path.join(outputDirectory, "native-openbao-support.json"),
    closed: { project, candidateSha, producerRunId: identity.runId, archiveSha256: identity.packageSha256,
      ownedContainersAbsent: true, ownedVolumesAbsent: true, ownedNetworksAbsent: true } };
}
test("retains only supporting observations after native and project cleanup", async t => {
  const { parameters, output, closed } = fixture(t);
  const result = await retain(parameters, async () => { assert.equal(fs.existsSync(output), false); return closed; });
  assert.equal(result.status, "passed-supporting-only");
  assert.equal(result.fullOperatorE2e, false);
  assert.deepEqual(JSON.parse(fs.readFileSync(output, "utf8")), result);
});
test("withholds evidence for residual networks, stale run or interrupted observations", async t => {
  const { parameters, output, observation, closed } = fixture(t);
  await assert.rejects(retain(parameters, async () => ({ ...closed, ownedNetworksAbsent: false })));
  await assert.rejects(retain({ ...parameters, runId: "999" }, async () => closed));
  fs.unlinkSync(observation);
  assert.equal(await retain(parameters, async () => closed), null);
  assert.equal(fs.existsSync(output), false);
});
