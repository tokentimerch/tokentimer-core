"use strict";

/**
 * Test suite for the protocol reference clients.
 *
 * Covers:
 *   1. Syntax-check guards: `bash -n` for tokentimer-protocol.sh, and the
 *      PowerShell parser ([Parser]::ParseFile, zero errors) for
 *      tokentimer-protocol.ps1.
 *   2. Deterministic-fixture comparison for each protocol step's
 *      "all"/individual dry-run body, reusing the canonical-JSON
 *      normalization convention from packages/contracts/certops/
 *      canonical-json.cjs (via the agent's own signing module) -- but for
 *      diffing NORMALIZED output, not for producing signed bytes. Live
 *      run-to-run fields (registrationId, generated ids, sentAt) are
 *      stripped before comparison, per the issue's explicit correction
 *      that byte-identical --json output across runs is not viable.
 *   3. The Ed25519 verify path (via the fixtures' valid/tampered/wrong-key
 *      job payloads) for both scripts.
 *   4. A tarball-content test (real `npm pack`, not just --dry-run, so the
 *      private-key scan below has real bytes to scan) confirming the
 *      reference/ scripts and README ship, while fixtures/ and the
 *      dev-only generator/tests do not.
 *   5. A private-key-scan check reusing pack-release.js's
 *      assertNoPrivateKeyMaterial against that same real tarball.
 *
 * Requires `bash`, `pwsh` or `powershell`, `openssl` 3.x, and `node` >=22 on
 * PATH; CI runs on ubuntu-latest, which ships all four. Steps that need an
 * unavailable interpreter are skipped (not failed) with t.skip(), so this
 * suite degrades gracefully on a bare-bones dev box while still failing
 * loudly on CI if any invariant actually breaks.
 */

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const referenceRoot = __dirname;
const shScript = path.join(referenceRoot, "tokentimer-protocol.sh");
const ps1Script = path.join(referenceRoot, "tokentimer-protocol.ps1");
const fixturesDir = path.join(referenceRoot, "fixtures");

function findPowerShell() {
  for (const candidate of ["pwsh", "powershell"]) {
    const probe = spawnSync(candidate, ["-NoProfile", "-Command", "$PSVersionTable.PSVersion.Major"], {
      encoding: "utf8",
    });
    if (probe.status === 0 && Number(probe.stdout.trim()) >= 7) return candidate;
  }
  return null;
}

function haveBash() {
  const probe = spawnSync("bash", ["--version"], { encoding: "utf8" });
  return probe.status === 0;
}

function haveOpenSsl3() {
  const probe = spawnSync("openssl", ["version"], { encoding: "utf8" });
  if (probe.status !== 0) return false;
  return /^OpenSSL (\d+)\./.test(probe.stdout) && Number(probe.stdout.match(/^OpenSSL (\d+)\./)[1]) >= 3;
}

const powerShellExe = findPowerShell();
const bashAvailable = haveBash();
const opensslAvailable = haveOpenSsl3();

// bash on this platform may be Git-for-Windows bash (MSYS) OR the WSL
// bash.exe shim in System32 (both are common on a Windows dev box, and
// which one a bare "bash" on PATH resolves to varies by machine). Neither
// reliably accepts a raw "C:\..." path as an argv entry: MSYS bash's
// backslash-as-escape-character eats the separators, and WSL bash expects
// its own "/mnt/c/..." mount path, not a Windows path at all. Converting
// to the WSL mount convention here is a no-op on a real POSIX host (no
// drive-letter prefix to match), so this is safe for CI (ubuntu-latest,
// real bash) too.
function toBashPath(windowsOrPosixPath) {
  const driveMatch = /^([A-Za-z]):[\\/]/.exec(windowsOrPosixPath);
  const slashified = windowsOrPosixPath.split(path.sep).join("/");
  if (!driveMatch) return slashified;
  return `/mnt/${driveMatch[1].toLowerCase()}/${slashified.slice(driveMatch[0].length)}`;
}

/**
 * Strips run-to-run-nondeterministic fields (generated ids, timestamps)
 * from a dry-run request envelope before comparing to a recorded fixture.
 * Mirrors the issue's explicit "not byte-identical" test strategy.
 */
function normalizeDryRunEnvelope(parsed) {
  const body = { ...parsed.body };
  if (typeof body.agentId === "string") body.agentId = "<normalized-agent-id>";
  if (typeof body.sentAt === "string") body.sentAt = "<normalized-timestamp>";
  if (body.body && typeof body.body === "object") {
    const inner = { ...body.body };
    if (typeof inner.registrationId === "string") inner.registrationId = "<normalized-registration-id>";
    if (typeof inner.jobId === "string" && inner.jobId.startsWith("ref-job-")) inner.jobId = "<normalized-job-id>";
    if (typeof inner.attemptId === "string" && inner.attemptId.startsWith("ref-attempt-")) inner.attemptId = "<normalized-attempt-id>";
    body.body = inner;
  }
  return { ...parsed, url: parsed.url.replace(/^https?:\/\/[^/]+/, "<normalized-origin>"), body };
}

function runSh(args) {
  // Also normalize any absolute Windows-style paths passed as flag values
  // (--job-file, --pubkey-file, ...), not just the script path itself.
  const normalizedArgs = args.map((arg) => (arg.includes("\\") ? toBashPath(arg) : arg));
  const result = spawnSync("bash", [toBashPath(shScript), ...normalizedArgs], { encoding: "utf8" });
  return result;
}

function runPs1(args) {
  const result = spawnSync(powerShellExe, ["-NoProfile", "-File", ps1Script, ...args], {
    encoding: "utf8",
  });
  return result;
}

describe("reference-client syntax guards", () => {
  it("tokentimer-protocol.sh passes `bash -n`", (t) => {
    if (!bashAvailable) return t.skip("bash not found on PATH");
    const result = spawnSync("bash", ["-n", toBashPath(shScript)], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
  });

  it("tokentimer-protocol.ps1 parses with zero errors ([Parser]::ParseFile)", (t) => {
    if (!powerShellExe) return t.skip("neither pwsh nor powershell found on PATH");
    const checkScript = [
      "$parseErrors = $null",
      "$tokens = $null",
      `[System.Management.Automation.Language.Parser]::ParseFile('${ps1Script.replace(/'/g, "''")}', [ref]$tokens, [ref]$parseErrors) | Out-Null`,
      "if ($parseErrors.Count -gt 0) { $parseErrors | ForEach-Object { Write-Output $_.ToString() }; exit 1 } else { exit 0 }",
    ].join("; ");
    const result = spawnSync(powerShellExe, ["-NoProfile", "-Command", checkScript], {
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stdout || result.stderr);
  });
});

describe("reference-client Ed25519 verify", () => {
  const signingKeyId = fs
    .readFileSync(path.join(fixturesDir, "signing-key-id.txt"), "utf8")
    .trim();
  const pubKeyFile = path.join(fixturesDir, "signing-public-key.pem");

  const scenarios = [
    { fixture: "job-signed-valid.json", allowed: true, rejectionReason: null },
    { fixture: "job-signed-tampered.json", allowed: false, rejectionReason: "job_integrity_failed" },
    { fixture: "job-signed-wrong-key.json", allowed: false, rejectionReason: "job_integrity_failed" },
  ];

  for (const scenario of scenarios) {
    it(`bash verify: ${scenario.fixture} -> allowed=${scenario.allowed}`, (t) => {
      if (!bashAvailable || !opensslAvailable) return t.skip("bash + OpenSSL 3.x required");
      const result = runSh([
        "--mode", "agent", "--step", "verify",
        "--job-file", path.join(fixturesDir, scenario.fixture),
        "--pubkey-file", pubKeyFile,
        "--signing-key-id", signingKeyId,
        "--json",
      ]);
      assert.equal(result.status, scenario.allowed ? 0 : 1, result.stderr);
      const parsed = JSON.parse(result.stdout.trim());
      assert.equal(parsed.allowed, scenario.allowed);
      if (scenario.rejectionReason) assert.equal(parsed.rejectionReason, scenario.rejectionReason);
    });

    it(`PowerShell verify: ${scenario.fixture} -> allowed=${scenario.allowed}`, (t) => {
      if (!powerShellExe) return t.skip("neither pwsh nor powershell found on PATH");
      const result = runPs1([
        "-Mode", "agent", "-Step", "verify",
        "-JobFile", path.join(fixturesDir, scenario.fixture),
        "-PubKeyFile", pubKeyFile,
        "-SigningKeyId", signingKeyId,
        "-Json",
      ]);
      assert.equal(result.status, scenario.allowed ? 0 : 1, result.stderr);
      const parsed = JSON.parse(result.stdout.trim());
      assert.equal(parsed.allowed, scenario.allowed);
      if (scenario.rejectionReason) assert.equal(parsed.rejectionReason, scenario.rejectionReason);
    });
  }

  it("bash and PowerShell verify agree on every fixture (cross-implementation parity)", (t) => {
    if (!bashAvailable || !opensslAvailable || !powerShellExe) {
      return t.skip("bash + OpenSSL 3.x + a PowerShell runtime are all required");
    }
    for (const scenario of scenarios) {
      const shResult = runSh([
        "--mode", "agent", "--step", "verify",
        "--job-file", path.join(fixturesDir, scenario.fixture),
        "--pubkey-file", pubKeyFile, "--signing-key-id", signingKeyId, "--json",
      ]);
      const psResult = runPs1([
        "-Mode", "agent", "-Step", "verify",
        "-JobFile", path.join(fixturesDir, scenario.fixture),
        "-PubKeyFile", pubKeyFile, "-SigningKeyId", signingKeyId, "-Json",
      ]);
      assert.equal(
        JSON.parse(shResult.stdout.trim()).allowed,
        JSON.parse(psResult.stdout.trim()).allowed,
        `bash/PowerShell disagreed on ${scenario.fixture}`,
      );
    }
  });
});

describe("reference-client deterministic dry-run fixtures", () => {
  const dryRunFixturesDir = path.join(fixturesDir, "dry-run");

  const cases = [
    {
      name: "agent register",
      shArgs: ["--mode", "agent", "--step", "register", "--api-url", "https://example.test", "--agent-id", "fixture-agent", "--json"],
      psArgs: ["-Mode", "agent", "-Step", "register", "-ApiUrl", "https://example.test", "-AgentId", "fixture-agent", "-Json"],
      fixture: "agent-register.json",
    },
    {
      name: "agent heartbeat",
      shArgs: ["--mode", "agent", "--step", "heartbeat", "--api-url", "https://example.test", "--agent-id", "fixture-agent", "--json"],
      psArgs: ["-Mode", "agent", "-Step", "heartbeat", "-ApiUrl", "https://example.test", "-AgentId", "fixture-agent", "-Json"],
      fixture: "agent-heartbeat.json",
    },
    {
      name: "agent claim",
      shArgs: ["--mode", "agent", "--step", "claim", "--api-url", "https://example.test", "--agent-id", "fixture-agent", "--json"],
      psArgs: ["-Mode", "agent", "-Step", "claim", "-ApiUrl", "https://example.test", "-AgentId", "fixture-agent", "-Json"],
      fixture: "agent-claim.json",
    },
    {
      name: "agent result",
      shArgs: ["--mode", "agent", "--step", "result", "--api-url", "https://example.test", "--agent-id", "fixture-agent", "--job-id", "job-1", "--attempt-id", "attempt-1", "--result-status", "succeeded", "--json"],
      psArgs: ["-Mode", "agent", "-Step", "result", "-ApiUrl", "https://example.test", "-AgentId", "fixture-agent", "-JobId", "job-1", "-AttemptId", "attempt-1", "-ResultStatus", "succeeded", "-Json"],
      fixture: "agent-result.json",
    },
    {
      name: "executor register",
      shArgs: ["--mode", "executor", "--step", "register", "--api-url", "https://example.test", "--workspace-id", "00000000-0000-4000-8000-000000000000", "--json"],
      psArgs: ["-Mode", "executor", "-Step", "register", "-ApiUrl", "https://example.test", "-WorkspaceId", "00000000-0000-4000-8000-000000000000", "-Json"],
      fixture: "executor-register.json",
    },
  ];

  before(() => {
    fs.mkdirSync(dryRunFixturesDir, { recursive: true });
  });

  for (const testCase of cases) {
    it(`bash ${testCase.name}: normalized dry-run body matches recorded fixture`, (t) => {
      if (!bashAvailable) return t.skip("bash not found on PATH");
      const result = runSh(testCase.shArgs);
      assert.equal(result.status, 0, result.stderr);
      const normalized = normalizeDryRunEnvelope(JSON.parse(result.stdout.trim()));
      const fixturePath = path.join(dryRunFixturesDir, testCase.fixture);
      if (process.env.TOKENTIMER_UPDATE_REFERENCE_FIXTURES === "1") {
        fs.writeFileSync(fixturePath, `${JSON.stringify(normalized, null, 2)}\n`, "utf8");
      }
      assert.ok(
        fs.existsSync(fixturePath),
        `missing recorded fixture ${fixturePath}; regenerate with ` +
          "TOKENTIMER_UPDATE_REFERENCE_FIXTURES=1 node --test reference/reference-client.test.js " +
          "and review the diff before committing",
      );
      const recorded = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
      assert.deepEqual(normalized, recorded);
    });

    it(`PowerShell ${testCase.name}: normalized dry-run body matches the SAME recorded fixture as bash`, (t) => {
      if (!powerShellExe) return t.skip("neither pwsh nor powershell found on PATH");
      const result = runPs1(testCase.psArgs);
      assert.equal(result.status, 0, result.stderr);
      const normalized = normalizeDryRunEnvelope(JSON.parse(result.stdout.trim()));
      const fixturePath = path.join(dryRunFixturesDir, testCase.fixture);
      assert.ok(fs.existsSync(fixturePath), `expected the bash test to have recorded ${fixturePath} first`);
      const recorded = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
      // Cross-implementation parity: both scripts must agree on the exact
      // same normalized shape, not just on their own recorded fixture.
      assert.deepEqual(normalized, recorded);
    });
  }
});

describe("reference-client packaging", () => {
  let tarballPath;
  let outDir;
  let packedEntries;

  before(() => {
    outDir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-agent-reference-pack-"));
    const { main } = require("../scripts/pack-release.js");
    const result = main([`--out-dir=${outDir}`]);
    tarballPath = result.tarballPath;
    const list = spawnSync("tar", ["-tzf", tarballPath], { encoding: "utf8" });
    assert.equal(list.status, 0, list.stderr);
    packedEntries = list.stdout.split(/\r?\n/).filter(Boolean);
  });

  after(() => {
    if (outDir) fs.rmSync(outDir, { recursive: true, force: true });
  });

  it("ships the reference scripts, helper, and README", () => {
    for (const expected of [
      "reference/tokentimer-protocol.sh",
      "reference/tokentimer-protocol.ps1",
      "reference/lib/canonicalize.cjs",
      "reference/README.md",
    ]) {
      assert.ok(
        packedEntries.some((entry) => entry.endsWith(expected)),
        `expected tarball to contain ${expected}`,
      );
    }
  });

  it("excludes the dev-only fixture generator, fixtures, and reference test file", () => {
    assert.ok(!packedEntries.some((entry) => entry.includes("reference/generate-fixtures.js")));
    assert.ok(!packedEntries.some((entry) => entry.includes("reference/fixtures/")));
    assert.ok(!packedEntries.some((entry) => entry.endsWith("reference-client.test.js")));
  });

  it("contains no private-key material anywhere in the tarball (reuses pack-release.js's scan)", () => {
    const { assertNoPrivateKeyMaterial } = require("../scripts/pack-release.js");
    assert.doesNotThrow(() => assertNoPrivateKeyMaterial(tarballPath));
  });
});
