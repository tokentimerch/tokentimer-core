"use strict";

/**
 * Test suite for the protocol reference clients.
 *
 * Covers:
 *   1. Syntax-check guards (bash -n, PowerShell Parser::ParseFile)
 *   2. Ed25519 verify scenarios (valid / tampered / wrong-key) + parity
 *   3. Deterministic dry-run body comparison (normalized)
 *   4. Packaging (npm pack content + private-key scan)
 *   5. Hardening: loopback-only plain HTTP, CaBundle reject, Node engines,
 *      no production src/signing import, schema validation of request bodies
 *   6. all-step / expired / future / verify-failure behaviors
 *
 * On CI (CI=true or GITHUB_ACTIONS=true), missing required tools fail the
 * suite rather than skipping. Locally, unavailable interpreters still skip
 * so a bare-bones dev box can run the rest.
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
const canonicalizeJs = path.join(referenceRoot, "lib", "canonicalize.cjs");
const fixturesDir = path.join(referenceRoot, "fixtures");
const dryRunFixturesDir = path.join(fixturesDir, "dry-run");

const onCI = Boolean(process.env.CI || process.env.GITHUB_ACTIONS);

function findPowerShell() {
  for (const candidate of ["pwsh", "powershell"]) {
    const probe = spawnSync(candidate, [
      "-NoProfile",
      "-Command",
      "if (($PSVersionTable.PSVersion.Major) -ge 7) { exit 0 } else { exit 1 }",
    ], { encoding: "utf8" });
    if (probe.status === 0) return candidate;
  }
  return null;
}

function findBash() {
  const probe = spawnSync("bash", ["-c", "echo ok"], { encoding: "utf8" });
  return probe.status === 0 ? "bash" : null;
}

function opensslAvailable() {
  const probe = spawnSync("openssl", ["version"], { encoding: "utf8" });
  if (probe.status !== 0) return false;
  const major = Number.parseInt(String(probe.stdout).match(/OpenSSL\s+(\d+)/)?.[1] || "0", 10);
  return major >= 3;
}

function toBashPath(windowsOrPosixPath) {
  if (process.platform !== "win32") return windowsOrPosixPath;
  const slashified = windowsOrPosixPath.split(path.sep).join("/");
  const m = slashified.match(/^([A-Za-z]):(.*)$/);
  if (!m) return slashified;
  return `/mnt/${m[1].toLowerCase()}${m[2]}`;
}

function requireOrSkip(t, available, label) {
  if (available) return true;
  if (onCI) {
    assert.fail(`${label} is required on CI but was not found`);
  }
  t.skip(`${label} not found`);
  return false;
}

const bashAvailable = Boolean(findBash());
const powerShellExe = findPowerShell();
const hasOpenSsl3 = opensslAvailable();

function runBash(args, env = {}) {
  return spawnSync("bash", [toBashPath(shScript), ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

function runPs1(args, env = {}) {
  return spawnSync(powerShellExe, [
    "-NoProfile",
    "-File",
    ps1Script,
    ...args,
  ], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

function normalizeDryRunEnvelope(envelope) {
  const clone = JSON.parse(JSON.stringify(envelope));
  if (clone.url) {
    clone.url = String(clone.url).replace(/^https?:\/\/[^/]+/i, "<normalized-origin>");
  }
  if (clone.body && typeof clone.body === "object") {
    if (typeof clone.body.agentId === "string") {
      clone.body.agentId = "<generated-agent-id>";
    }
    if (typeof clone.body.sentAt === "string") {
      clone.body.sentAt = "<timestamp>";
    }
    if (clone.body.body && typeof clone.body.body === "object") {
      if (typeof clone.body.body.registrationId === "string") {
        clone.body.body.registrationId = "<generated-registration-id>";
      }
    }
  }
  return clone;
}

describe("reference-client syntax guards", () => {
  it("tokentimer-protocol.sh passes `bash -n`", (t) => {
    if (!requireOrSkip(t, bashAvailable, "bash")) return;
    const result = spawnSync("bash", ["-n", toBashPath(shScript)], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
  });

  it("tokentimer-protocol.ps1 parses with zero errors", (t) => {
    if (!requireOrSkip(t, Boolean(powerShellExe), "PowerShell 7+")) return;
    const parseScript = `
$e = $null; $t = $null
$path = '${ps1Script.replace(/'/g, "''")}'
# Strip #requires so Windows PowerShell 5.1 Parser can still parse a PS7 script.
$raw = Get-Content -LiteralPath $path -Raw
$raw = $raw -replace '(?m)^#requires[^\\r\\n]*\\r?\\n', ''
$tmp = [System.IO.Path]::GetTempFileName() + '.ps1'
[System.IO.File]::WriteAllText($tmp, $raw, (New-Object System.Text.UTF8Encoding $false))
try {
  [void][System.Management.Automation.Language.Parser]::ParseFile($tmp, [ref]$t, [ref]$e)
  if ($e -and $e.Count -gt 0) { $e | ForEach-Object { $_.ToString() }; exit 1 }
  exit 0
} finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
`;
    const result = spawnSync(powerShellExe, ["-NoProfile", "-Command", parseScript], {
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stdout + result.stderr);
  });

  it("reference text files are UTF-8 without NUL bytes", () => {
    const files = [
      shScript,
      ps1Script,
      canonicalizeJs,
      path.join(referenceRoot, "README.md"),
      path.join(referenceRoot, "generate-fixtures.js"),
      path.join(referenceRoot, "reference-client.test.js"),
    ];
    for (const file of files) {
      const buf = fs.readFileSync(file);
      const nulls = buf.filter((b) => b === 0).length;
      assert.equal(nulls, 0, `${file} contains NUL bytes (likely UTF-16)`);
    }
  });
});

describe("reference-client Ed25519 verify", () => {
  const signingKeyId = fs
    .readFileSync(path.join(fixturesDir, "signing-key-id.txt"), "utf8")
    .trim();
  const pubKey = path.join(fixturesDir, "signing-public-key.pem");

  const scenarios = [
    { fixture: "job-signed-valid.json", allowed: true },
    { fixture: "job-signed-tampered.json", allowed: false },
    { fixture: "job-signed-wrong-key.json", allowed: false },
  ];

  for (const scenario of scenarios) {
    it(`bash verify: ${scenario.fixture} -> allowed=${scenario.allowed}`, (t) => {
      if (!requireOrSkip(t, bashAvailable && hasOpenSsl3, "bash + OpenSSL 3")) return;
      const result = runBash([
        "--mode", "agent",
        "--step", "verify",
        "--job-file", path.join(fixturesDir, scenario.fixture),
        "--pubkey-file", pubKey,
        "--signing-key-id", signingKeyId,
        "--json",
      ]);
      assert.equal(result.status === 0, scenario.allowed, result.stdout + result.stderr);
      const parsed = JSON.parse(result.stdout.trim().split(/\r?\n/).pop());
      assert.equal(parsed.allowed, scenario.allowed);
    });

    it(`PowerShell verify: ${scenario.fixture} -> allowed=${scenario.allowed}`, (t) => {
      if (!requireOrSkip(t, Boolean(powerShellExe), "PowerShell 7+")) return;
      const result = runPs1([
        "-Mode", "agent",
        "-Step", "verify",
        "-JobFile", path.join(fixturesDir, scenario.fixture),
        "-PubKeyFile", pubKey,
        "-SigningKeyId", signingKeyId,
        "-Json",
      ]);
      assert.equal(result.status === 0, scenario.allowed, result.stdout + result.stderr);
      const parsed = JSON.parse(result.stdout.trim().split(/\r?\n/).pop());
      assert.equal(parsed.allowed, scenario.allowed);
    });
  }

  it("bash and PowerShell verify agree on every fixture", (t) => {
    if (!requireOrSkip(t, bashAvailable && hasOpenSsl3 && powerShellExe, "bash+openssl+pwsh")) return;
    for (const scenario of scenarios) {
      const bash = runBash([
        "--mode", "agent", "--step", "verify", "--json",
        "--job-file", path.join(fixturesDir, scenario.fixture),
        "--pubkey-file", pubKey, "--signing-key-id", signingKeyId,
      ]);
      const ps = runPs1([
        "-Mode", "agent", "-Step", "verify", "-Json",
        "-JobFile", path.join(fixturesDir, scenario.fixture),
        "-PubKeyFile", pubKey, "-SigningKeyId", signingKeyId,
      ]);
      assert.equal(bash.status === 0, ps.status === 0, scenario.fixture);
    }
  });

  it("helper rejects an expired job via the time window", () => {
    const job = JSON.parse(
      fs.readFileSync(path.join(fixturesDir, "job-signed-valid.json"), "utf8"),
    );
    job.issuedAt = "2000-01-01T00:00:00.000Z";
    job.expiresAt = "2000-01-01T00:05:00.000Z";
    // Re-sign would be needed for signature; instead call checkJobTimeWindow directly.
    const { checkJobTimeWindow } = require("./lib/canonicalize.cjs");
    const result = checkJobTimeWindow({ job, nowMs: Date.now() });
    assert.equal(result.allowed, false);
    assert.equal(result.rejectionReason, "clock_drift_suspected");
  });

  it("helper rejects a future-dated job via the time window", () => {
    const job = JSON.parse(
      fs.readFileSync(path.join(fixturesDir, "job-signed-valid.json"), "utf8"),
    );
    job.issuedAt = "2099-01-01T00:00:00.000Z";
    job.expiresAt = "2099-01-01T00:05:00.000Z";
    const { checkJobTimeWindow } = require("./lib/canonicalize.cjs");
    const result = checkJobTimeWindow({ job, nowMs: Date.now() });
    assert.equal(result.allowed, false);
    assert.equal(result.rejectionReason, "clock_drift_suspected");
  });
});

describe("reference-client deterministic dry-run fixtures", () => {
  const cases = [
    {
      name: "agent-register",
      args: ["--mode", "agent", "--step", "register", "--api-url", "https://example.test", "--json"],
      psArgs: ["-Mode", "agent", "-Step", "register", "-ApiUrl", "https://example.test", "-Json"],
      fixture: "agent-register.json",
    },
    {
      name: "agent-heartbeat",
      args: ["--mode", "agent", "--step", "heartbeat", "--api-url", "https://example.test", "--agent-id", "agent-ref-1", "--json"],
      psArgs: ["-Mode", "agent", "-Step", "heartbeat", "-ApiUrl", "https://example.test", "-AgentId", "agent-ref-1", "-Json"],
      fixture: "agent-heartbeat.json",
    },
    {
      name: "agent-claim",
      args: ["--mode", "agent", "--step", "claim", "--api-url", "https://example.test", "--agent-id", "agent-ref-1", "--json"],
      psArgs: ["-Mode", "agent", "-Step", "claim", "-ApiUrl", "https://example.test", "-AgentId", "agent-ref-1", "-Json"],
      fixture: "agent-claim.json",
    },
    {
      name: "agent-result",
      args: [
        "--mode", "agent", "--step", "result", "--api-url", "https://example.test",
        "--agent-id", "agent-ref-1", "--job-id", "job-1", "--attempt-id", "attempt-1",
        "--result-status", "dry_run_complete", "--json",
      ],
      psArgs: [
        "-Mode", "agent", "-Step", "result", "-ApiUrl", "https://example.test",
        "-AgentId", "agent-ref-1", "-JobId", "job-1", "-AttemptId", "attempt-1",
        "-ResultStatus", "dry_run_complete", "-Json",
      ],
      fixture: "agent-result.json",
    },
  ];

  for (const testCase of cases) {
    it(`bash ${testCase.name}: normalized dry-run body matches recorded fixture`, (t) => {
      if (!requireOrSkip(t, bashAvailable, "bash")) return;
      const result = runBash(testCase.args);
      assert.equal(result.status, 0, result.stderr);
      const envelope = normalizeDryRunEnvelope(JSON.parse(result.stdout));
      const fixturePath = path.join(dryRunFixturesDir, testCase.fixture);
      if (process.env.TOKENTIMER_UPDATE_REFERENCE_FIXTURES === "1") {
        fs.mkdirSync(dryRunFixturesDir, { recursive: true });
        fs.writeFileSync(fixturePath, `${JSON.stringify(envelope, null, 2)}\n`, "utf8");
      }
      assert.ok(fs.existsSync(fixturePath), `missing fixture ${fixturePath}; regenerate with TOKENTIMER_UPDATE_REFERENCE_FIXTURES=1`);
      const expected = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
      assert.deepEqual(envelope, expected);
    });

    it(`PowerShell ${testCase.name}: matches the same recorded fixture`, (t) => {
      if (!requireOrSkip(t, Boolean(powerShellExe), "PowerShell 7+")) return;
      const result = runPs1(testCase.psArgs);
      assert.equal(result.status, 0, result.stderr + result.stdout);
      const envelope = normalizeDryRunEnvelope(JSON.parse(result.stdout));
      const expected = JSON.parse(
        fs.readFileSync(path.join(dryRunFixturesDir, testCase.fixture), "utf8"),
      );
      assert.deepEqual(envelope, expected);
    });
  }

  it("rejects executor mode", (t) => {
    if (!requireOrSkip(t, bashAvailable, "bash")) return;
    const result = runBash([
      "--mode", "executor", "--step", "register", "--api-url", "https://example.test",
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr + result.stdout, /agent/i);
  });

  it("rejects non-loopback plain HTTP", (t) => {
    if (!requireOrSkip(t, bashAvailable, "bash")) return;
    const result = runBash([
      "--mode", "agent", "--step", "register", "--api-url", "http://example.test", "--json",
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr + result.stdout, /loopback|https/i);
  });

  it("allows loopback plain HTTP for dry-run", (t) => {
    if (!requireOrSkip(t, bashAvailable, "bash")) return;
    const result = runBash([
      "--mode", "agent", "--step", "register", "--api-url", "http://127.0.0.1:8080", "--json",
    ]);
    assert.equal(result.status, 0, result.stderr);
  });

  it("PowerShell rejects -CaBundle", (t) => {
    if (!requireOrSkip(t, Boolean(powerShellExe), "PowerShell 7+")) return;
    const result = runPs1([
      "-Mode", "agent", "-Step", "register", "-ApiUrl", "https://example.test",
      "-CaBundle", "dummy.pem", "-Json",
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr + result.stdout, /CaBundle|not supported/i);
  });

  it("dry-run request bodies validate against the agent-protocol schema", (t) => {
    if (!requireOrSkip(t, bashAvailable, "bash")) return;
    const validate = require("../vendor/contracts/agent-protocol-validator.generated.js");
    for (const testCase of cases) {
      const result = runBash(testCase.args);
      assert.equal(result.status, 0, `${testCase.name}: ${result.stderr}`);
      const envelope = JSON.parse(result.stdout);
      const body = envelope.body;
      assert.ok(body && typeof body === "object", testCase.name);
      const ok = validate(body);
      assert.equal(ok, true, `${testCase.name}: ${JSON.stringify(validate.errors)}`);
    }
  });

  it("all dry-run walks register->heartbeat->claim->result without network", (t) => {
    if (!requireOrSkip(t, bashAvailable, "bash")) return;
    const result = runBash([
      "--mode", "agent", "--step", "all", "--api-url", "https://example.test",
      "--agent-id", "agent-ref-all",
      "--job-id", "job-1", "--attempt-id", "attempt-1",
      "--result-status", "dry_run_complete",
    ]);
    assert.equal(result.status, 0, result.stderr + result.stdout);
    assert.match(result.stderr + result.stdout, /register/i);
    assert.match(result.stderr + result.stdout, /heartbeat/i);
    assert.match(result.stderr + result.stdout, /claim/i);
    assert.match(result.stderr + result.stdout, /result/i);
  });

  it("all --execute without verify materials fails closed", (t) => {
    if (!requireOrSkip(t, bashAvailable, "bash")) return;
    const result = runBash([
      "--mode", "agent", "--step", "all", "--api-url", "https://example.test",
      "--execute",
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr + result.stdout, /pubkey|signing-key|verify/i);
  });
});

describe("reference-client contract independence", () => {
  it("canonicalize.cjs does not require production agent runtime modules", () => {
    const src = fs.readFileSync(canonicalizeJs, "utf8");
    assert.doesNotMatch(src, /require\([^)]*src\/signing/);
    assert.doesNotMatch(src, /require\([^)]*agent\/src/);
    assert.match(src, /canonical-json|ADR-0003|canonicalizeJobPayload/);
  });

  it("reference scripts have no production-runtime requires and no internal planning refs", () => {
    for (const file of [shScript, ps1Script, path.join(referenceRoot, "README.md")]) {
      const src = fs.readFileSync(file, "utf8");
      assert.doesNotMatch(src, /require\([^)]*src\/signing/, file);
      assert.doesNotMatch(src, /TOK-\d|linear\.app|\bM5c\b/, file);
    }
  });

  it("helper enforces Node engines range >=22 <25", () => {
    const src = fs.readFileSync(canonicalizeJs, "utf8");
    assert.match(src, />= 22/);
    assert.match(src, /< 25/);
  });
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
    assert.ok(packedEntries.some((e) => e.endsWith("reference/tokentimer-protocol.sh")));
    assert.ok(packedEntries.some((e) => e.endsWith("reference/tokentimer-protocol.ps1")));
    assert.ok(packedEntries.some((e) => e.endsWith("reference/lib/canonicalize.cjs")));
    assert.ok(packedEntries.some((e) => e.endsWith("reference/README.md")));
  });

  it("excludes fixtures, generator, and test file", () => {
    assert.ok(!packedEntries.some((e) => e.includes("reference/fixtures/")));
    assert.ok(!packedEntries.some((e) => e.endsWith("generate-fixtures.js")));
    assert.ok(!packedEntries.some((e) => e.endsWith("reference-client.test.js")));
  });

  it("contains no private-key material", () => {
    const { assertNoPrivateKeyMaterial } = require("../scripts/pack-release.js");
    assert.doesNotThrow(() => assertNoPrivateKeyMaterial(tarballPath));
  });
});