"use strict";

/**
 * Validates that every shipped agent JavaScript file:
 *   1. Parses under the current Node (node --check)
 *   2. Does not require/import paths that resolve outside packages/agent
 *   3. Does not require any bare package (node_modules) specifier at all,
 *      since the installer never runs `npm install` and only copies this
 *      package directory (see install-agent.sh); the shipped agent must
 *      have zero runtime dependencies. Devtime-only tools (ajv, eslint,
 *      etc.) must stay confined to scripts/build-*.js, which are not part
 *      of the shipped bin/src/vendor tree this check scans.
 *
 * The installer copies only this package directory, so monorepo-relative
 * imports (packages/log-scrub, apps/api, packages/contracts, ...) are
 * release blockers. Keep shared helpers under packages/agent/vendor instead.
 *
 * Also validates install-agent.ps1 (the Windows installer) the same way
 * node --check validates the shipped JavaScript: it must parse. This runs
 * only where a PowerShell interpreter is available (Windows runners, and
 * any host with PowerShell Core installed); elsewhere it is skipped with a
 * printed note rather than failing a Linux/macOS build over a Windows-only
 * tool being absent, since the dedicated Windows CI job (ci.yml) is the
 * one that actually exercises install-agent.ps1 on every PR.
 */

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const packageRoot = path.resolve(__dirname, "..");
const sourceRoots = [
  path.join(packageRoot, "bin"),
  path.join(packageRoot, "src"),
  path.join(packageRoot, "vendor"),
];

const REQUIRE_PATTERN =
  /(?:require\s*\(\s*|import\s*\(\s*|from\s+)(['"])([^'"]+)\1/g;

function collectShippedJavaScript(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) return collectShippedJavaScript(entryPath);
    if (entry.isFile() && entry.name.endsWith(".js") && !entry.name.endsWith(".test.js")) {
      return [entryPath];
    }
    if (entry.isFile() && entry.name.endsWith(".cjs")) {
      return [entryPath];
    }
    return [];
  });
}

function isBuiltin(specifier) {
  return specifier.startsWith("node:");
}

function assertImportStaysInsidePackage(filePath, specifier) {
  if (isBuiltin(specifier)) return null;
  if (!specifier.startsWith(".") && !specifier.startsWith("/")) {
    return `requires bare package "${specifier}"; the shipped agent has zero runtime dependencies (devtime-only tools like ajv must stay confined to scripts/build-*.js, which this check does not scan)`;
  }
  const resolved = path.resolve(path.dirname(filePath), specifier);
  const relative = path.relative(packageRoot, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    return `escapes package root via ${specifier} -> ${resolved}`;
  }
  return null;
}

const files = sourceRoots.flatMap(collectShippedJavaScript).sort();
const importErrors = [];

for (const file of files) {
  const result = spawnSync(process.execPath, ["--check", file], { stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status || 1);

  const source = fs.readFileSync(file, "utf8");
  REQUIRE_PATTERN.lastIndex = 0;
  let match;
  while ((match = REQUIRE_PATTERN.exec(source))) {
    const specifier = match[2];
    const problem = assertImportStaysInsidePackage(file, specifier);
    if (problem) {
      importErrors.push(`${path.relative(packageRoot, file)}: ${problem}`);
    }
  }
}

if (importErrors.length > 0) {
  process.stderr.write(
    "check-shipped-sources: shipped agent sources must be self-contained.\n" +
      "The installer only copies packages/agent; fix these monorepo-relative imports:\n" +
      importErrors.map((line) => `  - ${line}`).join("\n") +
      "\n",
  );
  process.exit(1);
}

process.stdout.write(
  `Validated ${files.length} shipped agent JavaScript files (syntax + self-contained imports).\n`,
);

/**
 * Parses install-agent.ps1 with PowerShell's own language parser (the
 * closest equivalent to `node --check` for a .ps1 file) so a syntax error
 * introduced in either installer script is caught by `build`, not
 * discovered later by an operator's `sc.exe create` failing partway
 * through. UTF-8-without-BOM is checked too: Windows tools can silently
 * emit UTF-16LE or a BOM, and either would still often "look right" in an
 * editor while breaking a strict byte-for-byte release policy.
 */
function checkInstallAgentPs1() {
  const ps1Path = path.join(packageRoot, "scripts", "install-agent.ps1");
  if (!fs.existsSync(ps1Path)) {
    process.stderr.write(
      "check-shipped-sources: scripts/install-agent.ps1 not found; the Windows installer is missing.\n",
    );
    process.exit(1);
  }

  const bytes = fs.readFileSync(ps1Path);
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    process.stderr.write(
      "check-shipped-sources: scripts/install-agent.ps1 has a UTF-8 BOM; it must be UTF-8 without BOM.\n",
    );
    process.exit(1);
  }
  let looksUtf16 = bytes.length > 32;
  for (let i = 1; looksUtf16 && i < Math.min(200, bytes.length - 1); i += 2) {
    if (bytes[i] !== 0) looksUtf16 = false;
  }
  if (looksUtf16) {
    process.stderr.write(
      "check-shipped-sources: scripts/install-agent.ps1 appears to be UTF-16LE; it must be UTF-8 without BOM.\n",
    );
    process.exit(1);
  }

  const parseScriptPath = path.join(
    require("node:os").tmpdir(),
    `tokentimer-ps1-check-${process.pid}-${Date.now()}.ps1`,
  );
  const parseScript =
    "param([Parameter(Mandatory=$true)][string]$TargetPath)\n" +
    "$parseErrors = $null\n" +
    "$null = [System.Management.Automation.Language.Parser]::ParseFile($TargetPath, [ref]$null, [ref]$parseErrors)\n" +
    "if ($parseErrors.Count -gt 0) {\n" +
    "  $parseErrors | ForEach-Object { [Console]::Error.WriteLine($_.Message) }\n" +
    "  exit 1\n" +
    "}\n" +
    "exit 0\n";
  const candidates = ["pwsh", "powershell"];
  let ran = false;
  try {
    fs.writeFileSync(parseScriptPath, parseScript, "utf8");
    for (const exe of candidates) {
      const result = spawnSync(
        exe,
        ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", parseScriptPath, ps1Path],
        { encoding: "utf8" },
      );
      if (result.error) continue;
      ran = true;
      if (result.status !== 0) {
        process.stderr.write(
          `check-shipped-sources: scripts/install-agent.ps1 failed to parse under ${exe}:\n${result.stderr || result.stdout}\n`,
        );
        process.exit(1);
      }
      process.stdout.write(`Validated scripts/install-agent.ps1 (parses under ${exe}, UTF-8 without BOM).\n`);
      break;
    }
  } finally {
    try {
      fs.unlinkSync(parseScriptPath);
    } catch (_err) {
      // Best effort cleanup.
    }
  }
  if (!ran) {
    process.stdout.write(
      "Skipped scripts/install-agent.ps1 parse check: no PowerShell interpreter (pwsh/powershell) on this host. " +
        "UTF-8-without-BOM was still verified. The dedicated Windows CI job exercises this script fully.\n",
    );
  }
}

checkInstallAgentPs1();

