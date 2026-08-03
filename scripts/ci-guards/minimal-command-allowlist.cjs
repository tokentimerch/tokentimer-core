#!/usr/bin/env node
"use strict";

// Guard: closes the "asserted by test, not by review" gap ADR-0012
// decision 8 calls for directly ("this is asserted by the sibling
// command-allowlist test, not just by review"). The bash reference
// client (packages/agent/reference/tokentimer-protocol.sh) declares
// exactly four external dependencies: bash, curl, jq, openssl. Anything
// else it reaches for silently -- stat, mktemp, sed, base64, coreutils
// helpers -- would be an undeclared fifth dependency that quietly works
// on this developer's machine and quietly breaks on a minimal container
// image, which is exactly the failure mode decision 8 names for
// `base64 -d` losing NUL bytes on some platforms.
//
// A real shell parser is out of scope; regex-based command-position
// extraction over bash source produces too many false positives from
// jq filter strings, case patterns, and JSON literals embedded in the
// script to be trustworthy (this was tried and discarded -- see git
// history). Instead this is a dynamic test: it runs the script itself
// with PATH restricted to a directory containing only shims for the
// four declared commands (each shim execs the real binary, so behavior
// is unchanged) plus nothing else, across every --step this client
// supports. If the script ever tries to exec a fifth command, bash
// reports "command not found" (exit 127) and this guard fails with the
// exact command name and the step that triggered it.
//
// This only proves the *dynamic* code paths hit by the invocations
// below are clean, not literally every branch (a bug behind an
// unreached branch would not be caught). That is the same caveat any
// runtime test carries and is preferable to a static heuristic that
// cannot tell a jq filter string from a command.

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const targetFile = path.join(repoRoot, "packages/agent/reference/tokentimer-protocol.sh");
const relTarget = path.relative(repoRoot, targetFile).replace(/\\/g, "/");

const ALLOWED_EXTERNAL_COMMANDS = ["bash", "curl", "jq", "openssl"];

function shQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function findBashRunner() {
  // Prefer a real `bash` on PATH (the normal case on Linux CI runners
  // and on macOS/WSL shells). Fall back to `wsl bash` on Windows dev
  // machines that have WSL but no native bash on PATH.
  //
  // On Windows, a `bash` on PATH is not proof of a native bash: WSL
  // installs a `bash.exe` shim under System32 that forwards straight
  // into the default WSL distro, so "bash resolves and runs" and "bash
  // understands Windows-style paths" are two different questions. The
  // path-translation probe below answers the second question directly
  // by testing a known-good directory (the repo root) both ways,
  // rather than trusting how the runner happened to be located.
  const direct = spawnSync("bash", ["--version"], { encoding: "utf8" });
  if (!direct.error && direct.status === 0) {
    return { command: "bash", prefixArgs: [] };
  }
  if (process.platform === "win32") {
    const wsl = spawnSync("wsl", ["bash", "--version"], { encoding: "utf8" });
    if (!wsl.error && wsl.status === 0) {
      return { command: "wsl", prefixArgs: ["bash"] };
    }
  }
  return null;
}

function runnerNeedsPathTranslation(runner) {
  const probeNative = spawnSync(runner.command, [...runner.prefixArgs, "-c", `test -d ${shQuote(repoRoot)}`], {
    encoding: "utf8",
  });
  if (probeNative.status === 0) return false;
  const translated = toWslPath(repoRoot);
  const probeTranslated = spawnSync(
    runner.command,
    [...runner.prefixArgs, "-c", `test -d ${shQuote(translated)}`],
    { encoding: "utf8" },
  );
  return probeTranslated.status === 0;
}

function findRealBinary(runner, name) {
  const result = spawnSync(runner.command, [...runner.prefixArgs, "-c", `command -v ${name}`], {
    encoding: "utf8",
  });
  if (result.status !== 0) return null;
  return result.stdout.trim();
}

function toWslPath(winPath) {
  // `wsl bash` needs a WSL-visible path for anything passed as a
  // filesystem argument (PATH entries, the script path itself). WSL
  // exposes the Windows filesystem under /mnt/<drive letter>/...
  const m = winPath.match(/^([A-Za-z]):[\\/](.*)$/);
  if (!m) return winPath.replace(/\\/g, "/");
  const drive = m[1].toLowerCase();
  const rest = m[2].replace(/\\/g, "/");
  return `/mnt/${drive}/${rest}`;
}

function buildShimDir(runner, tmpRoot) {
  const shimDir = path.join(tmpRoot, "shim-bin");
  fs.mkdirSync(shimDir, { recursive: true });
  for (const name of ALLOWED_EXTERNAL_COMMANDS) {
    const realPath = findRealBinary(runner, name);
    if (!realPath) {
      throw new Error(`could not resolve a real "${name}" binary via the bash runner to build its shim`);
    }
    const shimPath = path.join(shimDir, name);
    fs.writeFileSync(shimPath, `#!/bin/sh\nexec "${realPath}" "$@"\n`, { mode: 0o755 });
  }
  return shimDir;
}

function runStep(runner, shimDirForBash, scriptPathForBash, args, opts) {
  opts = opts || {};
  const quotedArgs = args.map(shQuote).join(" ");
  const command = `PATH=${shQuote(shimDirForBash)} ${shQuote(scriptPathForBash)} ${quotedArgs}`;
  const result = spawnSync(runner.command, [...runner.prefixArgs, "-c", command], {
    encoding: "utf8",
    input: opts.stdin,
    timeout: 15000,
  });
  return result;
}

function classifyFailure(result) {
  const combined = `${result.stdout || ""}\n${result.stderr || ""}`;
  const m = combined.match(/([A-Za-z0-9_.\/-]+):\s*command not found/);
  if (m) return m[1];
  if (result.status === 127) return "(unknown - exit 127 but no matching message)";
  return null;
}

// Sentinel self-test: proves the PATH-restriction + classifyFailure
// mechanism actually detects an undeclared command, using a throwaway
// synthetic script (not the real client) so the assertion does not
// depend on tokentimer-protocol.sh happening to still contain a
// violation. Without this, a bug that made classifyFailure silently
// swallow every failure (e.g. a typo'd regex) would show up as this
// guard always passing, no matter what the real script did.
function selfTestDetectsUndeclaredCommand(runner, shimDirForBash, tmpRoot, isWsl) {
  const sentinelHostPath = path.join(tmpRoot, "sentinel-undeclared-command.sh");
  fs.writeFileSync(
    sentinelHostPath,
    "#!/usr/bin/env bash\nstat /etc/hostname\n",
    { mode: 0o755 },
  );
  const sentinelPathForBash = isWsl ? toWslPath(sentinelHostPath) : sentinelHostPath;
  const result = runStep(runner, shimDirForBash, sentinelPathForBash, []);
  const badCommand = classifyFailure(result);
  if (badCommand !== "stat") {
    throw new Error(
      `sentinel self-test expected the undeclared "stat" command to be caught (exit 127, "stat: command not found") ` +
        `but got exit=${result.status} badCommand=${JSON.stringify(badCommand)} stderr=${JSON.stringify((result.stderr || "").slice(0, 300))}; ` +
        "the PATH-restriction/classifyFailure mechanism itself may be broken, so a pass against the real script cannot be trusted",
    );
  }
}

function main() {
  if (!fs.existsSync(targetFile)) {
    console.log(
      "minimal-command-allowlist: ok (vacuous pass - packages/agent/reference/tokentimer-protocol.sh does not exist yet)",
    );
    return;
  }

  const runner = findBashRunner();
  if (!runner) {
    console.log(
      "minimal-command-allowlist: skipped (no bash found on PATH and no usable `wsl bash`; this guard needs a real shell to dynamically enforce the command allowlist and cannot do so from Node alone on this host)",
    );
    return;
  }

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-allowlist-"));
  let shimDirHost;
  try {
    shimDirHost = buildShimDir(runner, tmpRoot);
  } catch (err) {
    console.error(`::error::minimal-command-allowlist: setup failed: ${err.message}`);
    process.exit(1);
  }

  const isWsl = runnerNeedsPathTranslation(runner);
  const shimDirForBash = isWsl ? toWslPath(shimDirHost) : shimDirHost;
  const scriptPathForBash = isWsl ? toWslPath(targetFile) : targetFile;

  try {
    selfTestDetectsUndeclaredCommand(runner, shimDirForBash, tmpRoot, isWsl);
  } catch (err) {
    console.error(`::error::minimal-command-allowlist: ${err.message}`);
    fs.rmSync(tmpRoot, { recursive: true, force: true });
    process.exit(1);
  }

  // A minimal Ed25519 test envelope, generated fresh each run so the
  // guard has no committed key material. This only needs to exercise
  // the --step verify code path (canonical-base64 check, the staging
  // file for openssl pkeyutl -verify, and jq parsing); the exact
  // verify verdict does not matter, only which external commands get
  // exec'd while producing it.
  const keygenArgWslPath = isWsl ? toWslPath(tmpRoot) : tmpRoot;
  const keygen = spawnSync(
    runner.command,
    [
      ...runner.prefixArgs,
      "-c",
      `openssl genpkey -algorithm ed25519 -out ${shQuote(keygenArgWslPath + "/key.pem")} && openssl pkey -in ${shQuote(keygenArgWslPath + "/key.pem")} -pubout -out ${shQuote(keygenArgWslPath + "/pub.pem")}`,
    ],
    { encoding: "utf8" },
  );
  if (keygen.status !== 0) {
    console.error("::error::minimal-command-allowlist: setup failed generating a test Ed25519 key with openssl");
    console.error(keygen.stderr || "");
    process.exit(1);
  }
  const tmpForBash = isWsl ? toWslPath(tmpRoot) : tmpRoot;
  const pubkeyForBash = `${tmpForBash}/pub.pem`;

  fs.writeFileSync(path.join(tmpRoot, "bootstrap-token.txt"), "test-bootstrap-token");
  fs.writeFileSync(path.join(tmpRoot, "credential.txt"), "test-credential");
  const bootstrapTokenForBash = `${tmpForBash}/bootstrap-token.txt`;
  const credentialForBash = `${tmpForBash}/credential.txt`;
  // Port 1 is a well-known privileged port with nothing listening in any
  // CI or dev environment; curl fails fast with connection-refused,
  // which is exactly what this guard wants -- it only needs the
  // credential-loading code to run before the network call fails, not
  // for the network call itself to succeed.
  const unreachableUrl = "http://127.0.0.1:1";

  const invocations = [
    { name: "--help", args: ["--help"] },
    { name: "--step verify (no envelope, usage error path)", args: ["--step", "verify", "--pubkey", pubkeyForBash], stdin: "" },
    { name: "--step verify (malformed JSON envelope)", args: ["--step", "verify", "--pubkey", pubkeyForBash], stdin: "not json" },
    {
      name: "--step verify (well-formed but unsigned-garbage envelope)",
      args: ["--step", "verify", "--pubkey", pubkeyForBash],
      stdin: JSON.stringify({ envelopeVersion: 2, payloadB64: "e30=", signatureB64: "A".repeat(86) + "==", signingKeyId: "k1" }),
    },
    { name: "--step claim (usage error, missing --live)", args: ["--step", "claim"] },
    { name: "unknown step (usage error)", args: ["--step", "bogus"] },
    {
      name: "--step register --live (exercises bootstrap-token-file loading, incl. check_secret_file_mode)",
      args: ["--step", "register", "--live", "--server-url", unreachableUrl, "--bootstrap-token-file", bootstrapTokenForBash],
    },
    {
      name: "--step heartbeat --live (exercises credential-file loading, incl. check_secret_file_mode)",
      args: ["--step", "heartbeat", "--live", "--server-url", unreachableUrl, "--agent-id", "agent-guard-test", "--credential-file", credentialForBash],
    },
    {
      name: "--step claim --live (exercises credential-file loading on the claim path)",
      args: ["--step", "claim", "--live", "--server-url", unreachableUrl, "--agent-id", "agent-guard-test", "--pubkey", pubkeyForBash, "--credential-file", credentialForBash],
    },
    {
      name: "--step result --live (exercises credential-file loading on the result path)",
      args: ["--step", "result", "--live", "--server-url", unreachableUrl, "--agent-id", "agent-guard-test", "--credential-file", credentialForBash],
    },
  ];

  const failures = [];
  for (const inv of invocations) {
    const result = runStep(runner, shimDirForBash, scriptPathForBash, inv.args, { stdin: inv.stdin });
    const badCommand = classifyFailure(result);
    if (badCommand) {
      failures.push({ invocation: inv.name, badCommand, stderr: (result.stderr || "").slice(0, 500) });
    }
  }

  fs.rmSync(tmpRoot, { recursive: true, force: true });

  if (failures.length > 0) {
    for (const f of failures) {
      console.error(
        `::error file=${relTarget}::minimal-command-allowlist: during "${f.invocation}", the script tried to exec an undeclared command: ${f.badCommand}`,
      );
    }
    console.error(`minimal-command-allowlist: ${failures.length} invocation(s) reached an undeclared command`);
    process.exit(1);
  }

  console.log(`minimal-command-allowlist: ok (${invocations.length} invocation(s) checked with PATH restricted to bash/curl/jq/openssl)`);
}

main();
