#!/usr/bin/env node
"use strict";

// Guard: closes the acceptance criterion ADR-0012 decision 8 states
// explicitly for the bash reference client (packages/agent/reference/
// tokentimer-protocol.sh): the decoded payloadB64 is decoded twice, once
// piped into `openssl pkeyutl -verify` for the Ed25519 verdict and,
// ONLY if that verdict is pass, a second time piped into `jq` to parse
// the job object. A signature-verdict failure must never reach the
// second decode: no parsing or action of any kind happens before the
// verdict from the first decode is known.
//
// This is a dynamic test, not a static one, for the same reason
// minimal-command-allowlist.cjs is dynamic: the property under test is
// about what actually executes at runtime, not what the source text
// looks like. A `jq` shim logs every invocation's stdin (truncated) to
// a witness file. Two envelopes are built from the SAME payload bytes,
// one with a valid signature and one with a tampered signature over
// the identical payload:
//
//   - the valid-signature run must exit 0 and the witness log must
//     show at least one jq invocation whose stdin contains the
//     decoded payload's jobId (proving decode #2 -> jq did run);
//   - the tampered-signature run must exit 1 (EXIT_VERIFY_FAILED) and
//     the witness log for that run must contain NO invocation whose
//     stdin contains the decoded payload's jobId anywhere (proving
//     decode #2 never reached jq once the verdict was a fail, not
//     merely that jq's output was discarded afterward).
//
// jq is legitimately invoked before a verdict exists, to parse the
// UNSIGNED outer wrapper (decision 2 step 1: the wrapper must be parsed
// first because it carries the fields verification needs). That is why
// this guard checks for the decoded PAYLOAD's own content reaching jq,
// not merely whether jq ran at all.

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const targetFile = path.join(repoRoot, "packages/agent/reference/tokentimer-protocol.sh");
const relTarget = path.relative(repoRoot, targetFile).replace(/\\/g, "/");

function shQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

// Mirrors minimal-command-allowlist.cjs's bash-runner discovery
// (native bash on PATH, falling back to `wsl bash` on a Windows dev
// machine), including its WSL path-translation probe, with one
// deliberate addition: a command-substitution self-check.
//
// Unlike that sibling guard, this one relies on `$(...)` command
// substitution inside the script text it hands to `-c` (`tmp=$(mktemp
// -d)`, `payload_b64=$(openssl base64 ...)`). On a Windows dev machine
// with WSL, `bash` on PATH commonly resolves to the System32 launcher
// shim, and confirmed empirically: invoking that shim's `-c`, or
// invoking `wsl bash -c` directly (without `-e`), both silently
// discard the *result* of any `$(...)` inside the script text -- the
// assigned variable comes back empty, no error, no nonzero exit --
// while `wsl -e bash -c` runs the byte-identical script text
// correctly. `wsl -e` runs the given executable directly without the
// extra command-line processing plain `wsl <command>` applies, which
// is exactly the processing that was eating the substitution. Because
// this failure mode is silent (not a nonzero exit, not stderr output),
// bash-on-PATH cannot be trusted at face value here the way the
// sibling guard trusts it: this probes command substitution itself
// before accepting a candidate runner, and prefers `wsl -e bash` over
// a `bash` on PATH that fails the probe.
function commandSubstitutionWorks(command, prefixArgs) {
  const probe = spawnSync(command, [...prefixArgs, "-c", "x=$(echo tokentimer-probe-ok); printf '%s' \"$x\""], {
    encoding: "utf8",
  });
  return !probe.error && probe.status === 0 && probe.stdout === "tokentimer-probe-ok";
}

function findBashRunner() {
  const direct = spawnSync("bash", ["--version"], { encoding: "utf8" });
  if (!direct.error && direct.status === 0 && commandSubstitutionWorks("bash", [])) {
    return { command: "bash", prefixArgs: [] };
  }
  if (process.platform === "win32") {
    const wsl = spawnSync("wsl", ["-e", "bash", "--version"], { encoding: "utf8" });
    if (!wsl.error && wsl.status === 0 && commandSubstitutionWorks("wsl", ["-e", "bash"])) {
      return { command: "wsl", prefixArgs: ["-e", "bash"] };
    }
  }
  // Neither candidate passed the command-substitution probe: fall
  // back to whichever one at least starts a real bash, since every
  // other guard in this family works fine without `$(...)` and a
  // false "skipped" here would be worse than a runner this one
  // specific probe distrusts more than it needs to.
  if (!direct.error && direct.status === 0) {
    return { command: "bash", prefixArgs: [] };
  }
  return null;
}

function toWslPath(winPath) {
  const m = winPath.match(/^([A-Za-z]):[\\/](.*)$/);
  if (!m) return winPath.replace(/\\/g, "/");
  const drive = m[1].toLowerCase();
  const rest = m[2].replace(/\\/g, "/");
  return `/mnt/${drive}/${rest}`;
}

function runnerNeedsPathTranslation(runner, repoRootPath) {
  const probeNative = spawnSync(runner.command, [...runner.prefixArgs, "-c", `test -d ${shQuote(repoRootPath)}`], {
    encoding: "utf8",
  });
  if (probeNative.status === 0) return false;
  const translated = toWslPath(repoRootPath);
  const probeTranslated = spawnSync(
    runner.command,
    [...runner.prefixArgs, "-c", `test -d ${shQuote(translated)}`],
    { encoding: "utf8" },
  );
  return probeTranslated.status === 0;
}

function runBash(runner, script) {
  return spawnSync(runner.command, [...runner.prefixArgs, "-c", script], {
    encoding: "utf8",
    timeout: 20000,
  });
}

// Builds, inside the bash process itself (never in Node, so the
// signing key and the two decodes stay entirely inside the same
// process family the client under test runs in), a valid Ed25519
// keypair, a payload, a valid detached signature over it, and a
// tampered signature of the same length over different bytes. `openssl
// pkeyutl -sign -rawin` needs a seekable file for its input (confirmed
// while building tokentimer-protocol.sh itself: a pipe is refused for
// oneshot Ed25519), so the payload is staged to a file for signing
// only; the client under test never sees this staging file, since it
// receives only the final base64 strings over its own stdin.
//
// The signing itself always happens in a directory bash creates for
// itself (`mktemp -d`), never in a directory Node created first: on a
// Windows host running this through `wsl bash`, a directory that Node
// creates via the Windows filesystem APIs and that WSL's /mnt/c 9p
// mount has never independently listed before is unreliable for an
// immediate write-then-read-back from the *same* bash invocation
// (confirmed empirically: `openssl ... -out payload.bin` followed a
// few lines later, in that same script, by another command opening
// that exact path intermittently gets ENOENT even though `ls` and
// `cat` on the identical path in between see the file just fine --
// apparently a 9p/DrvFS metadata-cache artifact tied to which side
// created the directory entry). Because of that, results cross back
// to Node only as text on stdout (never as a file Node then has to
// open across that boundary); Node writes the two small files the
// client under test actually needs (its pubkey, and later the
// envelope JSON) itself, since Node-writes-then-bash-reads in the
// other direction does not exhibit this problem.
const SETUP_SCRIPT = () => `
set -e
tmp=$(mktemp -d)
openssl genpkey -algorithm ed25519 -out "$tmp/key.pem" 2>/dev/null
openssl pkey -in "$tmp/key.pem" -pubout -out "$tmp/pub.pem" 2>/dev/null
printf '%s' '{"jobId":"two-decode-gate-job","nonce":"0123456789abcdef0123","action":"protocol_smoke","mode":"dry_run","workspaceId":"w1","signingKeyId":"k1"}' > "$tmp/payload.bin"
openssl pkeyutl -sign -inkey "$tmp/key.pem" -rawin -in "$tmp/payload.bin" -out "$tmp/sig.bin" 2>/dev/null
payload_b64=$(openssl base64 -A -in "$tmp/payload.bin")
sig_b64=$(openssl base64 -A -in "$tmp/sig.bin")
pub_pem=$(cat "$tmp/pub.pem")
printf 'TOKENTIMER_PAYLOAD_B64=%s\\n' "$payload_b64"
printf 'TOKENTIMER_SIG_B64=%s\\n' "$sig_b64"
printf 'TOKENTIMER_PUB_PEM_BEGIN\\n%s\\nTOKENTIMER_PUB_PEM_END\\n' "$pub_pem"
rm -rf "$tmp"
`;

function extractMarkerLine(stdout, marker) {
  const re = new RegExp(`^${marker}=(.*)$`, "m");
  const m = stdout.match(re);
  return m ? m[1] : null;
}

function extractPubPem(stdout) {
  const m = stdout.match(/TOKENTIMER_PUB_PEM_BEGIN\n([\s\S]*?)\nTOKENTIMER_PUB_PEM_END/);
  return m ? m[1] : null;
}

function buildJqShim(shimDir, realJq, realHead, realCat, witnessPath) {
  const shimPath = path.join(shimDir, "jq");
  // Logs a fixed prefix of stdin (bounded, so this shim itself never
  // becomes an unbounded buffer) before execing the real jq unchanged,
  // so the client's own behavior is not altered by the shim's presence.
  //
  // Uses absolute paths for `head`/`cat`, not bare names: this shim's
  // own PATH is deliberately restricted (mirroring the client's
  // command allowlist) to only the six shims in shimDir, and `head`/
  // `cat` are not among them, so a bare name here would silently fail
  // ("command not found"), leave the witness file empty or missing,
  // and -- because the client's own `jq -c '.' 2>/dev/null` swallows
  // whatever this shim writes to its own stderr -- surface only as a
  // confusing downstream pregate failure in the client under test, not
  // as an obvious error about this shim itself (this was chased down
  // the hard way once already; do not reintroduce it).
  const script = [
    "#!/bin/sh",
    `${shQuote(realHead)} -c 4096 <&0 > /tmp/.two-decode-gate-stdin.$$`,
    `printf '---INVOCATION---\\n' >> ${shQuote(witnessPath)}`,
    `${shQuote(realCat)} /tmp/.two-decode-gate-stdin.$$ >> ${shQuote(witnessPath)}`,
    `printf '\\n' >> ${shQuote(witnessPath)}`,
    `exec ${realJq} "$@" < /tmp/.two-decode-gate-stdin.$$`,
  ].join("\n");
  fs.writeFileSync(shimPath, script, { mode: 0o755 });
}

function buildPassthroughShim(shimDir, name, realPath) {
  fs.writeFileSync(path.join(shimDir, name), `#!/bin/sh\nexec ${realPath} "$@"\n`, { mode: 0o755 });
}

function main() {
  if (!fs.existsSync(targetFile)) {
    console.log("two-decode-gate: ok (vacuous pass - packages/agent/reference/tokentimer-protocol.sh does not exist yet)");
    return;
  }

  const runner = findBashRunner();
  if (!runner) {
    console.log(
      "two-decode-gate: skipped (no bash found on PATH and no usable `wsl bash`; this guard needs a real shell to dynamically enforce the two-decode gate and cannot do so from Node alone on this host)",
    );
    return;
  }

  const isWsl = runnerNeedsPathTranslation(runner, repoRoot);
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-two-decode-gate-"));
  const tmpForBash = isWsl ? toWslPath(tmpRoot) : tmpRoot;
  const scriptPathForBash = isWsl ? toWslPath(targetFile) : targetFile;

  try {
    const setup = runBash(runner, SETUP_SCRIPT());
    if (setup.status !== 0) {
      console.error("::error::two-decode-gate: setup failed generating the test envelope's key/payload/signature");
      console.error(setup.stderr || "");
      process.exit(1);
    }

    const payloadB64 = extractMarkerLine(setup.stdout, "TOKENTIMER_PAYLOAD_B64");
    const sigB64 = extractMarkerLine(setup.stdout, "TOKENTIMER_SIG_B64");
    const pubPem = extractPubPem(setup.stdout);
    if (!payloadB64 || !sigB64 || !pubPem) {
      console.error("::error::two-decode-gate: setup did not emit the expected payload/signature/pubkey markers");
      console.error(setup.stdout || "");
      process.exit(1);
    }
    fs.writeFileSync(path.join(tmpRoot, "pub.pem"), pubPem);
    const pubkeyForBash = `${tmpForBash}/pub.pem`;

    const goodEnvelope = JSON.stringify({
      envelopeVersion: 2,
      payloadB64,
      signatureB64: sigB64,
      signingKeyId: "k1",
    });
    // A tampered signature of the correct decoded length (64 bytes,
    // 88 base64 characters with padding) over the SAME payloadB64, so
    // the only thing that differs from the good envelope is whether
    // the signature actually verifies.
    const tamperedSigB64 = `${"A".repeat(86)}==`;
    const badEnvelope = JSON.stringify({
      envelopeVersion: 2,
      payloadB64,
      signatureB64: tamperedSigB64,
      signingKeyId: "k1",
    });

    const realJq = runBash(runner, "command -v jq").stdout.trim();
    const realBash = runBash(runner, "command -v bash").stdout.trim();
    const realCurl = runBash(runner, "command -v curl").stdout.trim();
    const realOpenssl = runBash(runner, "command -v openssl").stdout.trim();
    const realHead = runBash(runner, "command -v head").stdout.trim();
    const realCat = runBash(runner, "command -v cat").stdout.trim();
    const realMkdir = runBash(runner, "command -v mkdir").stdout.trim();
    const realRm = runBash(runner, "command -v rm").stdout.trim();
    if (!realJq || !realBash || !realCurl || !realOpenssl || !realMkdir || !realRm || !realHead || !realCat) {
      console.error("::error::two-decode-gate: could not resolve one of jq/bash/curl/openssl/mkdir/rm/head/cat to build shims");
      process.exit(1);
    }

    function runOnce(envelopeJson, label) {
      const shimDir = path.join(tmpRoot, `shim-${label}`);
      fs.mkdirSync(shimDir, { recursive: true });
      const witnessPath = path.join(tmpRoot, `witness-${label}.txt`);
      const witnessPathForBash = isWsl ? toWslPath(witnessPath) : witnessPath;
      buildJqShim(shimDir, realJq, realHead, realCat, witnessPathForBash);
      buildPassthroughShim(shimDir, "bash", realBash);
      buildPassthroughShim(shimDir, "curl", realCurl);
      buildPassthroughShim(shimDir, "openssl", realOpenssl);
      buildPassthroughShim(shimDir, "mkdir", realMkdir);
      buildPassthroughShim(shimDir, "rm", realRm);
      const shimDirForBash = isWsl ? toWslPath(shimDir) : shimDir;

      // The envelope is handed to the client over stdin, not via
      // --envelope-file: on a Windows/WSL host, a file Node just wrote
      // into a directory Node just created is not reliably visible yet
      // to a *separate* bash process trying to read it back (the same
      // DrvFS-cache asymmetry noted on SETUP_SCRIPT above), whereas
      // piping the same bytes over stdin crosses no such boundary.
      const command = `PATH=${shQuote(shimDirForBash)} ${shQuote(scriptPathForBash)} --step verify --pubkey ${shQuote(pubkeyForBash)}`;
      const result = spawnSync(runner.command, [...runner.prefixArgs, "-c", command], {
        encoding: "utf8",
        input: envelopeJson,
        timeout: 15000,
      });
      const witness = fs.existsSync(witnessPath) ? fs.readFileSync(witnessPath, "utf8") : "";
      return { exitCode: result.status, stderr: result.stderr || "", witness };
    }

    const good = runOnce(goodEnvelope, "good");
    const bad = runOnce(badEnvelope, "bad");

    const failures = [];

    // EXIT_VERIFY_FAILED=1 for a bad signature over an otherwise
    // well-formed envelope; EXIT_OK=0 for a good one.
    if (good.exitCode !== 0) {
      failures.push(`valid-signature run exited ${good.exitCode}, expected 0 (stderr: ${good.stderr.slice(0, 300)})`);
    }
    if (bad.exitCode !== 1) {
      failures.push(`tampered-signature run exited ${bad.exitCode}, expected 1 (EXIT_VERIFY_FAILED) (stderr: ${bad.stderr.slice(0, 300)})`);
    }

    if (!good.witness.includes("two-decode-gate-job")) {
      failures.push(
        "the valid-signature run's jq witness log never shows the decoded payload's jobId, so decode #2 -> jq apparently never ran even on a passing verdict; the assertion below would be vacuous",
      );
    }
    if (bad.witness.includes("two-decode-gate-job")) {
      failures.push(
        "the tampered-signature run's jq witness log contains the decoded payload's jobId: jq was invoked with the decoded payloadB64 bytes AFTER a failed signature verdict, violating ADR-0012 decision 8's two-decode gate (decode #2 must never run unless decode #1's verdict is pass)",
      );
    }

    if (failures.length > 0) {
      for (const f of failures) {
        console.error(`::error file=${relTarget}::two-decode-gate: ${f}`);
      }
      process.exit(1);
    }

    console.log("two-decode-gate: ok (valid signature reaches jq with the decoded payload; tampered signature never does)");
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

main();
