#!/usr/bin/env node
"use strict";

/*
 * Reproducible build script for the tokentimer-verify Go module.
 *
 * This is the "no make" build step referenced elsewhere in this milestone:
 * a plain Node script instead of a Makefile, invoked directly with
 * `node build.cjs` or via a pnpm script. Node is a normal dev/CI dependency
 * here; it never ships inside the compiled binary or is required by an
 * operator running the finished tokentimer-verify.exe.
 *
 * Reproducibility measures:
 *   - CGO_ENABLED=0: a pure-Go static binary, no libc/toolchain drift.
 *   - -trimpath: strips local filesystem paths from the compiled binary.
 *   - -ldflags "-s -w": strips symbol table and DWARF debug info, which
 *     otherwise embed absolute build-machine paths and timing-sensitive
 *     data that would make two honest builds diverge byte-for-byte.
 *   - GOFLAGS=-mod=mod is NOT set; this module has zero external
 *     dependencies (stdlib only), so there is no dependency resolution
 *     step whose version selection could vary between builds.
 *
 * What this script explicitly does NOT do, on purpose, and why that is
 * safe to defer:
 *   - Authenticode signing. There is no code-signing certificate available
 *     in this environment. The unsigned binary this script produces must
 *     NEVER ship inside a production bundle (ADR-0012 decision 8): only a
 *     signed artifact may reach an operator's host, verified against a
 *     pinned signer identity by tokentimer-protocol.ps1's defense-in-depth
 *     self-check and, more importantly, by the enforcing boundary outside
 *     the script (a trusted launcher or an App Control/WDAC policy).
 *   - Signer-identity validation. Once signing exists, a follow-up CI step
 *     must call Get-AuthenticodeSignature (or equivalent) against the just
 *     -built artifact and assert both "Valid" and the pinned subject +
 *     thumbprint allowlist, the same allowlist tokentimer-protocol.ps1
 *     documents in its own header.
 *   - RFC 3161 timestamping of the Authenticode signature, so verification
 *     survives the signing certificate's own expiry.
 *   - SBOM / provenance generation (for example SLSA provenance or a
 *     CycloneDX SBOM) tying the published binary hash back to this exact
 *     source tree and the exact toolchain version that built it.
 *
 * The insertion point for all four is directly after the `go build` call
 * below, before this script's final "reproducible unsigned build produced"
 * log line: a release pipeline can add a signing step there without
 * restructuring anything else, because this script already treats "the
 * binary that comes out of `go build`" as the reproducibility unit, and
 * signing is a transformation applied to that same, unchanged artifact.
 * These four items are release-blocking follow-up work, not implemented
 * by this script, and must not be treated as done because this script
 * runs cleanly.
 */

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const moduleDir = __dirname;
const distDir = path.join(moduleDir, "dist");

const TARGETS = [
  { goos: "windows", goarch: "amd64", outName: "tokentimer-verify-windows-amd64.exe" },
  { goos: "linux", goarch: "amd64", outName: "tokentimer-verify-linux-amd64" },
];

// The default (no --target) build produces the binary the local host can
// actually execute, named without a platform suffix, so
// tokentimer-protocol.ps1's default lookup path stays simple:
// dist/tokentimer-verify.exe on Windows, dist/tokentimer-verify elsewhere.
function hostTarget() {
  const goos = process.platform === "win32" ? "windows" : process.platform === "darwin" ? "darwin" : "linux";
  const goarch = process.arch === "arm64" ? "arm64" : "amd64";
  const outName = goos === "windows" ? "tokentimer-verify.exe" : "tokentimer-verify";
  return { goos, goarch, outName };
}

function build(target) {
  const outPath = path.join(distDir, target.outName);
  fs.mkdirSync(distDir, { recursive: true });

  const env = {
    ...process.env,
    CGO_ENABLED: "0",
    GOOS: target.goos,
    GOARCH: target.goarch,
    // GOFLAGS is intentionally left unset: no external modules exist to
    // pin a resolution mode for.
  };

  const args = ["build", "-trimpath", "-ldflags", "-s -w", "-o", outPath, "."];
  console.log(`tokentimer-verify build: GOOS=${target.goos} GOARCH=${target.goarch} -> ${path.relative(moduleDir, outPath)}`);
  const result = spawnSync("go", args, { cwd: moduleDir, env, stdio: "inherit" });
  if (result.error) {
    console.error(`tokentimer-verify build: failed to invoke go: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) {
    console.error(`tokentimer-verify build: go build exited with status ${result.status}`);
    process.exit(result.status || 1);
  }
  return outPath;
}

function main() {
  const wantAll = process.argv.includes("--all");
  const targets = wantAll ? TARGETS : [hostTarget()];
  const built = targets.map(build);

  console.log("");
  console.log("tokentimer-verify: reproducible unsigned build produced:");
  for (const outPath of built) {
    console.log(`  ${outPath}`);
  }
  console.log("");
  console.log(
    "This is an UNSIGNED build. Per ADR-0012 decision 8, it must never ship " +
      "inside a production bundle. Authenticode signing, signer-identity " +
      "validation, RFC 3161 timestamping, and SBOM/provenance generation are " +
      "release-blocking follow-up steps that insert directly after this " +
      "script's `go build` call; see the header comment in this file.",
  );
}

main();
