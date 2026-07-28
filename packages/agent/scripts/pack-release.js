"use strict";

/**
 * Build a release tarball for @tokentimer/agent and write a SHA-256 checksum
 * sidecar. Distribution is tarball + install-agent.sh (package stays private;
 * see README.md). This does not sign the artifact — signing infrastructure is
 * not present in this repository yet.
 *
 *   node scripts/pack-release.js [--out-dir DIR]
 */

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const packageRoot = path.resolve(__dirname, "..");
const pkg = JSON.parse(
  fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"),
);

/** Any of these appearing anywhere in the shipped tarball is a release
 * blocker: a production artifact must never contain private-key material,
 * even test-only fixtures. Checked both by filename and by content marker
 * (in case a key is embedded in a non "*.key.pem" file). */
const FORBIDDEN_FILENAME_PATTERN = /\.key(\.pem)?$/i;
// Requires a full PEM block (BEGIN...base64/whitespace...END), not just the
// marker substring, so this module's own detection logic and legitimate
// test/redaction code that merely *mentions* the marker do not self-match.
const PRIVATE_KEY_PEM_BLOCK_PATTERN =
  /-----BEGIN (?:RSA |EC |ENCRYPTED |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |ENCRYPTED |DSA )?PRIVATE KEY-----/;

/**
 * Extracts the tarball to a temp dir and scans every entry for private-key
 * material. Throws with the offending path(s) if any are found.
 * @param {string} tarballPath
 */
function assertNoPrivateKeyMaterial(tarballPath) {
  const extractDir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-agent-pack-scan-"));
  try {
    const extract = spawnSync("tar", ["-xzf", tarballPath, "-C", extractDir], {
      encoding: "utf8",
    });
    if (extract.status !== 0) {
      throw new Error(
        `pack-release: could not inspect tarball contents for private-key material ` +
          `(tar exited ${extract.status}): ${extract.stderr || extract.stdout || ""}`,
      );
    }

    const offenders = [];
    const walk = (dir) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const entryPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(entryPath);
          continue;
        }
        if (!entry.isFile()) continue;

        const relative = path.relative(extractDir, entryPath);
        if (FORBIDDEN_FILENAME_PATTERN.test(entry.name)) {
          offenders.push(`${relative} (forbidden filename pattern)`);
          continue;
        }

        // Best-effort content scan: only meaningful for text files, but a
        // private key embedded in a binary file would fail to load anyway.
        let content;
        try {
          content = fs.readFileSync(entryPath, "utf8");
        } catch {
          continue;
        }
        if (PRIVATE_KEY_PEM_BLOCK_PATTERN.test(content)) {
          offenders.push(`${relative} (contains a private-key PEM block)`);
        }
      }
    };
    walk(extractDir);

    if (offenders.length > 0) {
      throw new Error(
        "pack-release: refusing to ship a tarball containing private-key material:\n" +
          offenders.map((line) => `  - ${line}`).join("\n"),
      );
    }
  } finally {
    fs.rmSync(extractDir, { recursive: true, force: true });
  }
}

function parseArgs(argv) {
  let outDir = path.join(packageRoot, "dist");
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--out-dir") {
      outDir = path.resolve(argv[++i] || "");
    } else if (arg.startsWith("--out-dir=")) {
      outDir = path.resolve(arg.slice("--out-dir=".length));
    } else if (arg === "-h" || arg === "--help") {
      process.stdout.write("Usage: node scripts/pack-release.js [--out-dir DIR]\n");
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return { outDir };
}

function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

function main(argv = process.argv.slice(2)) {
  if (pkg.private !== true) {
    throw new Error(
      "refusing to pack: @tokentimer/agent is expected to remain private; " +
        "distribution is via tarball + install-agent.sh (see README.md)",
    );
  }

  const { outDir } = parseArgs(argv);
  fs.mkdirSync(outDir, { recursive: true });

  const pack = spawnSync(
    "npm",
    ["pack", "--pack-destination", outDir],
    {
      cwd: packageRoot,
      encoding: "utf8",
      shell: process.platform === "win32",
    },
  );
  if (pack.status !== 0) {
    throw new Error(
      `npm pack failed:\n${pack.stdout || ""}\n${pack.stderr || ""}`,
    );
  }

  const tarballName = pack.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .pop();
  if (!tarballName || !tarballName.endsWith(".tgz")) {
    throw new Error(`npm pack did not report a tarball name: ${pack.stdout}`);
  }

  const tarballPath = path.join(outDir, tarballName);
  if (!fs.existsSync(tarballPath)) {
    throw new Error(`packed tarball missing: ${tarballPath}`);
  }

  assertNoPrivateKeyMaterial(tarballPath);

  const digest = sha256File(tarballPath);
  const checksumName = `${tarballName}.sha256`;
  const checksumPath = path.join(outDir, checksumName);
  // Coreutils `sha256sum -c` friendly format: "<hash>  <filename>"
  fs.writeFileSync(checksumPath, `${digest}  ${tarballName}\n`, "utf8");

  process.stdout.write(
    [
      `Packed ${tarballName}`,
      `Version ${pkg.version}`,
      `SHA256 ${digest}`,
      `Checksum file ${checksumName}`,
      "Signing: not available in this repository (document checksum out-of-band).",
      "",
    ].join("\n"),
  );

  return { tarballPath, checksumPath, digest, version: pkg.version };
}

module.exports = { main, sha256File, assertNoPrivateKeyMaterial };

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`pack-release: ${error.message}\n`);
    process.exitCode = 1;
  }
}
