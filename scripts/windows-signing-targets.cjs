"use strict";

// Explicit first-party signing targets for an isolated Windows build stage.
// The Node runtime is third-party material and must retain its upstream signature.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const OWNED = Object.freeze([
  "scripts/install-agent.ps1",
  "src/acme/windows-command.ps1",
  "src/windows-material/connector.ps1",
  ...["amd64", "arm64"].flatMap(arch => [
    `bin/tokentimer-adcs-chain-${arch}.exe`,
    `bin/tokentimer-adcs-cmc-${arch}.exe`,
    `bin/tokentimer-agent-host-${arch}.exe`,
  ]),
]);

// Unknown native modules and installer formats must never slip past the
// explicitly selected signing targets. JavaScript remains a required payload.
const UNSUPPORTED_NATIVE = /\.(dll|com|sys|scr|ocx|cpl|drv|efi|msi|msp|msix|msixbundle|appx|appxbundle|node|pif|xll|ax|acm|tsp|ime)$/i;

function isPortableExecutable(file, size) {
  if (size < 64) return false;
  const fd = fs.openSync(file, "r");
  try {
    const header = Buffer.alloc(64);
    if (fs.readSync(fd, header, 0, header.length, 0) !== header.length || header.toString("ascii", 0, 2) !== "MZ") return false;
    const offset = header.readUInt32LE(0x3c);
    if (offset < 64 || offset > size - 4) return false;
    const signature = Buffer.alloc(4);
    return fs.readSync(fd, signature, 0, 4, offset) === 4 && signature.equals(Buffer.from([0x50, 0x45, 0, 0]));
  } finally { fs.closeSync(fd); }
}

function collect(root, architecture) {
  if (!path.isAbsolute(root) || !["amd64", "arm64"].includes(architecture)) throw new Error("Invalid stage identity");
  const rootStat = fs.lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new Error("Invalid package root");
  const found = new Set();
  const expected = new Set([...OWNED, `runtime/${architecture}/node.exe`].map(v => v.toLowerCase()));
  function walk(dir, relative) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const rel = relative ? `${relative}/${entry.name}` : entry.name;
      if (/[\r\n\\]/.test(rel)) throw new Error("Unsafe stage path");
      const current = path.join(dir, entry.name);
      const info = fs.lstatSync(current);
      if (info.isSymbolicLink()) throw new Error("Linked stage entry");
      if (info.isDirectory()) { walk(current, rel); continue; }
      if (!info.isFile() || info.nlink !== 1) throw new Error("Nonregular stage entry");
      if (/\.(cmd|bat|vbs|vbe|wsf|hta)$/i.test(rel)) throw new Error("Unsupported Windows executable script");
      if (UNSUPPORTED_NATIVE.test(rel) || (!expected.has(rel.toLowerCase()) && isPortableExecutable(current, info.size))) {
        throw new Error("Unsupported Windows native executable");
      }
      if (/\.(exe|ps1|psm1|psd1)$/i.test(rel)) {
        if (found.has(rel.toLowerCase())) throw new Error("Duplicate Windows path");
        found.add(rel.toLowerCase());
      }
    }
  }
  walk(root, "");
  if (found.size !== expected.size || [...found].some(name => !expected.has(name))) throw new Error("Unexpected or missing executable signing target");
  return OWNED.map(name => path.join(root, ...name.split("/")));
}

if (require.main === module) {
  try {
    const root = process.env.TT_SIGNING_PACKAGE_ROOT;
    const architecture = process.env.TT_SIGNING_ARCHITECTURE;
    const output = process.env.GITHUB_OUTPUT;
    if (!root || /[\r\n,]/.test(root) || !output) throw new Error("Signing stage unavailable");
    const eku = process.env.TT_SIGNING_PROFILE_EKU || "";
    if (!/^1\.3\.6\.1\.4\.1\.311\.97\.(?:[0-9]+\.){2,}[0-9]+$/.test(eku) || /^1\.3\.6\.1\.4\.1\.311\.97\.1\.(?:0|3\.1|4\.1)(?:\.|$)/.test(eku) || !/^[a-f0-9]{64}$/.test(process.env.TT_SIGNING_ISSUER_SHA256 || "")) throw new Error("Independent Public Trust profile and issuer pins are required");
    const files = collect(path.resolve(root), architecture);
    const runtime = path.join(root, "runtime", architecture, "node.exe");
    const nodeHash = crypto.createHash("sha256").update(fs.readFileSync(runtime)).digest("hex");
    if (!/^[a-f0-9]{64}$/.test(process.env.TT_SIGNING_NODE_EXPECTED || "") || nodeHash !== process.env.TT_SIGNING_NODE_EXPECTED) throw new Error("Third-party runtime does not match the independent pin");
    fs.appendFileSync(output, `files<<TT_SIGNING_FILES\n${files.join("\n")}\nTT_SIGNING_FILES\nnode_sha256=${nodeHash}\n`);
  } catch (err) {
    process.stderr.write(`Windows signing target selection failed: ${err.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { collect, OWNED };
