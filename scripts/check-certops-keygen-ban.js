#!/usr/bin/env node

// CertOps zero-custody CI guard.
//
// The control plane must never generate, derive, or import private key
// material for CERTIFICATES: agents generate keys locally and only public
// artifacts cross the wire. This check fails when key-generation or
// key-import crypto APIs appear in control-plane CertOps code
// (apps/api/services/certops, apps/api/routes certops files, and the
// certops worker loops).
//
// One deliberate exception exists (ADR-0003): the control-plane-owned
// Ed25519 JOB-SIGNING keypair in jobSigning.js. That key signs job
// envelopes; it is not certificate key material and does not violate the
// zero-custody invariant. The allowlist below is intentionally exact
// (file + API) so any new keygen call site must be reviewed here.

const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..");

const SCAN_TARGETS = [
  "apps/api/services/certops",
  "apps/api/routes",
  "apps/api/middleware",
  "apps/worker/src",
];

// Only certops-related files are in scope for routes/middleware/worker;
// the services/certops directory is scanned entirely.
function isInScope(rel) {
  if (rel.startsWith("apps/api/services/certops/")) return true;
  return /certops/i.test(path.basename(rel));
}

const FORBIDDEN_APIS = [
  { id: "generateKeyPair", re: /\bgenerateKeyPair(?:Sync)?\s*\(/ },
  { id: "createPrivateKey", re: /\bcreatePrivateKey\s*\(/ },
  { id: "generateKey", re: /\bcrypto\.generateKey(?:Sync)?\s*\(/ },
  { id: "createECDH", re: /\bcreateECDH\s*\(/ },
  { id: "diffieHellman", re: /\bcreateDiffieHellman(?:Group)?\s*\(/ },
  { id: "subtle.generateKey", re: /\bsubtle\.generateKey\s*\(/ },
  { id: "openssl-genkey", re: /\bopenssl\b[^\n]*\b(genrsa|genpkey|ecparam|req\s[^\n]*-newkey)\b/i },
  { id: "node-forge-keygen", re: /\bpki\.rsa\.generateKeyPair\s*\(/ },
];

// file (repo-relative, forward slashes) -> Set of allowed API ids
const ALLOWLIST = new Map([
  [
    "apps/api/services/certops/jobSigning.js",
    {
      allowed: new Set(["generateKeyPair", "createPrivateKey"]),
      reason:
        "ADR-0003 control-plane-owned Ed25519 JOB-SIGNING key (not certificate key material)",
    },
  ],
]);

function stripComments(source) {
  let out = source.replace(/\/\*[\s\S]*?\*\//g, "");
  out = out.replace(/(^|[^:\\])\/\/.*$/gm, "$1");
  return out;
}

function walkJsFiles(rootDir, relBase) {
  const results = [];
  if (!fs.existsSync(rootDir)) return results;
  for (const entry of fs.readdirSync(rootDir, { withFileTypes: true })) {
    if (
      entry.name === "node_modules" ||
      entry.name === "tests" ||
      entry.name === "dist"
    ) {
      continue;
    }
    const abs = path.join(rootDir, entry.name);
    const rel = path.posix.join(relBase.replace(/\\/g, "/"), entry.name);
    if (entry.isDirectory()) {
      results.push(...walkJsFiles(abs, rel));
    } else if (entry.name.endsWith(".js") && !entry.name.endsWith(".test.js")) {
      results.push({ abs, rel });
    }
  }
  return results;
}

function fail(message) {
  console.error(`check-certops-keygen-ban: ${message}`);
  process.exit(1);
}

const violations = [];
let filesScanned = 0;

for (const target of SCAN_TARGETS) {
  const rootDir = path.join(repoRoot, target);
  for (const file of walkJsFiles(rootDir, target)) {
    if (!isInScope(file.rel)) continue;
    filesScanned += 1;
    const source = stripComments(fs.readFileSync(file.abs, "utf8"));
    const lines = source.split("\n");
    for (const rule of FORBIDDEN_APIS) {
      if (!rule.re.test(source)) continue;
      const allowEntry = ALLOWLIST.get(file.rel);
      if (allowEntry && allowEntry.allowed.has(rule.id)) continue;
      const lineIndex = lines.findIndex((line) => rule.re.test(line));
      violations.push({
        file: file.rel,
        line: lineIndex >= 0 ? lineIndex + 1 : 0,
        api: rule.id,
      });
    }
  }
}

// The allowlisted file must still exist if listed, so stale entries are
// removed rather than silently allowing a future file with the same name.
for (const [rel, entry] of ALLOWLIST) {
  if (!fs.existsSync(path.join(repoRoot, rel))) {
    fail(
      `allowlist entry for ${rel} (${entry.reason}) points to a missing file; remove the stale entry`,
    );
  }
}

if (violations.length > 0) {
  const detail = violations
    .map((v) => `  ${v.file}:${v.line} uses forbidden key API [${v.api}]`)
    .join("\n");
  fail(
    `control-plane CertOps code must not generate or import private keys (zero-custody invariant):\n${detail}\n` +
      "If this is genuinely non-certificate key material sanctioned by an ADR, add an exact allowlist entry in scripts/check-certops-keygen-ban.js.",
  );
}

console.log(
  `check-certops-keygen-ban: ok (files scanned: ${filesScanned}, allowlist entries: ${ALLOWLIST.size})`,
);
