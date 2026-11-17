"use strict";
// Offline, non-executable package and report fixtures. Never real qualification.
const fs = require("node:fs"), path = require("node:path"), os = require("node:os"), crypto = require("node:crypto");
const { execFileSync } = require("node:child_process"), zlib = require("node:zlib");
const packager = require("../certops-agent-package"), packageContract = require("../certops-azure-keyvault-package.cjs");
const profiles = require("../certops-final-package-evidence.cjs");
const hash = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
function zip(entries) {
  const local = [], central = []; let offset = 0;
  for (const [name, input] of entries) {
    const data = Buffer.isBuffer(input) ? input : Buffer.from(input), file = Buffer.from(name);
    const header = Buffer.alloc(30), record = Buffer.alloc(46), crc = zlib.crc32(data);
    header.writeUInt32LE(0x04034b50); header.writeUInt16LE(20, 4); header.writeUInt32LE(crc, 14);
    header.writeUInt32LE(data.length, 18); header.writeUInt32LE(data.length, 22); header.writeUInt16LE(file.length, 26);
    record.writeUInt32LE(0x02014b50); record.writeUInt16LE(20, 4); record.writeUInt16LE(20, 6);
    record.writeUInt32LE(crc, 16); record.writeUInt32LE(data.length, 20); record.writeUInt32LE(data.length, 24);
    record.writeUInt16LE(file.length, 28); record.writeUInt32LE(offset, 42);
    local.push(header, file, data); central.push(record, file); offset += header.length + file.length + data.length;
  }
  const directory = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, directory, end]);
}
function candidate(t, sourceSha) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tt-content-fixture-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const packageRoot = path.join(root, "package");
  const write = (name, data) => { const file = path.join(packageRoot, name); fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, data); };
  write("package.json", JSON.stringify({ name: "@tokentimer/agent", version: "0.20.0" }));
  write("src/capabilities/qualified-capabilities.json", JSON.stringify({ qualified: packageContract.CAPABILITIES }, null, 2) + "\n");
  write("src/capabilities/qualified-capabilities.generated.js", require("../../packages/agent/scripts/build-qualified-capabilities").renderGeneratedModule(packageContract.CAPABILITIES));
  for (const file of ["bin/tokentimer-agent.js", "scripts/install-agent.ps1", "scripts/install-agent.sh",
    ...require("../verify-agent-native-package").EXPECTED_BINARIES.map(name => name.slice(8))]) write(file, "offline-non-executable-fixture");
  const archive = "tokentimer-agent-0.20.0.tgz", filename = path.join(root, archive);
  const tar = process.platform === "win32" ? path.join(process.env.SystemRoot, "System32/tar.exe") : "tar";
  execFileSync(tar, ["-czf", filename, "package"], { cwd: root, timeout: 10000 });
  const bytes = fs.readFileSync(filename), digest = hash(bytes);
  const receipt = { schemaVersion: 1, candidateSha: sourceSha, sourceKind: "workflow-checkout", buildMode: "azure-release-candidate",
    capabilitySource: "isolated-final-manifest", archive, packageVersion: "0.20.0", capabilities: packageContract.CAPABILITIES,
    packagerSha256: packager.digest(path.join(__dirname, "../../packages/agent/scripts/pack-release.js")),
    ...packageContract.TOOLCHAIN, runnerImage: { os: "ubuntu24", version: "offline-fixture" }, sha256: digest };
  return { digest, files: packager.inventory(packageRoot), entries: [[archive, bytes], [archive + ".sha256", `${digest}  ${archive}\n`],
    ["artifact.json", JSON.stringify(receipt)]] };
}
function report(profile, sourceSha, runId, packageArtifact, files) {
  const specification = profiles.PROFILES[profile], operator = profile.endsWith("operator-http-real-ca");
  const value = { schemaVersion: 1, profile, sourceSha, runId, packageArtifact, status: "passed", productionQualified: false,
    fullOperatorE2e: operator, counts: { passed: specification.scenarios.length, failed: 0, pending: 0, skipped: 0 },
    scenarios: specification.scenarios.map(id => ({ id, status: "passed" })),
    cleanup: { database: "completed", provider: "completed", agent: "completed", credentials: "completed", resources: "completed" },
    facts: {}, nativeService: null };
  if (operator) {
    value.facts = { http: { mutations: 3, directDatabaseInjection: false, signatureChecksBypassed: false },
      ca: { kind: "acme", fixture: false, requests: 1, leafSha256: "1".repeat(64), chainSha256: "2".repeat(64) },
      tls: { leafSha256: "1".repeat(64), chainSha256: "2".repeat(64), verifiedChain: true },
      jobs: { requestedBySha256: "1".repeat(64), approvedBySha256: "2".repeat(64), signerKeyIdSha256: "3".repeat(64),
        signed: 2, verified: 2, approved: 2, signatureFailureDenied: true, providerPutAttempts: 1,
        providerVersion: profile.startsWith("azure-") ? "1".repeat(32) : "1", exactVersionReads: 1, latestFallbacks: 0, restartRepublishAttempts: 0 },
      identities: ["issuer", "consumer"].map((role, i) => ({ role, subjectSha256: String(i).repeat(64), tokenRenewals: 1,
        crossRoleDenials: 1, crossRoleDeniedOperation: "opposite-identity-acquisition", consumerWriteStatus: i === 1 ? 403 : null })) };
    const observation = { unit: "tokentimer-agent.service", activeState: "active", subState: "running", mainPid: 123, procPid: 123,
      procStartTicks: "100", serviceUid: 1000, procUid: 1000, commandPackageEntry: "bin/tokentimer-agent.js", processEntrySha256: files["bin/tokentimer-agent.js"] };
    value.nativeService = { kind: "installed-linux-systemd", installedFileHashes: files, agentId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      enrolledAgentId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", before: observation,
      after: { ...observation, mainPid: 124, procPid: 124, procStartTicks: "101" } };
  } else if (profile === "azure-imds-managed-identity") value.facts = { authMode: profile, imdsHost: "169.254.169.254",
    metadataHeader: true, identities: ["issuer", "consumer"].map((role, i) => ({ role, hostIdSha256: String(i).repeat(64),
      identitySha256: String(i + 2).repeat(64), oppositeIdentitySha256: String(3 - i).repeat(64), imdsRequests: 2,
      ownTokenStatus: 200, oppositeIdentityTokenStatus: 400 })), azureReadStatus: 200, azureConsumerWriteStatus: 403, pinnedVersion: "1".repeat(32) };
  else {
    const start = Date.parse("2026-11-17T12:00:00Z") / 1000;
    value.facts = { issuedAt: start + 10, expiresAt: start + 3610, observedExpiredAt: start + 3610, renewedAt: start + 3611,
      renewedExpiresAt: start + 7211, forced401: false, clockOverridden: false, azureStatusBefore: 200, azureStatusExpired: 401,
      azureStatusAfter: 200, pinnedVersion: "1".repeat(32) };
  }
  return value;
}
module.exports = { zip, candidate, report, hash };
