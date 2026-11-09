"use strict";

// Only run on a disposable GitHub-hosted Windows runner. The caller supplies a
// local test API and a dedicated test database; no private keys enter the store.
if (process.platform !== "win32" || process.env.CERTOPS_REVOCATION_NATIVE_WINDOWS !== "1" ||
    process.env.RUNNER_ENVIRONMENT !== "github-hosted" || process.env.CI !== "true") {
  throw new Error("Native store fixture requires an explicitly enabled disposable GitHub-hosted Windows runner");
}
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { X509Certificate } = require("node:crypto");
const { Pool } = require("pg");
const { runWindowsDiscoveryScan } = require("../../src/index");
const { collectWindowsDiscoveryObservations } = require("../../src/discovery/windows");
const { createScanChecker } = require("../../src/revocation/observation");
const { loadTrustMaterial } = require("../../src/revocation/config");
const { checkObservedCertificate, resolveHelperPath } = require("../../src/revocation/helper");
const { createProtocolClient } = require("../../src/protocol");
const { listCertificateIdentities } = require("../../../../apps/api/services/certops/certificateIdentity");
const { cleanupFixture } = require("./windows-native-safety.cjs");

const storeCommand = String.raw`
$ErrorActionPreference = 'Stop'
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($env:TT_NATIVE_CERT_FILE)
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'LocalMachine')
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
try {
  $matches = @($store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })
  if ($env:TT_NATIVE_STORE_ACTION -eq 'add') {
    if ($matches.Count -ne 0) { throw 'Fixture certificate already exists' }
    $store.Add($cert)
  } elseif ($env:TT_NATIVE_STORE_ACTION -eq 'remove') {
    if ($matches.Count -ne 1 -or [Convert]::ToBase64String($matches[0].RawData) -cne [Convert]::ToBase64String($cert.RawData)) { throw 'Fixture ownership mismatch' }
    $store.Remove($matches[0])
    if (@($store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }).Count -ne 0) { throw 'Fixture certificate remains' }
  } else { throw 'Unknown action' }
} finally { $store.Close(); $cert.Dispose() }
`;

async function main() {
  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  const data = JSON.parse(raw);
  const api = new URL(process.env.TT_NATIVE_REVOCATION_API);
  assert.equal(api.protocol, "http:");
  assert.equal(api.hostname, "127.0.0.1");
  assert.equal(process.env.DB_HOST, "127.0.0.1");
  assert.match(process.env.DB_NAME, /^tt_native_revocation_[a-f0-9]{32}$/);
  const cert = new X509Certificate(data.leaf);
  const fingerprint = cert.fingerprint256.replaceAll(":", "").toLowerCase();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tt-native-revocation-"));
  const certFile = path.join(directory, "fixture.cer");
  fs.writeFileSync(certFile, cert.raw);
  const rootFile = path.join(directory, "root.pem"), intermediateFile = path.join(directory, "intermediate.pem");
  fs.writeFileSync(rootFile, data.root); fs.writeFileSync(intermediateFile, data.intermediate);
  const store = (action) => execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", storeCommand], {
    env: { ...process.env, TT_NATIVE_CERT_FILE: certFile, TT_NATIVE_STORE_ACTION: action }, windowsHide: true, stdio: "pipe",
  });
  const db = new Pool({ host: process.env.DB_HOST, port: Number(process.env.DB_PORT), user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME });
  let created = false;
  try {
    store("add");
    created = true;
    const revision = Number(data.revision);
    const client = createProtocolClient({ serverUrl: api.origin, allowInsecureLocalHttp: true,
      agentId: process.env.TT_NATIVE_REVOCATION_AGENT, protocolVersion: "1.0.0",
      getCredential: async () => process.env.TT_NATIVE_REVOCATION_CREDENTIAL,
      sequenceAllocator: { next: () => revision },
    });
    let trustStage = "not_called", helperStage = "not_called", helperDetail = "not_called", inputStage = "not_called";
    const checkRevocation = await createScanChecker({ enabled: true, allowedOrigins: [data.origin],
      trustAnchorFiles: [rootFile], intermediateFiles: [intermediateFile] }, {
      load: async (config) => {
        try { const material = await loadTrustMaterial(config); trustStage = "loaded"; return material; }
        catch (error) {
          const known = ["Windows trust stores unavailable", "Windows trust store entry invalid", "Windows trust store fingerprint mismatch", "observed revocation trust material unavailable or exceeds limits", "system trust enumeration failed"];
          trustStage = known.includes(error.message) ? error.message : "other trust error";
          throw error;
        }
      },
      check: async (options) => {
        const json = JSON.stringify({ leaf: options.certificatePem, roots: options.roots, intermediates: options.intermediates, systemRoots: options.systemRoots, systemIntermediates: options.systemIntermediates, allowedOrigins: options.allowedOrigins });
        inputStage = `roots:${options.roots.length},intermediates:${options.intermediates.length},system_roots:${options.systemRoots.length},system_intermediates:${options.systemIntermediates.length},bytes:${Buffer.byteLength(json)},helper_exists:${fs.existsSync(resolveHelperPath())},same_helper:${path.resolve(resolveHelperPath()).toLowerCase() === path.resolve(data.helperPath).toLowerCase()}`;
        const result = await checkObservedCertificate(options);
        helperStage = ["good", "revoked", "issuer_revoked", "unknown"].includes(result.verdict) ? result.verdict : "invalid";
        const known = ["verification unavailable", "invalid observed certificate", "input exceeds limits", "trust anchors unavailable", "invalid trust anchor", "invalid intermediate", "certificate chain validation failed", "multiple validated chains require disambiguation", "revocation data unavailable or unsupported", "validated chain unavailable", "chain certificate missing", "chain signature invalid"];
        helperDetail = known.includes(result.detail) ? result.detail : "other_or_none";
        return result;
      },
    });
    const result = await runWindowsDiscoveryScan({ client, observationRevision: revision,
      // Invoke the production collector, then restrict the disposable test's
      // report to its own unique certificate before it reaches the API.
      collect: async (options) => (await collectWindowsDiscoveryObservations(options)).filter((item) => item.locationKind === "windows_store" && item.fingerprintSha256 === fingerprint),
      checkRevocation,
    });
    assert.equal(result.observed, 1, "fixture must be discovered in LocalMachine/My");
    const grouped = await listCertificateIdentities({ workspaceId: process.env.TT_NATIVE_REVOCATION_WORKSPACE, client: db });
    assert.equal(grouped.items.length, 1);
    if (grouped.items[0].observedRevocation.verdict !== data.expected) {
      console.error(`Native revocation stages: trust=${trustStage}; helper=${helperStage}; detail=${helperDetail}; input=${inputStage}; stored=${grouped.items[0].observedRevocation.verdict}`);
    }
    assert.equal(grouped.items[0].observedRevocation.verdict, data.expected);
    if (data.expected === "unknown") assert.equal(grouped.items[0].observedRevocation.lastVerified.verdict, "revoked");
    process.stdout.write(JSON.stringify({ verdict: data.expected }));
  } finally {
    await cleanupFixture({ close: () => db.end(), remove: () => store("remove"), created,
      cleanupDir: () => {
        const resolved = fs.realpathSync(directory);
        assert.equal(path.dirname(resolved), fs.realpathSync(os.tmpdir()));
        assert.ok(path.basename(resolved).startsWith("tt-native-revocation-"));
        fs.rmSync(resolved, { recursive: true, force: true });
      },
    });
  }
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
