"use strict";

// Optional local end-to-end probe used by check_network_test.go. The generated
// certificates are public test data; private keys never leave that test.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { X509Certificate } = require("node:crypto");
const { runDiscoveryScan, runWindowsDiscoveryScan } = require("../../src/index");
const { checkObservedCertificate } = require("../../src/revocation/helper");
const { createProtocolClient } = require("../../src/protocol");

async function main() {
  let input = "";
  for await (const part of process.stdin) input += part;
  const data = JSON.parse(input);
  const cert = new X509Certificate(data.leaf);
  const fingerprintSha256 = cert.fingerprint256.replaceAll(":", "").toLowerCase();
  const checkRevocation = (item) => checkObservedCertificate({ ...item, helperPath: data.helperPath,
    roots: [data.root], intermediates: [data.intermediate], allowedOrigins: [data.origin] });
  const items = [];
  const client = createProtocolClient({ serverUrl: "http://127.0.0.1", allowInsecureLocalHttp: true,
    agentId: "probe-agent", protocolVersion: "1.0.0", getCredential: async () => "probe-credential",
    fetchImpl: async (_url, request) => {
      items.push(...JSON.parse(request.body).body.evidenceItems);
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tt-observed-probe-"));
  try {
    fs.writeFileSync(path.join(directory, "leaf.crt"), data.leaf);
    await runDiscoveryScan({ directories: [directory], client, checkRevocation });
    await runWindowsDiscoveryScan({ client, checkRevocation, collect: () => [{
      locationKind: "windows_store", locationSlot: "LocalMachine/My/test", fingerprintSha256,
      certificatePem: data.leaf, subject: cert.subject, issuer: cert.issuer,
      thumbprint: cert.fingerprint.replaceAll(":", ""), storeLocation: "LocalMachine", storeName: "My",
    }] });
    if (items.length !== 2) throw new Error(`expected two agent observations, got ${items.length}`);
    for (const item of items) {
      const metadata = Object.fromEntries(item.metadata.map(({ name, value }) => [name, value]));
      if (metadata.observedRevocationVerdict !== data.expected) throw new Error(`agent returned ${metadata.observedRevocationVerdict}; expected ${data.expected}`);
      if (data.expected === "issuer_revoked" && metadata.observedRevokedIssuerFingerprintSha256 !== new X509Certificate(data.intermediate).fingerprint256.replaceAll(":", "").toLowerCase()) throw new Error("agent returned the wrong revoked issuer fingerprint");
      if (/BEGIN CERTIFICATE|PRIVATE KEY/.test(JSON.stringify(item))) throw new Error("certificate material escaped agent");
    }
    process.stdout.write(JSON.stringify(items));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
