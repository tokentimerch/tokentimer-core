"use strict";

/**
 * Real-host ACME pipeline through createAcmeIssuer (#324) + CNG key path (#326).
 *
 * Requires on the host (set up by adcs-poc stage 34):
 *   - Pebble + pebble-challtestsrv on 127.0.0.1
 *   - Git Bash + acme.sh with dns_certops in LE home dnsapi/
 *   - TOKENTIMER_AGENT_CONFIG_DIR pointing at a config with pebble-challtestsrv
 *   - Pebble Root/Intermediate trusted in LocalMachine for certreq -accept
 *   - An IIS site ready for SNI bind
 *
 * Usage:
 *   node windows-acme-issuer-pipeline-verify.js <agentSrcDir> <workDir> <cn> <port> <siteName>
 */

const fs = require("node:fs");
const path = require("node:path");
const tls = require("node:tls");
const crypto = require("node:crypto");

const agentSrc = path.resolve(process.argv[2] || "");
const workDir = path.resolve(process.argv[3] || "");
const cn = process.argv[4] || "acme-issuer.tokentimer-verify.local";
const port = Number(process.argv[5] || 11443);
const siteName = process.argv[6] || "Default Web Site";

if (!agentSrc || !workDir) {
  console.error("usage: windows-acme-issuer-pipeline-verify.js <agentSrcDir> <workDir> <cn> <port> <site>");
  process.exit(2);
}

const { generateCsrViaCng, acceptCertificateViaCng, recordIssuedContainer } = require(
  path.join(agentSrc, "windows-cert-store"),
);
const { createAcmeIssuer } = require(path.join(agentSrc, "issuers"));
const { deployIisBinding } = require(path.join(agentSrc, "windows-iis"));

const bash = process.env.TT_VERIFY_BASH || "C:\\Program Files\\Git\\bin\\bash.exe";
const acmeSh =
  process.env.TT_VERIFY_ACMESH ||
  "C:\\ProgramData\\TokenTimerAgent\\tools\\acme.sh\\acme.sh";
const caEndpoint = process.env.TT_VERIFY_CA_ENDPOINT || "https://127.0.0.1:14000/dir";
const stateDir = process.env.TOKENTIMER_AGENT_CONFIG_DIR || "C:\\ProgramData\\TokenTimerAgent\\state";
const store = "My";

let passed = 0;
let failed = 0;
function check(name, ok, detail) {
  if (ok) {
    passed += 1;
    console.log(`PASS: ${name}${detail ? ` (${detail})` : ""}`);
  } else {
    failed += 1;
    console.log(`FAIL: ${name}${detail ? ` (${detail})` : ""}`);
  }
}

function writePem(filePath, pem) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, pem, { mode: 0o600 });
}

function thumbprintFromPem(pem) {
  const b64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----[\s\S]*/, "")
    .replace(/\s+/g, "");
  return crypto.createHash("sha1").update(Buffer.from(b64, "base64")).digest("hex").toUpperCase();
}

function tlsVerify(host, listenPort, expectedThumbprint) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: "127.0.0.1",
        port: listenPort,
        servername: host,
        rejectUnauthorized: false,
      },
      () => {
        const cert = socket.getPeerCertificate();
        const fp = (cert.fingerprint || "").replace(/:/g, "").toUpperCase();
        socket.end();
        resolve({ ok: fp === expectedThumbprint, fingerprint: fp });
      },
    );
    socket.on("error", (err) => resolve({ ok: false, error: err.message }));
    socket.setTimeout(10000, () => {
      socket.destroy();
      resolve({ ok: false, error: "tls timeout" });
    });
  });
}

async function runCycle(label) {
  const jobId = `acme-issuer-${label}-${crypto.randomBytes(4).toString("hex")}`;
  const certificateId = `cert-${label}-${crypto.randomBytes(4).toString("hex")}`;
  const scratchDir = path.join(workDir, jobId);
  const cngWorkDir = path.join(stateDir, "windows-cert-store");
  fs.mkdirSync(scratchDir, { recursive: true });
  console.log(`---- cycle ${label} jobId=${jobId} ----`);

  const csr = await generateCsrViaCng({
    commonName: cn,
    altNames: [cn],
    jobId: certificateId,
    algorithm: "rsa-2048",
    workDir: cngWorkDir,
  });
  check(`${label}: CNG CSR`, csr.ok === true, csr.ok ? csr.containerName : csr.stderrExcerpt);
  if (!csr.ok) return null;

  try {
    recordIssuedContainer({
      stateDir,
      containerName: csr.containerName,
      jobId,
      certificateId,
    });
  } catch (err) {
    console.log(`OBSERVE: recordIssuedContainer: ${err.message}`);
  }

  const logs = [];
  const issuer = createAcmeIssuer({
    acmeKind: "acme.sh",
    argv: [bash, acmeSh],
    caEndpoint,
    stateDir,
    scratchDir,
    jobId,
    checkCaEndpoint: (endpoint) =>
      endpoint === caEndpoint
        ? { allowed: true }
        : { allowed: false, rejectionReason: "ca_endpoint_not_allowlisted", detail: endpoint },
    info: (m) => {
      logs.push(m);
      console.log(`  | ${m}`);
    },
  });
  check(`${label}: issuer kind`, issuer.kind === "acme" && issuer.step === "acme");

  const issuance = await issuer.submit({ csrPem: csr.csrPem, domains: [cn] });
  check(
    `${label}: ACME issued via createAcmeIssuer`,
    issuance.outcome === "issued",
    issuance.outcome === "issued" ? "validation.passed" : issuance.detail,
  );
  if (issuance.outcome !== "issued") {
    console.log(`  | evidence: ${JSON.stringify(issuance.evidence || []).slice(0, 400)}`);
    return null;
  }
  const hasPassed = (issuance.evidence || []).some(
    (e) => e.eventType === "validation.passed" && (e.metadata || []).some((m) => m.name === "step" && m.value === "acme"),
  );
  check(`${label}: evidence step=acme`, hasPassed);

  const pemPath = path.join(scratchDir, "issued.fullchain.pem");
  writePem(pemPath, issuance.certificatePem);
  const leafThumb = thumbprintFromPem(issuance.certificatePem);

  const accept = await acceptCertificateViaCng({
    certificatePem: issuance.certificatePem,
    workDir: cngWorkDir,
    store,
  });
  check(`${label}: CNG accept`, accept.ok === true, accept.ok ? accept.thumbprint : accept.stderrExcerpt);
  if (!accept.ok) return null;

  const deploy = await deployIisBinding({
    binding: { address: "*", port, sniHost: cn, store, site: siteName },
    certificatePem: issuance.certificatePem,
  });
  check(
    `${label}: IIS deploy`,
    deploy.ok === true,
    deploy.ok === true ? `thumb=${accept.thumbprint}` : `${deploy.code || ""} ${deploy.detail || ""}`.trim(),
  );

  const tlsResult = await tlsVerify(cn, port, (accept.thumbprint || leafThumb).toUpperCase());
  check(
    `${label}: TLS handshake`,
    tlsResult.ok === true,
    tlsResult.ok ? tlsResult.fingerprint : tlsResult.error || tlsResult.fingerprint,
  );

  return { thumbprint: accept.thumbprint, containerName: csr.containerName, jobId };
}

(async () => {
  console.log(`agentSrc: ${agentSrc}`);
  console.log(`workDir: ${workDir}`);
  console.log(`cn=${cn} port=${port} site=${siteName}`);
  console.log(`caEndpoint=${caEndpoint}`);
  console.log(`stateDir=${stateDir}`);
  console.log(`bash=${bash}`);
  console.log(`acmeSh=${acmeSh}`);

  const first = await runCycle("issue");
  const second = await runCycle("renew");
  check("renew replaced prior cycle", Boolean(first && second && first.thumbprint !== second.thumbprint),
    first && second ? `${first.thumbprint} -> ${second.thumbprint}` : "missing cycle");

  console.log(`summary: ${passed}/${passed + failed} checks passed`);
  process.exit(failed === 0 ? 0 : 1);
})().catch((err) => {
  console.error(`UNCAUGHT ERROR: ${err && err.stack ? err.stack : err}`);
  process.exit(1);
});
