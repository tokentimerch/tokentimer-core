/*
 * Qualification notes: acme-csr-key-binding
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Return a genuinely CA-issued predecessor leaf for a different freshly generated CNG CSR. Require
 * ACME_CERTIFICATE_KEY_MISMATCH before acceptance/IIS mutation and deletion of only the new unaccepted
 * key; preserve predecessor association/export policy, trusted TLS, profile, protected credential and
 * exact restored configuration/service. Public CSR copies stay in the owned temporary fixture. Real
 * OpenSSL RSA/EC portable checks establish SPKI rejection only, not native CNG/SCM/IIS qualification.
 * The windows-acme-wrong-spki-before-accept case is required in every normal Server/key-profile cell.
 */
"use strict";
/** Signed installed Windows renewal with an owned command-output fault. A genuine
 * existing CA leaf is returned for the new native CSR; independent store/key,
 * HTTP.sys and authenticated TLS oracles must remain unchanged after rejection. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  tls = require("node:tls");
async function runWrongLeaf({
  publicSession,
  pool,
  workspaceId,
  certificateId,
  configDir,
  workDir,
  repoRoot,
  domain,
  port,
  roots,
  thumbprint,
  powershell,
  run,
  waitUntil,
  ownedJobs,
}) {
  assert.equal(process.platform, "win32");
  const configPath = path.join(configDir, "config.json"),
    original = fs.readFileSync(configPath),
    credential = fs.readFileSync(path.join(configDir, "credential"));
  const directory = fs.mkdtempSync(path.join(workDir, "wrong-leaf-"));
  const leafPath = path.join(directory, "genuine-public-leaf.pem"),
    receiptPath = path.join(directory, "public-receipt.json"),
    recipePath = path.join(directory, "recipe.json");
  const metadata = () =>
    powershell(
      `$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}';$r=$null;try{$r=if($c.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1'){[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)}else{[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c)};@{thumb=$c.Thumbprint;key=$r.Key.KeyName;unique=$r.Key.UniqueName;policy=[int]$r.Key.ExportPolicy;der=[Convert]::ToBase64String($c.RawData)}|ConvertTo-Json -Compress}finally{if($r){$r.Dispose()};$c.Dispose()}`,
    );
  const binding = () =>
    run("netsh.exe", [
      "http",
      "show",
      "sslcert",
      `hostnameport=${domain}:${port}`,
    ]);
  const peer = () =>
    new Promise((resolve, reject) => {
      const socket = tls.connect(
        {
          host: "127.0.0.1",
          port,
          servername: domain,
          ca: roots.map((root) => root.pem),
          rejectUnauthorized: true,
        },
        () => {
          try {
            assert.equal(socket.authorized, true);
            resolve(socket.getPeerCertificate().fingerprint.replace(/:/g, ""));
          } catch (error) {
            reject(error);
          } finally {
            socket.destroy();
          }
        },
      );
      socket.once("error", reject);
      socket.setTimeout(10000, () =>
        socket.destroy(new Error("Wrong-leaf trusted TLS oracle timeout")),
      );
    });
  const profile = async () =>
    (
      await pool.query(
        "SELECT mc.profile_id,cp.public_metadata FROM managed_certificates mc LEFT JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2",
        [workspaceId, certificateId],
      )
    ).rows[0];
  const before = metadata(),
    priorBinding = binding(),
    beforeProfile = await profile();
  assert.ok(beforeProfile?.public_metadata?.renewalProfile);
  const certificate = new crypto.X509Certificate(
    Buffer.from(JSON.parse(before).der, "base64"),
  );
  fs.writeFileSync(leafPath, certificate.toString(), { flag: "wx" });
  fs.writeFileSync(
    recipePath,
    JSON.stringify({ workDir, leafPath, receiptPath, certificateId }),
    { flag: "wx", mode: 0o600 },
  );
  let primary, proof;
  try {
    const config = JSON.parse(original);
    config.policy.allowedCommands["qualification-acmesh"] = {
      argv: [
        process.execPath,
        path.join(__dirname, "certops-windows-wrong-leaf-child.js"),
        recipePath,
      ],
    };
    fs.writeFileSync(configPath, JSON.stringify(config));
    require(
      path.join(repoRoot, "packages/agent/src/platform"),
    ).applyRestrictivePermissions(configPath, { kind: "file" });
    powershell("Restart-Service TokenTimerAgent -Force");
    await waitUntil(
      () => powershell("(Get-Service TokenTimerAgent).Status") === "Running",
    );
    const response = await publicSession.request(
      `/api/v1/workspaces/${workspaceId}/certops/jobs`,
      "POST",
      {
        operation: "renew",
        subjectType: "managed_certificate",
        subjectId: certificateId,
        idempotencyKey: crypto.randomUUID(),
      },
    );
    assert.equal(response.status, 201);
    const jobId = response.body.job.id;
    ownedJobs.push(jobId);
    const terminal = await waitUntil(async () => {
      const row = (
        await pool.query(
          "SELECT status,error_message FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
          [workspaceId, jobId],
        )
      ).rows[0];
      return ["failed", "succeeded", "rejected", "cancelled"].includes(
        row?.status,
      )
        ? row
        : null;
    });
    assert.equal(terminal.status, "failed");
    assert.match(terminal.error_message, /ACME_CERTIFICATE_KEY_MISMATCH/);
    const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    assert.equal(
      require(
        path.join(repoRoot, "packages/agent/src/issuers/csr-certificate-key"),
      ).certificateMatchesCsr(receipt.csrPem, certificate.toString()),
      false,
    );
    assert.equal(
      receipt.returnedLeafSha256,
      crypto
        .createHash("sha256")
        .update(fs.readFileSync(leafPath))
        .digest("hex"),
    );
    assert.ok(receipt.containers.length >= 1);
    // The predecessor has the same certificate-ID prefix; protect it explicitly.
    const protectedName = JSON.parse(before).key;
    const rejected = receipt.containers.filter(
      (name) => name !== protectedName,
    );
    assert.equal(rejected.length, 1);
    assert.equal(
      powershell(
        `[Security.Cryptography.CngKey]::Exists('${rejected[0]}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`,
      ),
      "False",
    );
    assert.equal(metadata(), before);
    assert.equal(binding(), priorBinding);
    assert.equal(await peer(), thumbprint);
    assert.deepEqual(await profile(), beforeProfile);
    assert.deepEqual(
      fs.readFileSync(path.join(configDir, "credential")),
      credential,
    );
    proof = {
      actualSignedRenewalFailed: true,
      actualCsrDiffersFromReturnedLeaf: true,
      genuineCaIssuedLeafReused: true,
      rejectedUnacceptedKeyRemoved: true,
      predecessorCustodyUnchanged: true,
      bindingAndTrustedTlsUnchanged: true,
      storedProfileUnchanged: true,
    };
  } catch (error) {
    primary = error;
  } finally {
    try {
      fs.writeFileSync(configPath, original);
      require(
        path.join(repoRoot, "packages/agent/src/platform"),
      ).applyRestrictivePermissions(configPath, { kind: "file" });
      powershell("Restart-Service TokenTimerAgent -Force");
      await waitUntil(
        () => powershell("(Get-Service TokenTimerAgent).Status") === "Running",
      );
      assert.deepEqual(fs.readFileSync(configPath), original);
    } catch (error) {
      primary = primary
        ? new AggregateError(
            [primary, error],
            "Wrong-leaf fault and owned configuration restoration failed",
          )
        : error;
    }
  }
  if (primary) throw primary;
  return { ...proof, configurationRestored: true };
}
const requiredScenarios = ["windows-acme-wrong-spki-before-accept"];
const requiredSources = [
  "tests/e2e/helpers/certops-windows-wrong-leaf.js",
  "tests/e2e/helpers/certops-windows-wrong-leaf-child.js",
  "packages/agent/src/issuers/csr-certificate-key.js",
  "packages/agent/src/issuers/der-extensions.js",
  "packages/agent/src/index.js",
];
function verifyProof(proof) {
  for (const field of [
    "actualSignedRenewalFailed",
    "actualCsrDiffersFromReturnedLeaf",
    "genuineCaIssuedLeafReused",
    "rejectedUnacceptedKeyRemoved",
    "predecessorCustodyUnchanged",
    "bindingAndTrustedTlsUnchanged",
    "storedProfileUnchanged",
    "configurationRestored",
  ])
    assert.equal(proof[field], true, field);
  return true;
}
async function qualifyWrongLeaf(context) {
  const {
    createHostGate,
  } = require("../../../packages/agent/scripts/host-gate");
  const keyProfile = process.env.CERTOPS_WINDOWS_KEY_PROFILE;
  assert.ok(
    ["rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384"].includes(
      keyProfile,
    ),
  );
  const hash = (file) => ({
    file,
    sha256: crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.join(context.repoRoot, file)))
      .digest("hex"),
  });
  const gate = createHostGate({
    suite: "windows-acme-wrong-spki",
    strict: true,
    evidenceLevel: "e2e",
    reportPath: `qualification-results/windows-wrong-spki-${keyProfile}.json`,
    fixtureSource: hash(requiredSources[0]),
    requiredCapabilities: ["windows", "system", "api", "installedAgent"],
    probeCapabilities: () => ({
      windows: { available: process.platform === "win32" },
      system: {
        available:
          context.powershell(
            "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
          ) === "S-1-5-18",
      },
      api: { available: true },
      installedAgent: {
        available:
          context.powershell("(Get-Service TokenTimerAgent).Status") ===
          "Running",
      },
    }),
  });
  gate.report.fixtureSources = requiredSources.map(hash);
  gate.report.qualificationEnvironment.keyProfile = keyProfile;
  await gate.preflight();
  gate.report.qualificationEnvironment.identity = "LocalSystem";
  try {
    await gate.scenario(requiredScenarios[0], async () => {
      gate.report.nativeWrongSpki = await runWrongLeaf(context);
      verifyProof(gate.report.nativeWrongSpki);
    });
  } finally {
    await gate.finish({ requiredScenarios });
  }
  return gate.report;
}
module.exports = {
  qualifyWrongLeaf,
  requiredScenarios,
  requiredSources,
  verifyProof,
};
