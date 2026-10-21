/*
 * Qualification notes: installed-public-iis-refusal
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Submit real public standalone deploy for genuinely installed CNG/IIS certificate: signed dispatch
 * must fail with specific unsupported Windows IIS deploy error. Early branch emits no certificate
 * failure evidence; require exactly matching CERTOPS_JOB_FAILED audit(job/claim/agent/operation), no
 * issuance/deploy/validation success evidence. Borrow same leaf/key for uniquely owned secondary SNI
 * site/port; both trusted TLS endpoints/native metadata/config/credential/pin and ACME receipt/DNS
 * counts remain fixed. Not direct CA database observation or multi-target admission. Register
 * unresolved shadow before mutation; assertCleanupSafe blocks uncertain public/native state. Remove
 * only exact secondary site/endpoint after association readback and recheck primary TLS.
 */
"use strict";
/** Installed-agent standalone IIS deploy refusal. A second exact owned SNI site
 * reuses the genuine existing leaf/key; public admission, signed execution and
 * both trusted TLS endpoints remain real. No certificate/key/CA is created here.
 * Parent cleanup must call assertCleanupSafe before deleting certificate state. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  tls = require("node:tls"),
  net = require("node:net"),
  { isDeepStrictEqual } = require("node:util");
const SCOPE = "installed-agent-public-standalone-iis-deploy-refusal",
  scenarioName = "windows-installed-public-iis-deploy-refusal";
const FLAGS = Object.freeze([
  "genuinePriorIssuance",
  "publicDeployAdmitted",
  "sameInstalledAgentClaimedOnce",
  "specificUnsupportedTargetFailure",
  "claimBoundFailureAudit",
  "nativeInventoryAndCustodyUnchanged",
  "bothBindingsAndTrustedTlsUnchanged",
  "actualAcmeClientNotInvoked",
  "dnsTrafficUnchanged",
  "credentialAndPinUnchanged",
  "exactOwnedShadowRemoved",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-windows-installed-iis-refusal.js",
  "tests/e2e/windows-real-journey.js",
  "tests/e2e/helpers/certops-windows-output-child.js",
  "tests/e2e/helpers/certops-windows-output-privacy.js",
  "apps/api/routes/certops.js",
  "apps/api/services/certops/jobs.js",
  "apps/api/services/certops/agentDispatch.js",
  "apps/api/services/certops/workspaceKillSwitch.js",
  "packages/agent/src/index.js",
  "packages/agent/src/windows-iis/index.js",
]);
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
function verifyProof(value) {
  assert.ok(
    value &&
      Object.keys(value).sort().join(",") ===
        ["scope", "jobId", "claimId", ...FLAGS].sort().join(","),
  );
  assert.equal(value.scope, SCOPE);
  assert.match(value.jobId, UUID);
  assert.match(value.claimId, UUID);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
function assertCleanupSafe(registry) {
  assert.ok(
    Array.isArray(registry) &&
      registry.every((row) => row.cleanupCompleted === true),
    "Unresolved installed IIS refusal shadow preserves native state",
  );
  return true;
}
function assertOwnedShadow(value, expected) {
  assert.ok(
    value &&
      value.site === expected.site &&
      value.path === expected.path &&
      value.coordinates === `*:${expected.port}:${expected.domain}` &&
      value.flags === 1 &&
      value.store === "My" &&
      typeof value.httpStore === "string" &&
      value.httpStore.toLowerCase() === "my" &&
      value.thumbprint.toLowerCase() === expected.thumbprint.toLowerCase(),
    "Foreign or replaced shadow site/binding preserved",
  );
  return true;
}
async function qualify({
  publicSession,
  pool,
  workspaceId,
  certificateId,
  initialJobId,
  configDir,
  domain,
  site,
  port,
  roots,
  thumbprint,
  powershell: ps,
  run,
  waitUntil,
  ownedJobs,
  shadowRegistry,
  acmeReceiptDirectory,
  dnsRequestCount,
}) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST, "1");
  assert.equal(
    ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),
    "S-1-5-18",
  );
  assert.match(site, /^CertOps-[a-f0-9-]{36}$/);
  assert.match(domain, /^certops-[a-f0-9]{12}\.example\.test$/);
  assert.match(thumbprint, /^[A-Fa-f0-9]{40}$/);
  assert.ok(Array.isArray(shadowRegistry) && Array.isArray(ownedJobs));
  assert.equal(
    path.resolve(acmeReceiptDirectory),
    path.join(path.dirname(configDir), "native-output-receipts"),
  );
  const receiptRoot = fs.lstatSync(acmeReceiptDirectory);
  assert.ok(receiptRoot.isDirectory() && !receiptRoot.isSymbolicLink());
  const quote = (value) => value.replace(/'/g, "''"),
    hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
  const prior = (
    await pool.query(
      "SELECT status,claim_id,claimed_by_agent_id,operation FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
      [workspaceId, initialJobId],
    )
  ).rows[0];
  assert.equal(prior?.status, "succeeded");
  assert.equal(prior.operation, "issue");
  assert.ok(prior.claim_id);
  assert.match(prior.claimed_by_agent_id, UUID);
  const shadowPort = await new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close((e) => (e ? reject(e) : resolve(p)));
    });
  });
  assert.notEqual(shadowPort, port);
  const physicalPath = ps(
      `Import-Module WebAdministration;$s=Get-Website -Name '${site}';if(!$s){throw 'Original owned site absent'};[string]$s.physicalPath`,
    ),
    shadowSite = `CertOps-Refusal-${crypto.randomUUID()}`,
    expected = {
      site: shadowSite,
      path: physicalPath,
      domain,
      port: shadowPort,
      thumbprint,
    };
  assert.ok(physicalPath && !physicalPath.includes("\n"));
  const receipt = {
    site: shadowSite,
    port: shadowPort,
    cleanupCompleted: false,
  };
  shadowRegistry.push(receipt);
  let allowCleanup = true,
    primary,
    result;
  const readShadow = () =>
    JSON.parse(
      ps(
        `Import-Module WebAdministration;$s=Get-Website -Name '${shadowSite}';$b=@(Get-WebBinding -Name '${shadowSite}' -Protocol https);$keys=@(Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object {[string]$_.GetValue('HostnamePort') -ieq '${domain}:${shadowPort}'});if(!$s-or$b.Count-ne 1-or$keys.Count-ne 1){throw 'Exact owned shadow absent'};@{site=$s.Name;path=[string]$s.physicalPath;coordinates=[string]$b[0].bindingInformation;flags=[int]$b[0].sslFlags;store=[string]$b[0].certificateStoreName;httpStore=[string]$keys[0].GetValue('SslCertStoreName');thumbprint=([BitConverter]::ToString([byte[]]$keys[0].GetValue('SslCertHash'))).Replace('-','')}|ConvertTo-Json -Compress`,
      ),
    );
  const peer = (p) =>
    new Promise((resolve, reject) => {
      const s = tls.connect(
        {
          host: "127.0.0.1",
          port: p,
          servername: domain,
          ca: roots.map((r) => r.pem),
          rejectUnauthorized: true,
        },
        () => {
          try {
            assert.equal(s.authorized, true);
            assert.equal(
              s
                .getPeerCertificate()
                .fingerprint.replace(/:/g, "")
                .toLowerCase(),
              thumbprint.toLowerCase(),
            );
            resolve();
          } catch (e) {
            reject(e);
          } finally {
            s.destroy();
          }
        },
      );
      s.once("error", reject);
      s.setTimeout(10000, () =>
        s.destroy(new Error("Installed refusal trusted TLS deadline")),
      );
    });
  const snapshot = () => ({
    certificates: JSON.parse(
      ps(
        "@(Get-ChildItem Cert:\\LocalMachine\\My|Sort-Object Thumbprint|ForEach-Object {@{thumb=$_.Thumbprint;key=$_.HasPrivateKey;der=[Convert]::ToBase64String($_.RawData)}})|ConvertTo-Json -Depth 4 -Compress",
      ),
    ),
    keys: JSON.parse(
      ps(
        "$p=Join-Path $env:ProgramData 'Microsoft\\Crypto\\Keys';if(!(Test-Path -LiteralPath $p)){throw 'Machine CNG metadata absent'};@(Get-ChildItem -LiteralPath $p -Force -File|Sort-Object Name|ForEach-Object {@{name=$_.Name;length=$_.Length;write=$_.LastWriteTimeUtc.Ticks}})|ConvertTo-Json -Depth 4 -Compress",
      ),
    ),
    custody: JSON.parse(
      ps(
        `$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}';$rsa=$null;try{$rsa=if($c.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1'){[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)}else{[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c)};if(!$rsa-or!$rsa.Key.IsMachineKey-or[int]$rsa.Key.ExportPolicy-ne 0-or$rsa.Key.Provider.Provider-ne 'Microsoft Software Key Storage Provider'){throw 'Exact protected machine CNG custody required'};@{name=$rsa.Key.KeyName;unique=$rsa.Key.UniqueName;provider=$rsa.Key.Provider.Provider;machine=$rsa.Key.IsMachineKey;policy=[int]$rsa.Key.ExportPolicy;public=[Convert]::ToBase64String($c.PublicKey.EncodedKeyValue.RawData)}|ConvertTo-Json -Compress}finally{if($rsa){$rsa.Dispose()};$c.Dispose()}`,
      ),
    ),
    binding: run("netsh.exe", [
      "http",
      "show",
      "sslcert",
      `hostnameport=${domain}:${port}`,
    ]),
    shadow: readShadow(),
    identity: ["config.json", "credential", "signing-key-pin.json"].map((f) =>
      hash(fs.readFileSync(path.join(configDir, f))),
    ),
    receipts: fs
      .readdirSync(acmeReceiptDirectory)
      .sort()
      .map((f) => [
        f,
        hash(fs.readFileSync(path.join(acmeReceiptDirectory, f))),
      ]),
    dns: dnsRequestCount(),
  });
  try {
    assert.equal(
      ps(
        `Import-Module WebAdministration;[bool](Test-Path 'IIS:\\Sites\\${shadowSite}')`,
      ),
      "False",
    );
    assert.equal(
      ps(
        `@(Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object {[string]$_.GetValue('HostnamePort') -ieq '${domain}:${shadowPort}'}).Count`,
      ),
      "0",
    );
    ps(
      `Import-Module WebAdministration;New-Website -Name '${shadowSite}' -PhysicalPath '${quote(physicalPath)}' -IPAddress '*' -Port ${shadowPort} -HostHeader '${domain}' -Ssl|Out-Null;Set-WebBinding -Name '${shadowSite}' -BindingInformation '*:${shadowPort}:${domain}' -PropertyName sslFlags -Value 1;$b=Get-WebBinding -Name '${shadowSite}' -Protocol https;$b.AddSslCertificate('${thumbprint}','My')`,
    );
    assertOwnedShadow(readShadow(), expected);
    await peer(port);
    await peer(shadowPort);
    const before = snapshot();
    assert.ok(
      before.receipts.length > 0,
      "Actual prior ACME invocation receipt required",
    );
    allowCleanup = false;
    const response = await publicSession.request(
      `/api/v1/workspaces/${workspaceId}/certops/jobs`,
      "POST",
      {
        operation: "deploy",
        subjectType: "managed_certificate",
        subjectId: certificateId,
        assignedAgentId: prior.claimed_by_agent_id,
        idempotencyKey: `installed-iis-refusal-${crypto.randomUUID()}`,
        payload: {
          target: {
            type: "windows-iis",
            reference: domain,
            store: "My",
            binding: { site, port, sniHost: domain },
          },
        },
      },
    );
    assert.equal(response.status, 201);
    const jobId = response.body.job.id;
    ownedJobs.push(jobId);
    assert.match(jobId, UUID);
    const terminal = await waitUntil(async () => {
      const row = (
        await pool.query(
          "SELECT status,error_message,claim_id,claimed_by_agent_id,attempt_count,operation,mode,source FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
          [workspaceId, jobId],
        )
      ).rows[0];
      return [
        "failed",
        "succeeded",
        "rejected",
        "blocked",
        "cancelled",
      ].includes(row?.status)
        ? row
        : null;
    });
    assert.equal(terminal.status, "failed");
    assert.equal(terminal.operation, "deploy");
    assert.equal(terminal.mode, "real");
    assert.equal(terminal.source, "api");
    assert.equal(terminal.attempt_count, 1);
    assert.equal(terminal.claimed_by_agent_id, prior.claimed_by_agent_id);
    assert.match(terminal.claim_id, UUID);
    assert.match(
      terminal.error_message,
      /deploy action does not yet support windows-iis targets/,
    );
    const audits = (
      await pool.query(
        "SELECT metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_JOB_FAILED' AND metadata->>'jobId'=$2",
        [workspaceId, jobId],
      )
    ).rows;
    assert.equal(audits.length, 1);
    const failure = audits[0].metadata;
    assert.equal(failure.claimId, terminal.claim_id);
    assert.equal(failure.operation, "deploy");
    assert.equal(failure.mode, "real");
    assert.equal(failure.source, "api");
    assert.equal(failure.jobStatus, "failed");
    assert.match(
      failure.errorMessage,
      /deploy action does not yet support windows-iis targets/,
    );
    const actor = (
      await pool.query(
        "SELECT agent_id FROM certops_agents WHERE workspace_id=$1 AND id=$2",
        [workspaceId, prior.claimed_by_agent_id],
      )
    ).rows[0];
    assert.equal(failure.agentId, actor.agent_id);
    const evidence = (
      await pool.query(
        "SELECT evidence_type FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2",
        [workspaceId, jobId],
      )
    ).rows;
    assert.equal(
      evidence.some((r) =>
        [
          "issuance.completed",
          "deployment.completed",
          "validation.passed",
        ].includes(r.evidence_type),
      ),
      false,
    );
    assert.ok(
      isDeepStrictEqual(snapshot(), before),
      "Refused signed deploy changed native state, credentials or actual ACME/DNS traffic",
    );
    await peer(port);
    await peer(shadowPort);
    allowCleanup = true;
    result = {
      scope: SCOPE,
      jobId,
      claimId: terminal.claim_id,
      ...Object.fromEntries(FLAGS.map((f) => [f, true])),
    };
  } catch (error) {
    primary = error;
    throw error;
  } finally {
    if (allowCleanup) {
      try {
        assertOwnedShadow(readShadow(), expected);
        ps(
          `Import-Module WebAdministration
Remove-Website -Name '${shadowSite}'
if(Test-Path 'IIS:\\Sites\\${shadowSite}'){throw 'Owned shadow site remains'}
function Read-OwnedEndpoint { @(Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object {[string]$_.GetValue('HostnamePort') -ieq '${domain}:${shadowPort}'}) }
$keys=@(Read-OwnedEndpoint)
if($keys.Count -gt 1){throw 'Ambiguous native shadow endpoint preserved'}
if($keys.Count -eq 1){
 if([string]$keys[0].GetValue('SslCertStoreName') -ine 'MY' -or ([BitConverter]::ToString([byte[]]$keys[0].GetValue('SslCertHash'))).Replace('-','') -ine '${thumbprint}'){throw 'Replaced native shadow endpoint preserved'}
 & netsh.exe http delete sslcert hostnameport=${domain}:${shadowPort}|Out-Null
 if($LASTEXITCODE -ne 0){throw 'Owned shadow endpoint removal failed'}
}
if(@(Read-OwnedEndpoint).Count -ne 0){throw 'Owned native shadow endpoint remains'}`,
        );
        await peer(port);
        receipt.cleanupCompleted = true;
      } catch (error) {
        throw new AggregateError(
          [...(primary ? [primary] : []), error],
          "Owned refusal shadow cleanup unconfirmed; preserve native state",
        );
      }
    }
  }
  verifyProof(result);
  return result;
}
module.exports = {
  SCOPE,
  scenarioName,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  assertCleanupSafe,
  assertOwnedShadow,
  qualify,
};
