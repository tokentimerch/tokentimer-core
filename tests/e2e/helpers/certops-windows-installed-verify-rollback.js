"use strict";
/** Real installed/public renewal with an owned HTTP.sys precedence fault.
 * The shadow initially serves the SAME predecessor. A real accepted new leaf
 * is independently bound to the current job receipt/native custody before
 * claiming final verification failure/rollback. Transient new-bind observation
 * is explicitly not qualified. No clock, CA response or result is substituted.
 * Unknown ownership/job state preserves the whole fixture for runner disposal. */
const assert = require("node:assert/strict");
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  net = require("node:net"),
  tls = require("node:tls");
const { isDeepStrictEqual } = require("node:util");
const installed = require("./certops-windows-installed-paths");
const controls = require("./certops-windows-service-controls");
const discovery = require("../../../packages/agent/src/windows-discovery");
const iis = require("../../../packages/agent/src/windows-iis");
const SCOPE =
  "installed-public-renewal-native-shadow-verify-failure-rollback-and-retry";
const SCENARIO = "windows-installed-public-renewal-verify-rollback";
const GUARD = ".installed-public-verify-rollback.guard";
const FLAGS = Object.freeze([
  "originalNativeSniAndTrustedTls",
  "exactOwnedShadowAndSiblingAdmission",
  "shadowInitiallyServedSamePredecessor",
  "actualPublicSignedCurrentClaim",
  "actualCaLeafAndProtectedCngAccepted",
  "claimBoundVerifyFailureAndRollbackEvidence",
  "nativePredecessorBindingRestored",
  "predecessorKeyAndTrustedTlsPreserved",
  "siblingBindingAndTrustedTlsPreserved",
  "exactShadowRemovedBeforeRetry",
  "freshPublicSignedRetrySucceeded",
  "freshLeafSpkiProtectedKeyAndTrustedTls",
  "profileAndProtectedStatePreserved",
  "failedAcceptedLeafOwnershipRecorded",
  "ownedEndpointCleanupCompleted",
]);
const REQUIRED_SOURCES = Object.freeze([
  "packages/contracts/certops/agent-protocol.schema.json",
  ...[
    "apps/api/routes/certops-agent.js",
    "apps/api/middleware/agent-auth.js",
    "apps/api/services/certops/evidence.js",
    "apps/api/services/certops/protocolSchemaValidation.js",
  ],
  ...new Set([
    "tests/e2e/helpers/certops-windows-installed-verify-rollback.js",
    ...controls.REQUIRED_SOURCES,
    "packages/agent/src/windows-discovery/index.js",
    "packages/agent/src/windows-iis/index.js",
    "packages/agent/src/windows-cert-store/index.js",
    "apps/api/routes/certops.js",
    "apps/api/services/certops/jobs.js",
    "apps/api/services/certops/agentDispatch.js",
    "apps/api/services/certops/jobSigning.js",
  ]),
]);
const active = new Set();
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const uuid = (value) =>
  typeof value === "string" &&
  /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
const spki = (leaf) =>
  sha(leaf.publicKey.export({ type: "spki", format: "der" }));
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "certificateId",
      "jobIds",
      "claimIds",
      "fingerprints",
      "spkiFingerprints",
      "failedJobStatus",
      "failureCode",
      "rolledBack",
      "retryJobStatus",
      "bindFailureQualified",
      "rollbackFailureQualified",
      "expiryCleanupQualified",
      "transientNewBindingObservationQualified",
      "appIdPreservationQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  assert.ok(uuid(p.certificateId));
  for (const name of ["jobIds", "claimIds"]) {
    assert.ok(
      Array.isArray(p[name]) &&
        p[name].length === 2 &&
        p[name].every(uuid) &&
        new Set(p[name]).size === 2,
    );
  }
  for (const name of ["fingerprints", "spkiFingerprints"]) {
    assert.ok(
      Array.isArray(p[name]) &&
        p[name].length === 3 &&
        p[name].every(
          (x) => typeof x === "string" && /^[a-f0-9]{64}$/.test(x),
        ) &&
        new Set(p[name]).size === 3,
    );
  }
  assert.equal(p.failedJobStatus, "failed");
  assert.equal(p.failureCode, "VERIFY_FAILED");
  assert.equal(p.rolledBack, true);
  assert.equal(p.retryJobStatus, "succeeded");
  for (const name of [
    "bindFailureQualified",
    "rollbackFailureQualified",
    "expiryCleanupQualified",
    "transientNewBindingObservationQualified",
    "appIdPreservationQualified",
  ])
    assert.equal(p[name], false);
  for (const flag of FLAGS) assert.equal(p[flag], true, flag);
  return true;
}
function assertCleanupSafe(root) {
  assert.ok(
    !active.has(root) && !fs.existsSync(path.join(root, GUARD)),
    "Preserve unresolved installed verification fault and borrowed custody",
  );
}
function readOwned(file, limit = 1048576) {
  const before = fs.lstatSync(file, { bigint: true });
  assert.ok(
    before.isFile() &&
      !before.isSymbolicLink() &&
      before.ino > 0n &&
      before.size > 0n &&
      before.size <= BigInt(limit),
  );
  assert.equal(
    path.resolve(fs.realpathSync.native(file)).toLowerCase(),
    path.resolve(file).toLowerCase(),
  );
  const fd = fs.openSync(
    file,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      opened.dev === before.dev &&
        opened.ino === before.ino &&
        opened.size === before.size,
    );
    const bytes = Buffer.alloc(Number(before.size) + 1);
    let used = 0;
    while (used < bytes.length) {
      const count = fs.readSync(fd, bytes, used, bytes.length - used, null);
      if (!count) break;
      used += count;
    }
    const after = fs.fstatSync(fd, { bigint: true }),
      current = fs.lstatSync(file, { bigint: true });
    assert.ok(
      used === Number(before.size) &&
        ["dev", "ino", "size", "mtimeNs", "ctimeNs"].every(
          (k) => opened[k] === after[k],
        ) &&
        current.isFile() &&
        !current.isSymbolicLink() &&
        current.dev === opened.dev &&
        current.ino === opened.ino,
      "Owned observation changed during bounded descriptor read",
    );
    return { bytes: bytes.subarray(0, used), stat: opened };
  } finally {
    fs.closeSync(fd);
  }
}
function beginGuard(root, registry) {
  root = path.resolve(root);
  assert.ok(Array.isArray(registry));
  assertCleanupSafe(root);
  const original = fs.lstatSync(root, { bigint: true });
  assert.ok(
    original.isDirectory() && !original.isSymbolicLink() && original.ino > 0n,
  );
  assert.equal(fs.realpathSync.native(root).toLowerCase(), root.toLowerCase());
  const file = path.join(root, GUARD),
    bytes = Buffer.from(crypto.randomBytes(32).toString("hex"));
  active.add(root);
  const row = { root, cleanupCompleted: false };
  registry.push(row);
  fs.writeFileSync(file, bytes, { flag: "wx", mode: 0o600 });
  const id = fs.lstatSync(file, { bigint: true });
  const check = () => {
    const currentRoot = fs.lstatSync(root, { bigint: true });
    assert.ok(
      currentRoot.isDirectory() &&
        !currentRoot.isSymbolicLink() &&
        currentRoot.dev === original.dev &&
        currentRoot.ino === original.ino,
      "Original verification fixture root required",
    );
    const current = readOwned(file, 64);
    assert.ok(
      current.stat.dev === id.dev &&
        current.stat.ino === id.ino &&
        current.bytes.equals(bytes),
      "Original verification receipt required",
    );
  };
  return {
    check,
    release() {
      check();
      fs.unlinkSync(file);
      active.delete(root);
      row.cleanupCompleted = true;
    },
  };
}
function select(rows, selector) {
  return rows.filter(
    (row) =>
      `${row.keyedBy}=${iis.canonicalSelectorValue(row.ipPort || "")}` ===
      selector,
  );
}
function assertOwnedEndpoint(actual, expected) {
  assert.ok(
    actual && isDeepStrictEqual(actual, expected),
    "Foreign or changed native endpoint preserved",
  );
}
function assertPrimaryRestored(actual, original) {
  assert.ok(
    actual &&
      typeof actual.appId === "string" &&
      /^\{?[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\}?$/i.test(actual.appId),
    "Actual product AppID required after rollback",
  );
  const projection = (row) => ({
    keyedBy: row.keyedBy,
    ipPort: iis.canonicalSelectorValue(row.ipPort || ""),
    thumbprint: row.thumbprint,
    storeName: String(row.storeName).toLowerCase(),
    settings: row.settings,
  });
  assert.ok(
    isDeepStrictEqual(projection(actual), projection(original)),
    "Primary selector/certificate/store/client settings not restored",
  );
}
function assertNoShadow(rows, port, hostname) {
  const own = `hostnameport=${hostname}:${port}`;
  for (const row of rows) {
    const value = iis.canonicalSelectorValue(row.ipPort || "");
    assert.match(value, /:\d+$/);
    if (Number(value.match(/:(\d+)$/)[1]) === port)
      assert.equal(
        `${row.keyedBy}=${value}`,
        own,
        "Foreign IP/wildcard/hostname endpoint on target port",
      );
  }
}
function validateClaim(row, expected) {
  assert.ok(
    row &&
      row.operation === "renew" &&
      row.mode === "real" &&
      row.source === "api" &&
      row.subject_id === expected.certificateId &&
      row.agent_id === expected.agentId &&
      row.attempt_count === 1 &&
      uuid(row.claim_id) &&
      row.payload?.certificateId === expected.certificateId,
    "Actual signed installed public renewal/current claim required",
  );
}
function validateIssued(record, jobId, certificateId, thumbprint) {
  assert.ok(
    record &&
      record.jobId === jobId &&
      record.certificateId === certificateId &&
      record.status === "enrolled_by_agent" &&
      record.acceptedStore === "My" &&
      record.acceptedThumbprint === thumbprint &&
      new RegExp(`^tokentimer-${certificateId}-[a-f0-9]{8}$`).test(
        record.containerName,
      ),
    "Actual accepted native ownership receipt must bind this job and managed certificate",
  );
}
function nativeCertificateScript(thumbprint) {
  assert.match(thumbprint, /^[A-F0-9]{40}$/);
  const challenge = crypto.randomBytes(32).toString("base64");
  return `
$c=Get-Item -LiteralPath 'Cert:\\LocalMachine\\My\\${thumbprint}' -ErrorAction Stop
$key=$null;$public=$null;$chain=$null
try {
 $data=[Convert]::FromBase64String('${challenge}')
 if($c.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1'){
  $key=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)
  $public=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($c)
  $signature=$key.SignData($data,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $valid=$public.VerifyData($data,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
 }else{
  $key=[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c)
  $public=[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($c)
  $signature=$key.SignData($data,[Security.Cryptography.HashAlgorithmName]::SHA256)
  $valid=$public.VerifyData($data,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256)
 }
 if(!$key-or!$key.Key.IsMachineKey-or[int]$key.Key.ExportPolicy-ne 0-or!$valid){throw 'Protected native private possession required'}
 $chain=[Security.Cryptography.X509Certificates.X509Chain]::new($true)
 $chain.ChainPolicy.RevocationMode=[Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
 if(!$chain.Build($c)){throw 'Actual machine-trusted ACME chain required'}
 @{thumb=$c.Thumbprint;der=[Convert]::ToBase64String($c.RawData);container=$key.Key.KeyName;unique=$key.Key.UniqueName;provider=$key.Key.Provider.Provider;policy=[int]$key.Key.ExportPolicy;machine=$key.Key.IsMachineKey;bits=$key.KeySize;possession=$valid;nativeChainTrusted=$true}|ConvertTo-Json -Compress
}finally{if($chain){$chain.Dispose()};if($public){$public.Dispose()};if($key){$key.Dispose()};$c.Dispose()}
`;
}
function nativeSiteScript(site, domain, port) {
  assert.match(site, /^[A-Za-z0-9_-]{1,128}$/);
  assert.match(domain, /^[a-z0-9.-]+$/);
  assert.ok(Number.isSafeInteger(port) && port > 0 && port <= 65535);
  return `Import-Module WebAdministration;$s=Get-Website -Name '${site}' -ErrorAction Stop;$b=@(Get-WebBinding -Name '${site}' -Protocol https);if(!$s-or$b.Count-ne 1-or[string]$b[0].bindingInformation-cne '*:${port}:${domain}'-or[int]$b[0].sslFlags-ne 1-or[string]$b[0].certificateStoreName-ine 'My'){throw 'Exact owned SNI site required'};@{site=$s.Name;id=[long]$s.Id;path=[string]$s.physicalPath;coordinates=[string]$b[0].bindingInformation;flags=[int]$b[0].sslFlags;store=[string]$b[0].certificateStoreName;thumb=([BitConverter]::ToString([byte[]]$b[0].certificateHash)).Replace('-','')}|ConvertTo-Json -Compress`;
}
function removeOwnedSiteScript(site, domain, port, expected) {
  // Re-observe the complete original site tuple in the SAME invocation as the
  // destructive command. A name alone never confers cleanup ownership.
  const encoded = Buffer.from(JSON.stringify(expected)).toString("base64");
  return `$actual=& {${nativeSiteScript(site, domain, port)}};$a=$actual|ConvertFrom-Json;$e=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'))|ConvertFrom-Json;foreach($name in @('site','id','path','coordinates','flags','store','thumb')){if([string]$a.$name-cne[string]$e.$name){throw 'Changed owned sibling site preserved'}};Remove-Website -Name '${site}';if(Get-Website -Name '${site}' -ErrorAction SilentlyContinue){throw 'Owned sibling site remains'}`;
}
function peer(c, port = c.port) {
  return new Promise((resolve, reject) => {
    let leaf, failure;
    const socket = tls.connect({ ...controls.tlsOptions(c), port }, () => {
      try {
        assert.equal(socket.authorized, true);
        leaf = new crypto.X509Certificate(socket.getPeerCertificate().raw);
      } catch {
        failure = true;
      }
      socket.end();
    });
    socket.setTimeout(10000, () =>
      socket.destroy(new Error("Owned verification TLS timeout")),
    );
    socket.on("error", () => {
      failure = true;
    });
    socket.once("close", () => {
      if (!failure && leaf) resolve(leaf);
      else reject(new Error("Owned trusted TLS observation/drain failed"));
    });
  });
}
async function freePort() {
  const server = net.createServer((socket) => socket.destroy());
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0 }, resolve);
  });
  const port = server.address().port;
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  return port;
}

async function qualifyInternal(c, rollbackFailure) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST, "1");
  const {
    receipt,
    configDir,
    ps,
    run,
    pool,
    workspaceId,
    certificateId,
    agentId,
    publicSession,
    ownedJobs,
    ownedShadows,
    waitUntil,
  } = c;
  assert.ok(
    uuid(certificateId) &&
      typeof agentId === "string" &&
      Array.isArray(ownedJobs) &&
      Array.isArray(ownedShadows),
  );
  installed.assertOwnedRoot(receipt);
  assert.equal(receipt.historicalSupportingOnly, false);
  assertCleanupSafe(receipt.root);
  const expectedInstalled = {
    host: path.join(receipt.root, "app/bin/tokentimer-agent-host-amd64.exe"),
    node: process.execPath,
    entry: path.join(receipt.root, "app/bin/tokentimer-agent.js"),
    config: configDir,
  };
  const observeInstalled = () => {
    const value = JSON.parse(ps(installed.observationScript()));
    installed.validateObservation(value, expectedInstalled);
    return value;
  };
  const installedBefore = observeInstalled();
  const guarded = beginGuard(receipt.root, ownedShadows);
  const owned = () => {
    installed.assertOwnedRoot(receipt);
    guarded.check();
  };
  const listing = async () => {
    owned();
    const result = await discovery.listHttpSysBindings({});
    assert.equal(result.ok, true, "Native supported IP/SNI inventory required");
    owned();
    return result.bindings;
  };
  const endpoint = async (selector) => {
    const rows = select(await listing(), selector);
    assert.ok(rows.length <= 1, "Ambiguous native selector");
    return rows[0];
  };
  const hostSelector = `hostnameport=${c.domain}:${c.port}`,
    shadowSelector = `ipport=127.0.0.1:${c.port}`;
  const originalLeaf = await peer(c),
    originalThumb = originalLeaf.fingerprint.replaceAll(":", "");
  assert.equal(originalThumb, c.thumbprint);
  const originalNative = JSON.parse(ps(nativeCertificateScript(originalThumb))),
    originalSni = await endpoint(hostSelector),
    originalSite = JSON.parse(ps(nativeSiteScript(c.site, c.domain, c.port)));
  if (rollbackFailure) assert.equal(originalNative.bits, 2048);
  assert.equal(originalSni?.thumbprint, originalThumb);
  assert.equal(String(originalSni.storeName).toLowerCase(), "my");
  assert.equal(originalSite.thumb, originalThumb);
  assertNoShadow(await listing(), c.port, c.domain);
  const files = () =>
    ["config.json", "credential", "signing-key-pin.json"].map((name) =>
      sha(readOwned(path.join(configDir, name)).bytes),
    );
  const profile = async () =>
    (
      await pool.query(
        "SELECT cp.id,cp.name,cp.status,cp.issuer_id,cp.renew_before_days,cp.description,cp.key_mode,cp.source,cp.source_ref,cp.public_metadata FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2",
        [workspaceId, certificateId],
      )
    ).rows;
  const protectedBefore = files(),
    profileBefore = await profile();
  assert.equal(profileBefore.length, 1);
  const storedProfile = profileBefore[0].public_metadata?.renewalProfile;
  assert.equal(storedProfile?.target?.type, "windows-iis");
  assert.equal(storedProfile.target.store, "My");
  assert.equal(storedProfile.target.binding.site, c.site);
  assert.equal(storedProfile.target.binding.port, c.port);
  assert.equal(storedProfile.target.binding.sniHost, c.domain);
  const agentRows = (
    await pool.query(
      "SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
      [workspaceId, agentId],
    )
  ).rows;
  assert.equal(agentRows.length, 1);
  const siblingPort = await freePort();
  assert.notEqual(siblingPort, c.port);
  const siblingSite = `CertOpsVerify-${crypto.randomUUID()}`,
    siblingSelector = `hostnameport=${c.domain}:${siblingPort}`;
  const siblingConflicts = (await listing()).filter(
    (row) =>
      Number(
        iis.canonicalSelectorValue(row.ipPort || "").match(/:(\d+)$/)?.[1],
      ) === siblingPort,
  );
  assert.equal(siblingConflicts.length, 0);
  assert.equal(
    ps(
      `Import-Module WebAdministration;[string][bool](Get-Website -Name '${siblingSite}' -ErrorAction SilentlyContinue)`,
    ),
    "False",
  );
  const siblingDirectory = path.join(
    receipt.root,
    `verify-sibling-${crypto.randomUUID()}`,
  );
  fs.mkdirSync(siblingDirectory);
  const siblingDirectoryId = fs.lstatSync(siblingDirectory, { bigint: true });
  const siblingContent = Buffer.from("Owned public verification sibling"),
    siblingFile = path.join(siblingDirectory, "index.htm");
  fs.writeFileSync(siblingFile, siblingContent, { flag: "wx" });
  const siblingFileId = fs.lstatSync(siblingFile, { bigint: true });
  owned();
  ps(
    `Import-Module WebAdministration;New-Website -Name '${siblingSite}' -PhysicalPath '${siblingDirectory.replaceAll("'", "''")}' -IPAddress '*' -Port ${siblingPort} -HostHeader '${c.domain}' -Ssl|Out-Null;Set-WebBinding -Name '${siblingSite}' -BindingInformation '*:${siblingPort}:${c.domain}' -PropertyName sslFlags -Value 1;$b=Get-WebBinding -Name '${siblingSite}' -Protocol https;$b.AddSslCertificate('${originalThumb}','My')`,
  );
  const siblingNative = await endpoint(siblingSelector),
    siblingIis = JSON.parse(
      ps(nativeSiteScript(siblingSite, c.domain, siblingPort)),
    );
  assert.equal(siblingNative?.thumbprint, originalThumb);
  assert.equal(String(siblingNative.storeName).toLowerCase(), "my");
  assert.equal(siblingIis.path.toLowerCase(), siblingDirectory.toLowerCase());
  assert.equal(siblingIis.thumb, originalThumb);
  assert.equal(sha((await peer(c, siblingPort)).raw), sha(originalLeaf.raw));
  const shadowAppId = crypto.randomUUID();
  run("netsh.exe", [
    "http",
    "add",
    "sslcert",
    shadowSelector,
    `certhash=${originalThumb}`,
    `appid={${shadowAppId}}`,
    "certstorename=My",
  ]);
  const shadowNative = await endpoint(shadowSelector);
  assert.equal(shadowNative?.thumbprint, originalThumb);
  assert.equal(String(shadowNative.storeName).toLowerCase(), "my");
  assert.equal(
    String(shadowNative.appId).replace(/[{}]/g, "").toLowerCase(),
    shadowAppId,
  );
  assert.ok(
    (
      await iis.checkSniPrecedenceConflict({
        binding: {
          address: "127.0.0.1",
          port: c.port,
          sniHost: c.domain,
          store: "My",
          site: c.site,
        },
      })
    )?.includes(shadowSelector),
    "Actual native shadow conflict must be observable",
  );
  assert.equal(sha((await peer(c)).raw), sha(originalLeaf.raw));
  let predecessorHolder;
  if (rollbackFailure) {
    const holder = require("./certops-windows-predecessor-holder");
    predecessorHolder = await holder.start({
      root: receipt.root,
      powershell: path.join(
        process.env.SystemRoot,
        "System32/WindowsPowerShell/v1.0/powershell.exe",
      ),
      thumbprint: originalThumb,
      derBase64: originalNative.der,
      containerName: originalNative.container,
      uniqueName: originalNative.unique,
      registry: ownedShadows,
    });
    owned();
    await predecessorHolder.remove();
    assert.equal(
      ps(
        `if(Test-Path -LiteralPath 'Cert:\\LocalMachine\\My\\${originalThumb}'){throw 'Owned public predecessor must be absent'};'Absent'`,
      ),
      "Absent",
    );
    // Native HTTP.sys may retain an already-established certificate context;
    // its continued TLS behavior is observed, never assumed from a cache.
    assert.equal(sha((await peer(c)).raw), sha(originalLeaf.raw));
    assert.equal(sha((await peer(c, siblingPort)).raw), sha(originalLeaf.raw));
  }
  const job = async (id) =>
    (
      await pool.query(
        "SELECT j.id,j.status,j.operation,j.mode,j.source,j.subject_id,j.claim_id,j.attempt_count,j.payload,j.error_message,a.agent_id FROM certificate_jobs j JOIN certops_agents a ON a.id=j.claimed_by_agent_id AND a.workspace_id=j.workspace_id WHERE j.workspace_id=$1 AND j.id=$2",
        [workspaceId, id],
      )
    ).rows[0];
  const submit = async () => {
    owned();
    const response = await publicSession.request(
      `/api/v1/workspaces/${workspaceId}/certops/jobs`,
      "POST",
      {
        operation: "renew",
        subjectType: "managed_certificate",
        subjectId: certificateId,
        assignedAgentId: agentRows[0].id,
        idempotencyKey: crypto.randomUUID(),
        payload: {
          reason: "Owned installed verification rollback qualification",
        },
      },
    );
    if (response.body?.job?.id) ownedJobs.push(response.body.job.id);
    assert.equal(response.status, 201);
    assert.ok(uuid(response.body.job.id));
    return response.body.job.id;
  };
  const failedJobId = await submit();
  const failed = await waitUntil(async () => {
    const row = await job(failedJobId);
    return ["succeeded", "failed", "cancelled", "rejected"].includes(
      row?.status,
    )
      ? row
      : null;
  });
  validateClaim(failed, c);
  const claim = failed.claim_id;
  const dispatches = (
    await pool.query(
      "SELECT nonce FROM certops_consumed_nonces WHERE workspace_id=$1 AND job_id=$2 AND issued_to_agent_id=$3",
      [workspaceId, failedJobId, agentRows[0].id],
    )
  ).rows;
  assert.equal(
    dispatches.length,
    1,
    "Exactly one actual signed failure dispatch required",
  );
  assert.equal(failed.status, "failed");
  assert.match(
    failed.error_message,
    rollbackFailure
      ? /IIS binding deploy failed \(VERIFY_FAILED\).*rolledBack: false/
      : /IIS binding deploy failed \(VERIFY_FAILED\).*rolledBack: true/,
  );
  const failures = (
    await pool.query(
      "SELECT e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.claim_id=j.claim_id AND e.evidence_type='validation.failed' AND e.metadata->>'step'='iis-bind'",
      [workspaceId, failedJobId],
    )
  ).rows;
  assert.ok(
    failures.some(
      (row) =>
        row.metadata.code === "VERIFY_FAILED" &&
        row.metadata.rolledBack === !rollbackFailure,
    ),
    "Actual current-claim verify failure/rollback evidence required",
  );
  const records = fs
    .readdirSync(path.join(configDir, "windows-cert-store/issued-containers"))
    .filter((name) => /\.json$/.test(name))
    .map((name) =>
      JSON.parse(
        readOwned(
          path.join(configDir, "windows-cert-store/issued-containers", name),
          8192,
        ).bytes.toString("utf8"),
      ),
    )
    .filter((record) => record.jobId === failedJobId);
  assert.equal(records.length, 1);
  validateIssued(
    records[0],
    failedJobId,
    certificateId,
    records[0].acceptedThumbprint,
  );
  const accepted = JSON.parse(
      ps(nativeCertificateScript(records[0].acceptedThumbprint)),
    ),
    acceptedLeaf = new crypto.X509Certificate(
      Buffer.from(accepted.der, "base64"),
    );
  assert.ok(
    accepted.container === records[0].containerName,
    "Accepted key receipt/native custody mismatch",
  );
  assert.equal(acceptedLeaf.checkHost(c.domain), c.domain);
  assert.notEqual(sha(acceptedLeaf.raw), sha(originalLeaf.raw));
  assert.notEqual(spki(acceptedLeaf), spki(originalLeaf));
  assert.notEqual(acceptedLeaf.serialNumber, originalLeaf.serialNumber);
  if (rollbackFailure) {
    assert.equal(
      await endpoint(hostSelector),
      undefined,
      "Absent predecessor must not be presented as a restored native SNI binding",
    );
    assert.equal(
      ps(
        `if(Test-Path -LiteralPath 'Cert:\\LocalMachine\\My\\${originalThumb}'){throw 'Owned predecessor unexpectedly reappeared'};'Absent'`,
      ),
      "Absent",
    );
    assert.equal(sha((await peer(c)).raw), sha(originalLeaf.raw));
    assertOwnedEndpoint(await endpoint(siblingSelector), siblingNative);
    assert.equal(sha((await peer(c, siblingPort)).raw), sha(originalLeaf.raw));
    owned();
    await predecessorHolder.restoreAndDrain();
  } else assertPrimaryRestored(await endpoint(hostSelector), originalSni);
  assert.ok(
    isDeepStrictEqual(
      JSON.parse(ps(nativeSiteScript(c.site, c.domain, c.port))),
      originalSite,
    ),
    "Original native IIS tuple not restored",
  );
  if (!rollbackFailure)
    assert.equal(sha((await peer(c)).raw), sha(originalLeaf.raw));
  assertOwnedEndpoint(await endpoint(siblingSelector), siblingNative);
  assert.equal(sha((await peer(c, siblingPort)).raw), sha(originalLeaf.raw));
  assert.ok(
    isDeepStrictEqual(
      JSON.parse(ps(nativeCertificateScript(originalThumb))),
      originalNative,
    ),
    "Original private custody changed during failed cutover",
  );
  assertOwnedEndpoint(await endpoint(shadowSelector), shadowNative);
  owned();
  run("netsh.exe", ["http", "delete", "sslcert", shadowSelector]);
  assert.equal(await endpoint(shadowSelector), undefined);
  if (rollbackFailure) assert.equal(await endpoint(hostSelector), undefined);
  else assert.equal(sha((await peer(c)).raw), sha(originalLeaf.raw));
  const retryJobId = await submit(),
    retry = await waitUntil(async () => {
      const row = await job(retryJobId);
      return ["succeeded", "failed", "cancelled", "rejected"].includes(
        row?.status,
      )
        ? row
        : null;
    });
  validateClaim(retry, c);
  assert.equal(retry.status, "succeeded");
  assert.notEqual(retry.claim_id, claim);
  const retryDispatches = (
    await pool.query(
      "SELECT nonce FROM certops_consumed_nonces WHERE workspace_id=$1 AND job_id=$2 AND issued_to_agent_id=$3",
      [workspaceId, retryJobId, agentRows[0].id],
    )
  ).rows;
  assert.equal(
    retryDispatches.length,
    1,
    "Exactly one actual signed retry dispatch required",
  );
  const latestLeaf = await peer(c),
    latestThumbprint = latestLeaf.fingerprint.replaceAll(":", "");
  assert.equal(
    new Set([sha(originalLeaf.raw), sha(acceptedLeaf.raw), sha(latestLeaf.raw)])
      .size,
    3,
  );
  assert.equal(
    new Set([spki(originalLeaf), spki(acceptedLeaf), spki(latestLeaf)]).size,
    3,
  );
  assert.ok(Date.parse(latestLeaf.validTo) > Date.parse(originalLeaf.validTo));
  assert.notEqual(latestLeaf.serialNumber, acceptedLeaf.serialNumber);
  const latest = JSON.parse(ps(nativeCertificateScript(latestThumbprint)));
  assert.ok(
    new Set([originalNative.container, accepted.container, latest.container])
      .size === 3,
    "Distinct actual protected native keys required",
  );
  for (const value of [originalNative, accepted, latest])
    assert.ok(
      value.machine === true &&
        value.policy === 0 &&
        value.provider === "Microsoft Software Key Storage Provider" &&
        value.possession === true &&
        value.nativeChainTrusted === true &&
        value.bits === storedProfile.keySize,
    );
  for (const leaf of [originalLeaf, acceptedLeaf, latestLeaf])
    assert.equal(
      leaf.publicKey.asymmetricKeyType,
      storedProfile.keyAlgorithm === "rsa" ? "rsa" : "ec",
    );
  const verified = (
    await pool.query(
      "SELECT e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.claim_id=j.claim_id AND e.evidence_type='validation.passed' AND e.metadata->>'step'='verify'",
      [workspaceId, retryJobId],
    )
  ).rows;
  assert.ok(
    verified.some(
      (row) =>
        String(row.metadata.fingerprintSha256)
          .replaceAll(":", "")
          .toLowerCase() === sha(latestLeaf.raw),
    ),
    "Actual retry current-claim trusted TLS evidence required",
  );
  await waitUntil(async () => {
    const row = (
      await pool.query(
        "SELECT fingerprint_sha256,profile_id FROM managed_certificates WHERE workspace_id=$1 AND id=$2",
        [workspaceId, certificateId],
      )
    ).rows[0];
    return (
      row &&
      String(row.fingerprint_sha256).replaceAll(":", "").toLowerCase() ===
        sha(latestLeaf.raw) &&
      row.profile_id === profileBefore[0].id
    );
  });
  assert.ok(
    isDeepStrictEqual(await profile(), profileBefore) &&
      isDeepStrictEqual(files(), protectedBefore) &&
      isDeepStrictEqual(observeInstalled(), installedBefore),
    "Operator profile/protected state/installed identities changed",
  );
  assert.equal((await endpoint(hostSelector))?.thumbprint, latestThumbprint);
  assertOwnedEndpoint(await endpoint(siblingSelector), siblingNative);
  assert.equal(sha((await peer(c, siblingPort)).raw), sha(originalLeaf.raw));
  assert.ok(
    isDeepStrictEqual(
      JSON.parse(ps(nativeSiteScript(siblingSite, c.domain, siblingPort))),
      siblingIis,
    ),
  );
  assert.ok(
    isDeepStrictEqual(
      JSON.parse(ps(nativeCertificateScript(originalThumb))),
      originalNative,
    ) &&
      isDeepStrictEqual(
        JSON.parse(ps(nativeCertificateScript(accepted.thumb))),
        accepted,
      ),
    "Borrowed predecessor or failed accepted custody changed",
  );
  const finalSni = await endpoint(hostSelector),
    finalSite = JSON.parse(ps(nativeSiteScript(c.site, c.domain, c.port)));
  // Exact original IIS tuple and complete native selector must still match
  // before removal. Never delete a certificate/key borrowed by these endpoints.
  owned();
  ps(removeOwnedSiteScript(siblingSite, c.domain, siblingPort, siblingIis));
  const remaining = await endpoint(siblingSelector);
  if (remaining) {
    assertOwnedEndpoint(remaining, siblingNative);
    owned();
    run("netsh.exe", ["http", "delete", "sslcert", siblingSelector]);
  }
  assert.equal(await endpoint(siblingSelector), undefined);
  assert.equal(await endpoint(shadowSelector), undefined);
  assert.equal(sha((await peer(c)).raw), sha(latestLeaf.raw));
  assertOwnedEndpoint(await endpoint(hostSelector), finalSni);
  assert.ok(
    isDeepStrictEqual(
      JSON.parse(ps(nativeSiteScript(c.site, c.domain, c.port))),
      finalSite,
    ),
  );
  const currentDirectory = fs.lstatSync(siblingDirectory, { bigint: true }),
    currentContent = readOwned(siblingFile, 1024);
  assert.ok(
    currentDirectory.isDirectory() &&
      !currentDirectory.isSymbolicLink() &&
      currentDirectory.dev === siblingDirectoryId.dev &&
      currentDirectory.ino === siblingDirectoryId.ino &&
      currentContent.stat.dev === siblingFileId.dev &&
      currentContent.stat.ino === siblingFileId.ino &&
      currentContent.bytes.equals(siblingContent),
    "Foreign sibling content preserved",
  );
  fs.unlinkSync(siblingFile);
  assert.deepEqual(fs.readdirSync(siblingDirectory), []);
  fs.rmdirSync(siblingDirectory);
  owned();
  guarded.release();
  const failedContract = rollbackFailure
    ? require("./certops-windows-installed-failed-rollback")
    : null;
  const proof = {
    scope: failedContract ? failedContract.SCOPE : SCOPE,
    certificateId,
    jobIds: [failedJobId, retryJobId],
    claimIds: [claim, retry.claim_id],
    fingerprints: [
      sha(originalLeaf.raw),
      sha(acceptedLeaf.raw),
      sha(latestLeaf.raw),
    ],
    spkiFingerprints: [
      spki(originalLeaf),
      spki(acceptedLeaf),
      spki(latestLeaf),
    ],
    failedJobStatus: "failed",
    failureCode: "VERIFY_FAILED",
    rolledBack: !rollbackFailure,
    retryJobStatus: "succeeded",
    bindFailureQualified: false,
    rollbackFailureQualified: rollbackFailure,
    ...(rollbackFailure
      ? { originalOperationAutomaticallyRecovered: false }
      : { expiryCleanupQualified: false }),
    transientNewBindingObservationQualified: false,
    appIdPreservationQualified: false,
    ...Object.fromEntries(
      (failedContract ? failedContract.FLAGS : FLAGS).map((name) => [
        name,
        true,
      ]),
    ),
  };
  (failedContract ? failedContract.verifyProof : verifyProof)(proof);
  return { proof, latestLeaf, latestThumbprint };
}
function qualify(c) {
  return qualifyInternal(c, false);
}
function qualifyFailedRollback(c) {
  return qualifyInternal(c, true);
}
module.exports = {
  SCOPE,
  SCENARIO,
  GUARD,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  assertCleanupSafe,
  beginGuard,
  assertOwnedEndpoint,
  assertPrimaryRestored,
  assertNoShadow,
  validateClaim,
  validateIssued,
  nativeCertificateScript,
  nativeSiteScript,
  removeOwnedSiteScript,
  readOwned,
  qualify,
  qualifyFailedRollback,
};
