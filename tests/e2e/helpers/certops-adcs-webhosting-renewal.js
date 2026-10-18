"use strict";
/** Genuine public AD CS issue/renew in WebHosting. The protected parent owns
 * the isolated IIS site, installed SYSTEM agent and store-qualified cleanup.
 * No clock, journal, CA response or inventory observation is manufactured. */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const tls = require("node:tls");
const {
  readEnrollmentJournal,
} = require("../../../packages/agent/src/issuers/adcs-enrollment");
const {
  buildEnrollmentContainerName,
  readIssuedContainerRecord,
} = require("../../../packages/agent/src/windows-cert-store");
const {
  readLedgerRow,
} = require("../../../packages/agent/src/windows-retention");
const REQUIRED_SCENARIOS = Object.freeze([
  "adcs-real-webhosting-issued-renewed-native-custody",
  "adcs-real-webhosting-discovery-and-retention-coordinates",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-adcs-webhosting-renewal.js",
  "tests/e2e/certops-adcs-real-e2e.test.js",
  "infra/certops-adcs/owned-issued-request.ps1",
  "apps/api/services/certops/certificateEnrollments.js",
  "apps/api/services/certops/agentObservations.js",
  "apps/api/services/certops/inventory.js",
  "packages/agent/src/index.js",
  "packages/agent/src/adcs-windows-iis.js",
  "packages/agent/src/windows-cert-store/index.js",
  "packages/agent/src/windows-iis/index.js",
  "packages/agent/src/discovery/windows.js",
  "packages/agent/src/issuers/adcs-enrollment-journal.js",
  "packages/agent/src/windows-retention/index.js",
]);
const FLAGS = Object.freeze([
  "publicIssueAndRenewInstalled",
  "twoIndependentCaRequests",
  "freshSerialSpkiAndKey",
  "webHostingProtectedCustody",
  "myCopiesAbsent",
  "exactNativeIisAndHttpSysStore",
  "trustedSniTls",
  "installedDiscoveryInventory",
  "immutableAcceptedStore",
  "predecessorRetentionStorePreserved",
  "storeQualifiedCleanupRegistered",
]);
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
function verifyProof(proof) {
  assert.deepEqual(
    Object.keys(proof).sort(),
    [
      "scope",
      "store",
      "expiryCleanupQualified",
      "requestIds",
      "fingerprints",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(
    proof.scope,
    "real-adcs-webhosting-issue-and-fresh-key-manual-renewal",
  );
  assert.equal(proof.store, "WebHosting");
  assert.equal(proof.expiryCleanupQualified, false);
  for (const field of FLAGS) assert.equal(proof[field], true, field);
  for (const [field, pattern] of [
    ["requestIds", /^[1-9][0-9]{0,9}$/],
    ["fingerprints", /^[a-f0-9]{64}$/],
  ]) {
    assert.ok(Array.isArray(proof[field]) && proof[field].length === 2);
    assert.equal(new Set(proof[field]).size, 2);
    for (const value of proof[field])
      assert.ok(typeof value === "string" && pattern.test(value));
  }
  assert.ok(proof.requestIds.every((id) => Number(id) <= 0xffffffff));
  return true;
}
/** Validate all candidates before removing any public store entry. A matching
 * subject is only a selector; durable exact container/store/thumb ownership
 * authorizes removal. Missing receipts preserve the whole fixture. */
function storeCleanupPlan(receipt, entries, readRecord, store, domainPattern) {
  assert.notEqual(receipt.resultOutboxPendingVerification, true, "Preserve native ownership while signed result restart remains unresolved");
  assert.notEqual(receipt.machineAclPendingVerification, true, "Preserve native ownership while live Enroll ACL recovery remains unresolved");
  assert.notEqual(receipt.httpLeafCrlPendingVerification, true, "Preserve native ownership while HTTP leaf CRL recovery remains unresolved");
  assert.notEqual(receipt.ocspPendingVerification, true, "Preserve native ownership while Microsoft OCSP recovery remains unresolved");
  assert.notEqual(receipt.workerPendingVerification, true, "Preserve native ownership while actual background renewal remains unresolved");
  assert.notEqual(receipt.pendingCaRenewalUnresolved, true, "Preserve native ownership while pending CA renewal remains unresolved");
  assert.notEqual(receipt.guiCancelPendingVerification, true, "Preserve native ownership while GUI Cancel remains unresolved");
  assert.equal(receipt.store, store);
  assert.match(receipt.domain, domainPattern);
  assert.match(receipt.certificateId, uuid);
  const containers = new Set(
    receipt.enrollmentIds.map((id) => {
      assert.match(id, uuid);
      return buildEnrollmentContainerName(id);
    }),
  );
  assert.ok(Array.isArray(entries) && entries.length <= 16);
  const seen = new Set();
  return entries.map((entry) => {
    assert.match(entry.thumbprint, /^[A-F0-9]{40}$/);
    assert.ok(!seen.has(entry.thumbprint));
    seen.add(entry.thumbprint);
    assert.ok(
      containers.has(entry.containerName),
      "Preserve unowned WebHosting key association",
    );
    const record = readRecord(entry.containerName);
    assert.ok(
      record &&
        record.status === "enrolled_by_agent" &&
        record.containerName === entry.containerName &&
        record.certificateId === receipt.certificateId &&
        record.acceptedStore === store &&
        record.acceptedThumbprint === entry.thumbprint,
      "Preserve public certificate without exact durable ownership",
    );
    return Object.freeze({
      thumbprint: entry.thumbprint,
      containerName: entry.containerName,
    });
  });
}
function cleanupPlan(receipt, entries, readRecord) {
  return storeCleanupPlan(
    receipt,
    entries,
    readRecord,
    "WebHosting",
    /^certops-adcs-[a-f0-9]{10}-webhosting\.example\.test$/,
  );
}
// Capacity uses a separate exact public fixture namespace and only My. It cannot
// authorize arbitrary stores or broaden the WebHosting selector.
function capacityCleanupPlan(receipt, entries, readRecord) {
  return storeCleanupPlan(
    receipt,
    entries,
    readRecord,
    "My",
    /^certops-adcs-[a-f0-9]{10}-capacity[0-5]\.example\.test$/,
  );
}
// The existing primary RSA fixture has its own registry; capacity selectors stay exact.
function backgroundCleanupPlan(receipt, entries, readRecord) {
  return storeCleanupPlan(receipt, entries, readRecord, "My", /^certops-adcs-[a-f0-9]{10}-rsa2048\.example\.test$/);
}
// Separate namespace and registry: issuer switching never broadens capacity
// selectors or authorizes removing another fixture's certificate.
function issuerSwitchCleanupPlan(receipt, entries, readRecord) {
  return storeCleanupPlan(receipt, entries, readRecord, "My", /^certops-adcs-[a-f0-9]{10}-issuer-switch\.example\.test$/);
}
function registerIssuerSwitchStoreCertificate(registry, { domain, certificateId }) {
  const receipt = { store: "My", domain, certificateId, enrollmentIds: [], thumbprints: [] };
  issuerSwitchCleanupPlan(receipt, [], () => null);
  assert.ok(Array.isArray(registry) && registry.length === 0);
  registry.push(receipt);
  return receipt;
}
function registerBackgroundStoreCertificate(registry, {domain, certificateId, enrollmentIds}) {
  const receipt = {store:"My",domain,certificateId,enrollmentIds:[...enrollmentIds],thumbprints:[]};
  backgroundCleanupPlan(receipt,[],()=>null);
  assert.equal(new Set(receipt.enrollmentIds).size,receipt.enrollmentIds.length);
  assert.ok(!registry.length);
  registry.push(receipt);
  return receipt;
}
// Later existing scenarios may accept another leaf for the same primary identity.
// Adopt only IDs already recorded by the parent and exact durable My receipts.
function refreshBackgroundEnrollmentOwnership(receipts, enrollmentIds, readRecord, {workspaceId,rows,readJournal}) {
  assert.match(workspaceId,uuid);
  assert.ok(Array.isArray(rows));
  for(const receipt of receipts) {
    backgroundCleanupPlan(receipt,[],()=>null);
    for(const id of enrollmentIds) {
      assert.match(id,uuid);
      const containerName=buildEnrollmentContainerName(id), record=readRecord(containerName);
      if(record?.certificateId !== receipt.certificateId) continue;
      if(record.status === "generated" && record.acceptedThumbprint === null && record.acceptedStore === null) continue;
      assert.equal(record.status,"enrolled_by_agent");
      assert.equal(record.containerName,containerName);
      assert.equal(record.acceptedStore,"My");
      assert.match(record.acceptedThumbprint,/^[A-F0-9]{40}$/);
      const matches=rows.filter(row=>row.id===id && row.workspace_id===workspaceId && row.certificate_id===receipt.certificateId);
      assert.equal(matches.length,1,"Preserve enrollment without exact workspace ownership");
      assert.ok(["installed","install_failed"].includes(matches[0].state));
      assert.ok(matches[0].job_ids.includes(record.jobId),"Preserve receipt with unowned issuing job");
      const journal=readJournal(id);
      assert.equal(journal.kind,"valid");
      assert.equal(journal.journal.containerName,containerName);
      assert.ok(["installed","install_failed"].includes(journal.journal.state));
      assert.match(journal.journal.leafSha256,/^[a-f0-9]{64}$/);
      if(!receipt.enrollmentIds.includes(id))receipt.enrollmentIds.push(id);
    }
  }
}
function registerCapacityStoreCertificate(registry, { domain, certificateId }) {
  const receipt = {
    store: "My",
    domain,
    certificateId,
    enrollmentIds: [],
    thumbprints: [],
  };
  capacityCleanupPlan(receipt, [], () => null);
  assert.ok(Array.isArray(registry));
  assert.ok(
    !registry.some(
      (row) => row.domain === domain || row.certificateId === certificateId,
    ),
  );
  registry.push(receipt);
  return receipt;
}
function confirmRegisteredKeyCleanup(receipts) {
  for (const receipt of receipts)
    receipt.keyCleanupCompleted =
      receipt.pendingCaRenewalUnresolved !== true &&
      receipt.cleanupCompleted === true &&
      receipt.enrollmentIds.every((id) =>
        receipt.removedEnrollmentIds?.includes(id),
      );
}
function assertRegisteredCleanupComplete(receipts) {
  for (const receipt of receipts)
    assert.ok(
      receipt.pendingCaRenewalUnresolved !== true &&
      receipt.cleanupCompleted === true &&
        receipt.keyCleanupCompleted === true &&
        receipt.enrollmentIds.every((id) =>
          receipt.removedEnrollmentIds?.includes(id),
        ),
      "Preserve durable native ownership state after incomplete public/key cleanup",
    );
  return true;
}
function captureServiceDrain(ps, { configDir, expectedServicePath }) {
  assert.ok(
    typeof configDir === "string" && typeof expectedServicePath === "string",
  );
  const escape = (value) => value.replace(/'/g, "''");
  const result = JSON.parse(
    ps(
      `$s=Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'";if(!$s-or$s.State-ne'Running'-or$s.PathName-ne'${escape(expectedServicePath)}'-or$s.StartName-ne'LocalSystem'){throw 'Owned service identity changed before drain capture'};$e=(Get-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent').Environment;if(@($e)-notcontains'TOKENTIMER_AGENT_CONFIG_DIR=${escape(configDir)}'){throw 'Owned service state directory changed'};$all=@(Get-CimInstance Win32_Process);$ids=@([int]$s.ProcessId);do{$before=$ids.Count;foreach($p in $all){if($ids-contains[int]$p.ParentProcessId-and$ids-notcontains[int]$p.ProcessId){$ids+=([int]$p.ProcessId)}}}while($before-ne$ids.Count);@{root=[int]$s.ProcessId;processes=@($all|Where-Object {$ids-contains[int]$_.ProcessId}|ForEach-Object {@{pid=[int]$_.ProcessId;parent=[int]$_.ParentProcessId;created=$_.CreationDate.ToUniversalTime().ToString('o')}})}|ConvertTo-Json -Depth 5 -Compress`,
    ),
  );
  assert.ok(Number.isInteger(result.root) && result.root > 0);
  assert.ok(
    Array.isArray(result.processes) &&
      result.processes.length >= 2 &&
      result.processes.length <= 64,
  );
  for (const item of result.processes) {
    assert.ok(Number.isInteger(item.pid) && item.pid > 0);
    assert.ok(Number.isFinite(Date.parse(item.created)));
  }
  return result;
}
function assertDrainAbsent(drain, current) {
  assert.ok(drain && Array.isArray(drain.processes));
  assert.ok(Array.isArray(current) && current.length <= 32768);
  const ids = new Set(drain.processes.map((row) => row.pid));
  for (const row of current) {
    assert.ok(
      !drain.processes.some(
        (prior) => prior.pid === row.pid && prior.created === row.created,
      ),
      "Preserve native fixture while captured service process remains",
    );
    // Windows retains ParentProcessId after exit. Refuse even an uncaptured late
    // child; never terminate a numeric PID or accept root exit as child drainage.
    assert.ok(
      !ids.has(row.parent),
      "Preserve native fixture while owned descendant remains",
    );
  }
  return true;
}
function cleanupRegisteredStore({ receipts, configDir, ps, drain }, capacity) {
  const validate = capacity === "issuer-switch" ? issuerSwitchCleanupPlan : capacity === "background" ? backgroundCleanupPlan : capacity ? capacityCleanupPlan : cleanupPlan;
  const store = capacity ? "My" : "WebHosting",
    otherStore = capacity ? "WebHosting" : "My";
  if (!receipts.length) return;
  assert.equal(
    ps("(Get-Service TokenTimerAgent -ErrorAction SilentlyContinue).Status"),
    "",
    "Owned service must be deleted before store cleanup",
  );
  const current = JSON.parse(
    ps(
      "@{processes=@(Get-CimInstance Win32_Process|ForEach-Object {@{pid=[int]$_.ProcessId;parent=[int]$_.ParentProcessId;created=$_.CreationDate.ToUniversalTime().ToString('o')}})}|ConvertTo-Json -Depth 4 -Compress",
    ),
  );
  assertDrainAbsent(drain, current.processes);
  for (const receipt of receipts) {
    validate(receipt, [], () => null);
    const enumerate = () =>
      JSON.parse(
        ps(
          `$domain='${receipt.domain}';if(@(Get-ChildItem Cert:\\LocalMachine\\${otherStore}|Where-Object Subject -eq "CN=$domain").Count){throw 'Unexpected cross-store copy preserved'};@{entries=@(Get-ChildItem Cert:\\LocalMachine\\${store}|Where-Object Subject -eq "CN=$domain"|ForEach-Object {$c=$_;$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if(!$k){throw 'Missing exact owned CNG association'};@{thumbprint=$c.Thumbprint;containerName=$k.Key.KeyName}}finally{if($k){$k.Dispose()};$c.Dispose()}})}|ConvertTo-Json -Depth 4 -Compress`,
        ),
      ).entries;
    const readRecord = (containerName) =>
      readIssuedContainerRecord({ stateDir: configDir, containerName });
    const plan = validate(receipt, enumerate(), readRecord);
    for (const entry of plan) {
      // Re-read immediately before each removal; public entries are removed before
      // the parent attempts any exact enrollment-container deletion.
      const fresh = validate(receipt, enumerate(), readRecord);
      assert.ok(
        fresh.some(
          (row) =>
            row.thumbprint === entry.thumbprint &&
            row.containerName === entry.containerName,
        ),
      );
      ps(
        `$c=Get-Item -LiteralPath 'Cert:\\LocalMachine\\${store}\\${entry.thumbprint}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if($k.Key.KeyName-ne'${entry.containerName}'){throw 'Foreign replacement preserved'}}finally{if($k){$k.Dispose()};$c.Dispose()};Remove-Item -LiteralPath 'Cert:\\LocalMachine\\${store}\\${entry.thumbprint}'`,
      );
    }
    assert.equal(enumerate().length, 0);
    receipt.cleanupCompleted = true;
  }
}
function cleanupWebHosting(context) {
  return cleanupRegisteredStore(context, false);
}
function cleanupCapacity(context) {
  return cleanupRegisteredStore(context, true);
}
async function qualifyWebHostingRenewal(context) {
  const {
    gate,
    fixture,
    api,
    agentRowId,
    configDir,
    isolated,
    ownedEnrollmentIds,
    ownedStoreCertificates,
    jobFinished,
    until,
    ps,
    command,
    tlsAuthority,
  } = context;
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  const { domain, site, port, issuerId, authority, certificateId } = isolated;
  assert.match(domain, /^certops-adcs-[a-f0-9]{10}-webhosting\.example\.test$/);
  assert.match(site, /^TTAdcsWebHosting[a-f0-9]{10}$/);
  assert.ok(Number.isInteger(port) && port > 1024 && port < 65536);
  assert.match(certificateId, uuid);
  assert.equal(
    ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),
    "S-1-5-18",
  );
  const config = JSON.parse(
    fs.readFileSync(path.join(configDir, "config.json"), "utf8"),
  );
  assert.ok(config.declaredTargetSelectors.includes(domain));
  assert.ok(
    config.windowsDiscovery.enabled &&
      config.windowsDiscovery.stores.includes("WebHosting"),
  );
  assert.ok(Array.isArray(ownedStoreCertificates));
  const root = path.resolve(__dirname, "../../..");
  gate.report.fixtureSources ??= [];
  for (const file of REQUIRED_SOURCES) {
    const sha256 = crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.join(root, file)))
        .digest("hex"),
      prior = gate.report.fixtureSources.find((row) => row.file === file);
    if (prior) assert.equal(prior.sha256, sha256);
    else gate.report.fixtureSources.push({ file, sha256 });
  }
  // Register the exact store/domain before a dispatch can accept any public leaf.
  const cleanup = {
    store: "WebHosting",
    domain,
    certificateId,
    enrollmentIds: [],
    thumbprints: [],
  };
  ownedStoreCertificates.push(cleanup);
  const peer = () =>
    new Promise((resolve, reject) => {
      const socket = tls.connect(
        {
          host: "127.0.0.1",
          port,
          servername: domain,
          ca: tlsAuthority(authority),
          rejectUnauthorized: true,
        },
        () => {
          try {
            assert.equal(socket.authorized, true);
            const leaf = new crypto.X509Certificate(
              socket.getPeerCertificate().raw,
            );
            assert.equal(leaf.checkHost(domain), domain);
            resolve(leaf);
          } catch (error) {
            reject(error);
          } finally {
            socket.destroy();
          }
        },
      );
      socket.once("error", reject);
      socket.setTimeout(10000, () =>
        socket.destroy(
          new Error("WebHosting trusted TLS observation timed out"),
        ),
      );
    });
  const leaves = [],
    requests = [],
    receipts = [];
  await gate.scenario(
    REQUIRED_SCENARIOS[0],
    async () => {
      for (let generation = 0; generation < 2; generation++) {
        const response = await fixture.request(`${api}/enrollments`, "POST", {
          issuerId,
          certificateId,
          agentId: agentRowId,
          target: {
            type: "windows-iis",
            reference: domain,
            store: "WebHosting",
            binding: { site, port, sniHost: domain },
          },
          authorizedDnsNames: [domain],
          keyAlgorithm: "rsa",
          keySize: 2048,
        });
        assert.equal(response.status, 201);
        const enrollmentId = response.body.enrollmentId;
        assert.match(enrollmentId, uuid);
        ownedEnrollmentIds.push(enrollmentId);
        cleanup.enrollmentIds.push(enrollmentId);
        await jobFinished(response.body.jobId);
        const state = (
          await fixture.pool.query(
            "SELECT state,request_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",
            [fixture.workspaceId, enrollmentId],
          )
        ).rows[0];
        assert.equal(state.state, "installed");
        const leaf = await peer(),
          thumb = leaf.fingerprint.replace(/:/g, "").toUpperCase(),
          fingerprint = leaf.fingerprint256.replace(/:/g, "").toLowerCase();
        cleanup.thumbprints.push(thumb);
        const native = JSON.parse(
          command("powershell.exe", [
            "-NoProfile",
            "-NonInteractive",
            "-File",
            path.join(root, "infra/certops-adcs/owned-issued-request.ps1"),
            "-CommonName",
            domain,
            "-FingerprintSha256",
            fingerprint,
          ]),
        );
        assert.equal(native.disposition, 20);
        assert.equal(native.subjectRequestCount, generation + 1);
        if (state.request_id != null)
          assert.equal(String(state.request_id), String(native.requestId));
        const custody = JSON.parse(
          ps(
            `$c=Get-Item 'Cert:\\LocalMachine\\WebHosting\\${thumb}';$k=$null;try{if(Test-Path 'Cert:\\LocalMachine\\My\\${thumb}'){throw 'Unexpected duplicate My copy'};$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);@{container=$k.Key.KeyName;machine=$k.Key.IsMachineKey;policy=[int]$k.Key.ExportPolicy;bits=$k.KeySize;der=[Convert]::ToBase64String($c.RawData)}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`,
          ),
        );
        assert.equal(
          custody.container,
          buildEnrollmentContainerName(enrollmentId),
        );
        assert.equal(custody.machine, true);
        assert.equal(custody.policy, 0);
        assert.equal(custody.bits, 2048);
        assert.equal(
          new crypto.X509Certificate(Buffer.from(custody.der, "base64"))
            .fingerprint256,
          leaf.fingerprint256,
        );
        const receipt = readIssuedContainerRecord({
          stateDir: configDir,
          containerName: custody.container,
        });
        assert.equal(receipt.status, "enrolled_by_agent");
        assert.equal(receipt.acceptedStore, "WebHosting");
        assert.equal(receipt.acceptedThumbprint, thumb);
        const journal = readEnrollmentJournal(configDir, enrollmentId);
        assert.equal(journal.kind, "valid");
        assert.equal(journal.journal.state, "installed");
        assert.equal(journal.journal.containerName, custody.container);
        assert.equal(
          journal.journal.csrSpkiSha256,
          crypto
            .createHash("sha256")
            .update(leaf.publicKey.export({ type: "spki", format: "der" }))
            .digest("hex"),
        );
        const binding = JSON.parse(
          ps(
            `Import-Module WebAdministration;$b=@(Get-WebBinding -Name '${site}' -Protocol https|Where-Object bindingInformation -eq '*:${port}:${domain}');$h=@(Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object {[string]$_.GetValue('HostnamePort') -ieq '${domain}:${port}'});if($b.Count-ne 1-or $h.Count-ne 1){throw 'Exact isolated binding required'};@{iisStore=[string]$b[0].certificateStoreName;httpStore=[string]$h[0].GetValue('SslCertStoreName');hash=[BitConverter]::ToString([byte[]]$h[0].GetValue('SslCertHash')).Replace('-','');flags=[int]$b[0].sslFlags}|ConvertTo-Json -Compress`,
          ),
        );
        assert.equal(binding.iisStore.toLowerCase(), "webhosting");
        assert.equal(binding.httpStore.toLowerCase(), "webhosting");
        assert.equal(binding.hash, thumb);
        assert.equal(binding.flags, 1);
        leaves.push(leaf);
        requests.push(String(native.requestId));
        receipts.push(receipt);
      }
      assert.notEqual(leaves[0].serialNumber, leaves[1].serialNumber);
      assert.notEqual(leaves[0].fingerprint256, leaves[1].fingerprint256);
      assert.equal(leaves[0].publicKey.equals(leaves[1].publicKey), false);
    },
    {
      evidenceLevel: "real-host",
      oracle:
        "two public native enrollments, independent exact CA leaf matches, nonexportable WebHosting keys and exact trusted IIS/HTTP.sys SNI cutover",
    },
  );
  await gate.scenario(
    REQUIRED_SCENARIOS[1],
    async () => {
      const leaf = leaves[1],
        fingerprint = leaf.fingerprint256.replace(/:/g, "").toLowerCase();
      await until(async () => {
        const rows = (
          await fixture.pool.query(
            "SELECT ct.windows_store FROM certificate_instances ci JOIN certificate_targets ct ON ct.workspace_id=ci.workspace_id AND ct.id=ci.target_id WHERE ci.workspace_id=$1 AND ci.observed_fingerprint_sha256=$2 AND ct.windows_site=$3 AND ct.windows_port=$4 AND ct.windows_sni_host=$5 AND ct.source='agent_windows'",
            [fixture.workspaceId, fingerprint, site, port, domain],
          )
        ).rows;
        return rows.some((row) => row.windows_store === "WebHosting");
      });
      const observations =
        await require("../../../packages/agent/src/discovery/windows").collectWindowsDiscoveryObservations(
          { stores: ["My", "WebHosting"] },
        );
      for (const value of leaves) {
        const hash = value.fingerprint256.replace(/:/g, "").toLowerCase();
        assert.equal(
          observations.filter(
            (row) =>
              row.locationKind === "windows_store" &&
              row.fingerprintSha256 === hash &&
              row.storeName === "WebHosting" &&
              row.keyPresent,
          ).length,
          1,
        );
        assert.equal(
          observations.filter(
            (row) => row.fingerprintSha256 === hash && row.storeName === "My",
          ).length,
          0,
        );
      }
      const originalThumb = leaves[0].fingerprint
          .replace(/:/g, "")
          .toUpperCase(),
        replacementThumb = leaf.fingerprint.replace(/:/g, "").toUpperCase();
      const row = readLedgerRow(
        path.join(configDir, "windows-retention"),
        originalThumb,
      );
      assert.ok(row);
      assert.equal(row.store, "WebHosting");
      assert.equal(row.oldThumbprint, originalThumb);
      assert.equal(row.replacementThumbprint, replacementThumb);
      assert.equal(row.cngKeyContainerId, receipts[0].containerName);
      assert.equal(row.ownershipProvenance, "tokentimer_installed");
      assert.notEqual(row.lifecycleState, "removed");
      assert.equal(
        readIssuedContainerRecord({
          stateDir: configDir,
          containerName: row.cngKeyContainerId,
        }).acceptedStore,
        "WebHosting",
      );
      assert.equal((await peer()).fingerprint256, leaf.fingerprint256);
      const proof = {
        scope: "real-adcs-webhosting-issue-and-fresh-key-manual-renewal",
        store: "WebHosting",
        expiryCleanupQualified: false,
        requestIds: requests,
        fingerprints: leaves.map((value) =>
          value.fingerprint256.replace(/:/g, "").toLowerCase(),
        ),
        ...Object.fromEntries(FLAGS.map((field) => [field, true])),
      };
      verifyProof(proof);
      gate.report.nativeWebHostingRenewal = proof;
    },
    {
      evidenceLevel: "real-host",
      oracle:
        "actual installed discovery ingestion and native store identity, immutable acceptedStore and unmodified production predecessor retention coordinates; no elapsed cleanup qualification",
    },
  );
}
module.exports = {
  REQUIRED_SCENARIOS,
  REQUIRED_SOURCES,
  FLAGS,
  verifyProof,
  qualifyWebHostingRenewal,
  cleanupPlan,
  capacityCleanupPlan,
  confirmRegisteredKeyCleanup,
  assertRegisteredCleanupComplete,
  registerCapacityStoreCertificate,
  cleanupCapacity,
  issuerSwitchCleanupPlan,
  registerIssuerSwitchStoreCertificate,
  cleanupIssuerSwitch: context => cleanupRegisteredStore(context,"issuer-switch"),
  backgroundCleanupPlan,
  refreshBackgroundEnrollmentOwnership,
  registerBackgroundStoreCertificate,
  cleanupBackground: context => cleanupRegisteredStore(context,"background"),
  captureServiceDrain,
  assertDrainAbsent,
  cleanupWebHosting,
};
