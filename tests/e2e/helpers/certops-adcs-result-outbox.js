"use strict";

// Real installed-agent certificate success whose authenticated result cannot
// reach the original API until after an ordinary retained-handle SCM restart.
// No local clock, retry deadline, result, claim or enrollment is manufactured.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const tls = require("node:tls");
const { isDeepStrictEqual } = require("node:util");
const {
  applyRestrictivePermissions,
} = require("../../../packages/agent/src/platform");
const {
  readEnrollmentJournal,
} = require("../../../packages/agent/src/issuers/adcs-enrollment");
const {
  buildEnrollmentContainerName,
  readIssuedContainerRecord,
} = require("../../../packages/agent/src/windows-cert-store");
const {
  verifyNativeRequestId,
  verifyInstalledEvidence,
} = require("./certops-adcs-live-enroll-acl");
const { startOwnedResultGateway } = require("./certops-adcs-result-gateway");
const configuration = require("./certops-adcs-result-configuration");
const service = require("./certops-adcs-result-service");
const SCENARIO = "adcs-real-native-success-result-outbox-scm-restart";
const FIELD = "nativeAdcsResultOutbox";
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-adcs-result-outbox.js",
  "tests/e2e/helpers/certops-adcs-result-gateway.js",
  "tests/e2e/helpers/certops-adcs-result-configuration.js",
  "tests/e2e/helpers/certops-adcs-result-service.js",
  "tests/e2e/helpers/certops-windows-stop-observer.js",
  "tests/e2e/helpers/certops-windows-stop-observer-process.js",
  "tests/e2e/helpers/certops-windows-stop-observer.ps1",
  "tests/e2e/helpers/certops-windows-installed-paths.js",
  "tests/e2e/helpers/certops-adcs-live-enroll-acl.js",
  "infra/certops-adcs/owned-ca-checkpoint.ps1",
  "infra/certops-adcs/owned-issued-request.ps1",
  "infra/certops-adcs/owned-request-observation.ps1",
  "packages/agent/src/platform/index.js",
  "packages/agent/src/platform/durability.js",
  "apps/api/routes/certops-agent.js",
  "apps/api/middleware/agent-auth.js",
  "apps/api/services/certops/agentObservations.js",
  "apps/api/services/certops/protocolSchemaValidation.js",
  "packages/contracts/certops/agent-protocol.schema.json",
  "packages/agent/src/outbox/index.js",
  "packages/agent/src/protocol/index.js",
  "packages/agent/src/config/index.js",
  "packages/agent/src/index.js",
  "packages/agent/src/adcs-windows-iis.js",
  "packages/agent/src/issuers/adcs-enrollment-journal.js",
  "packages/agent/src/windows-cert-store/index.js",
  "scripts/certops_adcs_result_outbox_proof.py",
]);
const SCOPE =
  "installed-adcs-native-success-durable-result-production-retry-after-scm-restart";
const FLAGS = Object.freeze([
  "actualNativeInstallationBeforeResultDelivery",
  "originalSignedClaimPreserved",
  "actualDurableRetryDeadline",
  "ordinaryRetainedHandleServiceStops",
  "sameProtectedConfigurationAndCredential",
  "sameLeafKeyAndCaRequestAfterRestart",
  "singleConsumedResultNonce",
  "claimBoundInstalledEvidence",
  "originalApiRestoredAndHealthy",
  "gatewayAndObserversDrained",
  "ownedCleanupRegistered",
]);
const active = new Set();
const GUARD = ".adcs-result-outbox-active.json";
const uuid = (value) =>
  typeof value === "string" &&
  /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value);
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
function assertCleanupSafe(workDir) {
  assert.ok(
    !active.has(path.resolve(workDir).toLowerCase()) &&
      !fs.existsSync(path.join(workDir, GUARD)),
    "Preserve unresolved native AD CS result delivery fixture",
  );
  configuration.assertCleanupSafe(workDir);
  service.assertCleanupSafe(workDir);
}
function verifyPersisted(entry, jobId, claimId, enrollmentId) {
  assert.ok(entry && typeof entry === "object" && !Array.isArray(entry));
  assert.match(entry.id, /^[A-Za-z0-9_.:-]{1,128}$/);
  assert.equal(entry.result?.jobId, jobId);
  assert.equal(entry.result?.claimId, claimId);
  assert.equal(entry.result?.status, "succeeded");
  if (enrollmentId !== undefined) {
    assert.equal(entry.result.enrollmentResult?.enrollmentId, enrollmentId);
    assert.equal(entry.result.enrollmentResult?.state, "installed");
  }
  assert.ok(Array.isArray(entry.evidence));
  assert.ok(
    Number.isSafeInteger(entry.attempts) &&
      entry.attempts >= 1 &&
      entry.attempts <= 5,
  );
  const attempted = Date.parse(entry.lastAttemptAt),
    due = Date.parse(entry.nextRetryAt);
  assert.ok(Number.isFinite(attempted) && Number.isFinite(due));
  const base = 15000 * 2 ** (entry.attempts - 1);
  assert.ok(
    due - attempted >= base * 0.8 && due - attempted <= base * 1.2,
    "Actual production retry deadline must match its recorded attempt",
  );
  return due;
}
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "enrollmentId",
      "jobId",
      "claimId",
      "requestId",
      "fingerprints",
      "caRequestCounts",
      "recordedAttempts",
      "retryDelayMs",
      "atomicTreeContainmentQualified",
      "backgroundTimerQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  for (const key of ["enrollmentId", "jobId", "claimId"])
    assert.ok(uuid(p[key]));
  verifyNativeRequestId(p.requestId);
  assert.ok(
    Array.isArray(p.fingerprints) &&
      p.fingerprints.length === 2 &&
      p.fingerprints.every(
        (v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v),
      ) &&
      new Set(p.fingerprints).size === 2,
  );
  assert.ok(
    Array.isArray(p.caRequestCounts) &&
      p.caRequestCounts.length === 3 &&
      p.caRequestCounts.every(
        (v) => Number.isSafeInteger(v) && v >= 0 && v <= 2048,
      ),
  );
  assert.equal(p.caRequestCounts[1], p.caRequestCounts[0] + 1);
  assert.equal(p.caRequestCounts[2], p.caRequestCounts[1]);
  assert.ok(
    Number.isSafeInteger(p.recordedAttempts) &&
      p.recordedAttempts >= 1 &&
      p.recordedAttempts <= 5,
  );
  const base = 15000 * 2 ** (p.recordedAttempts - 1);
  assert.ok(
    Number.isSafeInteger(p.retryDelayMs) &&
      p.retryDelayMs >= base * 0.8 &&
      p.retryDelayMs <= base * 1.2,
  );
  for (const flag of FLAGS) assert.equal(p[flag], true);
  assert.equal(p.atomicTreeContainmentQualified, false);
  assert.equal(p.backgroundTimerQualified, false);
  return true;
}
function readOriginalFile(file, expectedIdentity, maximum = 524288) {
  const identity = (s) => {
    assert.ok(s.isFile() && !s.isSymbolicLink() && s.ino > 0n && s.dev > 0n);
    return `${s.dev}:${s.ino}`;
  };
  const before = fs.lstatSync(file, { bigint: true });
  const id = identity(before);
  if (expectedIdentity) assert.equal(id, expectedIdentity);
  assert.ok(before.size > 0n && before.size <= BigInt(maximum));
  const fd = fs.openSync(
    file,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    assert.equal(identity(fs.fstatSync(fd, { bigint: true })), id);
    const buffer = Buffer.alloc(maximum + 1);
    let length = 0,
      count;
    while (
      length < buffer.length &&
      (count = fs.readSync(
        fd,
        buffer,
        length,
        buffer.length - length,
        length,
      )) > 0
    )
      length += count;
    const after = fs.fstatSync(fd, { bigint: true }),
      named = fs.lstatSync(file, { bigint: true });
    assert.equal(identity(after), id);
    assert.equal(identity(named), id);
    assert.equal(BigInt(length), before.size);
    assert.equal(after.size, before.size);
    assert.equal(named.size, before.size);
    assert.equal(after.mtimeNs, before.mtimeNs);
    assert.equal(after.ctimeNs, before.ctimeNs);
    assert.equal(named.mtimeNs, before.mtimeNs);
    assert.equal(named.ctimeNs, before.ctimeNs);
    assert.ok(length <= maximum);
    return { bytes: buffer.subarray(0, length), identity: id };
  } finally {
    fs.closeSync(fd);
  }
}

async function qualifyResultOutbox(c) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.ok(
    c.gate?.report,
    "Actual parent report is required for causal source binding",
  );
  c.gate.report.fixtureSources ??= [];
  for (const file of REQUIRED_SOURCES) {
    const digest = hash(
      fs.readFileSync(path.resolve(__dirname, "../../..", file)),
    );
    const existing = c.gate.report.fixtureSources.find(
      (row) => row.file === file,
    );
    if (existing)
      assert.equal(
        existing.sha256,
        digest,
        "Causal source changed within native qualification",
      );
    else c.gate.report.fixtureSources.push({ file, sha256: digest });
  }
  const {
    fixture,
    api,
    agentRowId,
    renewalFixture: current,
    configDir,
    workDir,
    run,
    command,
    ps,
    until,
    ownedEnrollmentIds,
    ownedStoreReceipt,
    ownedResultResources,
    configurationIdentity,
    tlsAuthority,
  } = c;
  assert.ok(Array.isArray(ownedResultResources));
  const { item, issuerId, certificateId, site, port, authority } = current;
  assert.match(run, /^[a-f0-9]{10}$/);
  assert.ok(uuid(issuerId) && uuid(certificateId) && uuid(agentRowId));
  assert.ok(Number.isInteger(port) && port > 0 && port < 65536);
  assert.equal(item.template, "TTQualificationRSAShort");
  assert.equal(item.domain, `certops-adcs-${run}-rsa2048.example.test`);
  assert.equal(site, `TTADCS-${run}-rsa2048`);
  assert.equal(ownedStoreReceipt.store, "My");
  assert.equal(ownedStoreReceipt.certificateId, certificateId);
  const root = path.resolve(workDir),
    guard = path.join(root, GUARD);
  active.add(root.toLowerCase());
  const guardBytes = Buffer.from(
    JSON.stringify({ token: crypto.randomUUID(), run }),
  );
  fs.writeFileSync(guard, guardBytes, { flag: "wx", mode: 0o600 });
  applyRestrictivePermissions(guard, { kind: "file" });
  const guardId = readOriginalFile(guard).identity;
  ownedStoreReceipt.resultOutboxPendingVerification = true;
  const register = (resource) => ownedResultResources.push(resource);
  const scm = service.createServiceController({
    workDir,
    configDir,
    ps,
    command,
    until,
    onCreated: register,
  });
  let completed = false,
    config,
    gateway;
  try {
    config = configuration.createConfigurationOwner({
      workDir,
      configDir,
      expectedIdentity: configurationIdentity,
      ps,
      verifyStopped: () => scm.assertStopped(),
    });
    const configObject = JSON.parse(
      readOriginalFile(
        path.join(configDir, "config.json"),
        configurationIdentity,
        65536,
      ).bytes,
    );
    const trust = readOriginalFile(
      configObject.caBundlePath,
      undefined,
      65536,
    ).bytes;
    gateway = await startOwnedResultGateway({
      upstreamUrl: config.originalServerUrl,
      upstreamCertificate: trust,
      onCreated: register,
    });
    const protectedFiles = ["credential", "signing-key-pin.json"].map(
      (name) => {
        const file = path.join(configDir, name),
          original = readOriginalFile(file, undefined, 65536);
        return {
          file,
          identity: original.identity,
          digest: hash(original.bytes),
          dacl: ps(configuration.permissionsScript(file)),
        };
      },
    );
    const verifyProtected = () => {
      for (const file of protectedFiles) {
        assert.ok(
          hash(readOriginalFile(file.file, file.identity, 65536).bytes) ===
            file.digest,
          "Original protected credential or pin changed",
        );
        assert.ok(
          ps(configuration.permissionsScript(file.file)) === file.dacl,
          "Original credential or pin DACL changed",
        );
      }
    };
    const native = (file, args) =>
      JSON.parse(
        command("powershell.exe", [
          "-NoProfile",
          "-NonInteractive",
          "-File",
          path.resolve(__dirname, "../../../infra/certops-adcs", file),
          ...args,
        ]),
      );
    const checkpoint = () =>
      native("owned-ca-checkpoint.ps1", ["-RunId", run])
        .nativeTotalRequestCount;
    const peer = () =>
      new Promise((resolve, reject) => {
        let leaf, failure;
        const socket = tls.connect(
          {
            host: "127.0.0.1",
            port,
            servername: item.domain,
            ca: tlsAuthority(authority),
            rejectUnauthorized: true,
          },
          () => {
            try {
              assert.equal(socket.authorized, true);
              leaf = new crypto.X509Certificate(
                socket.getPeerCertificate().raw,
              );
            } catch (error) {
              failure = error;
            }
            socket.destroy();
          },
        );
        socket.once("error", (error) => {
          failure = error;
          socket.destroy();
        });
        socket.once("close", () =>
          failure
            ? reject(failure)
            : leaf
              ? resolve(leaf)
              : reject(
                  new Error("Original trusted TLS observation incomplete"),
                ),
        );
        socket.setTimeout(10000, () => {
          failure = new Error("Native result fixture TLS deadline");
          socket.destroy();
        });
      });
    const challenge = crypto.randomBytes(32);
    const custody = (leaf, enrollmentId, jobId) => {
      const thumb = leaf.fingerprint.replace(/:/g, "").toUpperCase();
      const value = JSON.parse(
        ps(
          `$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumb}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);@{container=$k.Key.KeyName;unique=$k.Key.UniqueName;policy=[int]$k.Key.ExportPolicy;machine=$k.Key.IsMachineKey;provider=$k.Key.Provider.Provider;bits=$k.KeySize;der=[Convert]::ToBase64String($c.RawData);signature=[Convert]::ToBase64String($k.SignData([Convert]::FromBase64String('${challenge.toString("base64")}'),[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1))}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`,
        ),
      );
      assert.equal(value.policy, 0);
      assert.equal(value.machine, true);
      assert.equal(value.bits, 2048);
      assert.equal(value.provider, "Microsoft Software Key Storage Provider");
      assert.equal(
        crypto.verify(
          "sha256",
          challenge,
          leaf.publicKey,
          Buffer.from(value.signature, "base64"),
        ),
        true,
        "Actual protected machine key must sign for its public leaf",
      );
      assert.ok(
        value.container === buildEnrollmentContainerName(enrollmentId) &&
          value.unique &&
          Buffer.from(value.der, "base64").equals(leaf.raw),
        "Exact installed key and leaf ownership required",
      );
      const record = readIssuedContainerRecord({
        stateDir: configDir,
        containerName: value.container,
      });
      assert.equal(record?.status, "enrolled_by_agent");
      assert.equal(record.certificateId, certificateId);
      if (jobId) assert.equal(record.jobId, jobId);
      assert.equal(record.acceptedStore, "My");
      assert.equal(record.acceptedThumbprint, thumb);
      const binding = ps(
        `Import-Module WebAdministration;$b=@(Get-WebBinding -Name '${site}' -Protocol https|Where-Object bindingInformation -eq '*:${port}:${item.domain}');$s=@(Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object {[string]$_.GetValue('HostnamePort') -ieq '${item.domain}:${port}'});if($b.Count-ne 1-or$s.Count-ne 1-or$b[0].certificateStoreName-cne'My'-or[int]$b[0].sslFlags-ne 1-or[BitConverter]::ToString([byte[]]$s[0].GetValue('SslCertHash')).Replace('-','')-cne'${thumb}'-or[string]$s[0].GetValue('SslCertStoreName')-ine'My'){throw 'Exact native result fixture binding required'};$iisHash=$b[0].certificateHash;if($iisHash-is[byte[]]){$iisHash=[BitConverter]::ToString($iisHash).Replace('-','')};$iisHash=([string]$iisHash).ToUpperInvariant();if($iisHash-cne'${thumb}'){throw 'Exact IIS result certificate hash required'};@{iisHash=$iisHash;iisStore=[string]$b[0].certificateStoreName;coordinates=[string]$b[0].bindingInformation;flags=[int]$b[0].sslFlags;settings=@($s[0].GetValueNames()|Sort-Object|ForEach-Object {@{name=$_;kind=$s[0].GetValueKind($_).ToString();value=$s[0].GetValue($_)}})}|ConvertTo-Json -Depth 8 -Compress`,
      );
      return { value, record, binding };
    };
    const original = await peer();
    assert.equal(original.fingerprint256, current.observed.fingerprint256);
    assert.equal(
      (
        await fixture.pool.query(
          "SELECT count(*)::int AS count FROM certificate_jobs j LEFT JOIN certificate_enrollments e ON e.workspace_id=j.workspace_id AND e.current_job_id=j.id WHERE j.status IN ('pending','pending_approval','approved','claimed','running') OR (j.status='awaiting_issuer' AND e.state IN ('requested','prepared','submitting','pending_issuance','submission_uncertain','issued','validation_deferred','validated','installing','install_failed'))",
        )
      ).rows[0].count,
      0,
      "Result restart fixture requires otherwise idle agent admission",
    );
    const counts = [checkpoint()];
    await scm.stop();
    verifyProtected();
    config.applyGateway(gateway.agentUrl);
    await scm.start();
    const response = await fixture.request(`${api}/enrollments`, "POST", {
      issuerId,
      certificateId,
      agentId: agentRowId,
      target: {
        type: "windows-iis",
        reference: item.domain,
        store: "My",
        binding: { site, port, sniHost: item.domain },
      },
      authorizedDnsNames: [item.domain],
      keyAlgorithm: "rsa",
      keySize: 2048,
    });
    assert.equal(response.status, 201);
    const { enrollmentId, jobId } = response.body;
    assert.ok(uuid(enrollmentId) && uuid(jobId));
    ownedEnrollmentIds.push(enrollmentId);
    ownedStoreReceipt.enrollmentIds.push(enrollmentId);
    gateway.selectJob(jobId);
    const job = async () =>
      (
        await fixture.pool.query(
          "SELECT j.id,j.status,j.executor_kind,j.claim_id,j.claimed_by_agent_id,j.attempt_count,j.lease_expires_at,(SELECT count(*)::int FROM certops_consumed_nonces n WHERE n.workspace_id=j.workspace_id AND n.job_id=j.id AND n.issued_to_agent_id=$3 AND n.consumed_at IS NOT NULL) AS consumed_nonces FROM certificate_jobs j WHERE j.workspace_id=$1 AND j.id=$2",
          [fixture.workspaceId, jobId, agentRowId],
        )
      ).rows[0];
    const running = await until(async () => {
      const row = await job();
      return row?.status === "running" && uuid(row.claim_id) ? row : null;
    });
    assert.equal(running.executor_kind, "agent");
    assert.equal(running.attempt_count, 1);
    assert.equal(running.claimed_by_agent_id, agentRowId);
    gateway.bindClaim(running.claim_id);
    const outbox = path.join(configDir, "outbox");
    const persisted = await until(() => {
      if (gateway.observation().refusedResults < 1) return null;
      const values = fs
        .readdirSync(outbox)
        .filter((name) => /^outbox-[a-f0-9]{24}\.json$/.test(name))
        .map((name) => ({ name, ...readOriginalFile(path.join(outbox, name)) }))
        .map((v) => ({ ...v, entry: JSON.parse(v.bytes) }))
        .filter((v) => v.entry.result?.jobId === jobId);
      assert.ok(values.length <= 1);
      return values[0]?.entry.attempts >= 1 ? values[0] : null;
    });
    verifyPersisted(persisted.entry, jobId, running.claim_id, enrollmentId);
    const leaf = await peer();
    assert.notEqual(leaf.fingerprint256, original.fingerprint256);
    assert.notEqual(leaf.serialNumber, original.serialNumber);
    assert.ok(
      !leaf.publicKey
        .export({ format: "der", type: "spki" })
        .equals(original.publicKey.export({ format: "der", type: "spki" })),
      "Real renewal must generate a fresh protected key",
    );
    const journal = readEnrollmentJournal({
      stateDir: configDir,
      enrollmentId,
    });
    assert.equal(journal.kind, "valid");
    assert.equal(journal.journal.state, "installed");
    assert.equal(journal.journal.jobId, jobId);
    assert.ok(
      new crypto.X509Certificate(journal.artifacts.leafPem).raw.equals(
        leaf.raw,
      ),
    );
    const request = native("owned-issued-request.ps1", [
      "-CommonName",
      item.domain,
      "-FingerprintSha256",
      hash(leaf.raw),
    ]);
    verifyNativeRequestId(request.requestId, journal.journal.requestId);
    assert.equal(request.disposition, 20);
    const before = custody(leaf, enrollmentId, jobId);
    counts.push(checkpoint());
    assert.equal(counts[1], counts[0] + 1);
    ownedStoreReceipt.thumbprints.push(
      leaf.fingerprint.replace(/:/g, "").toUpperCase(),
    );
    await scm.stop();
    verifyProtected();
    const stoppedEntry = JSON.parse(
      readOriginalFile(path.join(outbox, persisted.name)).bytes,
    );
    const due = verifyPersisted(
      stoppedEntry,
      jobId,
      running.claim_id,
      enrollmentId,
    );
    assert.ok(
      isDeepStrictEqual(stoppedEntry.result, persisted.entry.result),
      "Durable original successful result changed",
    );
    const stoppedJob = await job();
    assert.equal(stoppedJob.status, "running");
    assert.equal(stoppedJob.claim_id, running.claim_id);
    assert.ok(
      Date.parse(stoppedJob.lease_expires_at) - Math.max(Date.now(), due) >
        120000,
      "Do not restart delivery without original live claim headroom",
    );
    gateway.restoreDelivery();
    await scm.start();
    const final = await until(
      async () => {
        const row = await job();
        return row?.status === "succeeded" &&
          !fs.existsSync(path.join(outbox, persisted.name))
          ? row
          : null;
      },
      Math.max(180000, due - Date.now() + 120000),
    );
    assert.ok(
      Date.now() >= due,
      "Actual production retry deadline must elapse",
    );
    assert.equal(final.executor_kind, "agent");
    assert.equal(final.claim_id, running.claim_id);
    assert.equal(final.claimed_by_agent_id, agentRowId);
    assert.equal(final.attempt_count, 1);
    assert.equal(final.consumed_nonces, 1);
    const evidence = (
      await fixture.pool.query(
        "SELECT claim_id,metadata FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 AND claim_id=$3 AND evidence_type='validation.passed' AND metadata->>'step'='verify'",
        [fixture.workspaceId, jobId, running.claim_id],
      )
    ).rows;
    verifyInstalledEvidence(final, evidence, leaf);
    const finalEnrollment = (
      await fixture.pool.query(
        "SELECT state,current_job_id,request_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",
        [fixture.workspaceId, enrollmentId],
      )
    ).rows[0];
    assert.equal(finalEnrollment.state, "installed");
    assert.equal(finalEnrollment.current_job_id, jobId);
    verifyNativeRequestId(request.requestId, finalEnrollment.request_id);
    const finalJournal = readEnrollmentJournal({
      stateDir: configDir,
      enrollmentId,
    });
    assert.ok(
      isDeepStrictEqual(finalJournal, journal),
      "Restart must preserve the exact installed enrollment journal and artifacts",
    );
    const gatewayResult = gateway.observation();
    assert.ok(
      gatewayResult.gatewayHealthy &&
        gatewayResult.forwardedResults >= 1 &&
        gatewayResult.mismatchedResults === 0,
    );
    assert.ok(
      isDeepStrictEqual(custody(leaf, enrollmentId, jobId), before),
      "Native result restart changed CNG/IIS custody",
    );
    assert.equal((await peer()).fingerprint256, leaf.fingerprint256);
    counts.push(checkpoint());
    assert.equal(counts[2], counts[1]);
    const dead = path.join(outbox, "dead-letter");
    if (fs.existsSync(dead)) assert.equal(fs.readdirSync(dead).length, 0);
    await scm.stop();
    verifyProtected();
    config.restore();
    const originalRestartAt = Date.now();
    await scm.start();
    await until(async () => {
      const row = (
        await fixture.pool.query(
          "SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND id=$2",
          [fixture.workspaceId, agentRowId],
        )
      ).rows[0];
      return row && Date.parse(row.last_seen_at) >= originalRestartAt;
    });
    verifyProtected();
    assert.equal((await peer()).fingerprint256, leaf.fingerprint256);
    await gateway.close();
    config.complete();
    assert.equal(gateway.hasLiveResource(), false);
    assert.ok(
      ownedResultResources.every(
        (resource) =>
          !(resource.hasLiveChild
            ? resource.hasLiveChild()
            : resource.hasLiveResource()) &&
          !(resource.hasOwnershipReceipt && resource.hasOwnershipReceipt()),
      ),
      "Every owned result gateway/observer must release",
    );
    assert.ok(readOriginalFile(guard, guardId).bytes.equals(guardBytes));
    fs.unlinkSync(guard);
    active.delete(root.toLowerCase());
    ownedStoreReceipt.resultOutboxPendingVerification = false;
    current.observed = leaf;
    current.currentEnrollmentId = enrollmentId;
    current.thumbprint = leaf.fingerprint.replace(/:/g, "").toUpperCase();
    const proof = {
      scope: SCOPE,
      enrollmentId,
      jobId,
      claimId: final.claim_id,
      requestId: request.requestId,
      fingerprints: [hash(original.raw), hash(leaf.raw)],
      caRequestCounts: counts,
      recordedAttempts: stoppedEntry.attempts,
      retryDelayMs: due - Date.parse(stoppedEntry.lastAttemptAt),
      atomicTreeContainmentQualified: false,
      backgroundTimerQualified: false,
      ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
    };
    verifyProof(proof);
    completed = true;
    return proof;
  } finally {
    if (!completed) {
      // Unknown native operation is never followed by speculative restoration.
      // Retain the config FD guard/state and close only the exact gateway.
      try {
        if (config) config.close();
      } finally {
        try {
          if (gateway) await gateway.close();
        } finally {
          const drains = await Promise.allSettled(
            ownedResultResources
              .filter((resource) => resource.waitForClose)
              .map((resource) => resource.waitForClose()),
          );
          assert.ok(
            drains.every((result) => result.status === "fulfilled"),
            "Preserve unresolved original service observer drainage",
          );
        }
      }
    }
  }
}
module.exports = {
  SCENARIO,
  REQUIRED_SOURCES,
  FIELD,
  SCOPE,
  FLAGS,
  verifyPersisted,
  verifyProof,
  readOriginalFile,
  assertCleanupSafe,
  qualifyResultOutbox,
};
