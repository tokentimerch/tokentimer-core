"use strict";
/* Actual configured five-minute native validation-deferral expiry: preserve its recorded deadline
 * through restart, wait real time and verify exact unaccepted-key cleanup under a scoped CRL
 * outage. Called only by the protected disposable-forest AD CS harness; native qualification
 * requires that workflow to execute.
 */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  tls = require("node:tls");
const { createCrlFault } = require("./certops-adcs-crl-fault");
const {
  readEnrollmentJournal,
} = require("../../../packages/agent/src/issuers/adcs-enrollment");
const {
  buildEnrollmentContainerName,
} = require("../../../packages/agent/src/windows-cert-store");
const deferredIdentityContract = require("./certops-adcs-deferred-identity");
const { verifyNativeRequestId } = require("./certops-adcs-live-enroll-acl");
async function qualifyValidationExpiry({
  gate,
  fixture,
  api,
  agentRowId,
  renewalFixture,
  configDir,
  workDir,
  run,
  command,
  ps,
  until,
  ownedEnrollmentIds,
  ownedFirewallRules,
  tlsAuthority,
}) {
  await gate.scenario(
    "adcs-real-elapsed-validation-deadline-frees-unaccepted-key",
    async () => {
      assert.equal(process.platform, "win32");
      assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
      const { item, issuerId, site, port, certificateId, authority, observed } =
        renewalFixture;
      const root = path.resolve(__dirname, "../../.."),
        configPath = path.join(configDir, "config.json"),
        original = fs.readFileSync(configPath),
        credential = fs.readFileSync(path.join(configDir, "credential"));
      gate.report.fixtureSources ??= [];
      for (const file of [
        "tests/e2e/helpers/certops-adcs-validation-expiry.js",
        "packages/agent/src/issuers/adcs-validation-deadline.js",
        "tests/e2e/helpers/certops-adcs-deferred-identity.js",
      ])
        if (!gate.report.fixtureSources.some((row) => row.file === file))
          gate.report.fixtureSources.push({
            file,
            sha256: crypto
              .createHash("sha256")
              .update(fs.readFileSync(path.join(root, file)))
              .digest("hex"),
          });
      const fault = createCrlFault({
        gate,
        workDir,
        run,
        observed,
        authority,
        command,
        ps,
        ownedFirewallRules,
      });
      const checkpoint = () =>
        JSON.parse(
          command("powershell.exe", [
            "-NoProfile",
            "-NonInteractive",
            "-File",
            path.join(root, "infra/certops-adcs/owned-ca-checkpoint.ps1"),
            "-RunId",
            run,
          ]),
        );
      const served = () =>
        new Promise((resolve, reject) => {
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
                resolve(socket.getPeerCertificate().fingerprint256);
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
              new Error("Validation expiry trusted TLS oracle timed out"),
            ),
          );
        });
      const restart = async () => {
        const before = (
          await fixture.pool.query(
            "SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND id=$2",
            [fixture.workspaceId, agentRowId],
          )
        ).rows[0].last_seen_at;
        command("sc.exe", ["stop", "TokenTimerAgent"]);
        await until(
          () => ps("(Get-Service TokenTimerAgent).Status") === "Stopped",
          30000,
        );
        command("sc.exe", ["start", "TokenTimerAgent"]);
        await until(
          async () =>
            Date.parse(
              (
                await fixture.pool.query(
                  "SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND id=$2",
                  [fixture.workspaceId, agentRowId],
                )
              ).rows[0].last_seen_at,
            ) > Date.parse(before),
          45000,
        );
        assert.ok(
          fs
            .readFileSync(path.join(configDir, "credential"))
            .equals(credential),
        );
      };
      let primaryError, enrollmentId, requestId;
      const cleanupErrors = [];
      try {
        const config = JSON.parse(original);
        config.adcs.validationTimeoutSeconds = 300;
        fs.writeFileSync(configPath, JSON.stringify(config));
        await restart();
        assert.equal(
          (await fault.probe()).verdict,
          "valid",
          "Actual outgoing certificate must pass native online chain validation before the fault",
        );
        const before = checkpoint();
        assert.equal(await served(), observed.fingerprint256);
        await fault.install();
        const created = await fixture.request(`${api}/enrollments`, "POST", {
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
          pollInterval: 60,
        });
        assert.equal(created.status, 201);
        enrollmentId = created.body.enrollmentId;
        ownedEnrollmentIds.push(enrollmentId);
        const row = async () =>
          (
            await fixture.pool.query(
              "SELECT state,request_id,next_poll_at,snapshot_sha256,current_job_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",
              [fixture.workspaceId, enrollmentId],
            )
          ).rows[0];
        const deferred = await until(async () => {
          const value = await row();
          return deferredIdentityContract.isDeferredPollReady(value)
            ? value
            : null;
        });
        const receipt = readEnrollmentJournal(configDir, enrollmentId);
        assert.equal(receipt.kind, "valid");
        assert.equal(receipt.journal.state, "validation_deferred");
        const deadline = receipt.journal.validationDeadlineAt,
          deadlineMs = Date.parse(deadline),
          windowMs = deadlineMs - Date.parse(receipt.journal.updatedAt);
        assert.ok(
          windowMs >= 270000 && windowMs <= 300000,
          "Native persisted deadline must reflect the bounded local five-minute configuration",
        );
        const incoming = new crypto.X509Certificate(receipt.artifacts.leafPem);
        assert.equal(incoming.checkHost(item.domain), item.domain);
        assert.equal(
          incoming.verify(
            new crypto.X509Certificate(
              Buffer.from(authority.certificateB64, "base64"),
            ).publicKey,
          ),
          true,
        );
        const observeIssued = () =>
          JSON.parse(
            command("powershell.exe", [
              "-NoProfile",
              "-NonInteractive",
              "-File",
              path.join(root, "infra/certops-adcs/owned-issued-request.ps1"),
              "-CommonName",
              item.domain,
              "-FingerprintSha256",
              incoming.fingerprint256.replace(/:/g, "").toLowerCase(),
            ]),
          );
        const deferredIdentity = deferredIdentityContract.observe({
          row: deferred,
          journal: receipt,
          nativeRequest: observeIssued(),
          jobId: created.body.jobId,
          state: "validation_deferred",
        });
        requestId = deferredIdentity.requestId;
        const afterIssue = checkpoint();
        assert.equal(
          afterIssue.nativeTotalRequestCount,
          before.nativeTotalRequestCount + 1,
        );
        const container = buildEnrollmentContainerName(enrollmentId);
        const hasKey = () =>
          ps(
            `[Security.Cryptography.CngKey]::Exists('${container}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`,
          );
        assert.equal(hasKey(), "True");
        const waitingStarted = process.hrtime.bigint();
        // A restart with the original (normally 24-hour) policy cannot extend a
        // deadline already committed to the actual enrollment journal.
        fs.writeFileSync(configPath, original);
        await restart();
        assert.equal(
          readEnrollmentJournal(configDir, enrollmentId).journal
            .validationDeadlineAt,
          deadline,
        );
        const elapsedMs = () =>
          Number(process.hrtime.bigint() - waitingStarted) / 1e6;
        while (elapsedMs() < 300000) {
          const current = await row();
          assert.equal(current.snapshot_sha256, deferred.snapshot_sha256);
          verifyNativeRequestId(
            requestId,
            current.request_id,
            readEnrollmentJournal(configDir, enrollmentId).journal.requestId,
          );
          assert.equal(
            readEnrollmentJournal(configDir, enrollmentId).journal
              .validationDeadlineAt,
            deadline,
          );
          if (Date.now() < deadlineMs) {
            assert.equal(current.state, "validation_deferred");
            assert.equal(hasKey(), "True");
          }
          await require("../../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments(
            { client: fixture.pool },
          );
          await new Promise((resolve) =>
            setTimeout(
              resolve,
              Math.min(10000, Math.max(1, 300000 - elapsedMs())),
            ),
          );
        }
        assert.ok(
          Date.now() > deadlineMs,
          "Actual native deadline must elapse without clock overrides",
        );
        const expired = await until(async () => {
          await require("../../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments(
            { client: fixture.pool },
          );
          const value = await row();
          return value.state === "validation_expired" ? value : null;
        }, 180000);
        const final = readEnrollmentJournal(configDir, enrollmentId);
        assert.equal(final.kind, "valid");
        assert.equal(final.journal.state, "validation_expired");
        assert.equal(final.journal.validationDeadlineAt, deadline);
        assert.equal(final.journal.snapshotSha256, deferred.snapshot_sha256);
        const finalNative = observeIssued();
        assert.equal(finalNative.disposition, 20);
        assert.equal(finalNative.requestId, requestId);
        verifyNativeRequestId(
          requestId,
          expired.request_id,
          final.journal.requestId,
        );
        assert.equal(hasKey(), "False");
        const thumbprint = incoming.fingerprint.replace(/:/g, "");
        assert.equal(
          ps(
            `$found=@();foreach($store in @('My','WebHosting')){$p='Cert:\\LocalMachine\\'+$store;if(Test-Path -LiteralPath $p){$found+=@(Get-ChildItem -LiteralPath $p|Where-Object Thumbprint -eq '${thumbprint}')}};$found.Count`,
          ),
          "0",
        );
        assert.deepEqual(checkpoint(), afterIssue);
        assert.equal(await served(), observed.fingerprint256);
        gate.report.nativeValidationExpiry = {
          configuredTimeoutSeconds: 300,
          defaultTimeoutSeconds: 86400,
          storedWindowSeconds: windowMs / 1000,
          monotonicObservedWaitSeconds: elapsedMs() / 1000,
          actualDeadline: deadline,
          requestId: String(requestId),
          snapshotSha256: deferred.snapshot_sha256,
          actualNativeRevocationUnknown: true,
          actualSignedContinuationExpired: true,
          persistedDeadlineSurvivedRestartAndPolicyRestoration: true,
          exactUnacceptedKeyFreed: true,
          noCertificateAccepted: true,
          noCaResubmission: true,
          outgoingTrustedTlsPreserved: true,
          nativeAndCaClocks: "actual",
          qualificationScope:
            "configured-five-minute-window-not-default-24-hour-elapsed",
        };
      } catch (error) {
        primaryError = error;
      } finally {
        try {
          await fault.close(primaryError);
        } catch (error) {
          cleanupErrors.push(error);
        }
        try {
          fs.writeFileSync(configPath, original);
          await restart();
        } catch (error) {
          cleanupErrors.push(error);
        }
        if (requestId)
          try {
            command("powershell.exe", [
              "-NoProfile",
              "-NonInteractive",
              "-File",
              path.join(root, "infra/certops-adcs/officer-action.ps1"),
              "-RequestId",
              String(requestId),
              "-Action",
              "revoke",
              "-CommonName",
              item.domain,
            ]);
          } catch (error) {
            cleanupErrors.push(error);
          }
      }
      if (gate.report.nativeValidationExpiry)
        gate.report.nativeValidationExpiry.chainCacheValueRestored =
          fault.cacheRestored;
      if (cleanupErrors.length)
        throw new AggregateError(
          [...(primaryError ? [primaryError] : []), ...cleanupErrors],
          "Actual elapsed validation-expiry fixture or cleanup failed",
        );
      if (primaryError) throw primaryError;
    },
    {
      evidenceLevel: "real-host",
      oracle:
        "genuine native program-scoped CRL outage, public60-second poll policy, locally configured actual five-minute deadline retained across real SYSTEM restart, monotonic real wait and actual-clock signed continuation frees only the unaccepted key; no journal/DB date rewriting",
    },
  );
}
module.exports = { qualifyValidationExpiry };
