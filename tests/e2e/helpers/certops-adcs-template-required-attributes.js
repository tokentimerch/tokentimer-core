"use strict";
/** Live required-attribute boundaries absent from the original template cases.
 * This source invokes only the owned lab mutator and genuine native/public
 * preflight/enrollment paths. Parent cleanup must retain all state while any
 * registered LDAP restoration receipt is unresolved. Disposable qualification CA only.
 */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  tls = require("node:tls");
const { isDeepStrictEqual } = require("node:util");
const descriptor = require("../../../infra/certops-adcs/template-required-attribute-cases.json");
const {
  readEnrollmentJournal,
} = require("../../../packages/agent/src/issuers/adcs-enrollment");
const {
  buildEnrollmentContainerName,
  readIssuedContainerRecord,
} = require("../../../packages/agent/src/windows-cert-store");
const SCOPE =
  "actual-ldap-required-template-attribute-refusal-and-exact-native-restoration";
const REQUIRED_SCENARIOS = Object.freeze(
  descriptor.cases.map(
    (value) => `adcs-real-required-template-${value.id}-refused-restored`,
  ),
);
const FLAGS = Object.freeze([
  "knownSafeNativeControlBefore",
  "restorationRegisteredBeforeMutation",
  "actualLdapMutationObserved",
  "actualNativePreflightUnreadable",
  "publicConfirmationRefused",
  "signedInstalledJobRefused",
  "noCaRequestOrCngAllocation",
  "installedPredecessorPreserved",
  "exactOriginalAttributesRestored",
  "freshNativeSafeControlAfter",
  "originalConfigCredentialPreserved",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-adcs-template-required-attributes.js",
  "infra/certops-adcs/template-required-attribute-cases.json",
  "infra/certops-adcs/template-safety-mutation.ps1",
  "tests/e2e/helpers/certops-adcs-preflight-cohorts.js",
  "infra/certops-adcs/owned-ca-checkpoint.ps1",
  "packages/agent/src/issuers/adcs-preflight.js",
  "packages/agent/src/config/index.js",
  "packages/agent/src/adcs-windows-iis.js",
  "packages/agent/src/issuers/adcs-enrollment.js",
  "packages/agent/src/windows-cert-store/index.js",
]);
const registered = new WeakSet(),
  hex = /^[a-f0-9]{64}$/,
  uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const digest = (value) =>
  crypto.createHash("sha256").update(value).digest("hex");
function verifyProof(value) {
  assert.deepEqual(
    Object.keys(value).sort(),
    ["scope", "cases", "predecessorFingerprint", "templateOid"].sort(),
  );
  assert.equal(value.scope, SCOPE);
  assert.match(value.predecessorFingerprint, hex);
  assert.match(value.templateOid, /^\d+(?:\.\d+)+$/);
  assert.ok(Array.isArray(value.cases));
  assert.equal(value.cases.length, descriptor.cases.length);
  for (let index = 0; index < descriptor.cases.length; index++) {
    const item = value.cases[index],
      expected = descriptor.cases[index];
    assert.deepEqual(
      Object.keys(item).sort(),
      [
        "caseId",
        "preflightVerdict",
        "reason",
        "observedField",
        "observedValue",
        "enrollmentId",
        "jobId",
        ...FLAGS,
      ].sort(),
    );
    assert.equal(item.caseId, expected.id);
    assert.equal(item.preflightVerdict, "unreadable");
    assert.equal(item.reason, "template_unreadable");
    assert.equal(item.observedField, expected.observedField);
    assert.equal(item.observedValue, expected.observedValue);
    assert.match(item.enrollmentId, uuid);
    assert.match(item.jobId, uuid);
    assert.notEqual(item.enrollmentId, item.jobId);
    for (const flag of FLAGS) assert.equal(item[flag], true);
  }
  assert.equal(
    new Set(value.cases.flatMap((item) => [item.enrollmentId, item.jobId]))
      .size,
    descriptor.cases.length * 2,
  );
  return true;
}
function assertCleanupSafe(receipts) {
  assert.ok(Array.isArray(receipts));
  for (const receipt of receipts) {
    assert.ok(
      registered.has(receipt),
      "Unknown LDAP restoration receipt cannot authorize cleanup",
    );
    assert.equal(
      receipt.restored,
      true,
      "Preserve native/public state while owned template restoration is unresolved",
    );
  }
}
async function qualifyRequiredTemplateAttributes(context) {
  const {
    gate,
    fixture,
    api,
    caConfig,
    agentRowId,
    renewalFixture: live,
    preflightCohorts,
    run,
    command,
    ps,
    until,
    configDir,
    ownedEnrollmentIds,
    ownedTemplateAttributeRestorations,
    tlsAuthority,
    serviceOwned,
  } = context;
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.equal(serviceOwned, true);
  assert.match(run, /^[a-f0-9]{10}$/);
  assert.ok(Array.isArray(ownedTemplateAttributeRestorations));
  assert.equal(
    ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),
    "S-1-5-18",
  );
  assert.equal(live.item.template, "TTQualificationRSAShort");
  const root = path.resolve(__dirname, "../../.."),
    query = (sql, values = []) => fixture.pool.query(sql, values),
    original = readEnrollmentJournal(configDir, live.currentEnrollmentId);
  assert.equal(original.kind, "valid");
  assert.equal(original.journal.state, "installed");
  const predecessor = new crypto.X509Certificate(original.artifacts.leafPem);
  assert.equal(predecessor.fingerprint256, live.observed.fingerprint256);
  assert.equal(
    original.journal.containerName,
    buildEnrollmentContainerName(live.currentEnrollmentId),
  );
  const configFile = path.join(configDir, "config.json"),
    credentialFile = path.join(configDir, "credential"),
    configBefore = fs.readFileSync(configFile),
    credentialBefore = fs.readFileSync(credentialFile);
  const originalRecord = readIssuedContainerRecord({
    stateDir: configDir,
    containerName: original.journal.containerName,
  });
  assert.equal(originalRecord?.status, "enrolled_by_agent");
  assert.equal(originalRecord.acceptedStore, "My");
  const peer = () =>
    new Promise((resolve, reject) => {
      const socket = tls.connect(
        {
          host: "127.0.0.1",
          port: live.port,
          servername: live.item.domain,
          ca: tlsAuthority(live.authority),
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
          new Error(
            "Required template attribute trusted TLS deadline exceeded",
          ),
        ),
      );
    });
  const custody = () =>
      ps(
        `$c=Get-Item 'Cert:\\LocalMachine\\My\\${predecessor.fingerprint.replace(/:/g, "")}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);if(!$k-or!$k.Key.IsMachineKey-or[int]$k.Key.ExportPolicy-ne 0-or$k.Key.KeyName-ne'${original.journal.containerName}'){throw 'Owned predecessor CNG association required'};$h=[Security.Cryptography.SHA256]::Create();try{[Convert]::ToBase64String($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($k.Key.UniqueName)))}finally{$h.Dispose()}}finally{if($k){$k.Dispose()};$c.Dispose()}`,
      ),
    nativeBefore = custody();
  const endpoint = () =>
    require("../../../packages/agent/src/windows-iis").queryCurrentBinding({
      binding: { site: live.site, port: live.port, sniHost: live.item.domain },
    });
  const bindingBefore = await endpoint();
  assert.equal(bindingBefore.ok, true);
  assert.equal(
    bindingBefore.thumbprint.toLowerCase(),
    predecessor.fingerprint.replace(/:/g, "").toLowerCase(),
  );
  const preserve = async () => {
    assert.equal(await peer(), predecessor.fingerprint256);
    assert.ok(
      custody() === nativeBefore,
      "Owned predecessor native key identity changed",
    );
    assert.ok(
      isDeepStrictEqual(await endpoint(), bindingBefore),
      "Owned predecessor binding changed",
    );
    assert.ok(
      isDeepStrictEqual(
        readIssuedContainerRecord({
          stateDir: configDir,
          containerName: original.journal.containerName,
        }),
        originalRecord,
      ),
      "Owned predecessor accepted record changed",
    );
    assert.ok(
      fs.readFileSync(configFile).equals(configBefore),
      "Original agent configuration changed",
    );
    assert.ok(
      fs.readFileSync(credentialFile).equals(credentialBefore),
      "Original registered credential changed",
    );
  };
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
  const restart = async () => {
    const cutoff = (await query("SELECT clock_timestamp() AS cutoff")).rows[0]
      .cutoff;
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
            await query(
              "SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND id=$2",
              [fixture.workspaceId, agentRowId],
            )
          ).rows[0].last_seen_at,
        ) > Date.parse(cutoff),
      45000,
    );
  };
  gate.report.fixtureSources ??= [];
  for (const file of REQUIRED_SOURCES) {
    const sha256 = digest(fs.readFileSync(path.join(root, file))),
      matches = gate.report.fixtureSources.filter((item) => item.file === file);
    if (matches.length) {
      assert.equal(matches.length, 1);
      assert.equal(matches[0].sha256, sha256);
    } else gate.report.fixtureSources.push({ file, sha256 });
  }
  const facts = [];
  let templateOid;
  for (let index = 0; index < descriptor.cases.length; index++) {
    const selected = descriptor.cases[index];
    await gate.scenario(
      REQUIRED_SCENARIOS[index],
      async () => {
        const knownSafe = await preflightCohorts.preflight(live.item.template);
        assert.equal(knownSafe.result.templateCheck.verdict, "safe");
        assert.equal(knownSafe.result.caCheck.verdict, "safe");
        assert.match(
          knownSafe.result.templateCheck.templateOid,
          /^\d+(?:\.\d+)+$/,
        );
        if (templateOid)
          assert.equal(knownSafe.result.templateCheck.templateOid, templateOid);
        else templateOid = knownSafe.result.templateCheck.templateOid;
        assert.equal(knownSafe.result.templateCheck.minimalKeySize, 2048);
        assert.equal(
          knownSafe.result.templateCheck.enrolleeSuppliesSubject,
          true,
        );
        await preserve();
        const before = checkpoint();
        const receipt = {
          caseId: selected.id,
          ownershipToken: crypto.randomUUID(),
          restored: false,
        };
        registered.add(receipt);
        ownedTemplateAttributeRestorations.push(receipt);
        const mutate = (action) =>
          JSON.parse(
            command("powershell.exe", [
              "-NoProfile",
              "-NonInteractive",
              "-File",
              path.join(
                root,
                "infra/certops-adcs/template-safety-mutation.ps1",
              ),
              "-Action",
              action,
              "-CaseId",
              selected.id,
              "-RunId",
              run,
              "-OwnershipToken",
              receipt.ownershipToken,
            ]),
          );
        let primary, cleanup;
        let admitted, actual;
        try {
          assert.equal(mutate("apply").applied, true);
          await restart();
          actual = await preflightCohorts.preflight(live.item.template);
          assert.equal(
            actual.result.caCheck.verdict,
            "safe",
            "Only the live template predicate may make confirmation unsafe",
          );
          assert.ok(
            actual.result.caCertificates.some(
              (value) => value.keySha256 === live.authority.keySha256,
            ),
          );
          assert.equal(actual.result.caConfig, caConfig);
          assert.equal(actual.result.template, live.item.template);
          const observed = actual.result.templateCheck;
          assert.equal(observed.verdict, "unreadable");
          assert.ok(observed.reasons.includes("template_unreadable"));
          assert.equal(
            observed[selected.observedField],
            selected.observedValue,
          );
          assert.equal(observed.templateOid, templateOid);
          const confirmation = await actual.confirm({
            caKeySha256: live.authority.keySha256,
            caConfig: actual.result.caConfig,
            template: live.item.template,
          });
          assert.equal(confirmation.status, 400);
          assert.equal(confirmation.body.code, "CERTOPS_SNAPSHOT_INVALID");
          admitted = await fixture.request(`${api}/enrollments`, "POST", {
            issuerId: live.issuerId,
            certificateId: live.certificateId,
            agentId: agentRowId,
            target: {
              type: "windows-iis",
              reference: live.item.domain,
              store: "My",
              binding: {
                site: live.site,
                port: live.port,
                sniHost: live.item.domain,
              },
            },
            authorizedDnsNames: [live.item.domain],
            keyAlgorithm: "rsa",
            keySize: 2048,
          });
          assert.equal(admitted.status, 201);
          ownedEnrollmentIds.push(admitted.body.enrollmentId);
          const outcome = await until(async () => {
            const value = (
              await query(
                "SELECT status,result_metadata,claim_id,claimed_by_agent_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
                [fixture.workspaceId, admitted.body.jobId],
              )
            ).rows[0];
            if (value?.status === "succeeded")
              throw new Error("Unreadable live template was issued");
            return value?.status === "failed" ? value : null;
          });
          assert.equal(
            outcome.result_metadata.enrollmentResult.state,
            "refused",
          );
          assert.equal(
            outcome.result_metadata.enrollmentResult.errorCode,
            "ADCS_TEMPLATE_UNSAFE",
          );
          assert.match(outcome.claim_id, uuid);
          assert.equal(outcome.claimed_by_agent_id, agentRowId);
          assert.ok(
            isDeepStrictEqual(checkpoint(), before),
            "Template refusal must precede any actual CA request",
          );
          assert.equal(
            ps(
              `[Security.Cryptography.CngKey]::Exists('${buildEnrollmentContainerName(admitted.body.enrollmentId)}',[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)`,
            ),
            "False",
          );
          await preserve();
        } catch (error) {
          primary = error;
        } finally {
          try {
            const restored = mutate("restore");
            assert.equal(restored.restored, true);
            assert.equal(restored.exactPublicAttributesVerified, true);
            await restart();
            const safe = await preflightCohorts.preflight(live.item.template);
            assert.equal(safe.result.templateCheck.verdict, "safe");
            assert.equal(safe.result.caCheck.verdict, "safe");
            assert.ok(
              isDeepStrictEqual(
                safe.result.templateCheck,
                knownSafe.result.templateCheck,
              ),
              "Restored native template descriptor must match the original known-safe control",
            );
            await preserve();
            receipt.restored = true;
          } catch (error) {
            cleanup = error;
          }
        }
        if (cleanup)
          throw new AggregateError(
            [...(primary ? [primary] : []), cleanup],
            "Owned LDAP template restoration unproven; preserve all fixture state",
          );
        if (primary) throw primary;
        facts.push({
          caseId: selected.id,
          preflightVerdict: actual.result.templateCheck.verdict,
          reason: "template_unreadable",
          observedField: selected.observedField,
          observedValue: selected.observedValue,
          enrollmentId: admitted.body.enrollmentId,
          jobId: admitted.body.jobId,
          ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
        });
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "Actual owned LDAP zero/missing required attribute reaches native unreadable preflight, public confirmation and signed pre-key refusal; exact restoration and independent fresh safe descriptor preserve serving custody/TLS",
      },
    );
  }
  const value = {
    scope: SCOPE,
    cases: facts,
    predecessorFingerprint: predecessor.fingerprint256
      .replace(/:/g, "")
      .toLowerCase(),
    templateOid,
  };
  verifyProof(value);
  gate.report.nativeRequiredTemplateAttributes = value;
  return value;
}
module.exports = {
  SCOPE,
  FLAGS,
  REQUIRED_SCENARIOS,
  REQUIRED_SOURCES,
  verifyProof,
  assertCleanupSafe,
  qualifyRequiredTemplateAttributes,
};
