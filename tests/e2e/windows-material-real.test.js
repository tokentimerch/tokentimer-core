"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const http = require("node:http");
const { execFile, execFileSync } = require("node:child_process");
const {
  createWindowsConnector,
} = require("../../packages/agent/src/windows-material");
const {
  createMaterialStore,
  writeProtectedFile,
  readProtectedFile,
} = require("../../packages/agent/src/material-store");
const {
  executePinnedDeployment,
  reconcilePinnedDeployment,
} = require("../../packages/agent/src/material-store/lifecycle");
const {
  computeCertificateFingerprint,
  parseDnsSans,
} = require("../../packages/agent/src/verify");

const nativeWindowsLab = process.env.TT_WINDOWS_MATERIAL_REAL === "1";
test(
  "real Windows/IIS: shared import, service ACL, exact SNI consumers, interruption, reconciliation and retained rollback",
  // skip-reason: no-host — requires an elevated, disposable Windows Server/IIS VM.
  { skip: !nativeWindowsLab, timeout: 900000 },
  async (t) => {
    assert.equal(process.platform, "win32");
    const suffix = crypto.randomBytes(4).toString("hex");
    const directory = fs.mkdtempSync(
      path.join(os.tmpdir(), "tt-iis-material-"),
    );
    const store = `TTQualification${suffix}`,
      port = 45443;
    const sites = [`TTQualification${suffix}A`, `TTQualification${suffix}B`];
    const powershell = path.join(
      process.env.SystemRoot,
      "System32/WindowsPowerShell/v1.0/powershell.exe",
    );
    function ps(script) {
      return execFileSync(
        powershell,
        [
          "-NoProfile",
          "-NonInteractive",
          "-EncodedCommand",
          Buffer.from(script, "utf16le").toString("base64"),
        ],
        {
          encoding: "utf8",
          windowsHide: true,
          timeout: 120000,
          env: {
            ...process.env,
            PSModulePath: path.join(
              process.env.SystemRoot,
              "System32/WindowsPowerShell/v1.0/Modules",
            ),
          },
        },
      );
    }
    const caption = ps("(Get-CimInstance Win32_OperatingSystem).Caption");
    assert.match(caption, /Server/);
    const realAddress = process.env.TT_WINDOWS_MATERIAL_KV_ADDRESS;
    const provider = realAddress ? "openbao-kv2" : "vault-kv2";
    if (realAddress)
      assert.match(realAddress, /^http:\/\/127\.0\.0\.1:[0-9]+$/);
    t.diagnostic(
      `Native ${caption.trim()}; material transport: ${realAddress ? "real OpenBao KV v2" : "local HTTP fixture"}`,
    );
    let certificatePem = fs.readFileSync(
      path.join(
        __dirname,
        "../../packages/agent/src/verify/fixtures/leaf.crt.pem",
      ),
      "utf8",
    );
    let privateKeyPem = fs.readFileSync(
      path.join(
        __dirname,
        "../../packages/agent/src/verify/fixtures/leaf.key.pem",
      ),
      "utf8",
    );
    let generatedRenewal;
    const algorithm = process.env.TT_WINDOWS_MATERIAL_KEY_ALGORITHM || "rsa";
    assert.ok(["rsa", "ec-p256", "ec-p384", "ec-p521"].includes(algorithm));
    if (algorithm !== "rsa") {
      privateKeyPem = crypto.generateKeyPairSync("ec", {
        namedCurve: {
          "ec-p256": "prime256v1",
          "ec-p384": "secp384r1",
          "ec-p521": "secp521r1",
        }[algorithm],
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
      }).privateKey;
      const keyFile = path.join(directory, "generated-key.pem");
      writeProtectedFile(keyFile, privateKeyPem);
      const openssl = path.join(
        process.env.ProgramFiles,
        "Git/usr/bin/openssl.exe",
      );
      function leaf(serial) {
        const outputFile = path.join(directory, `generated-leaf-${serial}.pem`);
        execFileSync(
          openssl,
          [
            "req",
            "-new",
            "-x509",
            "-key",
            keyFile,
            "-out",
            outputFile,
            "-days",
            "2",
            "-sha256",
            "-subj",
            "/CN=valid.example.com",
            "-set_serial",
            String(serial),
            "-addext",
            "basicConstraints=critical,CA:false",
            "-addext",
            "extendedKeyUsage=serverAuth",
            "-addext",
            "subjectAltName=DNS:valid.example.com,DNS:www.valid.example.com",
          ],
          { windowsHide: true, stdio: "pipe", timeout: 30000 },
        );
        return fs.readFileSync(outputFile, "utf8");
      }
      certificatePem = leaf(1);
      generatedRenewal = leaf(2);
    }
    t.diagnostic(`Native key algorithm: ${algorithm}`);
    const sans = parseDnsSans(
      new crypto.X509Certificate(certificatePem).subjectAltName,
    );
    assert.ok(sans.length >= 2);
    t.after(() => {
      // Delete only this run's uniquely named sites and store, including keys
      // created in that store. No shared My/WebHosting cleanup is performed.
      ps(
        `$ErrorActionPreference='Stop';Add-Type -Path (Join-Path $env:windir 'System32/inetsrv/Microsoft.Web.Administration.dll');$m=New-Object Microsoft.Web.Administration.ServerManager;foreach($name in @('${sites.join("','")}')){if($m.Sites[$name]){$m.Sites.Remove($m.Sites[$name])}};$m.CommitChanges();$m.Dispose();$s=New-Object System.Security.Cryptography.X509Certificates.X509Store('${store}','LocalMachine');$s.Open('ReadWrite');foreach($c in $s.Certificates){$rsa=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);$ec=[System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c);if($rsa -is [System.Security.Cryptography.RSACng]){$rsa.Key.Delete();$rsa.Dispose()};if($ec -is [System.Security.Cryptography.ECDsaCng]){$ec.Key.Delete();$ec.Dispose()};$s.Remove($c)};$s.Close()`,
      );
      fs.rmSync(directory, { recursive: true, force: true });
    });
    ps(
      `$ErrorActionPreference='Stop';Add-Type -Path (Join-Path $env:windir 'System32/inetsrv/Microsoft.Web.Administration.dll');$m=New-Object Microsoft.Web.Administration.ServerManager;$root=Join-Path $env:SystemDrive 'inetpub/wwwroot';$a=$m.Sites.Add('${sites[0]}','https','127.0.0.1:${port}:${sans[0]}',$root);$a.Bindings[0].SslFlags=1;$b=$m.Sites.Add('${sites[1]}','https','127.0.0.1:${port}:${sans[1]}',$root);$b.Bindings[0].SslFlags=1;$m.CommitChanges();$m.Dispose()`,
    );
    const ids = {
      workspaceId: crypto.randomUUID(),
      groupId: crypto.randomUUID(),
      materialVersionId: crypto.randomUUID(),
    };
    const bundle = {
      schemaVersion: 1,
      ...ids,
      certificatePem,
      privateKeyPem,
      fingerprintSha256: computeCertificateFingerprint(certificatePem),
      sans,
    };
    const bundles = new Map([[bundle.materialVersionId, bundle]]);
    const server = http.createServer((req, res) => {
      const materialVersionId = new URL(req.url, "http://fixture").pathname
        .split("/")
        .at(-1);
      const selected = bundles.get(materialVersionId);
      if (!selected) {
        res.writeHead(404).end();
        return;
      }
      res.end(
        JSON.stringify({
          data: {
            data: selected,
            metadata: { version: 1, deletion_time: "", destroyed: false },
          },
        }),
      );
    });
    server.keepAliveTimeout = 60000;
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    t.after(() => {
      server.closeAllConnections();
      server.close();
    });
    const tokenFile = path.join(directory, "token");
    writeProtectedFile(tokenFile, "synthetic-customer-side-token");
    const stores = {
      qualification: {
        provider,
        address: realAddress || `http://127.0.0.1:${server.address().port}`,
        mount: "secret",
        tokenFile,
        timeoutMs: 30000,
        groups: {
          [ids.groupId]: {
            workspaceId: ids.workspaceId,
            prefix: `${ids.workspaceId}/${ids.groupId}`,
            keyAlgorithm: new crypto.X509Certificate(certificatePem).publicKey
              .asymmetricKeyType,
            sans,
          },
        },
      },
    };
    const rootToken = "isolated-windows-openbao-only";
    const prefix = stores.qualification.groups[ids.groupId].prefix;
    const role = `tt-windows-${suffix}`;
    async function providerApi(route, method, body) {
      const response = await fetch(new URL(`/v1${route}`, realAddress), {
        method,
        headers: {
          "X-Vault-Token": rootToken,
          "Content-Type": "application/json",
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      assert.ok(
        response.ok,
        `Owned OpenBao fixture operation returned ${response.status}`,
      );
      return response.status === 204 ? null : response.json();
    }
    async function saveBundle(selected, invalid = false) {
      bundles.set(selected.materialVersionId, selected);
      if (!realAddress) return;
      if (invalid) {
        // A privileged hostile write must still be rejected by the consumer.
        await providerApi(
          `/secret/data/${prefix}/bundles/${selected.materialVersionId}`,
          "POST",
          { options: { cas: 0 }, data: selected },
        );
        return;
      }
      const issuerFile = path.join(directory, "issuer-token");
      writeProtectedFile(issuerFile, rootToken);
      const issuer = createMaterialStore(
        { qualification: { ...stores.qualification, tokenFile: issuerFile } },
        {
          ...ids,
          provider,
          materialStoreRef: "qualification",
          materialVersionId: selected.materialVersionId,
        },
        { fixtureLoopbackHttp: true },
      );
      const receipt = await issuer.publish(selected);
      assert.equal(receipt.provider, provider);
      assert.equal(receipt.providerVersion, 1);
      assert.deepEqual(await issuer.publish(selected), receipt);
    }
    if (realAddress) {
      await providerApi(`/sys/policies/acl/${role}`, "PUT", {
        policy: `path "secret/data/${prefix}/bundles/*" { capabilities = ["read"] }`,
      });
      const issued = await providerApi("/auth/token/create", "POST", {
        policies: [role],
        no_default_policy: true,
        ttl: "15m",
      });
      writeProtectedFile(tokenFile, issued.auth.client_token);
      t.after(async () => {
        await providerApi("/auth/token/revoke", "POST", {
          token: issued.auth.client_token,
        });
        for (const materialVersionId of bundles.keys())
          await providerApi(
            `/secret/metadata/${prefix}/bundles/${materialVersionId}`,
            "DELETE",
          );
        await providerApi(`/sys/policies/acl/${role}`, "DELETE");
      });
    }
    await saveBundle(bundle);
    const stateDir = path.join(directory, "state"),
      bindings = {};
    const policyEngine = { checkTargetScope: () => ({ allowed: true }) };
    function jobFor(i, generation = 1, selected = bundle) {
      const bindingId = Object.keys(bindings)[i];
      return {
        workspaceId: ids.workspaceId,
        agentId: "qualification-agent",
        materialDeployment: {
          ...ids,
          materialVersionId: selected.materialVersionId,
          bindingId,
          materialStoreRef: "qualification",
          provider,
          providerVersion: 1,
          generation,
          fingerprintSha256: selected.fingerprintSha256,
          deploymentProfileRef: `iis${i}`,
          profileRevision: 1,
          authorizationRevision: 1,
          verificationPolicy: "served",
        },
      };
    }
    for (let i = 0; i < 2; i++)
      bindings[crypto.randomUUID()] = {
        workspaceId: ids.workspaceId,
        groupId: ids.groupId,
        agentId: "qualification-agent",
        materialStoreRef: "qualification",
        deploymentProfileRef: `iis${i}`,
        profileRevision: 1,
        authorizationRevision: 1,
        verificationPolicy: "served",
        connector: "windows-material-iis-v1",
        serviceAccountSids: ["S-1-5-20"],
        target: {
          type: "windows-iis",
          reference: `iis${i}`,
          store,
          binding: {
            site: sites[i],
            address: "127.0.0.1",
            port,
            sniHost: sans[i],
            store,
          },
        },
        probes: [{ dialAddress: "127.0.0.1", port, sni: sans[i] }],
      };
    const execute = (job, checkLease = async () => {}) =>
      executePinnedDeployment({
        job,
        stores,
        bindings,
        stateDir,
        policyEngine,
        checkLease,
        fixtureLoopbackHttp: true,
        windowsConnector: createWindowsConnector({
          binding: bindings[job.materialDeployment.bindingId],
          stateDir,
          execFileImpl: (file, args, options, callback) =>
            execFile(file, args, options, (error, stdout, stderr) => {
              // Only the helper's fixed phase/HRESULT may enter CI diagnostics.
              const diagnostic = String(stderr || "").match(
                /^material_windows_connector_failed:[a-z0-9A-F-]+:[0-9A-F]{8}$/m,
              );
              if (error && diagnostic)
                process.stderr.write(diagnostic[0] + "\n");
              callback(error, stdout, stderr);
            }),
        }),
      });
    const first = await execute(jobFor(0));
    assert.equal(first.status, "succeeded", first.errorMessage);
    assert.equal(first.deploymentReceipt.servedVerified, true);
    // Prove the configured service identity can actually use the persisted
    // non-exportable key. This isolated task has only public helper/source
    // files and an output marker, never access to PFX or credential staging.
    const probeDirectory = fs.mkdtempSync(
      path.join(os.tmpdir(), "tt-service-key-"),
    );
    const taskName = `TTMaterialProbe${suffix}`;
    const probeFile = path.join(probeDirectory, "probe.ps1");
    const outputFile = path.join(probeDirectory, "result.txt");
    const helperFile = path.join(probeDirectory, "MaterialImport.cs");
    const quote = (value) => "'" + value.replace(/'/g, "''") + "'";
    fs.copyFileSync(
      path.join(
        __dirname,
        "../../packages/agent/src/windows-material/MaterialImport.cs",
      ),
      helperFile,
    );
    fs.writeFileSync(outputFile, "");
    fs.writeFileSync(
      probeFile,
      `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';try{Add-Type -Path ${quote(helperFile)};[TokenTimer.MaterialImport]::Verify('${store}','${new crypto.X509Certificate(certificatePem).fingerprint.replace(/:/g, "")}','${bundle.fingerprintSha256}',[string[]]@('S-1-5-20'));[IO.File]::WriteAllText(${quote(outputFile)},'verified')}catch{[IO.File]::WriteAllText(${quote(outputFile)},'failed')}`,
    );
    t.after(() => {
      ps(
        `Unregister-ScheduledTask -TaskName '${taskName}' -Confirm:$false -ErrorAction SilentlyContinue`,
      );
      fs.rmSync(probeDirectory, { recursive: true, force: true });
    });
    ps(
      `$ErrorActionPreference='Stop';$sid=New-Object Security.Principal.SecurityIdentifier('S-1-5-20');$acl=Get-Acl -LiteralPath ${quote(probeDirectory)};$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'));Set-Acl -LiteralPath ${quote(probeDirectory)} -AclObject $acl;$output=Get-Acl -LiteralPath ${quote(outputFile)};$output.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'Write','Allow'));Set-Acl -LiteralPath ${quote(outputFile)} -AclObject $output;$action=New-ScheduledTaskAction -Execute ${quote(powershell)} -Argument ${quote('-NoProfile -NonInteractive -File "' + probeFile + '"')};$principal=New-ScheduledTaskPrincipal -UserId 'S-1-5-20' -LogonType ServiceAccount;Register-ScheduledTask -TaskName '${taskName}' -Action $action -Principal $principal | Out-Null;Start-ScheduledTask -TaskName '${taskName}'`,
    );
    const probeDeadline = Date.now() + 60000;
    while (!fs.readFileSync(outputFile, "utf8") && Date.now() < probeDeadline)
      await new Promise((resolve) => setTimeout(resolve, 500));
    assert.equal(
      fs.readFileSync(outputFile, "utf8"),
      "verified",
      "NetworkService can sign with the imported key under its read ACL",
    );
    const second = await execute(jobFor(1));
    assert.equal(second.status, "succeeded", second.errorMessage);
    assert.equal(
      second.deploymentReceipt.fingerprintSha256,
      first.deploymentReceipt.fingerprintSha256,
    );
    assert.notEqual(
      second.deploymentReceipt.bindingId,
      first.deploymentReceipt.bindingId,
    );
    assert.equal(
      (await execute(jobFor(0))).status,
      "succeeded",
      "idempotent import and binding selection",
    );
    const verify = {
      ...jobFor(0, 2),
      materialDeployment: {
        ...jobFor(0, 2).materialDeployment,
        verificationOnly: true,
      },
    };
    assert.equal((await execute(verify)).status, "succeeded");
    const interruptedJob = jobFor(0, 3);
    let checks = 0;
    const interrupted = await execute(interruptedJob, async () => {
      if (++checks === 4)
        throw Object.assign(new Error(), {
          code: "material_lease_unavailable",
        });
    });
    assert.equal(interrupted.status, "orphaned_unknown_effect");
    await assert.rejects(execute(interruptedJob), {
      code: "material_binding_uncertain",
    });
    const record = JSON.parse(
      readProtectedFile(
        path.join(
          stateDir,
          "material-bindings",
          `${interruptedJob.materialDeployment.bindingId}.json`,
        ),
        16384,
      ),
    );
    assert.equal(record.uncertain, true);
    assert.equal(JSON.stringify(record).includes("PRIVATE KEY"), false);
    assert.equal(
      (
        await reconcilePinnedDeployment({
          job: interruptedJob,
          bindings,
          stateDir,
          policyEngine,
        })
      ).reconciled,
      true,
    );
    assert.equal((await execute(interruptedJob)).status, "succeeded");
    const caCertificate = fs.readFileSync(
      path.join(
        __dirname,
        "../../packages/agent/src/verify/fixtures/selfsigned.crt.pem",
      ),
      "utf8",
    );
    const invalidCa = {
      ...bundle,
      materialVersionId: crypto.randomUUID(),
      certificatePem: caCertificate,
      fingerprintSha256: computeCertificateFingerprint(caCertificate),
    };
    await saveBundle(invalidCa, true);
    await assert.rejects(execute(jobFor(0, 4, invalidCa)), {
      code: "material_bundle_invalid",
    });
    assert.equal(
      JSON.parse(
        readProtectedFile(
          path.join(
            stateDir,
            "material-bindings",
            `${interruptedJob.materialDeployment.bindingId}.json`,
          ),
        ),
      ).generation,
      3,
      "invalid CA material is rejected before binding state or native mutation",
    );
    const renewedCertificate =
      generatedRenewal ||
      fs.readFileSync(
        path.join(
          __dirname,
          "../../packages/agent/src/verify/fixtures/material-renewed.crt.pem",
        ),
        "utf8",
      );
    const renewed = {
      ...bundle,
      materialVersionId: crypto.randomUUID(),
      certificatePem: renewedCertificate,
      fingerprintSha256: computeCertificateFingerprint(renewedCertificate),
    };
    assert.notEqual(renewed.fingerprintSha256, bundle.fingerprintSha256);
    await saveBundle(renewed);
    assert.equal(
      (await execute(jobFor(0, 4, renewed))).status,
      "succeeded",
      "new material activates on the first consumer",
    );
    const independent = jobFor(1, 2);
    independent.materialDeployment.verificationOnly = true;
    assert.equal(
      (await execute(independent)).status,
      "succeeded",
      "the second consumer still serves the original material",
    );
    const rollback = await execute(jobFor(0, 5));
    assert.equal(rollback.status, "succeeded", rollback.errorMessage);
    assert.equal(
      rollback.deploymentReceipt.fingerprintSha256,
      bundle.fingerprintSha256,
    );
    await assert.rejects(execute(jobFor(0, 4, renewed)), {
      code: "material_stale_generation",
    });
    await assert.rejects(execute(jobFor(0, 1)), {
      code: "material_stale_generation",
    });
    const wrong = jobFor(1, 2);
    wrong.materialDeployment.authorizationRevision = 2;
    await assert.rejects(execute(wrong), {
      code: "material_binding_policy_denied",
    });
  },
);
