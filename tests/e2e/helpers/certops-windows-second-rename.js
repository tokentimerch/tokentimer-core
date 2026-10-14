"use strict";
/** Deterministic second-rename activation-function qualification. The child
 * executes only the candidate's real copy/swap functions, not installer CLI
 * setup. Native directory events and identities establish restoration; installed
 * service/custody/TLS oracles are additional hosted-only checks. No private
 * certificate material, configuration bytes or process arguments enter reports. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  tls = require("node:tls");
const { spawn, spawnSync } = require("node:child_process");
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const requiredScenarios = [
  "windows-activation-second-rename-restores-predecessor",
  "windows-activation-restoration-preserves-installed-custody",
  "windows-activation-second-rename-owned-cleanup",
];
const requiredSources = [
  "tests/e2e/helpers/certops-windows-second-rename.js",
  "tests/e2e/helpers/certops-windows-second-rename-driver.ps1",
  "packages/agent/scripts/install-agent.ps1",
  "scripts/certops-installer-second-rename-support.js",
  "scripts/certops-installer-swap.test.ps1",
  "tests/e2e/windows-real-journey.js",
];
const factFields = [
  "childIdentityVerifiedBeforeActivation",
  "actualProductionFunctions",
  "nativeOrderedRestoreEvents",
  "originalDirectoryIdentityRestored",
  "heldStagingIdentityUnchanged",
  "explicitStagingCleanupFailure",
  "candidateNeverActivated",
  "predecessorFilesUnchanged",
  "sameRunningServicePid",
  "configurationAndCredentialUnchanged",
  "cngCustodyUnchanged",
  "bindingAndTrustedTlsUnchanged",
  "freshAuthenticatedHeartbeat",
  "nativeHandleReleased",
  "ownedStagingRemoved",
  "ownedChildDrained",
];
function verifyProof(facts) {
  for (const field of factFields) assert.equal(facts[field], true, field);
  assert.equal(
    facts.scope,
    "production-activation-functions-not-installer-cli",
  );
  return true;
}
function inventory(root) {
  const result = [];
  function visit(dir) {
    for (const name of fs.readdirSync(dir).sort()) {
      const file = path.join(dir, name),
        s = fs.lstatSync(file);
      assert.equal(s.isSymbolicLink(), false);
      if (s.isDirectory()) visit(file);
      else {
        assert.equal(s.isFile(), true);
        result.push([
          path.relative(root, file),
          crypto
            .createHash("sha256")
            .update(fs.readFileSync(file))
            .digest("hex"),
        ]);
      }
    }
  }
  visit(root);
  return result;
}
function powershell(script) {
  const executable = path.join(
    process.env.SystemRoot,
    "System32/WindowsPowerShell/v1.0/powershell.exe",
  );
  const r = spawnSync(
    executable,
    [
      "-NoProfile",
      "-NonInteractive",
      "-EncodedCommand",
      Buffer.from(script, "utf16le").toString("base64"),
    ],
    { encoding: "utf8", windowsHide: true, timeout: 15000, maxBuffer: 65536 },
  );
  assert.ifError(r.error);
  assert.equal(r.status, 0, "Owned PowerShell observation failed");
  return r.stdout.trim();
}
function nativeIdentity(child, token, driver) {
  const result = JSON.parse(
    powershell(
      `$p=Get-CimInstance Win32_Process -Filter 'ProcessId=${child.pid}';if(!$p){throw 'Owned driver is absent'};@{pid=$p.ProcessId;parentPid=$p.ParentProcessId;created=$p.CreationDate.ToUniversalTime().ToString('o');executable=$p.ExecutablePath;command=$p.CommandLine}|ConvertTo-Json -Compress`,
    ),
  );
  assert.equal(result.pid, child.pid);
  assert.equal(result.parentPid, process.pid);
  assert.equal(
    path.resolve(result.executable).toLowerCase(),
    path
      .resolve(
        process.env.SystemRoot,
        "System32/WindowsPowerShell/v1.0/powershell.exe",
      )
      .toLowerCase(),
  );
  assert.ok(
    result.command.includes(token) &&
      result.command.toLowerCase().includes(driver.toLowerCase()),
  );
  assert.ok(Number.isFinite(Date.parse(result.created)));
  return result;
}
async function until(check, ms = 30000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const value = await check();
    if (value) return value;
    await delay(50);
  }
  throw new Error("Owned activation protocol deadline exceeded");
}
/** Shared by the installed fixture and the explicit nonprivileged temporary-file
 * regression. The go file is published only after independent CIM measurement;
 * unparsed or late receipts therefore never authorize unowned process cleanup. */
async function runActivationFault({
  repoRoot,
  workDir,
  packageDir,
  installer = path.join(repoRoot, "packages/agent/scripts/install-agent.ps1"),
  onRestored = async () => {},
}) {
  assert.equal(process.platform, "win32");
  const app = path.join(workDir, "app"),
    before = inventory(app),
    directory = fs.mkdtempSync(path.join(workDir, "second-rename-"));
  const prefix = path.join(directory, "receipt"),
    go = path.join(directory, "go"),
    release = path.join(directory, "release"),
    token = crypto.randomBytes(16).toString("hex"),
    driver = path.join(__dirname, "certops-windows-second-rename-driver.ps1");
  const executable = path.join(
    process.env.SystemRoot,
    "System32/WindowsPowerShell/v1.0/powershell.exe",
  );
  const env = Object.fromEntries(
    [
      "SystemRoot",
      "WINDIR",
      "ComSpec",
      "PATH",
      "PATHEXT",
      "TEMP",
      "TMP",
      "SystemDrive",
      "ProgramFiles",
      "ProgramData",
      "USERPROFILE",
      "APPDATA",
      "LOCALAPPDATA",
    ]
      .filter((key) => process.env[key] !== undefined)
      .map((key) => [key, process.env[key]]),
  );
  const child = spawn(
    executable,
    [
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      driver,
      "-Installer",
      installer,
      "-PackageDirectory",
      packageDir,
      "-OwnedRoot",
      workDir,
      "-ReceiptPrefix",
      prefix,
      "-GoPath",
      go,
      "-ReleasePath",
      release,
      "-Token",
      token,
      "-OwnerProcessId",
      String(process.pid),
    ],
    { env, stdio: "ignore", windowsHide: true },
  );
  let closed = false,
    identity,
    restored,
    primary,
    drained = false;
  const exit = new Promise((resolve) => {
    child.once("error", () => {
      closed = true;
      resolve({ error: true });
    });
    child.once("close", (code, signal) => {
      closed = true;
      resolve({ code, signal });
    });
  });
  const staged = () => `${app}.staging.${child.pid}`,
    previous = () => `${app}.previous.${child.pid}`;
  try {
    assert.ok(
      Number.isInteger(child.pid) && child.pid > 0,
      "Owned driver failed spawn",
    );
    // Capture independently before reading any child-created ownership receipt.
    identity = await until(() => {
      assert.equal(closed, false);
      try {
        return nativeIdentity(child, token, driver);
      } catch {
        return null;
      }
    }, 10000);
    fs.writeFileSync(go, token, { flag: "wx" });
    await until(() => {
      assert.equal(
        closed,
        false,
        "Activation driver exited before restoration proof",
      );
      return fs.existsSync(prefix + ".restored.json");
    });
    assert.deepEqual(nativeIdentity(child, token, driver), identity);
    restored = JSON.parse(fs.readFileSync(prefix + ".restored.json", "utf8"));
    assert.equal(restored.phase, "restored");
    assert.equal(restored.token, token);
    for (const key of ["pid", "parentPid", "created"])
      assert.equal(restored[key], identity[key]);
    assert.match(restored.originalId, /^[a-f0-9]{8}:[a-f0-9]{16}$/);
    assert.equal(restored.restoredId, restored.originalId);
    assert.match(restored.stagingId, /^[a-f0-9]{8}:[a-f0-9]{16}$/);
    assert.notEqual(restored.originalId, restored.stagingId);
    assert.deepEqual(restored.renameEvents, [
      ["app", `app.previous.${child.pid}`],
      [`app.previous.${child.pid}`, "app"],
    ]);
    assert.equal(restored.shareMask, 3);
    assert.equal(
      restored.errorKind,
      "staging-cleanup-blocked-after-restoration",
    );
    assert.equal(restored.previousAbsent, true);
    assert.equal(restored.stagingPresent, true);
    assert.equal(fs.existsSync(previous()), false);
    assert.equal(fs.existsSync(staged()), true);
    assert.equal(
      fs.statSync(app, { bigint: true }).ino,
      BigInt(`0x${restored.originalId.split(":")[1]}`),
    );
    assert.equal(
      fs.statSync(staged(), { bigint: true }).ino,
      BigInt(`0x${restored.stagingId.split(":")[1]}`),
    );
    assert.deepEqual(inventory(app), before);
    await onRestored();
  } catch (error) {
    primary = error;
  } finally {
    try {
      if (!closed && !fs.existsSync(release))
        fs.writeFileSync(release, token, { flag: "wx" });
      let timer;
      const result = await Promise.race([
        exit,
        new Promise((_, reject) => {
          timer = setTimeout(
            () => reject(new Error("Owned activation child did not drain")),
            identity ? 20000 : 35000,
          );
        }),
      ]).finally(() => clearTimeout(timer));
      assert.equal(
        result.code,
        0,
        "Owned activation child failed or was interrupted",
      );
      drained = true;
      const receipt = JSON.parse(
        fs.readFileSync(prefix + ".closed.json", "utf8"),
      );
      assert.deepEqual(receipt, {
        ...restored,
        phase: "closed",
        stagingPresent: false,
      });
      assert.equal(fs.existsSync(staged()), false);
      assert.equal(fs.existsSync(previous()), false);
      assert.deepEqual(inventory(app), before);
    } catch (error) {
      if (!closed && identity) {
        try {
          assert.deepEqual(nativeIdentity(child, token, driver), identity);
          const killed = spawnSync(
            "taskkill.exe",
            ["/PID", String(child.pid), "/T", "/F"],
            { stdio: "ignore", windowsHide: true, timeout: 10000 },
          );
          assert.equal(killed.status, 0);
          await until(() => closed, 10000);
        } catch (cleanup) {
          error = new AggregateError(
            [error, cleanup],
            "Owned activation process could not be verified and drained",
          );
        }
      }
      primary = primary
        ? new AggregateError(
            [primary, error],
            "Activation fault and owned cleanup failed",
          )
        : error;
    }
  }
  if (primary) throw primary;
  assert.equal(drained, true);
  return {
    childIdentityVerifiedBeforeActivation: true,
    actualProductionFunctions: true,
    nativeOrderedRestoreEvents: true,
    originalDirectoryIdentityRestored: true,
    heldStagingIdentityUnchanged: true,
    explicitStagingCleanupFailure: true,
    candidateNeverActivated: true,
    predecessorFilesUnchanged: true,
    nativeHandleReleased: true,
    ownedStagingRemoved: true,
    ownedChildDrained: true,
  };
}
async function qualifySecondRename(context) {
  const {
    repoRoot,
    workDir,
    pool,
    workspaceId,
    agentId,
    configDir,
    domain,
    port,
    roots,
    thumbprint,
    powershell: ps,
    run,
    waitUntil,
  } = context;
  assert.equal(process.platform, "win32");
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.CERTOPS_REAL_WINDOWS_REQUIRED, "1");
  assert.ok(process.env.RUNNER_TEMP);
  assert.ok(
    path
      .resolve(workDir)
      .startsWith(path.resolve(process.env.RUNNER_TEMP) + path.sep),
  );
  assert.equal(process.env.CERTOPS_WINDOWS_KEY_PROFILE, "rsa-2048");
  const hash = (file) => ({
    file,
    sha256: crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.join(repoRoot, file)))
      .digest("hex"),
  });
  const gate =
    require("../../../packages/agent/scripts/host-gate").createHostGate({
      suite: "windows-activation-second-rename",
      strict: true,
      evidenceLevel: "e2e",
      reportPath: "qualification-results/windows-second-rename-activation.json",
      fixtureSource: hash(requiredSources[0]),
      requiredCapabilities: ["windows", "system", "installedAgent", "api"],
      probeCapabilities: () => ({
        windows: { available: process.platform === "win32" },
        system: {
          available:
            ps(
              "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
            ) === "S-1-5-18",
        },
        installedAgent: {
          available: ps("(Get-Service TokenTimerAgent).Status") === "Running",
        },
        api: { available: true },
      }),
    });
  gate.report.fixtureSources = requiredSources.map(hash);
  gate.report.qualificationEnvironment.keyProfile = "rsa-2048";
  const pid = () =>
      ps(
        "[string](Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\").ProcessId",
      ),
    beforePid = pid();
  assert.match(beforePid, /^[1-9][0-9]*$/);
  const config = fs.readFileSync(path.join(configDir, "config.json")),
    credential = fs.readFileSync(path.join(configDir, "credential"));
  const custody = () =>
    JSON.parse(
      ps(
        `$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}';$k=$null;try{$k=if($c.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1'){[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)}else{[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c)};@{thumb=$c.Thumbprint;key=$k.Key.KeyName;unique=$k.Key.UniqueName;provider=$k.Key.Provider.Provider;policy=[int]$k.Key.ExportPolicy;der=[Convert]::ToBase64String($c.RawData)}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`,
      ),
    );
  const originalCustody = custody();
  assert.equal(originalCustody.policy, 0);
  const binding = () =>
      run("netsh.exe", [
        "http",
        "show",
        "sslcert",
        `hostnameport=${domain}:${port}`,
      ]),
    originalBinding = binding();
  const seen = async () =>
    (
      await pool.query(
        "SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
        [workspaceId, agentId],
      )
    ).rows[0]?.last_seen_at;
  let proof, primary;
  await gate.preflight();
  gate.report.qualificationEnvironment.identity = "LocalSystem";
  try {
    await gate.scenario(requiredScenarios[0], async () => {
      proof = await runActivationFault({
        repoRoot,
        workDir,
        packageDir: context.packageDir,
        installer: context.installerFixture,
        onRestored: async () => {
          assert.equal(pid(), beforePid);
          assert.equal(ps("(Get-Service TokenTimerAgent).Status"), "Running");
          // Boolean comparisons prevent assertion diagnostics from exposing
          // configuration or credential bytes on a failed custody invariant.
          assert.equal(
            fs.readFileSync(path.join(configDir, "config.json")).equals(config),
            true,
            "Configuration must remain byte-identical",
          );
          assert.equal(
            fs
              .readFileSync(path.join(configDir, "credential"))
              .equals(credential),
            true,
            "Credential must remain byte-identical",
          );
          assert.deepEqual(custody(), originalCustody);
          assert.equal(binding(), originalBinding);
          const afterRestoration = await seen();
          assert.ok(Number.isFinite(Date.parse(afterRestoration)));
          await waitUntil(async () => {
            assert.equal(pid(), beforePid);
            return Date.parse(await seen()) > Date.parse(afterRestoration);
          });
          const peer = await new Promise((resolve, reject) => {
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
                  resolve(
                    socket.getPeerCertificate().fingerprint.replace(/:/g, ""),
                  );
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
                new Error("Restored predecessor TLS deadline exceeded"),
              ),
            );
          });
          assert.equal(peer, thumbprint);
          assert.equal(pid(), beforePid);
        },
      });
    });
    await gate.scenario(requiredScenarios[1], () => {
      Object.assign(proof, {
        sameRunningServicePid: true,
        configurationAndCredentialUnchanged: true,
        cngCustodyUnchanged: true,
        bindingAndTrustedTlsUnchanged: true,
        freshAuthenticatedHeartbeat: true,
        scope: "production-activation-functions-not-installer-cli",
      });
      verifyProof(proof);
    });
  } catch (error) {
    primary = error;
  } finally {
    try {
      await gate.scenario(requiredScenarios[2], () => {
        assert.ok(proof);
        verifyProof(proof);
        gate.report.nativeSecondRename = proof;
      });
    } catch (error) {
      primary = primary
        ? new AggregateError(
            [primary, error],
            "Activation qualification and cleanup failed",
          )
        : error;
    }
    try {
      await gate.finish({ requiredScenarios });
    } catch (error) {
      primary = primary
        ? new AggregateError(
            [primary, error],
            "Activation qualification and report failed",
          )
        : error;
    }
  }
  if (primary) throw primary;
  return gate.report;
}
module.exports = {
  runActivationFault,
  qualifySecondRename,
  verifyProof,
  requiredScenarios,
  requiredSources,
  factFields,
};
