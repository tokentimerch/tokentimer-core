"use strict";
/** Explicit operator-owned SCM state handoff, not automatic in-place re-registration.
 * Runs only after actual predecessor retirement on the disposable installed-agent
 * journey. Existing identity state is preserved; no credential, bootstrap
 * transaction or outbound queue is migrated. Native execution is host gated. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  tls = require("node:tls");
const { spawn } = require("node:child_process");
const COPY_ENTRIES = Object.freeze([
  "keys",
  "windows-cert-store",
  "windows-retention",
  "trust-receipts",
  "job-journal",
  "adcs-enrollments",
  "signing-key-pin.json",
  "replay-store.json",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-windows-installed-handoff.js",
  "tests/e2e/helpers/certops-windows-registration-job.ps1",
  "tests/e2e/windows-real-journey.js",
  "packages/agent/bin/tokentimer-agent.js",
  "packages/agent/src/index.js",
  "packages/agent/src/config/index.js",
  "packages/agent/src/platform/index.js",
  "packages/agent/src/protocol/index.js",
  "packages/agent/windows-service-host/main.go",
  "packages/agent/windows-service-host/host.go",
  "packages/agent/windows-service-host/service_windows.go",
  "apps/api/routes/certops.js",
  "apps/api/services/certops/agentRegistry.js",
  "apps/api/services/certops/agentCredentials.js",
  "scripts/certops-stack-reporter.js",
  ".github/workflows/certops-windows-e2e.yml",
]);
const SCOPE =
  "explicit-operator-protected-state-installed-scm-handoff-not-automatic-reregistration";
const FLAGS = Object.freeze([
  "retiredPredecessorCredentialFenced",
  "publicConflictBootstrapUnconsumed",
  "unusedConflictBootstrapRevoked",
  "publicReplacementBootstrapConsumed",
  "unmodifiedCliRegisteredReplacement",
  "registrationChildDrained",
  "sameInstalledServicePathAndSystemIdentity",
  "freshReplacementScmHeartbeat",
  "sourceStateBytesPreserved",
  "protectedCustodyAndJournalCopiesPreserved",
  "signingPinPreserved",
  "nativeCngBindingAndTrustedTlsPreserved",
  "predecessorJobsNotReplayed",
  "noBootstrapInServiceRegistry",
  "replacementRetiredAndServiceStopped",
  "originalRegistryRestored",
  "ownedStateRemoved",
]);
function verifyProof(proof) {
  assert.ok(proof && typeof proof === "object" && !Array.isArray(proof));
  assert.deepEqual(Object.keys(proof).sort(), ["scope", ...FLAGS].sort());
  assert.equal(proof.scope, SCOPE);
  for (const flag of FLAGS) assert.equal(proof[flag], true, flag);
  return true;
}
function stateFiles(directory) {
  const rows = [];
  function visit(current) {
    for (const name of fs.readdirSync(current).sort()) {
      const file = path.join(current, name),
        stat = fs.lstatSync(file);
      assert.equal(
        stat.isSymbolicLink(),
        false,
        "Refuse state reparse/symlink traversal",
      );
      assert.ok(
        stat.isFile() || stat.isDirectory(),
        "Refuse nonregular state entry",
      );
      if (stat.isDirectory()) visit(file);
      else
        rows.push({
          file: path.relative(directory, file).replace(/\\/g, "/"),
          sha256: crypto
            .createHash("sha256")
            .update(fs.readFileSync(file))
            .digest("hex"),
        });
    }
  }
  visit(directory);
  return rows;
}
function copyCustody(source, target, platform) {
  assert.equal(fs.existsSync(target), false);
  fs.mkdirSync(target);
  platform.applyRestrictivePermissions(target, { kind: "directory" });
  platform.assertRestrictivePermissions(target);
  for (const entry of COPY_ENTRIES) {
    const from = path.join(source, entry);
    if (!fs.existsSync(from)) continue;
    const copy = (input, output) => {
      const stat = fs.lstatSync(input);
      assert.equal(
        stat.isSymbolicLink(),
        false,
        "Refuse custody reparse/symlink traversal",
      );
      assert.ok(stat.isDirectory() || stat.isFile());
      if (stat.isDirectory()) {
        fs.mkdirSync(output);
        platform.applyRestrictivePermissions(output, { kind: "directory" });
        platform.assertRestrictivePermissions(output);
        for (const name of fs.readdirSync(input))
          copy(path.join(input, name), path.join(output, name));
      } else {
        fs.copyFileSync(input, output, fs.constants.COPYFILE_EXCL);
        platform.applyRestrictivePermissions(output, { kind: "file" });
        platform.assertRestrictivePermissions(output);
      }
    };
    copy(from, path.join(target, entry));
  }
  return stateFiles(target);
}
function verifyDrainReceipt(value, expected) {
  assert.ok(value && typeof value === "object");
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "token",
      "wrapperPid",
      "ownerPid",
      "nativeRootPid",
      "rootExitCode",
      "activeNativeProcesses",
      "retainedJobDrained",
    ].sort(),
  );
  for (const name of ["token", "wrapperPid", "ownerPid"])
    assert.ok(
      value[name] === expected[name],
      "Owned native job receipt identity mismatch",
    );
  assert.ok(Number.isInteger(value.nativeRootPid) && value.nativeRootPid > 0);
  assert.ok(
    Number.isInteger(value.rootExitCode) &&
      value.rootExitCode >= 0 &&
      value.rootExitCode <= 0xffffffff,
  );
  assert.equal(value.activeNativeProcesses, 0);
  assert.equal(value.retainedJobDrained, true);
  return true;
}
function createOwnedHandoffResource({ hasLiveChild, drain, restore, receipt }) {
  let released = false;
  return {
    hasLiveChild,
    hasOwnershipReceipt: () => !released || fs.existsSync(receipt),
    async close() {
      if (released) {
        assert.equal(hasLiveChild(), false);
        assert.equal(fs.existsSync(receipt), false);
        return;
      }
      await drain();
      assert.equal(
        hasLiveChild(),
        false,
        "Owned registration child remains alive",
      );
      await restore();
      if (fs.existsSync(receipt)) fs.unlinkSync(receipt);
      released = true;
    },
  };
}
async function qualifyInstalledStateHandoff({
  pool,
  baseUrl,
  workspaceId,
  oldAgentId,
  publicSession,
  packageRoot,
  configDir,
  workDir,
  ps,
  command,
  waitUntil,
  domain,
  site,
  port,
  roots,
  thumbprint,
  keyProfile,
  ownedHandoffs,
}) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST, "1");
  assert.equal(
    ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),
    "S-1-5-18",
  );
  assert.ok(Array.isArray(ownedHandoffs));
  assert.equal(path.dirname(configDir), workDir);
  assert.match(path.basename(workDir), /^certops-windows-journey-/);
  assert.match(thumbprint, /^[a-f0-9]{40}$/i);
  assert.match(site, /^CertOps-[a-f0-9-]{36}$/i);
  const platform = require(path.join(packageRoot, "src/platform")),
    oldConfig = JSON.parse(
      fs.readFileSync(path.join(configDir, "config.json")),
    ),
    oldCredential = fs.readFileSync(path.join(configDir, "credential"));
  const old = (
    await pool.query(
      "SELECT id,status,credential_hash FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
      [workspaceId, oldAgentId],
    )
  ).rows[0];
  assert.equal(old.status, "retired");
  const jobs = async () =>
      (
        await pool.query(
          "SELECT id,status,attempt_count,claim_id FROM certificate_jobs WHERE workspace_id=$1 AND assigned_agent_id=$2 ORDER BY id",
          [workspaceId, old.id],
        )
      ).rows,
    beforeJobs = await jobs();
  const service = () =>
      JSON.parse(
        ps(
          "$s=Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\";if(-not $s){throw 'Owned service absent'};@{path=$s.PathName;owner=$s.StartName;state=$s.State;pid=[int]$s.ProcessId}|ConvertTo-Json -Compress",
        ),
      ),
    initialService = service();
  assert.equal(initialService.state, "Stopped");
  assert.equal(initialService.pid, 0);
  assert.ok(
    ["LocalSystem", "NT AUTHORITY\\SYSTEM"].includes(initialService.owner),
  );
  const host = path.join(packageRoot, "bin/tokentimer-agent-host-amd64.exe");
  assert.equal(
    initialService.path
      .toLowerCase()
      .startsWith(('"' + host + '"').toLowerCase()),
    true,
  );
  const registry = () =>
    JSON.parse(
      ps(
        "$k=Get-Item 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent';$exists=@($k.GetValueNames()) -contains 'Environment';@{exists=$exists;kind=$(if($exists){[string]$k.GetValueKind('Environment')}else{$null});values=$(if($exists){@($k.GetValue('Environment',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))}else{@()})}|ConvertTo-Json -Compress",
      ),
    );
  const oldRegistry = registry();
  assert.equal(oldRegistry.exists, true);
  assert.equal(oldRegistry.kind, "MultiString");
  assert.ok(Array.isArray(oldRegistry.values));
  assert.equal(
    oldRegistry.values.some((value) =>
      /^TOKENTIMER_AGENT_BOOTSTRAP_TOKEN(?:_ID)?=/i.test(value),
    ),
    false,
  );
  assert.equal(
    oldRegistry.values.filter((value) =>
      /^TOKENTIMER_AGENT_CONFIG_DIR=/i.test(value),
    ).length,
    1,
  );
  assert.equal(
    oldRegistry.values
      .find((value) => /^TOKENTIMER_AGENT_CONFIG_DIR=/i.test(value))
      .split("=")
      .slice(1)
      .join("=")
      .toLowerCase(),
    configDir.toLowerCase(),
  );
  // Native reparse rejection includes junctions and other Windows reparse types.
  const quoted = (value) => String(value).replace(/'/g, "''");
  ps(
    `$root=Get-Item -LiteralPath '${quoted(configDir)}';if($root.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'State root is a reparse point'};$pending=New-Object 'System.Collections.Generic.Stack[string]';$pending.Push('${quoted(configDir)}');while($pending.Count){foreach($entry in @(Get-ChildItem -LiteralPath $pending.Pop() -Force)){if($entry.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'State contains reparse points'};if($entry.PSIsContainer){$pending.Push($entry.FullName)}}}`,
  );
  const oldSnapshot = stateFiles(configDir),
    pin = fs.readFileSync(path.join(configDir, "signing-key-pin.json"));
  const directory = fs.mkdtempSync(path.join(workDir, "installed-handoff-"));
  platform.applyRestrictivePermissions(directory, { kind: "directory" });
  const target = path.join(directory, "state"),
    conflict = path.join(directory, "conflict"),
    receipt = path.join(directory, "registry-ownership.json");
  const entry = path.join(packageRoot, "bin/tokentimer-agent.js"),
    entryHash = crypto
      .createHash("sha256")
      .update(fs.readFileSync(entry))
      .digest("hex");
  let child,
    childClosed,
    childProtocol,
    childToken,
    childDrainProven = true,
    changed = false,
    replacementId,
    conflictTokenId,
    freshTokenId,
    primary;
  const failures = [];
  const facts = { scope: SCOPE };
  const freshServiceOwned = () => {
    const current = service();
    assert.equal(
      current.path,
      initialService.path,
      "Refuse foreign service replacement",
    );
    assert.equal(current.owner, initialService.owner);
    return current;
  };
  const readProtocol = (file) =>
    JSON.parse(fs.readFileSync(file, "utf8").replace(/^\uFEFF/, ""));
  // Wrapper exit is insufficient: retain ownership until its native job reports
  // zero active members and the wrapper itself has closed.
  const drain = async () => {
    if (!child) return;
    if (child.exitCode === null && child.signalCode === null) {
      const stop = path.join(childProtocol, "stop");
      if (fs.existsSync(stop))
        assert.equal(fs.readFileSync(stop, "utf8"), childToken);
      else fs.writeFileSync(stop, childToken, { flag: "wx" });
    }
    await waitUntil(
      () => child.exitCode !== null || child.signalCode !== null,
      45000,
    );
    await childClosed;
    const closed = readProtocol(path.join(childProtocol, "closed.json"));
    verifyDrainReceipt(closed, {
      token: childToken,
      wrapperPid: child.pid,
      ownerPid: process.pid,
    });
    assert.equal(
      child.exitCode,
      0,
      "Native job wrapper failed before publishing safe drainage",
    );
    childDrainProven = true;
    child = null;
    return closed;
  };
  const setRegistry = (values) => {
    const encoded = Buffer.from(JSON.stringify(values), "utf8").toString(
      "base64",
    );
    ps(
      `$values=@([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'))|ConvertFrom-Json);New-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent' -Name Environment -PropertyType MultiString -Value ([string[]]$values) -Force|Out-Null`,
    );
  };
  const resource = createOwnedHandoffResource({
    hasLiveChild: () =>
      !childDrainProven ||
      (!!child && child.exitCode === null && child.signalCode === null),
    drain,
    receipt,
    // Restore only the exact service and original-or-owned registry value.
    // Any foreign replacement leaves the protected receipt in place.
    restore: async () => {
      freshServiceOwned();
      if (!changed)
        assert.ok(
          JSON.stringify(registry()) === JSON.stringify(oldRegistry),
          "Refuse changed original registry ownership",
        );
      if (changed) {
        const current = freshServiceOwned();
        if (current.state !== "Stopped")
          command("sc.exe", ["stop", "TokenTimerAgent"]);
        await waitUntil(() => freshServiceOwned().state === "Stopped", 30000);
        const values = registry().values;
        assert.ok(
          JSON.stringify(values) === JSON.stringify(oldRegistry.values) ||
            JSON.stringify(values) ===
              JSON.stringify(
                oldRegistry.values
                  .filter(
                    (value) => !/^TOKENTIMER_AGENT_CONFIG_DIR=/i.test(value),
                  )
                  .concat(`TOKENTIMER_AGENT_CONFIG_DIR=${target}`),
              ),
          "Refuse changed registry ownership",
        );
        setRegistry(oldRegistry.values);
        assert.ok(
          JSON.stringify(registry()) === JSON.stringify(oldRegistry),
          "Original service registry restoration mismatch",
        );
        changed = false;
      }
      assert.equal(service().state, "Stopped");
    },
  });
  ownedHandoffs.push(resource);
  fs.writeFileSync(
    receipt,
    JSON.stringify({ servicePath: initialService.path, oldRegistry, target }),
  );
  platform.applyRestrictivePermissions(receipt, { kind: "file" });
  // Gate native child creation until the actual wrapper process identity is
  // measured. Bootstrap authorization is inherited in memory, never in argv.
  const launch = async (bootstrap, state, label) => {
    childDrainProven = false;
    childToken = crypto.randomBytes(16).toString("hex");
    childProtocol = path.join(directory, label);
    fs.mkdirSync(childProtocol);
    platform.applyRestrictivePermissions(childProtocol, { kind: "directory" });
    const wrapper = path.resolve(
      __dirname,
      "certops-windows-registration-job.ps1",
    );
    child = spawn(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-File",
        wrapper,
        "-NodePath",
        process.execPath,
        "-Entry",
        entry,
        "-ProtocolDirectory",
        childProtocol,
        "-Token",
        childToken,
        "-OwnerProcessId",
        String(process.pid),
      ],
      {
        env: {
          ...process.env,
          TOKENTIMER_AGENT_CONFIG_DIR: state,
          TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: bootstrap.plaintextToken,
          TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID: String(bootstrap.token.id),
        },
        windowsHide: true,
        stdio: "ignore",
      },
    );
    childClosed = new Promise((resolve, reject) => {
      child.once("close", resolve);
      child.once("error", reject);
    });
    childClosed.catch(() => {});
    const ready = await waitUntil(() => {
      assert.equal(child.exitCode, null);
      assert.equal(child.signalCode, null);
      try {
        return readProtocol(path.join(childProtocol, "ready.json"));
      } catch {
        return null;
      }
    }, 45000);
    assert.equal(ready.token, childToken);
    assert.equal(ready.wrapperPid, child.pid);
    assert.equal(ready.ownerPid, process.pid);
    const actual = JSON.parse(
      ps(
        `$p=Get-CimInstance Win32_Process -Filter 'ProcessId=${child.pid}';if(-not $p){throw 'Owned launch wrapper exited'};@{pid=[int]$p.ProcessId;parent=[int]$p.ParentProcessId;created=$p.CreationDate.ToUniversalTime().ToString('o');executable=$p.ExecutablePath;command=$p.CommandLine;sid=(Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid).Sid}|ConvertTo-Json -Compress`,
      ),
    );
    assert.equal(actual.pid, child.pid);
    assert.equal(actual.parent, process.pid);
    assert.equal(actual.created, ready.creationTime);
    assert.equal(actual.sid, "S-1-5-18");
    assert.equal(
      actual.executable.toLowerCase(),
      path
        .join(
          process.env.SystemRoot,
          "System32/WindowsPowerShell/v1.0/powershell.exe",
        )
        .toLowerCase(),
    );
    assert.ok(
      actual.command.includes(childToken) &&
        actual.command.toLowerCase().includes(wrapper.toLowerCase()),
    );
    fs.writeFileSync(path.join(childProtocol, "run"), childToken, {
      flag: "wx",
    });
  };
  const bootstrap = async (label) => {
    const response = await publicSession.request(
      `/api/v1/workspaces/${workspaceId}/certops/agent-bootstrap-tokens`,
      "POST",
      {
        name: `installed-state-${label}`,
        expiresAt: new Date(Date.now() + 600000).toISOString(),
      },
    );
    assert.equal(response.status, 201);
    assert.ok(
      typeof response.body.plaintextToken === "string" &&
        response.body.plaintextToken.startsWith("ttboot_"),
      "Public bootstrap response shape invalid",
    );
    return response.body;
  };
  const tokenState = async (id) =>
    (
      await pool.query(
        "SELECT status FROM certops_agent_bootstrap_tokens WHERE workspace_id=$1 AND id=$2",
        [workspaceId, id],
      )
    ).rows[0]?.status;
  const tlsPeer = () =>
    new Promise((resolve, reject) => {
      const socket = tls.connect(
        {
          host: "127.0.0.1",
          port,
          servername: domain,
          ca: roots.map((root) => root.pem || root),
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
        socket.destroy(new Error("Installed handoff trusted TLS deadline")),
      );
    });
  const getter =
    keyProfile.keyAlgorithm === "rsa"
      ? "[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)"
      : "[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c)";
  const native = () =>
    JSON.parse(
      ps(
        `$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumbprint}';$k=$null;try{$k=${getter};Import-Module WebAdministration;$bindings=@(Get-WebBinding -Name '${quoted(site)}' -Protocol https | Where-Object {$_.bindingInformation -eq '*:${port}:${domain}'});if($bindings.Count -ne 1){throw 'Owned SNI binding absent'};$httpSys=(& netsh.exe http show sslcert hostnameport=${domain}:${port});if($LASTEXITCODE -ne 0){throw 'Owned HTTP.sys binding absent'};@{der=[Convert]::ToBase64String($c.RawData);container=$k.Key.KeyName;provider=$k.Key.Provider.Provider;machine=$k.Key.IsMachineKey;exportPolicy=[int]$k.Key.ExportPolicy;bits=$k.KeySize;bindingThumbprint=[string]$bindings[0].certificateHash;bindingFlags=[int]$bindings[0].sslFlags;bindingStore=[string]$bindings[0].certificateStoreName;httpSys=($httpSys -join [Environment]::NewLine)}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`,
      ),
    );
  const beforeNative = native(),
    beforeTls = await tlsPeer();
  assert.equal(beforeNative.machine, true);
  assert.equal(beforeNative.exportPolicy, 0);
  try {
    const envelope = {
      schemaVersion: 1,
      protocolVersion: "1.0.0",
      messageType: "heartbeat",
      agentId: oldAgentId,
      sentAt: new Date().toISOString(),
      body: {
        agentVersion: JSON.parse(
          fs.readFileSync(path.join(packageRoot, "package.json")),
        ).version,
      },
    };
    const fenced = await fetch(
      new URL("/api/v1/certops/agent/heartbeat", baseUrl),
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${oldCredential.toString("utf8").trim()}`,
        },
        body: JSON.stringify(envelope),
        signal: AbortSignal.timeout(15000),
      },
    );
    assert.equal(fenced.status, 410);
    await fenced.arrayBuffer();
    facts.retiredPredecessorCredentialFenced = true;
    fs.mkdirSync(conflict);
    platform.applyRestrictivePermissions(conflict, { kind: "directory" });
    const conflictConfig = {
      ...oldConfig,
      agentId: oldAgentId,
      execution: { ...oldConfig.execution, enabled: false },
      windowsDiscovery: { enabled: false },
    };
    fs.writeFileSync(
      path.join(conflict, "config.json"),
      JSON.stringify(conflictConfig),
    );
    platform.applyRestrictivePermissions(path.join(conflict, "config.json"), {
      kind: "file",
    });
    const deniedBootstrap = await bootstrap("conflict");
    conflictTokenId = deniedBootstrap.token.id;
    await launch(deniedBootstrap, conflict, "conflict-launch");
    await waitUntil(
      () => child.exitCode !== null || child.signalCode !== null,
      45000,
    );
    const failed = await drain();
    assert.equal(failed.rootExitCode, 1);
    assert.equal(await tokenState(deniedBootstrap.token.id), "active");
    assert.equal(fs.existsSync(path.join(conflict, "credential")), false);
    const conflictResponse = await fetch(
      new URL("/api/v1/certops/agent/register", baseUrl),
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${deniedBootstrap.plaintextToken}`,
        },
        body: JSON.stringify({
          schemaVersion: 1,
          protocolVersion: "1.0.0",
          messageType: "register",
          agentId: oldAgentId,
          sentAt: new Date().toISOString(),
          body: {
            bootstrapTokenId: deniedBootstrap.token.id,
            registrationId: crypto.randomUUID(),
            hostname: "owned-scm-conflict",
            platform: "win32",
            agentVersion: JSON.parse(
              fs.readFileSync(path.join(packageRoot, "package.json")),
            ).version,
            declaredCapabilities: [],
          },
        }),
        signal: AbortSignal.timeout(15000),
      },
    );
    assert.equal(conflictResponse.status, 409);
    assert.equal(
      (await conflictResponse.json()).code,
      "CERTOPS_AGENT_REGISTRATION_CONFLICT",
    );
    assert.equal(await tokenState(deniedBootstrap.token.id), "active");
    facts.publicConflictBootstrapUnconsumed = true;
    // Separate identity from custody: no predecessor credential, pending
    // registration transaction, outbound queue or sequence allocator migrates.
    const copied = copyCustody(configDir, target, platform);
    assert.ok(copied.some((row) => row.file.startsWith("job-journal/")));
    assert.ok(copied.some((row) => row.file.startsWith("windows-cert-store/")));
    assert.ok(copied.some((row) => row.file.startsWith("windows-retention/")));
    assert.ok(copied.some((row) => row.file === "signing-key-pin.json"));
    const replacementAgentId = `scm-replacement-${crypto.randomUUID()}`,
      config = {
        ...oldConfig,
        agentId: replacementAgentId,
        execution: { ...oldConfig.execution, enabled: false },
        windowsDiscovery: { enabled: false },
      };
    fs.writeFileSync(path.join(target, "config.json"), JSON.stringify(config));
    platform.applyRestrictivePermissions(path.join(target, "config.json"), {
      kind: "file",
    });
    const freshBootstrap = await bootstrap("replacement");
    freshTokenId = freshBootstrap.token.id;
    await launch(freshBootstrap, target, "replacement-launch");
    const registered = await waitUntil(async () => {
      assert.equal(child.exitCode, null);
      assert.equal(child.signalCode, null);
      const row = (
        await pool.query(
          "SELECT id,status,last_seen_at,created_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",
          [workspaceId, replacementAgentId],
        )
      ).rows[0];
      return row && Date.parse(row.last_seen_at) > Date.parse(row.created_at)
        ? row
        : null;
    }, 45000);
    replacementId = registered.id;
    assert.equal(registered.status, "active");
    assert.notEqual(replacementId, old.id);
    assert.equal(await tokenState(freshBootstrap.token.id), "used");
    facts.publicReplacementBootstrapConsumed =
      facts.unmodifiedCliRegisteredReplacement = true;
    await drain();
    facts.registrationChildDrained = true;
    assert.ok(
      fs.readFileSync(path.join(target, "signing-key-pin.json")).equals(pin),
    );
    facts.signingPinPreserved = true;
    freshServiceOwned();
    changed = true;
    setRegistry(
      oldRegistry.values
        .filter((value) => !/^TOKENTIMER_AGENT_CONFIG_DIR=/i.test(value))
        .concat(`TOKENTIMER_AGENT_CONFIG_DIR=${target}`),
    );
    const marker = (await pool.query("SELECT now() AS marker")).rows[0].marker;
    command("sc.exe", ["start", "TokenTimerAgent"]);
    await waitUntil(() => freshServiceOwned().state === "Running", 30000);
    await waitUntil(
      async () =>
        Date.parse(
          (
            await pool.query(
              "SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND id=$2",
              [workspaceId, replacementId],
            )
          ).rows[0].last_seen_at,
        ) > Date.parse(marker),
      45000,
    );
    const running = freshServiceOwned();
    assert.ok(running.pid > 0);
    const processIdentity = JSON.parse(
      ps(
        `$p=Get-CimInstance Win32_Process -Filter 'ProcessId=${running.pid}';@{sid=(Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid).Sid;executable=$p.ExecutablePath}|ConvertTo-Json -Compress`,
      ),
    );
    assert.equal(processIdentity.sid, "S-1-5-18");
    assert.equal(processIdentity.executable.toLowerCase(), host.toLowerCase());
    facts.sameInstalledServicePathAndSystemIdentity =
      facts.freshReplacementScmHeartbeat = true;
    assert.equal(
      registry().values.some((value) =>
        /^TOKENTIMER_AGENT_BOOTSTRAP_TOKEN(?:_ID)?=/i.test(value),
      ),
      false,
    );
    facts.noBootstrapInServiceRegistry = true;
    for (const row of copied)
      assert.equal(
        crypto
          .createHash("sha256")
          .update(fs.readFileSync(path.join(target, row.file)))
          .digest("hex"),
        row.sha256,
      );
    facts.protectedCustodyAndJournalCopiesPreserved = true;
    assert.ok(
      JSON.stringify(native()) === JSON.stringify(beforeNative),
      "Native custody or binding changed",
    );
    assert.equal(await tlsPeer(), beforeTls);
    facts.nativeCngBindingAndTrustedTlsPreserved = true;
    assert.ok(
      JSON.stringify(await jobs()) === JSON.stringify(beforeJobs),
      "Predecessor jobs changed during identity handoff",
    );
    facts.predecessorJobsNotReplayed = true;
    assert.ok(
      JSON.stringify(stateFiles(configDir)) === JSON.stringify(oldSnapshot),
      "Original protected state changed",
    );
    facts.sourceStateBytesPreserved = true;
    const retired = await publicSession.request(
      `/api/v1/workspaces/${workspaceId}/certops/agents/${replacementId}/retire`,
      "POST",
      { reason: "disposable operator state handoff complete" },
    );
    assert.equal(retired.status, 200);
    await waitUntil(() => freshServiceOwned().state === "Stopped", 30000);
    facts.replacementRetiredAndServiceStopped = true;
  } catch (error) {
    primary = error;
  } finally {
    if (replacementId)
      try {
        const row = (
          await pool.query(
            "SELECT status FROM certops_agents WHERE workspace_id=$1 AND id=$2",
            [workspaceId, replacementId],
          )
        ).rows[0];
        if (row?.status !== "retired") {
          const retired = await publicSession.request(
            `/api/v1/workspaces/${workspaceId}/certops/agents/${replacementId}/retire`,
            "POST",
            { reason: "owned state handoff cleanup" },
          );
          assert.equal(retired.status, 200);
        }
      } catch (error) {
        failures.push(error);
      }
    if (freshTokenId)
      try {
        if ((await tokenState(freshTokenId)) === "active") {
          const revoked = await publicSession.request(
            `/api/v1/workspaces/${workspaceId}/certops/agent-bootstrap-tokens/${freshTokenId}/revoke`,
            "POST",
            {},
          );
          assert.equal(revoked.status, 200);
        }
      } catch (error) {
        failures.push(error);
      }
    if (conflictTokenId)
      try {
        const revoked = await publicSession.request(
          `/api/v1/workspaces/${workspaceId}/certops/agent-bootstrap-tokens/${conflictTokenId}/revoke`,
          "POST",
          {},
        );
        assert.equal(revoked.status, 200);
        facts.unusedConflictBootstrapRevoked = true;
      } catch (error) {
        failures.push(error);
      }
    try {
      await resource.close();
      facts.originalRegistryRestored = true;
    } catch (error) {
      failures.push(error);
    }
    if (!resource.hasLiveChild() && !resource.hasOwnershipReceipt())
      try {
        assert.equal(path.dirname(directory), workDir);
        assert.equal(fs.lstatSync(directory).isSymbolicLink(), false);
        fs.rmSync(directory, { recursive: true });
        facts.ownedStateRemoved = true;
      } catch (error) {
        failures.push(error);
      }
  }
  if (primary || failures.length)
    throw new AggregateError(
      [...(primary ? [primary] : []), ...failures],
      "Installed operator state handoff or owned restoration failed",
    );
  assert.equal(
    crypto.createHash("sha256").update(fs.readFileSync(entry)).digest("hex"),
    entryHash,
  );
  assert.ok(
    JSON.stringify(stateFiles(configDir)) === JSON.stringify(oldSnapshot),
    "Original protected state changed",
  );
  assert.ok(
    JSON.stringify(await jobs()) === JSON.stringify(beforeJobs),
    "Predecessor jobs changed during identity handoff",
  );
  verifyProof(facts);
  return facts;
}
module.exports = {
  qualifyInstalledStateHandoff,
  copyCustody,
  stateFiles,
  COPY_ENTRIES,
  REQUIRED_SOURCES,
  SCOPE,
  FLAGS,
  verifyProof,
  createOwnedHandoffResource,
  verifyDrainReceipt,
};
