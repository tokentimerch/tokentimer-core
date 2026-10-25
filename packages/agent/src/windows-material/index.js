"use strict";
const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");
const childProcess = require("node:child_process");
const net = require("node:net");
const {
  assertValidBinding,
  deployIisBinding,
  queryCurrentBinding,
} = require("../windows-iis");
const {
  acquireStoreLock,
  computeSha1ThumbprintFromPem,
} = require("../windows-cert-store");
const { windowsSystem32Tool } = require("../platform");
const {
  writeProtectedJson,
  readProtectedFile,
  protectDirectory,
  failure,
} = require("../material-store");
const { makePkcs12 } = require("./pkcs12");

const CONNECTOR = "windows-material-iis-v1";
function validateWindowsBinding(binding, policyEngine) {
  if (
    binding.connector !== CONNECTOR ||
    binding.target?.type !== "windows-iis" ||
    (binding.activationMode !== undefined &&
      binding.activationMode !== "rebind") ||
    binding.target.store !== binding.target.binding?.store ||
    !Array.isArray(binding.serviceAccountSids) ||
    binding.serviceAccountSids.length > 16 ||
    binding.serviceAccountSids.some(
      (sid) =>
        !/^S-1-(?:\d+-){1,14}\d+$/.test(sid) ||
        ["S-1-1-0", "S-1-5-11", "S-1-5-32-545"].includes(sid),
    )
  )
    throw failure("material_windows_policy_denied");
  try {
    assertValidBinding(binding.target.binding);
  } catch {
    throw failure("material_windows_policy_denied");
  }
  const address = binding.target.binding.address;
  if (
    [
      "root",
      "ca",
      "authroot",
      "trust",
      "trustedpublisher",
      "trustedpeople",
      "disallowed",
      "smartcardroot",
    ].includes(binding.target.store.toLowerCase())
  )
    throw failure("material_windows_policy_denied");
  if (
    !["*", "0.0.0.0", "[::]"].includes(address) &&
    !net.isIP(address.replace(/^\[|\]$/g, ""))
  )
    throw failure("material_windows_policy_denied");
  if (!policyEngine.checkTargetScope(binding.target.reference).allowed)
    throw failure("material_destination_denied");
  // Every TLS probe must cover this exact listener and an authorized identity.
  if (
    binding.probes.some(
      (p) =>
        net.isIP(p.dialAddress) === 0 ||
        p.port !== binding.target.binding.port ||
        (binding.target.binding.sniHost &&
          p.sni.toLowerCase() !== binding.target.binding.sniHost.toLowerCase()),
    )
  )
    throw failure("material_probe_config_invalid");
}

function createWindowsConnector({
  binding,
  stateDir,
  execFileImpl = childProcess.execFile,
}) {
  const target = binding.target.binding;
  const powershellPath = path.join(
    path.dirname(windowsSystem32Tool("cmd")),
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
  );
  async function invoke(operation, bundle, signal) {
    const file = path.join(
      stateDir,
      "material-windows-staging",
      `${crypto.randomUUID()}.json`,
    );
    let pfx;
    try {
      const password = crypto.randomBytes(32).toString("hex");
      if (operation === "import") pfx = makePkcs12(bundle, password);
      writeProtectedJson(file, {
        operation,
        binding: target,
        serviceAccountSids: binding.serviceAccountSids,
        ...(bundle
          ? {
              thumbprint: computeSha1ThumbprintFromPem(bundle.certificatePem),
              fingerprint: bundle.fingerprintSha256,
            }
          : {}),
        ...(pfx ? { pfx: pfx.toString("base64"), password } : {}),
      });
      const result = await new Promise((resolve, reject) => {
        execFileImpl(
          powershellPath,
          [
            "-NoProfile",
            "-NonInteractive",
            "-File",
            path.join(__dirname, "connector.ps1"),
            "-InputFile",
            file,
          ],
          {
            windowsHide: true,
            timeout: 60000,
            maxBuffer: 16384,
            encoding: "utf8",
            signal,
            env: {
              ...process.env,
              PSModulePath: path.join(path.dirname(powershellPath), "Modules"),
            },
          },
          (error, stdout) => {
            if (error) {
              reject(failure(`material_windows_${operation}_failed`));
              return;
            }
            try {
              const value = JSON.parse(stdout.trim());
              if (value.ok !== true) throw new Error();
              resolve({ ok: true });
            } catch {
              reject(failure(`material_windows_${operation}_failed`));
            }
          },
        );
      });
      return result;
    } finally {
      pfx?.fill(0);
      fs.rmSync(file, { force: true });
    }
  }
  async function withLock(work) {
    // The same store mutex as local CNG enrollment, plus a host-wide binding
    // mutex: http.sys hostname selectors are shared even across stores/sites.
    const locks = [];
    try {
      for (const name of [
        ...new Set(["My", target.store, "tokentimer-iis-bindings"]),
      ])
        locks.push(acquireStoreLock(stateDir, name));
      const staging = path.join(stateDir, "material-windows-staging");
      protectDirectory(staging);
      // The global IIS mutex proves no other live connector owns these files.
      // A killed helper/host may leave a protected PFX/password input behind.
      for (const name of fs.readdirSync(staging))
        if (/^[a-f0-9-]{36}\.json$/.test(name)) {
          const file = path.join(staging, name);
          readProtectedFile(file, 512 * 1024);
          fs.unlinkSync(file);
        }
      const run = (i, signal) =>
        i === locks.length
          ? work(signal)
          : locks[i].run((nextSignal) =>
              run(
                i + 1,
                signal ? AbortSignal.any([signal, nextSignal]) : nextSignal,
              ),
            );
      return await run(0);
    } finally {
      for (const lock of locks.reverse()) lock.release();
    }
  }
  async function verify(bundle, signal) {
    await invoke("verify", bundle, signal);
    const current = await queryCurrentBinding({
      binding: target,
      execFileImpl,
      powershellPath,
      timeoutMs: 30000,
      signal,
    });
    return (
      current.ok === true &&
      current.thumbprint === computeSha1ThumbprintFromPem(bundle.certificatePem)
    );
  }
  return {
    withLock,
    preflight: (signal) => invoke("preflight", null, signal),
    import: (bundle, signal) => invoke("import", bundle, signal),
    async activate(bundle, signal) {
      await invoke("preflight", null, signal);
      const result = await deployIisBinding({
        binding: target,
        certificatePem: bundle.certificatePem,
        execFileImpl,
        powershellPath,
        netshPath: windowsSystem32Tool("netsh"),
        signal,
      });
      if (!result.ok) throw failure("material_windows_activation_failed");
      await invoke("commit", bundle, signal);
      if (!(await verify(bundle, signal)))
        throw failure("material_windows_binding_mismatch");
    },
    verify,
  };
}
module.exports = { CONNECTOR, validateWindowsBinding, createWindowsConnector };
