"use strict";
/* Genuine hierarchy-only HTTP intermediate revocation fault. Existing offline
 * root publication supplies the actual CRL; no CA extension, response, clock or
 * journal is fabricated. This directly exercises the shipped CryptoAPI helper,
 * not a new installed-agent enrollment or an OCSP/HTTP-only leaf journey.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const tls = require("node:tls");
const net = require("node:net");
const { isDeepStrictEqual, promisify } = require("node:util");
const { execFile } = require("node:child_process");
const {
  applyRestrictivePermissions,
} = require("../../../packages/agent/src/platform");
const {
  resolveAdcsChainHelperPath,
  validateCertificateChain,
} = require("../../../packages/agent/src/issuers/chain-helper");
const execute = promisify(execFile);
const SCOPE =
  "native-hierarchy-http-intermediate-crl-unavailable-and-recovered";
const SCENARIO = "adcs-hierarchy-http-intermediate-crl-fault-recovers";
const HTTP_CRL = "http://10.64.0.7/pki/TTQualificationOfflineRoot.crl";
const active = new Set();
const FLAGS = Object.freeze([
  "actualIntermediateHttpOnlyCdp",
  "actualPublicHttpCrlFetched",
  "freshNativeChainValidBefore",
  "exactProgramScopedHttpBlock",
  "httpAvailableOutsideHelper",
  "issuingCaLdapAvailable",
  "freshNativeRevocationUnknown",
  "exactFirewallRuleRemoved",
  "freshNativeChainValidAfter",
  "originalChainCachePolicyRestored",
  "sameNonexportableCngCustody",
  "sameNativeBindingAndTrustedTls",
  "ownedGuardReleased",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-adcs-http-intermediate-crl.js",
  "infra/certops-adcs/hierarchy-root.ps1",
  "infra/certops-adcs/hierarchy-subordinate.ps1",
  "packages/agent/src/issuers/chain-helper.js",
  "packages/agent/reference/adcs-chain/chaincore/chain_windows.go",
  "packages/agent/src/platform/index.js",
  "scripts/certops_adcs_http_crl_proof.py",
]);
const digest = (bytes) =>
  crypto.createHash("sha256").update(bytes).digest("hex");
function verifyProof(proof) {
  assert.deepEqual(
    Object.keys(proof).sort(),
    [
      "scope",
      "transport",
      "revocationTarget",
      "nativeHelperSha256",
      "publicCrlSha256",
      "leafFingerprint",
      "nativeVerdicts",
      "installedAgentQualified",
      "httpOnlyLeafQualified",
      "ocspQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(proof.scope, SCOPE);
  assert.equal(proof.transport, "http");
  assert.equal(proof.revocationTarget, "intermediate");
  for (const key of [
    "nativeHelperSha256",
    "publicCrlSha256",
    "leafFingerprint",
  ])
    assert.match(proof[key], /^[a-f0-9]{64}$/);
  assert.deepEqual(proof.nativeVerdicts, [
    "valid",
    "revocation_unknown",
    "valid",
  ]);
  for (const flag of FLAGS) assert.equal(proof[flag], true, flag);
  for (const flag of [
    "installedAgentQualified",
    "httpOnlyLeafQualified",
    "ocspQualified",
  ])
    assert.equal(proof[flag], false);
  return proof;
}
function publicCdp(text) {
  const urls = [...String(text).matchAll(/https?:\/\/[^\s<>"')]+/gi)].map(
    (match) => match[0],
  );
  assert.deepEqual(
    [...new Set(urls)],
    [HTTP_CRL],
    "Exact existing hierarchy HTTP CRL required",
  );
  assert.doesNotMatch(
    text,
    /ldap:\/\//i,
    "Intermediate CRL fault requires no LDAP alternate",
  );
  return HTTP_CRL;
}
function nativeEnvironment() {
  return Object.fromEntries(
    ["PATH", "SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP"]
      .filter((key) => process.env[key])
      .map((key) => [key, process.env[key]]),
  );
}
function ownedBytes(file, maximum) {
  const named = fs.lstatSync(file, { bigint: true });
  assert.ok(
    named.isFile() &&
      !named.isSymbolicLink() &&
      named.ino > 0n &&
      named.size > 0n &&
      named.size <= BigInt(maximum),
  );
  const fd = fs.openSync(file, "r");
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      before.isFile() && before.dev === named.dev && before.ino === named.ino,
    );
    const bytes = Buffer.alloc(maximum + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = fs.readSync(fd, bytes, length, bytes.length - length, null);
      if (!count) break;
      length += count;
    }
    const after = fs.fstatSync(fd, { bigint: true }),
      current = fs.lstatSync(file, { bigint: true });
    assert.ok(
      length > 0 &&
        length <= maximum &&
        after.size === BigInt(length) &&
        after.size === before.size &&
        after.mtimeNs === before.mtimeNs &&
        current.isFile() &&
        !current.isSymbolicLink() &&
        current.dev === before.dev &&
        current.ino === before.ino,
    );
    return {
      bytes: bytes.subarray(0, length),
      identity: `${before.dev}:${before.ino}`,
    };
  } finally {
    fs.closeSync(fd);
  }
}
async function fetchPublicCrl() {
  const response = await fetch(HTTP_CRL, {
    redirect: "error",
    signal: AbortSignal.timeout(10000),
  });
  assert.equal(response.status, 200);
  assert.ok(response.body);
  const reader = response.body.getReader(),
    chunks = [];
  let length = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      length += part.value.length;
      assert.ok(length <= 65536, "Bounded public CRL required");
      chunks.push(Buffer.from(part.value));
    }
  } finally {
    await reader.cancel();
  }
  const bytes = Buffer.concat(chunks);
  assert.ok(
    bytes.length >= 100 && bytes[0] === 0x30,
    "Actual DER CRL publication required",
  );
  return digest(bytes);
}
function assertNoHttpCrlGuard(workDir) {
  assert.equal(
    active.has(path.resolve(workDir)),
    false,
    "Preserve unresolved in-memory HTTP CRL ownership",
  );
  assert.equal(
    fs.existsSync(path.join(workDir, "http-intermediate-crl-owner.json")),
    false,
    "Preserve unresolved native HTTP CRL fixture",
  );
}
async function qualifyHttpIntermediateCrl(c) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.equal(process.env.CERTOPS_ADCS_HIERARCHY, "subordinate");
  const {
    gate,
    workDir,
    run,
    renewalFixture: current,
    command,
    ps,
    tlsAuthority,
    registerOwnership,
  } = c;
  assert.equal(
    ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),
    "S-1-5-18",
  );
  assert.match(run, /^[a-f0-9]{10}$/);
  const { item, site, port, authority, observed } = current;
  assertNoHttpCrlGuard(workDir);
  assert.match(
    item.domain,
    /^certops-adcs-[a-f0-9]{10}-rsa2048\.example\.test$/,
  );
  assert.match(site, /^TTADCS-[a-f0-9]{10}-rsa2048$/);
  assert.ok(Number.isInteger(port) && port > 0 && port < 65536);
  const root = path.resolve(__dirname, "../../..");
  const selected = resolveAdcsChainHelperPath();
  assert.equal(selected.error, undefined);
  const program = path.resolve(selected.path),
    programFile = ownedBytes(program, 16 * 1024 * 1024),
    programHash = digest(programFile.bytes),
    escaped = program.replace(/'/g, "''");
  const nonce = crypto.randomUUID(),
    rule = `TTQualificationHttpIntermediate-${run}-${nonce}`;
  const guard = path.join(workDir, "http-intermediate-crl-owner.json");
  const guardBytes = Buffer.from(JSON.stringify({ nonce, rule, programHash }));
  active.add(path.resolve(workDir));
  fs.writeFileSync(guard, guardBytes, { flag: "wx", mode: 0o600 });
  applyRestrictivePermissions(guard, { kind: "file" });
  const guardId = fs.lstatSync(guard, { bigint: true });
  assert.ok(guardId.isFile() && !guardId.isSymbolicLink() && guardId.ino > 0n);
  let released = false,
    firewallOwned = false,
    cacheRestored = false;
  const resource = {
    hasOwnershipReceipt: () => !released,
    assertCleanupSafe: () => assertNoHttpCrlGuard(workDir),
  };
  registerOwnership(resource); // Parent retains this before any native policy mutation.
  const leafPath = path.join(workDir, `http-crl-leaf-${nonce}.cer`),
    caPath = path.join(workDir, `http-crl-ca-${nonce}.cer`),
    cachePath = path.join(workDir, `http-crl-cache-${nonce}.xml`);
  fs.writeFileSync(leafPath, observed.raw, { flag: "wx" });
  fs.writeFileSync(caPath, Buffer.from(authority.certificateB64, "base64"), {
    flag: "wx",
  });
  const q = (value) => value.replace(/'/g, "''");
  const cdp = ps(
    `$c=[Security.Cryptography.X509Certificates.X509Certificate2]::new('${q(caPath)}');try{if($c.Issuer -cne 'CN=TTQualificationOfflineRoot'){throw 'Actual hierarchy intermediate required'};$e=@($c.Extensions|Where-Object {$_.Oid.Value -eq '2.5.29.31'});if($e.Count -ne 1){throw 'Actual intermediate CDP missing'};$e[0].Format($true)}finally{$c.Dispose()}`,
  );
  publicCdp(cdp);
  const thumb = observed.fingerprint.replace(/:/g, "").toUpperCase();
  const custody = () =>
    JSON.parse(
      ps(
        `$c=Get-Item 'Cert:\\LocalMachine\\My\\${thumb}';$k=$null;try{$k=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);@{container=$k.Key.KeyName;unique=$k.Key.UniqueName;exportPolicy=[int]$k.Key.ExportPolicy;machine=$k.Key.IsMachineKey;provider=$k.Key.Provider.Provider;bits=$k.KeySize;der=[Convert]::ToBase64String($c.RawData)}|ConvertTo-Json -Compress}finally{if($k){$k.Dispose()};$c.Dispose()}`,
      ),
    );
  const binding = () =>
    ps(
      `Import-Module WebAdministration;$b=@(Get-WebBinding -Name '${site}' -Protocol https|Where-Object bindingInformation -eq '*:${port}:${item.domain}');$s=@(Get-ChildItem -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslSniBindingInfo'|Where-Object {[string]$_.GetValue('HostnamePort') -ieq '${item.domain}:${port}'});if($b.Count -ne 1 -or $s.Count -ne 1){throw 'Exact hierarchy native binding required'};@{coordinates=[string]$b[0].bindingInformation;flags=[int]$b[0].sslFlags;hash=[BitConverter]::ToString([byte[]]$s[0].GetValue('SslCertHash')).Replace('-','');store=[string]$s[0].GetValue('SslCertStoreName')}|ConvertTo-Json -Compress`,
    );
  const peer = () =>
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
            resolve(
              new crypto.X509Certificate(socket.getPeerCertificate().raw)
                .fingerprint256,
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
          new Error("Hierarchy HTTP CRL TLS observation timed out"),
        ),
      );
    });
  const before = custody(),
    bindingBefore = binding();
  assert.equal(before.exportPolicy, 0);
  assert.equal(before.machine, true);
  assert.equal(before.provider, "Microsoft Software Key Storage Provider");
  assert.equal(before.bits, 2048);
  assert.equal(
    new crypto.X509Certificate(Buffer.from(before.der, "base64"))
      .fingerprint256,
    observed.fingerprint256,
  );
  const initialBinding = JSON.parse(bindingBefore);
  assert.equal(initialBinding.hash, thumb);
  assert.equal(initialBinding.store.toUpperCase(), "MY");
  assert.equal(initialBinding.flags, 1);
  assert.equal(initialBinding.coordinates, `*:${port}:${item.domain}`);
  assert.ok(before.container && before.unique);
  assert.equal(await peer(), observed.fingerprint256);
  const unchanged = async () => {
    assert.ok(
      isDeepStrictEqual(custody(), before),
      "Hierarchy native CNG custody changed",
    );
    assert.equal(binding(), bindingBefore);
    assert.equal(await peer(), observed.fingerprint256);
  };
  const clearCache = () => {
    command("certutil.exe", ["-urlcache", "CRL", "delete"]);
    command("certutil.exe", [
      "-setreg",
      "chain\\ChainCacheResyncFiletime",
      "@now",
    ]);
  };
  const probe = () => {
    const currentProgram = ownedBytes(program, 16 * 1024 * 1024);
    assert.ok(
      currentProgram.identity === programFile.identity &&
        digest(currentProgram.bytes) === programHash,
      "Exact native chain helper changed",
    );
    return validateCertificateChain({
      helperPath: program,
      certPath: leafPath,
      caKeySha256: authority.keySha256,
      caCertPath: caPath,
      revocationCheck: "require",
      execFileImpl: (file, args, options) =>
        execute(file, args, { ...options, env: nativeEnvironment() }),
    });
  };
  ps(
    `$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CertDllCreateCertificateChainEngine\\Config');try{$state=@{exists=[bool]($key -and @($key.GetValueNames()) -contains 'ChainCacheResyncFiletime')};if($state.exists){$state.kind=$key.GetValueKind('ChainCacheResyncFiletime').ToString();if($state.kind -notin @('QWord','Binary')){throw 'Unsupported chain-cache policy'};$state.value=$key.GetValue('ChainCacheResyncFiletime')};$state|Export-Clixml -LiteralPath '${q(cachePath)}' -NoClobber -Encoding UTF8}finally{if($key){$key.Dispose()}}`,
  );
  applyRestrictivePermissions(cachePath, { kind: "file" });
  const cache = ownedBytes(cachePath, 8192);
  const restore = () => {
    const currentCache = ownedBytes(cachePath, 8192);
    assert.ok(
      currentCache.identity === cache.identity &&
        currentCache.bytes.equals(cache.bytes),
      "Original cache policy receipt changed",
    );
    if (firewallOwned) {
      ps(
        `$r=@(Get-NetFirewallRule -Name '${rule}' -ErrorAction SilentlyContinue);if($r.Count -ne 1){throw 'Owned HTTP CRL rule missing'};$a=$r[0]|Get-NetFirewallApplicationFilter;$address=$r[0]|Get-NetFirewallAddressFilter;$p=$r[0]|Get-NetFirewallPortFilter;if($r[0].DisplayName -cne '${rule}' -or [string]$r[0].Direction -cne 'Outbound' -or [string]$r[0].Action -cne 'Block' -or $a.Program -ine '${escaped}' -or [string]$address.RemoteAddress -cne '10.64.0.7' -or [string]$p.RemotePort -cne '80' -or [string]$p.Protocol -notin @('TCP','6')){throw 'Foreign HTTP CRL rule replacement'};Remove-NetFirewallRule -Name '${rule}';if(@(Get-NetFirewallRule -Name '${rule}' -ErrorAction SilentlyContinue).Count){throw 'Owned rule removal unproven'}`,
      );
      firewallOwned = false;
    }
    clearCache();
    ps(
      `$state=[Management.Automation.PSSerializer]::Deserialize([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${Buffer.from(cache.bytes.toString("utf8").replace(/^\uFEFF/, "")).toString("base64")}')));$key=[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CertDllCreateCertificateChainEngine\\Config');try{if($state.exists){$kind=[Microsoft.Win32.RegistryValueKind][Enum]::Parse([Microsoft.Win32.RegistryValueKind],$state.kind);if($state.kind -eq 'Binary'){$value=[byte[]]$state.value;$key.SetValue('ChainCacheResyncFiletime',$value,$kind);if([Convert]::ToBase64String([byte[]]$key.GetValue('ChainCacheResyncFiletime')) -cne [Convert]::ToBase64String($value)){throw 'Native chain cache mismatch'}}else{$key.SetValue('ChainCacheResyncFiletime',[long]$state.value,$kind);if([long]$key.GetValue('ChainCacheResyncFiletime') -ne [long]$state.value){throw 'Native chain cache mismatch'}};if($key.GetValueKind('ChainCacheResyncFiletime').ToString() -cne $state.kind){throw 'Native chain cache kind mismatch'}}else{$key.DeleteValue('ChainCacheResyncFiletime',$false);if(@($key.GetValueNames()) -contains 'ChainCacheResyncFiletime'){throw 'Native cache policy absence not restored'}}}finally{$key.Dispose()}`,
    );
    cacheRestored = true;
  };
  let proof;
  try {
    await gate.scenario(
      SCENARIO,
      async () => {
        const publicCrlSha256 = await fetchPublicCrl();
        clearCache();
        assert.equal((await probe()).verdict, "valid");
        assert.equal(
          ps(
            `@(Get-NetFirewallRule -Name '${rule}' -ErrorAction SilentlyContinue).Count`,
          ),
          "0",
        );
        firewallOwned = true;
        ps(
          `New-NetFirewallRule -Name '${rule}' -DisplayName '${rule}' -Direction Outbound -Action Block -Program '${escaped}' -RemoteAddress '10.64.0.7' -Protocol TCP -RemotePort 80 | Out-Null`,
        );
        await fetchPublicCrl();
        const ldap = await new Promise((resolve) => {
          const socket = net.connect({ host: "10.64.0.4", port: 389 }, () => {
            socket.destroy();
            resolve(true);
          });
          socket.once("error", () => {
            socket.destroy();
            resolve(false);
          });
          socket.setTimeout(3000, () => {
            socket.destroy();
            resolve(false);
          });
        });
        assert.equal(ldap, true);
        clearCache();
        assert.equal((await probe()).verdict, "revocation_unknown");
        await unchanged();
        restore();
        assert.equal(cacheRestored, true);
        assert.equal((await probe()).verdict, "valid");
        await unchanged();
        const currentGuard = ownedBytes(guard, 4096);
        assert.ok(
          currentGuard.identity === `${guardId.dev}:${guardId.ino}` &&
            currentGuard.bytes.equals(guardBytes),
        );
        fs.unlinkSync(guard);
        released = true;
        active.delete(path.resolve(workDir));
        proof = verifyProof({
          scope: SCOPE,
          transport: "http",
          revocationTarget: "intermediate",
          nativeHelperSha256: programHash,
          publicCrlSha256,
          leafFingerprint: observed.fingerprint256
            .replace(/:/g, "")
            .toLowerCase(),
          nativeVerdicts: ["valid", "revocation_unknown", "valid"],
          installedAgentQualified: false,
          httpOnlyLeafQualified: false,
          ocspQualified: false,
          ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
        });
        gate.report.fixtureSources ??= [];
        for (const file of REQUIRED_SOURCES)
          gate.report.fixtureSources.push({
            file,
            sha256: digest(fs.readFileSync(path.join(root, file))),
          });
      },
      {
        evidenceLevel: "real-host",
        oracle:
          "existing hierarchy HTTP-only intermediate CDP, exact chain-helper program firewall fault and actual valid/unknown/recovered native chain with unchanged CNG/IIS/trusted TLS",
      },
    );
    return proof;
  } finally {
    if (firewallOwned || !cacheRestored) restore();
    // A failed native observation retains the guard/private snapshot for the
    // parent, even if best-effort rule/cache restoration itself succeeds.
  }
}
module.exports = {
  SCOPE,
  SCENARIO,
  HTTP_CRL,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  publicCdp,
  nativeEnvironment,
  ownedBytes,
  assertNoHttpCrlGuard,
  qualifyHttpIntermediateCrl,
};
