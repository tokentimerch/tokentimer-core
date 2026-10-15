"use strict";
/** Shared supporting native IP HTTP.sys precedence/rollback controls. The
 * original IPv6 variants and explicit IPv4 wildcard retain distinct proof scopes.
 * Certificates and
 * keys remain owned by the enclosing IIS fixture. An unresolved resource guard
 * prevents its finally block from deleting borrowed custody. No installed-agent
 * or CA qualification is inferred from this native binding fixture. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  net = require("node:net"),
  tls = require("node:tls");
const iis = require("../../src/windows-iis"),
  discovery = require("../../src/windows-discovery"),
  platform = require("../../src/platform");
const SCOPE = "native-ipv6-sni-shadow-rollback-with-ipv4-sibling";
const WILDCARD_SCOPE =
  "native-ipv6-wildcard-sni-shadow-rollback-with-ipv4-sibling";
function variantContract(variant) {
  assert.ok(
    variant === "concrete" ||
      variant === "wildcard" ||
      variant === "ipv4-wildcard",
    "Only explicit native IP variants are supported",
  );
  if (variant === "ipv4-wildcard")
    return {
      address: "0.0.0.0",
      scope: "native-ipv4-wildcard-sni-shadow-rollback-with-ipv4-sibling",
    };
  return variant === "concrete"
    ? { address: "[::1]", scope: SCOPE }
    : { address: "[::]", scope: WILDCARD_SCOPE };
}
const SCENARIOS = Object.freeze(["windows-iis-ipv6-native-shadow-rollback"]);
const FLAGS = Object.freeze([
  "actualIpv6LoopbackAvailable",
  "borrowedCertificatesVerified",
  "actualIpv6ShadowObserved",
  "productionPrecedenceWarning",
  "actualProductionVerifyFailed",
  "actualProductionRollback",
  "nativeHostnameEndpointRestored",
  "trustedIpv6ShadowObserved",
  "trustedIpv6BaselineRecovered",
  "ipv4SiblingUnchanged",
  "ownedSitesAndEndpointsRemoved",
]);
const REQUIRED_SOURCES = Object.freeze([
  "packages/agent/scripts/host/ipv6-shadow-fixture.js",
  "packages/agent/scripts/host/iis-fixture.js",
  "packages/agent/scripts/host/windows-host.test.js",
  "packages/agent/src/windows-iis/index.js",
  "packages/agent/src/windows-discovery/index.js",
  "packages/agent/src/verify/index.js",
  "packages/agent/src/platform/index.js",
]);
const guardName = ".preserve-ipv6-shadow.json";
function flagsForVariant(variant) {
  return variant === "ipv4-wildcard"
    ? FLAGS.map((k) =>
        k.replaceAll("Ipv6", "Ipv4").replace("trustedIpv6", "trustedIpv4"),
      )
    : FLAGS;
}
function verifyVariantProof(p, variant) {
  const flags = flagsForVariant(variant);
  assert.deepEqual(
    Object.keys(p).sort(),
    ["scope", "installedAgentQualified", "caQualified", ...flags].sort(),
  );
  assert.equal(p.scope, variantContract(variant).scope);
  assert.equal(p.installedAgentQualified, false);
  assert.equal(p.caQualified, false);
  for (const key of flags) assert.equal(p[key], true, key);
  return true;
}
function verifyProof(proof) {
  return verifyVariantProof(proof, "concrete");
}
function assertCleanupSafe(root) {
  assert.equal(
    fs.existsSync(path.join(root, guardName)),
    false,
    "Preserve borrowed IIS certificate keys while IPv6 resource ownership is unresolved",
  );
}
function fileId(file) {
  const s = fs.lstatSync(file, { bigint: true });
  assert.equal(s.isSymbolicLink(), false);
  assert.ok(s.ino > 0n);
  assert.equal(
    fs.realpathSync(file).toLowerCase(),
    path.resolve(file).toLowerCase(),
  );
  return String(s.ino);
}
function certificatesForFixture(certificates) {
  assert.equal(certificates.length, 4);
  const rows = [0, 1, 3].map((i) => certificates[i]);
  for (const row of rows) {
    assert.match(row.thumbprint, /^[A-F0-9]{40}$/);
    const c = new crypto.X509Certificate(Buffer.from(row.der, "base64"));
    assert.equal(c.fingerprint.replace(/:/g, ""), row.thumbprint);
    assert.equal(c.checkHost("localhost"), "localhost");
  }
  assert.equal(new Set(rows.map((r) => r.thumbprint)).size, 3);
  return rows;
}
function pem(c) {
  return `-----BEGIN CERTIFICATE-----\n${c.der}\n-----END CERTIFICATE-----\n`;
}
async function loopbackPort(host = "::1") {
  const server = net.createServer((socket) => socket.destroy());
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(
      { host, port: 0, ...(host.includes(":") ? { ipv6Only: true } : {}) },
      resolve,
    );
  });
  const port = server.address().port;
  await new Promise((resolve, reject) =>
    server.close((e) => (e ? reject(e) : resolve())),
  );
  return port;
}
async function assertPortAvailable(host, port) {
  const server = net.createServer((socket) => socket.destroy());
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(
      { host, port, ...(host.includes(":") ? { ipv6Only: true } : {}) },
      resolve,
    );
  });
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
}
async function siblingPort(excluded) {
  for (let attempt = 0; attempt < 8; attempt++) {
    const port = await loopbackPort("127.0.0.1");
    if (port !== excluded) return port;
  }
  throw new Error("Distinct isolated IPv4 sibling port unavailable");
}
function trustedThumb(host, port, cert) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host,
        port,
        servername: "localhost",
        ca: pem(cert),
        rejectUnauthorized: true,
      },
      () => {
        try {
          assert.equal(socket.authorized, true);
          resolve(socket.getPeerCertificate().fingerprint.replace(/:/g, ""));
        } catch (e) {
          reject(e);
        } finally {
          socket.destroy();
        }
      },
    );
    socket.once("error", reject);
    socket.setTimeout(5000, () =>
      socket.destroy(new Error("Owned IPv6 TLS probe deadline")),
    );
  });
}
async function expectTls(host, port, certificate) {
  const end = performance.now() + 20000;
  let failure;
  do {
    try {
      assert.equal(
        await trustedThumb(host, port, certificate),
        certificate.thumbprint,
      );
      return;
    } catch (e) {
      failure = e;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  } while (performance.now() < end);
  throw failure;
}
function selectEndpoint(rows, selector) {
  return rows.filter(
    (row) =>
      `${row.keyedBy}=${iis.canonicalSelectorValue(row.ipPort || "")}` ===
      selector,
  );
}
function assertOwnedEndpoint(row, { thumbprints, appIds }) {
  assert.ok(row);
  assert.ok(thumbprints.includes(row.thumbprint));
  assert.equal(String(row.storeName).toLowerCase(), "my");
  assert.ok(
    appIds
      .map((v) => v.replace(/[{}]/g, "").toLowerCase())
      .includes(String(row.appId).replace(/[{}]/g, "").toLowerCase()),
    "Foreign HTTP.sys application identity; preserve resources",
  );
}
function assertNoPortConflicts(rows, ports) {
  for (const row of rows) {
    assert.equal(
      typeof row.ipPort,
      "string",
      "Complete native endpoint coordinates required",
    );
    const match = /:([0-9]+)$/.exec(iis.canonicalSelectorValue(row.ipPort));
    assert.ok(match, "Native endpoint port unavailable");
    assert.equal(
      ports.includes(Number(match[1])),
      false,
      "Refuse any pre-existing wildcard, IP or hostname endpoint on owned fixture ports",
    );
  }
}
function siteScript({ name, directory, information, sni }) {
  assert.match(name, /^CertOps-IPv[46]-[a-f0-9-]{36}$/);
  assert.match(
    information,
    /^(?:\[::1\]|127\.0\.0\.1):[0-9]{1,5}:(?:localhost)?$/,
  );
  const escaped = directory.replace(/'/g, "''");
  return `Add-Type -Path "$env:SystemRoot\\System32\\inetsrv\\Microsoft.Web.Administration.dll";$m=[Microsoft.Web.Administration.ServerManager]::new();try{if($m.Sites['${name}']){throw 'Refuse pre-existing owned site name'};$s=$m.Sites.Add('${name}','https','${information}','${escaped}');$s.Bindings[0].SslFlags=${sni ? 1 : 0};$s.ServerAutoStart=$true;$m.CommitChanges();@{siteId=[long]$s.Id}|ConvertTo-Json -Compress}finally{$m.Dispose()}`;
}
async function qualifyIpv6ShadowVariant(
  { certificates, powershell, run: executeNative, workDir },
  variant,
) {
  const selectedVariant = variantContract(variant);
  const ipv4Wildcard = variant === "ipv4-wildcard";
  const targetHost = ipv4Wildcard ? "127.0.0.1" : "::1";
  const targetAddress = ipv4Wildcard ? "127.0.0.1" : "[::1]";
  const flags = flagsForVariant(variant);
  assert.equal(process.platform, "win32");
  assertCleanupSafe(workDir);
  const [shadow, baseline, incoming] = certificatesForFixture(certificates),
    port = await loopbackPort(
      ipv4Wildcard ? "0.0.0.0" : variant === "wildcard" ? "::" : "::1",
    ),
    siblingPortValue = await siblingPort(port),
    nonce = crypto.randomUUID(),
    rootId = fileId(workDir),
    directory = fs.mkdtempSync(path.join(workDir, "ipv6-shadow-")),
    directoryId = fileId(directory),
    guard = path.join(workDir, guardName),
    v6 = `CertOps-IPv${ipv4Wildcard ? 4 : 6}-${nonce}`,
    v4 = `CertOps-IPv4-${ipv4Wildcard ? crypto.randomUUID() : nonce}`;
  platform.applyRestrictivePermissions(directory, { kind: "directory" });
  fs.writeFileSync(
    path.join(directory, "index.htm"),
    "Owned IPv6 precedence fixture",
  );
  const binding = {
      address: targetAddress,
      port,
      store: "My",
      site: v6,
      sniHost: "localhost",
    },
    hostSelector = `hostnameport=localhost:${port}`,
    v4Selector = `ipport=127.0.0.1:${siblingPortValue}`,
    shadowSelector = `ipport=${selectedVariant.address}:${port}`,
    appIds = {
      host: crypto.randomUUID(),
      v4: crypto.randomUUID(),
      shadow: crypto.randomUUID(),
    },
    record = {
      nonce,
      directory,
      sites: [v6, v4],
      port,
      siblingPort: siblingPortValue,
      appIds,
      shadowAddress: selectedVariant.address,
      borrowedThumbprints: [
        shadow.thumbprint,
        baseline.thumbprint,
        incoming.thumbprint,
      ],
    };
  fs.writeFileSync(guard, JSON.stringify(record), { flag: "wx" });
  platform.applyRestrictivePermissions(guard, { kind: "file" });
  const guardId = fileId(guard),
    guardHash = crypto
      .createHash("sha256")
      .update(fs.readFileSync(guard))
      .digest("hex");
  const owned = () => {
    assert.equal(fileId(workDir), rootId);
    assert.equal(fileId(directory), directoryId);
    assert.equal(fileId(guard), guardId);
    assert.equal(
      crypto.createHash("sha256").update(fs.readFileSync(guard)).digest("hex"),
      guardHash,
    );
  };
  const run = (...args) => {
    owned();
    try {
      const result = executeNative(...args);
      owned();
      return result;
    } catch {
      throw new Error(
        "Owned IPv6 HTTP.sys operation refused; preserve private ownership state",
      );
    }
  };
  const ps = (script) => {
    owned();
    try {
      const result = powershell(script);
      owned();
      return result;
    } catch {
      throw new Error(
        "Owned IPv6 native operation refused; preserve borrowed key ownership",
      );
    }
  };
  const listing = async () => {
    owned();
    const result = await discovery.listHttpSysBindings({});
    assert.equal(
      result.ok,
      true,
      "Complete native HTTP.sys inventory required",
    );
    owned();
    return result.bindings;
  };
  const endpoint = async (selector) => {
    const rows = selectEndpoint(await listing(), selector);
    assert.ok(rows.length <= 1, "Ambiguous native endpoint");
    return rows[0];
  };
  const baselinePolicy = {
      thumbprints: [baseline.thumbprint],
      appIds: [appIds.host],
    },
    v4Policy = { thumbprints: [baseline.thumbprint], appIds: [appIds.v4] },
    shadowPolicy = {
      thumbprints: [shadow.thumbprint],
      appIds: [appIds.shadow],
    };
  const proof = {
    scope: selectedVariant.scope,
    installedAgentQualified: false,
    caQualified: false,
  };
  const ownedFiles = new Map();
  const trackFile = (name) => {
    const file = path.join(directory, name);
    ownedFiles.set(name, {
      id: fileId(file),
      sha256: crypto
        .createHash("sha256")
        .update(fs.readFileSync(file))
        .digest("hex"),
    });
  };
  trackFile("index.htm");
  const siteIds = {};
  let completeSetup = false,
    primary;
  try {
    owned();
    if (variant === "wildcard") {
      await assertPortAvailable("::", port);
      await assertPortAvailable("127.0.0.1", port);
    }
    assertNoPortConflicts(await listing(), [port, siblingPortValue]);
    for (const selector of [hostSelector, v4Selector, shadowSelector])
      assert.equal(
        await endpoint(selector),
        undefined,
        "Refuse existing native endpoint",
      );
    siteIds.v6 = JSON.parse(
      ps(
        siteScript({
          name: v6,
          directory,
          information: `${targetAddress}:${port}:localhost`,
          sni: true,
        }),
      ),
    ).siteId;
    siteIds.v4 = JSON.parse(
      ps(
        siteScript({
          name: v4,
          directory,
          information: `127.0.0.1:${siblingPortValue}:`,
          sni: false,
        }),
      ),
    ).siteId;
    for (const id of Object.values(siteIds))
      assert.ok(
        Number.isSafeInteger(id) && id > 0 && id <= 0xffffffff,
        "Actual native IIS site identity required",
      );
    assert.notEqual(siteIds.v6, siteIds.v4);
    fs.writeFileSync(
      path.join(directory, "site-identities.json"),
      JSON.stringify(siteIds),
      { flag: "wx" },
    );
    platform.applyRestrictivePermissions(
      path.join(directory, "site-identities.json"),
      { kind: "file" },
    );
    trackFile("site-identities.json");
    for (const [selector, cert, appId] of [
      [hostSelector, baseline, appIds.host],
      [v4Selector, baseline, appIds.v4],
    ])
      run("netsh.exe", [
        "http",
        "add",
        "sslcert",
        selector,
        `certhash=${cert.thumbprint}`,
        `appid={${appId}}`,
        "certstorename=My",
      ]);
    assertOwnedEndpoint(await endpoint(hostSelector), baselinePolicy);
    assertOwnedEndpoint(await endpoint(v4Selector), v4Policy);
    completeSetup = true;
    assert.equal(
      await iis.checkSniPrecedenceConflict({ binding }),
      undefined,
      "Clean IPv6 SNI baseline must have no pre-existing shadow",
    );
    await expectTls(targetHost, port, baseline);
    await expectTls("127.0.0.1", siblingPortValue, baseline);
    run("netsh.exe", [
      "http",
      "add",
      "sslcert",
      shadowSelector,
      `certhash=${shadow.thumbprint}`,
      `appid={${appIds.shadow}}`,
      "certstorename=My",
    ]);
    assertOwnedEndpoint(await endpoint(shadowSelector), shadowPolicy);
    const warning = await iis.checkSniPrecedenceConflict({ binding });
    assert.ok(warning?.includes(shadowSelector));
    assert.ok(warning.includes(hostSelector));
    await expectTls(targetHost, port, shadow);
    await expectTls("127.0.0.1", siblingPortValue, baseline);
    const result = await iis.deployIisBinding({
      binding,
      certificatePem: pem(incoming),
      verifyTimeoutMs: 3000,
    });
    assert.equal(result.ok, false);
    assert.equal(result.code, "VERIFY_FAILED");
    assert.equal(result.rolledBack, true);
    assert.equal(result.outgoingThumbprint, baseline.thumbprint);
    // The unchanged product generates a fresh HTTP.sys AppId for each bind,
    // including rollback. Adopt only its bounded successful rollback readback;
    // an interrupted/unknown bind never grants new cleanup ownership.
    const restored = await endpoint(hostSelector);
    assert.equal(restored?.thumbprint, baseline.thumbprint);
    assert.equal(String(restored.storeName).toLowerCase(), "my");
    assert.match(
      restored.appId,
      /^\{?[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}\}?$/,
    );
    baselinePolicy.appIds.push(restored.appId);
    assertOwnedEndpoint(restored, baselinePolicy);
    assertOwnedEndpoint(await endpoint(v4Selector), v4Policy);
    await expectTls(targetHost, port, shadow);
    await expectTls("127.0.0.1", siblingPortValue, baseline);
    assertOwnedEndpoint(await endpoint(shadowSelector), shadowPolicy);
    run("netsh.exe", ["http", "delete", "sslcert", shadowSelector]);
    assert.equal(await endpoint(shadowSelector), undefined);
    await expectTls(targetHost, port, baseline);
    await expectTls("127.0.0.1", siblingPortValue, baseline);
    Object.assign(
      proof,
      Object.fromEntries(
        flags
          .filter((k) => k !== "ownedSitesAndEndpointsRemoved")
          .map((k) => [k, true]),
      ),
    );
  } catch (e) {
    primary = e;
    throw e;
  } finally {
    try {
      owned();
      assert.equal(
        completeSetup,
        true,
        "Partial native setup preserves guard for owned host teardown",
      );
      ps(
        `Add-Type -Path "$env:SystemRoot\\System32\\inetsrv\\Microsoft.Web.Administration.dll";$m=[Microsoft.Web.Administration.ServerManager]::new();try{foreach($entry in @(@{Name='${v6}';Id=${siteIds.v6};Flags=1;Binding='${targetAddress}:${port}:localhost'},@{Name='${v4}';Id=${siteIds.v4};Flags=0;Binding='127.0.0.1:${siblingPortValue}:'})){$s=$m.Sites[$entry.Name];if(!$s -or [long]$s.Id -ne $entry.Id -or $s.Bindings.Count -ne 1 -or $s.Bindings[0].Protocol -cne 'https' -or [int]$s.Bindings[0].SslFlags -ne $entry.Flags -or $s.Bindings[0].BindingInformation -cne $entry.Binding -or $s.Applications['/'].VirtualDirectories['/'].PhysicalPath -cne '${directory.replace(/'/g, "''")}'){throw 'Foreign native site replacement; preserve borrowed custody'};$null=$s.Id};}finally{$m.Dispose()}`,
      );
      for (const [selector, policy] of [
        [shadowSelector, shadowPolicy],
        [
          hostSelector,
          {
            ...baselinePolicy,
            thumbprints: [baseline.thumbprint, incoming.thumbprint],
          },
        ],
        [v4Selector, v4Policy],
      ]) {
        const row = await endpoint(selector);
        if (row) {
          assertOwnedEndpoint(row, policy);
          run("netsh.exe", ["http", "delete", "sslcert", selector]);
        }
        assert.equal(await endpoint(selector), undefined);
      }
      ps(
        `Add-Type -Path "$env:SystemRoot\\System32\\inetsrv\\Microsoft.Web.Administration.dll";$m=[Microsoft.Web.Administration.ServerManager]::new();try{foreach($entry in @(@{Name='${v6}';Id=${siteIds.v6};Flags=1;Binding='${targetAddress}:${port}:localhost'},@{Name='${v4}';Id=${siteIds.v4};Flags=0;Binding='127.0.0.1:${siblingPortValue}:'})){$s=$m.Sites[$entry.Name];if(!$s -or [long]$s.Id -ne $entry.Id -or $s.Bindings.Count -ne 1 -or $s.Bindings[0].Protocol -cne 'https' -or [int]$s.Bindings[0].SslFlags -ne $entry.Flags -or $s.Bindings[0].BindingInformation -cne $entry.Binding -or $s.Applications['/'].VirtualDirectories['/'].PhysicalPath -cne '${directory.replace(/'/g, "''")}'){throw 'Foreign native site replacement; preserve borrowed custody'};$m.Sites.Remove($s)};$m.CommitChanges()}finally{$m.Dispose()}`,
      );
      ps(
        `Add-Type -Path "$env:SystemRoot\\System32\\inetsrv\\Microsoft.Web.Administration.dll";$m=[Microsoft.Web.Administration.ServerManager]::new();try{if($m.Sites['${v6}'] -or $m.Sites['${v4}']){throw 'Owned IPv6 fixture sites remain'}}finally{$m.Dispose()}`,
      );
      for (const selector of [hostSelector, v4Selector, shadowSelector])
        assert.equal(await endpoint(selector), undefined);
      owned();
      assert.equal(
        JSON.stringify(fs.readdirSync(directory).sort()),
        JSON.stringify([...ownedFiles.keys()].sort()),
        "Unexpected fixture file preserves private ownership state",
      );
      for (const [name, receipt] of ownedFiles) {
        const file = path.join(directory, name);
        assert.equal(fileId(file), receipt.id);
        assert.equal(fs.lstatSync(file).isFile(), true);
        assert.equal(
          crypto
            .createHash("sha256")
            .update(fs.readFileSync(file))
            .digest("hex"),
          receipt.sha256,
        );
        fs.unlinkSync(file);
      }
      fs.rmdirSync(directory);
      assert.equal(fileId(workDir), rootId);
      assert.equal(fileId(guard), guardId);
      assert.equal(
        crypto
          .createHash("sha256")
          .update(fs.readFileSync(guard))
          .digest("hex"),
        guardHash,
      );
      fs.unlinkSync(guard);
      proof.ownedSitesAndEndpointsRemoved = true;
    } catch {
      throw new Error(
        primary
          ? "IPv6 qualification failed and cleanup ownership remains unresolved; preserve borrowed keys"
          : "IPv6 cleanup ownership remains unresolved; preserve borrowed keys",
      );
    }
  }
  verifyVariantProof(proof, variant);
  return proof;
}
function qualifyIpv6Shadow(context) {
  return qualifyIpv6ShadowVariant(context, "concrete");
}
module.exports = {
  qualifyIpv6ShadowVariant,
  verifyVariantProof,
  variantContract,
  flagsForVariant,
  WILDCARD_SCOPE,
  qualifyIpv6Shadow,
  verifyProof,
  assertCleanupSafe,
  certificatesForFixture,
  siteScript,
  assertOwnedEndpoint,
  selectEndpoint,
  assertNoPortConflicts,
  SCOPE,
  SCENARIOS,
  FLAGS,
  REQUIRED_SOURCES,
  guardName,
};
