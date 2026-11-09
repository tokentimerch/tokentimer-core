"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { X509Certificate } = require("node:crypto");
const { validateObservedRevocation, readCertificateBundle, freshSystemRoots, loadTrustMaterial } = require("./config");

const cert = fs.readFileSync(path.join(__dirname, "../verify/fixtures/chain-leaf.crt.pem"), "utf8");

test("legacy configurations remain disabled and enabled checks require authorized origins", () => {
  assert.equal(validateObservedRevocation().enabled, false);
  assert.equal(validateObservedRevocation().explicitlyDisabled, true);
  assert.deepEqual(validateObservedRevocation({ enabled: true }).allowedOrigins, []);
  assert.equal(validateObservedRevocation({ enabled: true }).enabled, true);
  assert.equal(validateObservedRevocation({ enabled: false, allowedOrigins: ["https://pki.example"] }).enabled, false);
  for (const origin of ["https://pki.example/a.crl", "http://u:p@pki.example", "file:///tmp/a", "https://pki.example/#fragment"]) {
    assert.throws(() => validateObservedRevocation({ enabled: true, allowedOrigins: [origin] }));
  }
  assert.deepEqual(validateObservedRevocation({ enabled: true, allowedOrigins: ["http://pki.example:8080"] }).allowedOrigins, ["http://pki.example:8080"]);
});

test("system trust is reloaded and Windows disallowed certificates are excluded", async () => {
  let calls = 0;
  const run = (_executable, _args, options) => { calls++; assert.equal(options.shell, false); return { status: 0, stdout: JSON.stringify([cert]) }; };
  const thumbprint = new X509Certificate(cert).fingerprint.replace(/:/g, "").toLowerCase();
  const config = { enabled: true, trustAnchorFiles: [], intermediateFiles: [] };
  const windowsStores = () => ({ denied: new Map([[thumbprint, "unused"]]), ca: new Map() });
  await assert.rejects(() => loadTrustMaterial(config, { systemRoots: () => freshSystemRoots({ run }), platform: "win32", windowsStores }), /unavailable/);
  await assert.rejects(() => loadTrustMaterial(config, { systemRoots: () => freshSystemRoots({ run }), platform: "win32", windowsStores }), /unavailable/);
  assert.equal(calls, 2);
});

test("trust bundles accept public certificates but reject private material and symlinks", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-observed-trust-"));
  try {
    const bundle = path.join(dir, "bundle.pem");
    fs.writeFileSync(bundle, cert + "\n" + cert);
    assert.equal(readCertificateBundle(bundle).length, 2);
    const roots = await loadTrustMaterial({ enabled: true, trustAnchorFiles: [bundle], intermediateFiles: [] }, { systemRoots: () => [cert], platform: "linux" });
    assert.equal(roots.roots.length, 1);
    assert.equal(roots.systemRoots.length, 0, "an explicit duplicate retains strict handling");
    fs.appendFileSync(bundle, "\n-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n");
    assert.throws(() => readCertificateBundle(bundle), /non-certificate/);
    const link = path.join(dir, "link.pem");
    try { fs.symlinkSync(bundle, link); } catch (_) { t.diagnostic("symlink creation unavailable on this host"); return; }
    assert.throws(() => readCertificateBundle(link), /symbolic link/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("Windows disallowed store also excludes explicitly configured intermediates", async () => {
  const root = fs.readFileSync(path.join(__dirname, "../verify/fixtures/ca.crt.pem"), "utf8");
  const thumbprint = new X509Certificate(cert).fingerprint.replace(/:/g, "").toLowerCase();
  const config = { enabled: true, trustAnchorFiles: [], intermediateFiles: [path.join(__dirname, "../verify/fixtures/chain-leaf.crt.pem")] };
  const material = await loadTrustMaterial(config, { systemRoots: () => [root], platform: "win32", windowsStores: () => ({ denied: new Map([[thumbprint, cert]]), ca: new Map() }) });
  assert.equal(material.systemRoots.length, 1);
  assert.equal(material.intermediates.length, 0);
});

test("platform and explicit trust stay separate for strict helper validation", async () => {
  const rootFile = path.join(__dirname, "../verify/fixtures/ca.crt.pem");
  const intermediateFile = path.join(__dirname, "../verify/fixtures/intermediate.crt.pem");
  const root = new X509Certificate(fs.readFileSync(rootFile)).toString();
  const intermediate = new X509Certificate(fs.readFileSync(intermediateFile));
  const thumbprint = intermediate.fingerprint.replace(/:/g, "").toLowerCase();
  const config = { enabled: true, trustAnchorFiles: [rootFile], intermediateFiles: [] };
  const material = await loadTrustMaterial(config, { systemRoots: () => [cert], platform: "win32", windowsStores: () => ({ denied: new Map(), ca: new Map([[thumbprint, intermediate.toString()]]) }) });
  assert.deepEqual(material.roots, [root]);
  assert.deepEqual(material.systemRoots, [cert]);
  assert.deepEqual(material.intermediates, []);
  assert.deepEqual(material.systemIntermediates, [intermediate.toString()]);
});
