"use strict";
/** Disposable IP-binding policy preservation. All writes target the parent
 * fixture's exact owned endpoint; the parent retains certificate/site cleanup.
 * Raw registry DWORDs and independent trusted TLS are the native oracles. This
 * does not negotiate a client certificate or claim client-auth enforcement. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { deployIisBinding, queryCurrentBinding } = require("../../src/windows-iis");
const CASES = [
  { id: "revocation-cached-no-usage", checkMode: 0x10006, freshness: 3600, retrievalTimeout: 5000, revocation: true, cachedOnly: true, usage: false },
  { id: "no-revocation-normal-usage", checkMode: 0x5, freshness: 120, retrievalTimeout: 7000, revocation: false, cachedOnly: false, usage: true },
];
const FLAGS = ["nativeNondefaultSettingsObserved", "actualProductionCutover", "publicCandidateAbsentBeforeRollback", "actualNativeRollbackSucceeded", "rawSettingsPreservedAfterCutoverAndRollback", "trustedTlsVerifiedAfterEveryTransition", "unrelatedEndpointPreserved", "originalCertificateRestored"];
const SCOPE = "native-http-sys-client-policy-preservation-not-client-auth-handshake";
const REQUIRED_SOURCES = ["packages/agent/scripts/host/iis-client-settings-fixture.js", "packages/agent/scripts/host/iis-fixture.js", "packages/agent/scripts/host/windows-host.test.js", "packages/agent/src/windows-iis/index.js", "packages/agent/src/windows-discovery/index.js", "packages/agent/src/verify/index.js", "packages/agent/src/verify/fixtures/chain-leaf.crt.pem"];
function verifyProof(proof) {
  assert.deepEqual(Object.keys(proof).sort(), ["scope", "clientAuthHandshakeQualified", "cases"].sort());
  assert.equal(proof.scope, SCOPE); assert.equal(proof.clientAuthHandshakeQualified, false);
  assert.equal(proof.cases.length, CASES.length);
  for (const [index, item] of proof.cases.entries()) {
    assert.deepEqual(Object.keys(item).sort(), ["id", "checkMode", "freshness", "retrievalTimeout", ...FLAGS].sort());
    for (const key of ["id", "checkMode", "freshness", "retrievalTimeout"]) assert.equal(item[key], CASES[index][key]);
    for (const flag of FLAGS) assert.equal(item[flag], true, flag);
  }
  return true;
}
async function qualifyClientSettings({ binding, certificates, powershell, run, unrelatedPort, expectServed, pem }) {
  assert.equal(process.platform, "win32");
  assert.equal(binding.address, "127.0.0.1"); assert.equal(binding.store, "My"); assert.equal(binding.sniHost, undefined);
  assert.match(binding.site, /^CertOps-[a-f0-9-]{36}$/);
  for (const port of [binding.port, unrelatedPort]) assert.ok(Number.isInteger(port) && port > 0 && port <= 65535);
  assert.notEqual(binding.port, unrelatedPort);
  for (const certificate of certificates.slice(0, 2)) assert.match(certificate.thumbprint, /^[A-F0-9]{40}$/);
  const endpoint = `ipport=127.0.0.1:${binding.port}`;
  const read = port => JSON.parse(powershell(`$k=Get-Item -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslBindingInfo\\127.0.0.1:${port}'; $values=@{};foreach($name in $k.GetValueNames()|Sort-Object){$value=$k.GetValue($name);$values[$name]=@{kind=[string]$k.GetValueKind($name);value=$value}}; @{checkMode=[uint32]$k.GetValue('DefaultSslCertCheckMode',0);freshness=[uint32]$k.GetValue('DefaultSslRevocationFreshnessTime',0);retrievalTimeout=[uint32]$k.GetValue('DefaultSslRevocationUrlRetrievalTimeout',0);flags=[uint32]$k.GetValue('DefaultFlags',0);thumb=[BitConverter]::ToString([byte[]]$k.GetValue('SslCertHash')).Replace('-','');values=$values}|ConvertTo-Json -Depth 8 -Compress`));
  const unrelated = read(unrelatedPort);
  const flags = read(binding.port).flags;
  const candidatePem = fs.readFileSync(path.resolve(__dirname, "../../src/verify/fixtures/chain-leaf.crt.pem"), "utf8");
  const candidateThumb = new crypto.X509Certificate(candidatePem).fingerprint.replace(/:/g, "");
  const assertCandidateAbsent = () => assert.equal(powershell(`@(Get-ChildItem Cert:\\LocalMachine -Recurse -ErrorAction Stop | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509Certificate2] -and $_.Thumbprint -eq '${candidateThumb}' }).Count`), "0", "Rollback candidate must genuinely be absent from every machine store");
  assertCandidateAbsent();
  const cases = [];
  for (const item of CASES) {
    run("netsh.exe", ["http", "update", "sslcert", endpoint, `certhash=${certificates[0].thumbprint}`, `appid={${crypto.randomUUID()}}`, "certstorename=My", `verifyclientcertrevocation=${item.revocation ? "enable" : "disable"}`, `verifyrevocationwithcachedclientcertonly=${item.cachedOnly ? "enable" : "disable"}`, `usagecheck=${item.usage ? "enable" : "disable"}`, `revocationfreshnesstime=${item.freshness}`, `urlretrievaltimeout=${item.retrievalTimeout}`]);
    const observe = async thumb => {
      const actual = read(binding.port);
      // Independent raw HTTP.sys bit constants: NO_REVOCATION=1,
      // CACHED_CLIENT_CERT_ONLY=2, FRESHNESS_TIME=4, NO_USAGE_CHECK=0x10000.
      for (const key of ["checkMode", "freshness", "retrievalTimeout"]) assert.equal(actual[key], item[key], key);
      assert.equal(actual.flags, flags); assert.equal(actual.thumb, thumb);
      for (const name of ["DefaultSslCertCheckMode", "DefaultSslRevocationFreshnessTime", "DefaultSslRevocationUrlRetrievalTimeout"]) assert.equal(actual.values[name]?.kind, "DWord", name);
      const production = await queryCurrentBinding({ binding }); assert.equal(production.ok, true);
      assert.equal(production.thumbprint, thumb);
      assert.equal(production.parameters.verifyClientCertRevocation, item.revocation);
      assert.equal(production.parameters.verifyRevocationWithCachedClientCertOnly, item.cachedOnly);
      assert.equal(production.parameters.usageCheck, item.usage);
      assert.equal(production.parameters.revocationFreshnessTime, item.freshness);
      assert.equal(production.parameters.urlRetrievalTimeout, item.retrievalTimeout);
      await expectServed(binding.port, thumb);
      assert.deepEqual(read(unrelatedPort), unrelated, "Unrelated native endpoint changed");
      await expectServed(unrelatedPort, certificates[0].thumbprint);
    };
    await observe(certificates[0].thumbprint);
    const cutover = await deployIisBinding({ binding, certificatePem: pem(certificates[1]), verifyTimeoutMs: 15000 });
    assert.equal(cutover.ok, true); assert.equal(cutover.outgoingThumbprint, certificates[0].thumbprint);
    await observe(certificates[1].thumbprint);
    assertCandidateAbsent();
    const rollback = await deployIisBinding({ binding, certificatePem: candidatePem, verifyTimeoutMs: 5000 });
    assert.equal(rollback.ok, false); assert.equal(rollback.code, "BIND_FAILED");
    assert.equal(rollback.rolledBack, true); assert.equal(rollback.outgoingThumbprint, certificates[1].thumbprint);
    await observe(certificates[1].thumbprint);
    const restore = await deployIisBinding({ binding, certificatePem: pem(certificates[0]), verifyTimeoutMs: 15000 });
    assert.equal(restore.ok, true); assert.equal(restore.outgoingThumbprint, certificates[1].thumbprint);
    await observe(certificates[0].thumbprint);
    cases.push({ id: item.id, checkMode: item.checkMode, freshness: item.freshness, retrievalTimeout: item.retrievalTimeout, ...Object.fromEntries(FLAGS.map(flag => [flag, true])) });
  }
  const proof = { scope: SCOPE, clientAuthHandshakeQualified: false, cases }; verifyProof(proof); return proof;
}
module.exports = { CASES, FLAGS, SCOPE, REQUIRED_SOURCES, verifyProof, qualifyClientSettings };
