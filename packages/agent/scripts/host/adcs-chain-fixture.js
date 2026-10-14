"use strict";
/* Windows host helper: compile the candidate native chain validator and exercise actual local
 * fixture chains/pins/revocation policy. Called by windows-host.test.js; its CA/key inputs are
 * test-only files in the owned work directory, not a domain AD CS issuance claim.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { validateCertificateChain } = require("../../src/issuers/chain-helper");
async function qualifyNativeChain({ run, workDir }) {
  const directory = path.join(workDir, "native-chain"); fs.mkdirSync(directory);
  const helper = path.join(directory, "tokentimer-adcs-chain.exe");
  run("go", ["build", "-trimpath", "-buildvcs=false", "-o", helper, "."], {
    cwd: path.resolve(__dirname, "../../reference/adcs-chain"), timeout: 180000,
    env: { ...process.env, GOOS: "windows", GOARCH: process.arch === "arm64" ? "arm64" : "amd64" },
  });
  const caCertPath = path.join(workDir, "ca.pem");
  const ca = new crypto.X509Certificate(fs.readFileSync(caCertPath));
  const caKeySha256 = crypto.createHash("sha256").update(ca.publicKey.export({ type: "spki", format: "der" })).digest("hex");
  const certPath = path.join(workDir, "rsa-2048-My/issued.pem");
  assert.equal(new crypto.X509Certificate(fs.readFileSync(certPath)).verify(ca.publicKey), true);
  const check = (cert, pin = caKeySha256, mode = "require") => validateCertificateChain({ helperPath: helper,
    certPath: cert, caCertPath, caKeySha256: pin, revocationCheck: mode, timeoutMs: 30000 });
  const unavailable = await check(certPath);
  assert.equal(unavailable.verdict, "revocation_unknown", "trusted local signer has no CDP; real CryptoAPI must expose unavailability");
  assert.equal(unavailable.exitCode, 1);
  const derPath = path.join(directory, "leaf.der");
  fs.writeFileSync(derPath, new crypto.X509Certificate(fs.readFileSync(certPath)).raw);
  const derVerdict = await check(derPath);
  assert.equal(derVerdict.verdict, unavailable.verdict, "real native PEM and DER inputs must agree");
  const malformedPath = path.join(directory, "malformed.pem");
  fs.writeFileSync(malformedPath, "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n");
  const malformed = await check(malformedPath);
  assert.equal(malformed.verdict, "invalid");
  assert.equal(malformed.exitCode, 2);
  assert.equal(malformed.ok, false);
  const missing = await check(path.join(directory, "never-created.pem"));
  assert.equal(missing.verdict, "invalid");
  assert.equal(missing.exitCode, 2);
  assert.equal(missing.ok, false);
  const wrongPin = await check(certPath, caKeySha256 === "0".repeat(64) ? "1".repeat(64) : "0".repeat(64));
  assert.equal(wrongPin.verdict, "ca_key_changed", "native pinned issuer public key must reject a different hash");
  const renewedCaPath = path.join(directory, "renewed-same-key-ca.pem");
  run("openssl", ["req", "-x509", "-key", path.join(workDir, "ca.key"), "-out", renewedCaPath, "-days", "2",
    "-set_serial", "424242", "-subj", "/CN=CertOps Disposable Qualification CA",
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
  const renewedCa = new crypto.X509Certificate(fs.readFileSync(renewedCaPath));
  assert.notEqual(renewedCa.fingerprint256, ca.fingerprint256);
  assert.equal(crypto.createHash("sha256").update(renewedCa.publicKey.export({ type: "spki", format: "der" })).digest("hex"), caKeySha256);
  const sameKeyRenewal = await validateCertificateChain({ helperPath: helper, certPath, caCertPath: renewedCaPath,
    caKeySha256, revocationCheck: "require", timeoutMs: 30000 });
  assert.equal(sameKeyRenewal.verdict, "revocation_unknown", "changed CA certificate with identical issuer key must not produce ca_key_changed");
  const config = path.join(directory, "signer.cnf");
  const quoted = (file) => '"' + file.replaceAll("\\", "/") + '"';
  fs.writeFileSync(path.join(directory, "index.txt"), "");
  fs.writeFileSync(path.join(directory, "serial"), "A001\n");
  fs.writeFileSync(config, `[ca]\ndefault_ca=qualification\n[qualification]\ndatabase=${quoted(path.join(directory, "index.txt"))}\nserial=${quoted(path.join(directory, "serial"))}\nnew_certs_dir=${quoted(directory)}\ncertificate=${quoted(caCertPath)}\nprivate_key=${quoted(path.join(workDir, "ca.key"))}\ndefault_md=sha256\npolicy=qualification_subject\ncopy_extensions=copy\ndefault_days=1\n[qualification_subject]\ncommonName=supplied\n`);
  const expired = path.join(directory, "expired.pem");
  run("openssl", ["ca", "-batch", "-notext", "-config", config, "-in", path.join(workDir, "rsa-2048-My/signing.csr"),
    "-out", expired, "-startdate", "20200101000000Z", "-enddate", "20200102000000Z"]);
  const certificate = new crypto.X509Certificate(fs.readFileSync(expired));
  assert.equal(certificate.verify(ca.publicKey), true);
  assert.ok(Date.parse(certificate.validTo) < Date.now(), "fixture must be genuinely expired at the real clock");
  const strictExpired = await check(expired);
  const bestEffortExpired = await check(expired, caKeySha256, "best-effort");
  assert.equal(strictExpired.verdict, "invalid");
  assert.equal(bestEffortExpired.verdict, "invalid", "best-effort revocation may not turn an expired certificate into a valid one");
  assert.ok((Number(strictExpired.result?.trustStatus) & 1) === 1, "CryptoAPI must report the actual time-invalid trust bit");
  const future = path.join(directory, "not-yet-valid.pem");
  // OpenSSL's CA index forbids repeated subjects unless explicitly configured;
  // a separate owned index signs the same public key without altering host time.
  fs.writeFileSync(path.join(directory, "index.txt"), "");
  const tomorrow = new Date(Date.now() + 86400000);
  const nextDay = new Date(tomorrow.getTime() + 86400000);
  const stamp = (date) => date.toISOString().replace(/[-:]/g, "").replace("T", "").replace(/\.\d+Z$/, "Z");
  run("openssl", ["ca", "-batch", "-notext", "-config", config, "-in", path.join(workDir, "rsa-2048-My/signing.csr"),
    "-out", future, "-startdate", stamp(tomorrow), "-enddate", stamp(nextDay)]);
  const futureCertificate = new crypto.X509Certificate(fs.readFileSync(future));
  assert.equal(futureCertificate.verify(ca.publicKey), true);
  assert.ok(Date.parse(futureCertificate.validFrom) > Date.now());
  const futureVerdict = await check(future);
  assert.equal(futureVerdict.verdict, "invalid");
  assert.ok((Number(futureVerdict.result?.trustStatus) & 1) === 1);
  fs.writeFileSync(path.join(workDir, "windows-native-chain.log"), JSON.stringify({ trustedWithoutCdp: unavailable.verdict,
    changedCaPin: wrongPin.verdict, expired: strictExpired.verdict, bestEffortExpired: bestEffortExpired.verdict,
    notYetValid: futureVerdict.verdict, der: derVerdict.verdict, malformed: malformed.verdict, absent: missing.verdict,
    sameKeyCaRenewal: sameKeyRenewal.verdict }));
}
module.exports = { qualifyNativeChain };
