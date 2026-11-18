"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const { X509Certificate } = require("node:crypto");
const { isIPv4 } = require("node:net");

const mode = process.env.TT_UX_OPERATOR_CA || "pebble";
assert.ok(["pebble", "openbao-pki"].includes(mode), "Unknown lab CA mode");
const operatorCa = mode === "openbao-pki";
const directory = "/lab-input/operator-ca";
const caEndpoint = operatorCa
  ? "https://ca.wildcard.test:8200/v1/pki/roles/operator/acme/directory"
  : "https://pebble:14000/dir";
const dnsProvider = operatorCa ? "rfc2136" : "pebble-challtestsrv";
const transportCa = operatorCa ? directory + "/transport.pem" : "/lab-input/pebble-ca.pem";
const issuerRoot = operatorCa ? directory + "/issuer.pem" : null;
const dnsService = operatorCa ? "operator-dns" : "challtestsrv";
const dnsPort = operatorCa ? 53 : 8053;

function dnsCredentials() {
  if (!operatorCa) return { baseUrl: "http://127.0.0.1:18055", allowInsecureLocalHttp: true };
  const { server, keyName, keySecretBase64 } = JSON.parse(fs.readFileSync(directory + "/dns.json", "utf8"));
  assert.equal(server, dnsService);
  assert.equal(keyName, "tt-operator.");
  assert.match(keySecretBase64, /^[A-Za-z0-9+/]{43}=$/);
  return { server, keyName, keySecretBase64 };
}

function dnsResolver(address) {
  assert.ok(isIPv4(address), "Expected the lab's IPv4 DNS service");
  if (operatorCa) assert.match(address, /^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)/);
  return address + ":" + dnsPort;
}

function loadOperatorRoot() {
  assert.ok(operatorCa);
  const pem = fs.readFileSync(issuerRoot, "utf8");
  const issuer = new X509Certificate(pem);
  const transport = new X509Certificate(fs.readFileSync(transportCa));
  assert.ok(issuer.ca && issuer.checkIssued(issuer) && issuer.verify(issuer.publicKey));
  assert.notEqual(issuer.fingerprint256, transport.fingerprint256);
  return pem;
}

module.exports = {
  mode, operatorCa, caEndpoint, dnsProvider, transportCa, issuerRoot, dnsService, dnsPort,
  dnsCredentials, dnsResolver, loadOperatorRoot,
};
