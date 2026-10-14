"use strict";
const Module = require("node:module");
const { X509Certificate } = require("node:crypto");

// Only upstream transports are replaced in this isolated test process. The
// production scanners, certificate parsers and returned normalization run intact.
async function scanFixtureSources(publicPem, privatePem, options = {}) {
  const certificate = new X509Certificate(publicPem);
  const expiry = new Date(certificate.validTo);
  const originalLoad = Module._load;
  const originalFetch = global.fetch;
  const calls = [];
  const arn = "arn:aws:acm:us-east-1:123456789012:certificate/qualification";
  const aws = {
    GetCallerIdentityCommand: class { constructor(input) { this.input = input; this.kind = "identity"; } },
    ListCertificatesCommand: class { constructor(input) { this.input = input; this.kind = "list"; } },
    DescribeCertificateCommand: class { constructor(input) { this.input = input; this.kind = "describe"; } },
  };
  class Client {
    async send(command) {
      calls.push(`aws:${command.kind}`);
      if (command.kind === "identity") return { Account: "123456789012" };
      if (command.kind === "list" && options.awsDenied) throw Object.assign(new Error("Fixture ACM access denied"), { name: "AccessDeniedException", $metadata: { httpStatusCode: 403 } });
      if (command.kind === "list") return { CertificateSummaryList: [{ CertificateArn: arn, DomainName: "scanner.integration.invalid" }] };
      if (command.kind === "describe") return { Certificate: { CertificateArn: arn, DomainName: "scanner.integration.invalid", NotAfter: expiry, Status: "ISSUED", Issuer: certificate.issuer, Serial: certificate.serialNumber, SubjectAlternativeNames: ["scanner.integration.invalid"] } };
      throw new Error("Unexpected upstream AWS fixture command");
    }
  }
  const axios = async config => {
    const url = new URL(config.url); calls.push(`${url.hostname}${url.pathname}`);
    if (url.hostname === "qualification.vault.azure.net") {
      if (url.pathname === "/certificates") return { data: { value: [{ id: "https://qualification.vault.azure.net/certificates/qualification", attributes: { enabled: true, exp: Math.floor(expiry.getTime() / 1000) } }] } };
      if (url.pathname === "/certificates/qualification") return { data: { id: "https://qualification.vault.azure.net/certificates/qualification", cer: certificate.raw.toString("base64"), attributes: { exp: Math.floor(expiry.getTime() / 1000) } } };
    }
    if (url.hostname === "certificatemanager.googleapis.com" && Object.hasOwn(options, "gcpMalformed")) return { data: options.gcpMalformed === true ? "malformed-list-body" : options.gcpMalformed };
    if (url.hostname === "certificatemanager.googleapis.com" && options.gcpEmpty) return { data: {} };
    if (url.hostname === "certificatemanager.googleapis.com" && options.gcpStatus) throw Object.assign(new Error("Fixture upstream failure"), { response: { status: options.gcpStatus, data: { error: { code: options.gcpStatus, message: "Fixture upstream failure" } } } });
    if (url.hostname === "certificatemanager.googleapis.com" && options.gcpPagination) return { data: { certificates: [{ name: "projects/qualification-project/locations/global/certificates/" + (url.searchParams.has("pageToken") ? "page-two" : "page-one"), expireTime: expiry.toISOString(), sanDnsnames: ["scanner.integration.invalid"] }], ...(url.searchParams.has("pageToken") ? {} : { nextPageToken: "fixture-next" }) } };
    if (url.hostname === "certificatemanager.googleapis.com") return { data: { certificates: [{ name: "projects/qualification-project/locations/global/certificates/qualification", expireTime: expiry.toISOString(), sanDnsnames: ["scanner.integration.invalid"], managed: { state: "ACTIVE" } }] } };
    if (url.hostname === "compute.googleapis.com" && Object.hasOwn(options, "computeMalformed")) return { data: options.computeMalformed };
    if (url.hostname === "compute.googleapis.com") return { data: { ...(options.gcpUnreachable ? { unreachables: ["regions/unreachable"] } : {}), items: { global: { sslCertificates: [{ name: "qualification-compute", expireTime: expiry.toISOString(), subjectAlternativeNames: ["scanner.integration.invalid"], selfLink: "https://compute.googleapis.com/compute/v1/projects/qualification-project/global/sslCertificates/qualification-compute" }] } } } };
    throw new Error("Unexpected upstream HTTP fixture request");
  };
  const vault = {
    "/v1/sys/mounts": { data: { "secret/": { type: "kv", options: { version: "2" } }, "pki/": { type: "pki" } } },
    "/v1/secret/metadata/": { data: { keys: ["qualification"] } },
    "/v1/secret/data/qualification": { data: { data: { certificate: publicPem, private_key: privatePem }, metadata: { version: 1 } } },
    "/v1/pki/certs": { data: { keys: [certificate.serialNumber] } },
    [`/v1/pki/cert/${certificate.serialNumber}`]: { data: { certificate: publicPem } },
  };
  const modules = ["aws", "azure", "gcp", "vault"].map(provider => require.resolve(`../../../apps/api/services/${provider}Integration`));
  const cached = modules.map(file => require.cache[file]);
  try {
    for (const file of modules) delete require.cache[file];
    Module._load = function(request, parent, main) {
      if (request === "axios") return axios;
      if (request === "@aws-sdk/client-sts") return { STSClient: Client, GetCallerIdentityCommand: aws.GetCallerIdentityCommand };
      if (request === "@aws-sdk/client-acm") return { ACMClient: Client, ListCertificatesCommand: aws.ListCertificatesCommand, DescribeCertificateCommand: aws.DescribeCertificateCommand };
      return originalLoad.call(this, request, parent, main);
    };
    global.fetch = async (input) => {
      const url = new URL(input); calls.push(`${url.hostname}${url.pathname}`);
      if (url.hostname !== "vault.integration.invalid" || !Object.hasOwn(vault, url.pathname)) throw new Error("Unexpected upstream Vault fixture request");
      return new Response(JSON.stringify(vault[url.pathname]), { status: 200, headers: { "content-type": "application/json" } });
    };
    const outputs = [];
    outputs.push({ provider: "aws", ...await require(modules[0]).scanAWS({ accessKeyId: "qualification", secretAccessKey: "qualification", include: { secrets: false, iam: false, certificates: true } }) });
    outputs.push({ provider: "azure", ...await require(modules[1]).scanAzure({ vaultUrl: "https://qualification.vault.azure.net", token: "qualification", include: { secrets: false, certificates: true, keys: false } }) });
    outputs.push({ provider: "gcp", ...await require(modules[2]).scanGCP({ projectId: "qualification-project", accessToken: "qualification", include: { secrets: false, certificates: true } }) });
    outputs.push({ provider: "vault", ...await require(modules[3]).scanVault({ address: "https://vault.integration.invalid", token: "qualification", include: { kv: true, pki: true } }) });
    return { outputs, calls, expiry: expiry.toISOString().slice(0, 10) };
  } finally {
    Module._load = originalLoad; global.fetch = originalFetch;
    for (const [index, file] of modules.entries()) { delete require.cache[file]; if (cached[index]) require.cache[file] = cached[index]; }
  }
}
module.exports = { scanFixtureSources };
