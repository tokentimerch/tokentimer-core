"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  createInClusterCertManagerClient,
} = require(
  path.resolve(__dirname, "../../apps/k8s-controller/src/cert-manager-client.js"),
);
const {
  createCertManagerObserver,
} = require(
  path.resolve(__dirname, "../../apps/k8s-controller/src/cert-manager-observer.js"),
);
const {
  createControllerRuntime,
} = require(
  path.resolve(__dirname, "../../apps/k8s-controller/src/runtime.js"),
);
const {
  MAX_DECODED_TLS_CRT_BYTES,
  MAX_ENCODED_TLS_CRT_BYTES,
  createTlsCertificateFallback,
  decodeTlsCertificateData,
} = require(
  path.resolve(__dirname, "../../apps/k8s-controller/src/tls-certificate-fallback.js"),
);

const PUBLIC_LEAF_CERT = `-----BEGIN CERTIFICATE-----
MIIDgjCCAmqgAwIBAgIUKJShixxx/7TH81hKwHE3UsvIFMkwDQYJKoZIhvcNAQEL
BQAwNDEYMBYGA1UEAwwPY2VydG9wcy5leGFtcGxlMRgwFgYDVQQKDA9Ub2tlblRp
bWVyIFRlc3QwHhcNMjYwNjI2MDA0MDU5WhcNMjcwNjI2MDA0MDU5WjA0MRgwFgYD
VQQDDA9jZXJ0b3BzLmV4YW1wbGUxGDAWBgNVBAoMD1Rva2VuVGltZXIgVGVzdDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANoaAIgElNelqNg6TsY++HnK
rFeOgn7csJYu9AbFfQRAoFO592aVI9QdyejoGesSy+tDN06vJl411Ntz6caB2+fd
+qkllZ+c39IZEbp++PDp7dD+4aEC68tGoZ9F/9dOGRaZ4xSFp0W0+5hd8E5q4E9U
MSdc4cUjQKuZX+jwBQqy+SRxhhNh6GPVWg3Cr6W0F53yFxWlb8q+4cwOZg0AP7sK
2u8UvordGO3o4eiPsVtmRh87YeRnUDRuzPb4Mi/Fo9Cr+1Fq3Q3xdWH9LhP0DSmD
89Ho84nvn+DfM+Dbnb7PsmNgqOVictn/LxHMOrl1F04BkvY9rNuBkh7wHC7TOR8C
AwEAAaOBizCBiDAdBgNVHQ4EFgQUoOXgW3/xFso+3GDIpFqimZ2K2TUwHwYDVR0j
BBgwFoAUoOXgW3/xFso+3GDIpFqimZ2K2TUwDwYDVR0TAQH/BAUwAwEB/zA1BgNV
HREELjAsgg9jZXJ0b3BzLmV4YW1wbGWCE2FwaS5jZXJ0b3BzLmV4YW1wbGWHBH8A
AAEwDQYJKoZIhvcNAQELBQADggEBAGi4XAScskH5bdxNbXwtEqlep2eDyseUyulF
g2yILrkiA22+WveOZrmReuxHx+umHVAO4O6JtHwD1figZyKgCrMzrREqmRwGj6pb
jgaW6Eeck+zFh1cKTH6ZUYlN6yOHOhKR0nBnseSuoh/gEangQVLRug3SqCCi6GQI
aOAUKMHYsxTyfjtE2k7URQYy7fbfLW/k+68l+xI/ktwFlS+MncmrS+Lx+dWwxVCn
EucPyYnACaKyw2oY6kCVaW9OReglxzoFzLxZvqxyrA1LpWjzgJiR7nIpZCappsi9
gB1JS6DPep8dhLORucnHS/Opy2xOB0lB3kmNoh5bierJUVeReSc=
-----END CERTIFICATE-----`;

const encodedCertificate = Buffer.from(PUBLIC_LEAF_CERT).toString("base64");

function readyObservation(overrides = {}) {
  return {
    certificateName: "web",
    certificateUid: "certificate-uid",
    clusterId: "cluster-a",
    namespace: "team-a",
    ready: true,
    secretName: "web-tls",
    workspaceId: "workspace-a",
    ...overrides,
  };
}

function fakePrivateKeyDer() {
  return Buffer.from([
    0x30, 0x08, 0x02, 0x01, 0x00, 0x30, 0x03, 0x06, 0x01, 0x2a,
  ]);
}

function fakePfxDer() {
  return Buffer.from([0x30, 0x05, 0x02, 0x01, 0x03, 0x30, 0x00]);
}

function fakeJks() {
  return Buffer.from([0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, 2, 0, 0, 0, 0]);
}

function certificateResource() {
  return {
    metadata: {
      generation: 1,
      name: "web",
      namespace: "team-a",
      resourceVersion: "1",
      uid: "certificate-uid",
    },
    spec: { secretName: "web-tls" },
    status: { conditions: [{ status: "True", type: "Ready" }] },
  };
}

function createObserverClient() {
  const watchCalls = [];
  return {
    async close() {},
    async list({ resource }) {
      return {
        items: resource === "Certificate" ? [certificateResource()] : [],
        resourceVersion: `${resource}-rv`,
      };
    },
    async start() {},
    watchCalls,
    async watch(options) {
      const call = { ...options };
      watchCalls.push(call);
      return { close() {} };
    },
  };
}

function tick() {
  return new Promise((resolve) => setImmediate(resolve));
}

function assertCode(action, code) {
  return assert.rejects(action, (error) => error?.code === code);
}

describe("CertOps tls.crt fallback", () => {
  it("does not create CoreV1Api when fallback is disabled", async () => {
    const madeClients = [];
    class KubeConfig {
      loadFromCluster() {}
      makeApiClient(type) {
        madeClients.push(type.name);
        return {};
      }
    }
    class CoreV1Api {}
    class CustomObjectsApi {}
    class Watch {}

    const client = createInClusterCertManagerClient({
      loadClient: async () => ({ CoreV1Api, CustomObjectsApi, KubeConfig, Watch }),
    });
    await client.start();

    assert.deepEqual(madeClients, ["CustomObjectsApi"]);
    await assertCode(
      () => client.readTlsCertificate({ namespace: "team-a", secretName: "web-tls" }),
      "CERTOPS_SECRET_FALLBACK_DISABLED",
    );
  });

  it("uses one object-parameter Secret get and reads only data tls.crt", async () => {
    const calls = [];
    const data = new Proxy({ "tls.crt": encodedCertificate }, {
      get(target, property) {
        if (property !== "tls.crt") {
          throw new Error(`Unexpected Secret data access: ${String(property)}`);
        }
        return target[property];
      },
      ownKeys() {
        throw new Error("Secret data must not be enumerated");
      },
    });
    const coreApiClient = {
      async readNamespacedSecret(options) {
        calls.push(options);
        return { body: { data } };
      },
    };
    class KubeConfig {
      loadFromCluster() {}
      makeApiClient(type) {
        return type.name === "CoreV1Api" ? coreApiClient : {};
      }
    }
    class CoreV1Api {}
    class CustomObjectsApi {}
    class Watch {}

    const client = createInClusterCertManagerClient({
      loadClient: async () => ({ CoreV1Api, CustomObjectsApi, KubeConfig, Watch }),
      secretFallbackEnabled: true,
    });
    await client.start();

    assert.equal(
      await client.readTlsCertificate({ namespace: "team-a", secretName: "web-tls" }),
      encodedCertificate,
    );
    assert.deepEqual(calls, [{ name: "web-tls", namespace: "team-a" }]);
  });

  it("never forwards a Secret object or raw tls.crt encoding to the parser or delivery", async () => {
    const secret = { data: { "tls.crt": encodedCertificate } };
    const coreApiClient = {
      async readNamespacedSecret() {
        return { body: secret };
      },
    };
    class KubeConfig {
      loadFromCluster() {}
      makeApiClient(type) {
        return type.name === "CoreV1Api" ? coreApiClient : {};
      }
    }
    class CoreV1Api {}
    class CustomObjectsApi {}
    class Watch {}
    const client = createInClusterCertManagerClient({
      loadClient: async () => ({ CoreV1Api, CustomObjectsApi, KubeConfig, Watch }),
      secretFallbackEnabled: true,
    });
    await client.start();
    let parserInput;
    const fallback = createTlsCertificateFallback({
      enabled: true,
      kubernetesClient: client,
      parsePublicCertificateMaterial(input) {
        parserInput = input;
        return {
          publicCertificate: {
            certificatePem: PUBLIC_LEAF_CERT,
            fingerprintSha256: "a".repeat(64),
          },
        };
      },
    });
    const delivered = [];
    const enriched = await fallback.enrichObservation(readyObservation());
    delivered.push(enriched);

    assert.equal(Buffer.isBuffer(parserInput), true);
    assert.notEqual(parserInput, secret);
    assert.equal(JSON.stringify(delivered).includes(encodedCertificate), false);
    assert.equal(JSON.stringify(delivered).includes('"data"'), false);
  });

  it("makes zero Secret reads when disabled, not Ready, or already fingerprint-sufficient", async () => {
    const calls = [];
    const reader = {
      async readTlsCertificate(options) {
        calls.push(options);
        return encodedCertificate;
      },
    };
    const disabled = createTlsCertificateFallback({ kubernetesClient: reader });
    const enabled = createTlsCertificateFallback({ enabled: true, kubernetesClient: reader });

    await disabled.enrichObservation(readyObservation());
    await enabled.enrichObservation(readyObservation({ ready: false }));
    await enabled.enrichObservation(readyObservation({
      publicCertificate: { fingerprintSha256: "a".repeat(64) },
    }));

    assert.deepEqual(calls, []);
  });

  it("reads exactly the referenced Secret for an eligible Ready observation and allowlists public fields", async () => {
    const calls = [];
    const fallback = createTlsCertificateFallback({
      enabled: true,
      kubernetesClient: {
        async readTlsCertificate(options) {
          calls.push(options);
          return encodedCertificate;
        },
      },
    });
    const enriched = await fallback.enrichObservation(readyObservation({
      notAfter: "2026-10-21T10:00:00.000Z",
      notBefore: "2026-07-21T10:00:00.000Z",
    }));

    assert.deepEqual(calls, [{ namespace: "team-a", secretName: "web-tls" }]);
    assert.equal(enriched.notBefore, "2026-07-21T10:00:00.000Z");
    assert.equal(enriched.notAfter, "2026-10-21T10:00:00.000Z");
    assert.deepEqual(Object.keys(enriched.publicCertificate).sort(), [
      "certificatePem",
      "fingerprintSha256",
      "issuer",
      "publicKeyAlgorithm",
      "publicKeySize",
      "serialNumber",
      "signatureAlgorithm",
      "subject",
      "subjectAltNames",
    ]);
    assert.match(enriched.publicCertificate.fingerprintSha256, /^[a-f0-9]{64}$/);
  });

  it("strictly rejects missing, malformed, non-canonical, encoded-oversized, and decoded-oversized data", () => {
    assert.throws(() => decodeTlsCertificateData(), (error) => error?.code === "CERTOPS_TLS_CRT_MISSING");
    assert.throws(() => decodeTlsCertificateData("not_base64!"), (error) => error?.code === "CERTOPS_TLS_CRT_INVALID_BASE64");
    assert.throws(() => decodeTlsCertificateData("YQ"), (error) => error?.code === "CERTOPS_TLS_CRT_INVALID_BASE64");
    assert.throws(
      () => decodeTlsCertificateData("A".repeat(MAX_ENCODED_TLS_CRT_BYTES + 1)),
      (error) => error?.code === "CERTOPS_TLS_CRT_TOO_LARGE",
    );
    assert.throws(
      () => decodeTlsCertificateData(Buffer.alloc(MAX_DECODED_TLS_CRT_BYTES + 1).toString("base64")),
      (error) => error?.code === "CERTOPS_TLS_CRT_TOO_LARGE",
    );
  });

  it("fails closed for missing, invalid, malformed, and private tls.crt material", async () => {
    const inputs = [
      [undefined, "CERTOPS_TLS_CRT_MISSING"],
      ["not_base64!", "CERTOPS_TLS_CRT_INVALID_BASE64"],
      [Buffer.from("not a certificate").toString("base64"), "CERTOPS_CERTIFICATE_PARSE_FAILED"],
      [Buffer.from("-----BEGIN PRIVATE KEY-----\nignored\n-----END PRIVATE KEY-----").toString("base64"), "PRIVATE_KEY_MATERIAL_REJECTED"],
      [fakePrivateKeyDer().toString("base64"), "PRIVATE_KEY_MATERIAL_REJECTED"],
      [fakePfxDer().toString("base64"), "PRIVATE_KEY_MATERIAL_REJECTED"],
      [fakeJks().toString("base64"), "PRIVATE_KEY_MATERIAL_REJECTED"],
    ];

    for (const [encoded, code] of inputs) {
      const fallback = createTlsCertificateFallback({
        enabled: true,
        kubernetesClient: { async readTlsCertificate() { return encoded; } },
      });
      await assertCode(() => fallback.enrichObservation(readyObservation()), code);
    }
  });

  it("accepts a complete PEM chain and uses the first certificate as the leaf", async () => {
    const fallback = createTlsCertificateFallback({
      enabled: true,
      kubernetesClient: {
        async readTlsCertificate() {
          return Buffer.from(`${PUBLIC_LEAF_CERT}\n${PUBLIC_LEAF_CERT}`).toString("base64");
        },
      },
    });
    const enriched = await fallback.enrichObservation(readyObservation());

    assert.match(enriched.publicCertificate.subject, /CN=certops\.example/);
    assert.match(enriched.publicCertificate.certificatePem, /BEGIN CERTIFICATE/);
    assert.match(enriched.notBefore, /^2026-06-26T/);
    assert.match(enriched.notAfter, /^2027-06-26T/);
  });

  it("blocks malicious enrichment output before the observation handler and logs no raw material", async () => {
    const client = createObserverClient();
    const delivered = [];
    const logs = [];
    const malicious = "-----BEGIN PRIVATE KEY-----\nnever-log\n-----END PRIVATE KEY-----";
    const observer = createCertManagerObserver({
      client,
      clusterId: "cluster-a",
      enrichObservation: async (observation) => ({ ...observation, harmlessField: malicious }),
      logger: { debug() {}, error() {}, info() {}, warn(message, metadata) { logs.push({ message, metadata }); } },
      observationHandler: async (observation) => delivered.push(observation),
      workspaceId: "workspace-a",
    });
    await observer.start({ trackWork: (work) => work });
    await tick();
    await tick();

    assert.deepEqual(delivered, []);
    assert.match(JSON.stringify(logs), /PRIVATE_KEY_MATERIAL_REJECTED/);
    assert.doesNotMatch(JSON.stringify(logs), /never-log|BEGIN PRIVATE KEY/);
  });

  it("keeps watches alive after fallback failure and logs only a safe error code", async () => {
    const client = createObserverClient();
    const logs = [];
    const rawFailure = "raw-tls-certificate-data";
    const fallback = createTlsCertificateFallback({
      enabled: true,
      kubernetesClient: {
        async readTlsCertificate() {
          throw new Error(rawFailure);
        },
      },
    });
    const observer = createCertManagerObserver({
      client,
      clusterId: "cluster-a",
      enrichObservation: fallback.enrichObservation,
      logger: { debug() {}, error() {}, info() {}, warn(message, metadata) { logs.push({ message, metadata }); } },
      observationHandler: async () => assert.fail("must not deliver a partial observation"),
      workspaceId: "workspace-a",
    });
    await observer.start({ trackWork: (work) => work });
    await tick();
    await tick();

    assert.equal(observer.isReady(), true);
    assert.equal(client.watchCalls.length, 2);
    assert.match(JSON.stringify(logs), /CERTOPS_TLS_CRT_READ_FAILED/);
    assert.doesNotMatch(JSON.stringify(logs), new RegExp(rawFailure));
  });

  it("prevents new Secret reads during shutdown and waits for tracked fallback work", async () => {
    const client = createObserverClient();
    let releaseRead;
    let readStarted;
    const readStartedPromise = new Promise((resolve) => { readStarted = resolve; });
    const readReleasePromise = new Promise((resolve) => { releaseRead = resolve; });
    let reads = 0;
    const fallback = createTlsCertificateFallback({
      enabled: true,
      kubernetesClient: {
        async readTlsCertificate() {
          reads += 1;
          readStarted();
          await readReleasePromise;
          return encodedCertificate;
        },
      },
    });
    const observer = createCertManagerObserver({
      client,
      clusterId: "cluster-a",
      enrichObservation: fallback.enrichObservation,
      observationHandler: async () => {},
      workspaceId: "workspace-a",
    });
    const runtime = createControllerRuntime({
      kubernetesClient: observer,
      reporter: { async close() {}, isAlive: () => true, isReady: () => true, async start() {}, async stopAcceptingWork() {} },
    });
    await runtime.start();
    await readStartedPromise;
    await runtime.stopAcceptingWork();
    client.watchCalls.find((call) => call.resource === "Certificate").onEvent(
      "MODIFIED",
      certificateResource(),
    );
    assert.equal(reads, 1);
    releaseRead();
    assert.equal(await runtime.waitForIdle(1_000), true);
    assert.equal(reads, 1);
  });
});
