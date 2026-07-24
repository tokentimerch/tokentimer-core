"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { Readable } = require("node:stream");
const path = require("node:path");

const {
  MAX_SECRET_RESPONSE_BYTES,
  MAX_TLS_CRT_JSON_BYTES,
  createTlsCrtSecretReader,
  extractTlsCertificateFromSecretJson,
} = require(path.resolve(
  __dirname,
  "../../apps/k8s-controller/src/tls-crt-secret-reader.js",
));

function chunks(value, width = 7) {
  const result = [];
  for (let index = 0; index < value.length; index += width) {
    result.push(Buffer.from(value.slice(index, index + width)));
  }
  return Readable.from(result);
}

describe("CertOps streaming tls.crt Secret reader", () => {
  it("uses the in-cluster authenticated request options and exact Secret path", async () => {
    const certificate = Buffer.from("public certificate").toString("base64");
    const calls = [];
    const reader = createTlsCrtSecretReader({
      kubeConfig: {
        async applyToHTTPSOptions(options) {
          options.headers.Authorization = "Bearer mounted-service-account-token";
        },
        getCurrentCluster() {
          return { server: "https://kubernetes.default.svc:443" };
        },
      },
      requestFn(url, options, onResponse) {
        calls.push({ options, url: url.toString() });
        const request = new EventEmitter();
        request.setTimeout = () => {};
        request.destroy = (error) => {
          if (error) request.emit("error", error);
          request.emit("close");
        };
        request.end = () => {
          setImmediate(() => {
            const response = Readable.from([
              Buffer.from(JSON.stringify({
                data: {
                  other: "not-decoded",
                  "tls.crt": certificate,
                },
              })),
            ]);
            response.statusCode = 200;
            response.headers = { "content-type": "application/json" };
            onResponse(response);
          });
        };
        return request;
      },
    });

    assert.equal(
      await reader.read({ namespace: "team-a", secretName: "web-tls" }),
      certificate,
    );
    assert.equal(
      calls[0].url,
      "https://kubernetes.default.svc/api/v1/namespaces/team-a/secrets/web-tls",
    );
    assert.equal(calls[0].options.method, "GET");
    assert.equal(calls[0].options.headers.Accept, "application/json");
    assert.match(calls[0].options.headers.Authorization, /^Bearer /);
    await reader.close();
  });

  it("extracts only tls.crt without deserializing another Secret data value", async () => {
    const certificate = Buffer.from("public certificate").toString("base64");
    const privateSentinel = "PRIVATE-MATERIAL-MUST-NOT-BE-MATERIALIZED";
    const serialized = JSON.stringify({
      apiVersion: "v1",
      data: {
        "another.binary.value": privateSentinel,
        "tls.crt": certificate,
      },
      kind: "Secret",
      metadata: { name: "web-tls", namespace: "team-a" },
    });

    const result = await extractTlsCertificateFromSecretJson(chunks(serialized));

    assert.equal(result, certificate);
    assert.equal(result.includes(privateSentinel), false);
  });

  it("returns missing when data or tls.crt is absent", async () => {
    assert.equal(
      await extractTlsCertificateFromSecretJson(chunks('{"kind":"Secret"}')),
      undefined,
    );
    assert.equal(
      await extractTlsCertificateFromSecretJson(chunks('{"data":{"other":"value"}}')),
      undefined,
    );
  });

  it("rejects duplicate, non-string, escaped, and oversized tls.crt values", async () => {
    for (const serialized of [
      '{"data":{"tls.crt":"one","tls.crt":"two"}}',
      '{"data":{"tls.crt":null}}',
      '{"data":{"tls.crt":"ab\\u0063"}}',
      JSON.stringify({ data: { "tls.crt": "a".repeat(MAX_TLS_CRT_JSON_BYTES + 1) } }),
    ]) {
      await assert.rejects(
        () => extractTlsCertificateFromSecretJson(chunks(serialized, 1024)),
        (error) => String(error?.code || "").startsWith("CERTOPS_"),
      );
    }
  });

  it("bounds the complete Kubernetes response", async () => {
    const serialized = JSON.stringify({
      data: { other: "a".repeat(MAX_SECRET_RESPONSE_BYTES) },
    });
    await assert.rejects(
      () => extractTlsCertificateFromSecretJson(chunks(serialized, 4096)),
      { code: "CERTOPS_SECRET_RESPONSE_TOO_LARGE" },
    );
  });
});
