"use strict";

const { it } = require("node:test");
const assert = require("node:assert/strict");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const { createForwardProxy, createHttpTarget, createHttpsTarget } = require("../../scripts/proxy-smoke/fixtures");

const execFileAsync = promisify(execFile);
const helperPath = require.resolve("../../packages/webhook-safety/request");
const childScript = `
  const { createPostWebhook } = require(process.argv[1]);
  const postWebhook = createPostWebhook({
    isPrivateOrReservedIP: () => false,
    shouldEnforcePrivateIpCheck: () => true,
    canonicalizeHost: (host) => host.toLowerCase(),
  });
  const url = process.env.TEST_SCHEME + '://sni-ok.example:' + process.env.TEST_PORT + '/hook';
  postWebhook(url, {
    body: { ping: true }, proxyMode: 'always', ca: process.env.TEST_CA,
    lookupAll: async () => [{ address: '127.0.0.1', family: 4 }],
    timeoutMs: 3000,
  }).then((response) => {
    if (response.status !== 200) throw new Error('Unexpected status: ' + response.status);
  }).catch((error) => { console.error(error); process.exitCode = 1; });
`;

for (const flag of ["0", "1"]) {
  for (const scheme of ["http", "https"]) {
    it(`uses one explicit ${scheme} proxy hop with NODE_USE_ENV_PROXY=${flag}`, async () => {
      const target = scheme === "https"
        ? createHttpsTarget({ commonName: "sni-ok.example", dnsNames: ["sni-ok.example"] })
        : createHttpTarget();
      const proxy = createForwardProxy();
      let hits = 0;
      target.server.on("request", () => { hits += 1; });
      try {
        const port = await target.listen();
        const proxyPort = await proxy.listen();
        const proxyUrl = `http://127.0.0.1:${proxyPort}`;
        await execFileAsync(process.execPath, ["-e", childScript, helperPath], {
          timeout: 8000,
          env: {
            ...process.env,
            NODE_ENV: "test", NODE_OPTIONS: "", NODE_USE_ENV_PROXY: flag,
            HTTP_PROXY: proxyUrl, HTTPS_PROXY: proxyUrl, NO_PROXY: "",
            http_proxy: "", https_proxy: "", no_proxy: "", ALL_PROXY: "", all_proxy: "",
            TEST_SCHEME: scheme, TEST_PORT: String(port), TEST_CA: target.certPem || "",
          },
        });
        assert.equal(hits, 1, "one request must reach the origin");
        assert.equal(proxy.connections.length, 1, "one request must reach the proxy");
        assert.equal(proxy.connections[0].host, "127.0.0.1", "the proxy must use the pinned address");
        assert.equal(proxy.connections[0].port, port);
        assert.equal(proxy.connections[0].via, scheme === "https" ? "connect" : "http");
      } finally {
        if (proxy.server.listening) await proxy.close();
        if (target.server.listening) await target.close();
      }
    });
  }
}
