#!/usr/bin/env node
"use strict";

// Real behavioral proof that Node's corporate-proxy support
// (NODE_USE_ENV_PROXY=1) actually works for both HTTP clients this
// codebase uses in the webhook path: global fetch/undici (API "Test"
// button) and axios (worker delivery), over both plain HTTP and HTTPS.
//
// Unit tests already cover the route/allowlist wiring
// (tests/integration/webhook-test-endpoint.test.js). This script proves
// the runtime proxy *behavior* end to end using a real local forward-proxy
// fixture, a real self-signed HTTPS target, and freshly spawned child
// processes (NODE_USE_ENV_PROXY is read at Node bootstrap, so setting it
// after the process has started would be too late and give a false pass).
//
// Run: node scripts/proxy-smoke-test.js  (or `pnpm run test:proxy-smoke`)
// CI runs this once per Node version in its matrix (see .github/workflows/ci.yml).
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

const { isNodeUseEnvProxySupported } = require("../packages/node-compat/index.js");
const { createForwardProxy, createHttpTarget, createHttpsTarget } = require("./proxy-smoke/fixtures.js");

const FETCH_PROBE_PATH = path.join(__dirname, "proxy-smoke", "probes", "fetch-probe.js");
const AXIOS_PROBE_PATH = path.join(__dirname, "proxy-smoke", "probes", "axios-probe.mjs");

const PROBE_TIMEOUT_MS = 5000;
const SPAWN_KILL_TIMEOUT_MS = 9000;

const HTTPS_TARGET_HOSTNAME = "localhost";
const HTTP_TARGET_HOSTNAME = "127.0.0.1";
// RFC 2606 reserved TLD: guaranteed to never resolve via real DNS, so a
// direct (non-proxied) connection attempt fails fast. The proxy fixture
// below aliases this name to the real HTTP target, so it *is* reachable
// once traffic actually goes through the proxy.
const UNREACHABLE_DIRECT_HOSTNAME = "proxy-smoke-unreachable.invalid";

const results = [];

function record(name, passed, detail) {
  results.push({ name, passed, detail });
  const status = passed ? "PASS" : "FAIL";
  console.log(`[${status}] ${name}${detail ? ` — ${detail}` : ""}`);
}

/**
 * Spawn a probe script with a fully explicit env object (never inherited
 * ambient env) so scenarios can't cross-contaminate, and a hard kill
 * timeout so a hung child is treated as a failure rather than an
 * indefinite wait.
 */
function runProbe(scriptPath, env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [scriptPath], { env });
    let stdout = "";
    let stderr = "";
    let killedForTimeout = false;

    const killer = setTimeout(() => {
      killedForTimeout = true;
      child.kill("SIGKILL");
    }, SPAWN_KILL_TIMEOUT_MS);

    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (err) => {
      clearTimeout(killer);
      resolve({ ok: false, error: `spawn error: ${err.message}`, stdout, stderr });
    });
    child.on("exit", (code) => {
      clearTimeout(killer);
      if (killedForTimeout) {
        resolve({ ok: false, error: "probe timed out and was killed", stdout, stderr });
        return;
      }
      const resultLine = stdout
        .split("\n")
        .find((line) => line.startsWith("PROXY_SMOKE_RESULT:"));
      if (!resultLine) {
        resolve({
          ok: false,
          error: `probe exited (code ${code}) without a result line`,
          stdout,
          stderr,
        });
        return;
      }
      try {
        const parsed = JSON.parse(resultLine.slice("PROXY_SMOKE_RESULT:".length));
        resolve({ ...parsed, exitCode: code });
      } catch (err) {
        resolve({ ok: false, error: `failed to parse probe result: ${err.message}`, stdout, stderr });
      }
    });
  });
}

function baseEnv(extra) {
  return {
    PATH: process.env.PATH,
    PROXY_SMOKE_TIMEOUT_MS: String(PROBE_TIMEOUT_MS),
    ...extra,
  };
}

async function main() {
  console.log(`Node.js ${process.version} — NODE_USE_ENV_PROXY supported: ${isNodeUseEnvProxySupported()}`);
  if (!isNodeUseEnvProxySupported()) {
    console.error(
      "This Node.js version does not support NODE_USE_ENV_PROXY (requires 22.21.0+ or 24.5.0+). " +
        "The CI matrix must only select supported versions; refusing to run a smoke test that " +
        "cannot exercise the feature it proves.",
    );
    process.exitCode = 1;
    return;
  }

  const httpTarget = createHttpTarget();
  const httpPort = await httpTarget.listen();
  const httpsTarget = createHttpsTarget({
    commonName: HTTPS_TARGET_HOSTNAME,
    dnsNames: [HTTPS_TARGET_HOSTNAME],
    ipAddresses: ["127.0.0.1"],
  });
  const httpsPort = await httpsTarget.listen();

  const proxy = createForwardProxy({
    hostAliases: {
      [UNREACHABLE_DIRECT_HOSTNAME]: { host: "127.0.0.1", port: httpPort },
    },
  });
  const proxyPort = await proxy.listen();
  const proxyUrl = `http://127.0.0.1:${proxyPort}`;

  const caCertPath = path.join(os.tmpdir(), `proxy-smoke-ca-${process.pid}-${Date.now()}.pem`);
  fs.writeFileSync(caCertPath, httpsTarget.certPem);

  const httpTargetUrl = `http://${HTTP_TARGET_HOSTNAME}:${httpPort}/`;
  const httpsTargetUrl = `https://${HTTPS_TARGET_HOSTNAME}:${httpsPort}/`;
  const unreachableTargetUrl = `http://${UNREACHABLE_DIRECT_HOSTNAME}:${httpPort}/`;

  function resetConnections() {
    proxy.connections.length = 0;
  }

  try {
    // --- 1 & 2: fetch through the proxy, HTTPS (CONNECT) and HTTP (absolute-URI) ---
    resetConnections();
    const fetchHttps = await runProbe(
      FETCH_PROBE_PATH,
      baseEnv({
        NODE_USE_ENV_PROXY: "1",
        HTTPS_PROXY: proxyUrl,
        NODE_EXTRA_CA_CERTS: caCertPath,
        PROXY_SMOKE_TARGET_URL: httpsTargetUrl,
      }),
    );
    record(
      "fetch + NODE_USE_ENV_PROXY=1: HTTPS target reached via CONNECT tunnel",
      fetchHttps.ok === true && proxy.wasConnectedTo(HTTPS_TARGET_HOSTNAME),
      JSON.stringify(fetchHttps),
    );

    resetConnections();
    const fetchHttp = await runProbe(
      FETCH_PROBE_PATH,
      baseEnv({
        NODE_USE_ENV_PROXY: "1",
        HTTP_PROXY: proxyUrl,
        PROXY_SMOKE_TARGET_URL: httpTargetUrl,
      }),
    );
    record(
      "fetch + NODE_USE_ENV_PROXY=1: HTTP target reached via absolute-URI proxy request",
      fetchHttp.ok === true && proxy.wasConnectedTo(HTTP_TARGET_HOSTNAME),
      JSON.stringify(fetchHttp),
    );

    // --- 3 & 4: axios through the proxy, HTTPS and HTTP (no flag needed) ---
    resetConnections();
    const axiosHttps = await runProbe(
      AXIOS_PROBE_PATH,
      baseEnv({
        HTTPS_PROXY: proxyUrl,
        NODE_EXTRA_CA_CERTS: caCertPath,
        WEBHOOK_ALLOW_PRIVATE_IPS: "true",
        PROXY_SMOKE_TARGET_URL: httpsTargetUrl,
      }),
    );
    record(
      "axios: HTTPS target reached via CONNECT tunnel (proxies regardless of NODE_USE_ENV_PROXY)",
      axiosHttps.ok === true && proxy.wasConnectedTo(HTTPS_TARGET_HOSTNAME),
      JSON.stringify(axiosHttps),
    );

    resetConnections();
    const axiosHttp = await runProbe(
      AXIOS_PROBE_PATH,
      baseEnv({
        HTTP_PROXY: proxyUrl,
        WEBHOOK_ALLOW_PRIVATE_IPS: "true",
        PROXY_SMOKE_TARGET_URL: httpTargetUrl,
      }),
    );
    record(
      "axios: HTTP target reached via absolute-URI proxy request (proxies regardless of NODE_USE_ENV_PROXY)",
      axiosHttp.ok === true && proxy.wasConnectedTo(HTTP_TARGET_HOSTNAME),
      JSON.stringify(axiosHttp),
    );

    // --- 5: NO_PROXY bypass — fixture must see nothing, for both clients ---
    resetConnections();
    const fetchNoProxy = await runProbe(
      FETCH_PROBE_PATH,
      baseEnv({
        NODE_USE_ENV_PROXY: "1",
        HTTPS_PROXY: proxyUrl,
        NO_PROXY: HTTPS_TARGET_HOSTNAME,
        NODE_EXTRA_CA_CERTS: caCertPath,
        PROXY_SMOKE_TARGET_URL: httpsTargetUrl,
      }),
    );
    record(
      "fetch + NO_PROXY: bypasses the proxy entirely (direct connection, nothing recorded)",
      fetchNoProxy.ok === true && !proxy.wasConnectedTo(HTTPS_TARGET_HOSTNAME),
      JSON.stringify(fetchNoProxy),
    );

    resetConnections();
    const axiosNoProxy = await runProbe(
      AXIOS_PROBE_PATH,
      baseEnv({
        HTTPS_PROXY: proxyUrl,
        NO_PROXY: HTTPS_TARGET_HOSTNAME,
        NODE_EXTRA_CA_CERTS: caCertPath,
        WEBHOOK_ALLOW_PRIVATE_IPS: "true",
        PROXY_SMOKE_TARGET_URL: httpsTargetUrl,
      }),
    );
    record(
      "axios + NO_PROXY: bypasses the proxy entirely (direct connection, nothing recorded)",
      axiosNoProxy.ok === true && !proxy.wasConnectedTo(HTTPS_TARGET_HOSTNAME),
      JSON.stringify(axiosNoProxy),
    );

    // --- 6: the core regression this release fixes. Proxy env vars are
    // present and the target is reachable ONLY through the proxy (a
    // reserved-TLD hostname that fails real DNS directly, aliased inside
    // the proxy fixture to the real target). Without NODE_USE_ENV_PROXY,
    // fetch must ignore the proxy vars and fail going direct; axios must
    // succeed regardless, because its proxy support never depended on the
    // flag in the first place.
    resetConnections();
    const fetchHalfOn = await runProbe(
      FETCH_PROBE_PATH,
      baseEnv({
        HTTP_PROXY: proxyUrl,
        PROXY_SMOKE_TARGET_URL: unreachableTargetUrl,
      }),
    );
    record(
      "fetch WITHOUT NODE_USE_ENV_PROXY: ignores proxy env, fails against a proxy-only target",
      fetchHalfOn.ok === false,
      JSON.stringify(fetchHalfOn),
    );

    const axiosHalfOn = await runProbe(
      AXIOS_PROBE_PATH,
      baseEnv({
        HTTP_PROXY: proxyUrl,
        WEBHOOK_ALLOW_PRIVATE_IPS: "true",
        PROXY_SMOKE_TARGET_URL: unreachableTargetUrl,
      }),
    );
    record(
      "axios WITHOUT NODE_USE_ENV_PROXY: still proxies, succeeds against the same proxy-only target",
      axiosHalfOn.ok === true && proxy.wasConnectedTo(UNREACHABLE_DIRECT_HOSTNAME),
      JSON.stringify(axiosHalfOn),
    );
  } finally {
    await proxy.close();
    await httpTarget.close();
    await httpsTarget.close();
    fs.unlinkSync(caCertPath);
  }

  const failed = results.filter((r) => !r.passed);
  console.log("");
  console.log(`--- Proxy smoke test summary (Node.js ${process.version}) ---`);
  for (const r of results) {
    console.log(`${r.passed ? "PASS" : "FAIL"}  ${r.name}`);
  }
  if (failed.length > 0) {
    console.error("");
    console.error(`${failed.length}/${results.length} scenario(s) failed:`);
    for (const r of failed) {
      console.error(`  - ${r.name}: ${r.detail}`);
    }
    process.exitCode = 1;
  } else {
    console.log("");
    console.log(`All ${results.length} scenarios passed.`);
    process.exitCode = 0;
  }
}

main().catch((err) => {
  console.error("proxy-smoke-test: unexpected failure:", err);
  process.exitCode = 1;
});
