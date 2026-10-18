"use strict";
/**
 * Runs the real DNS hook subprocess against an owned local authoritative DNS/API fixture.
 * Invoked by the DNS routing workflow to check zone selection, policy boundaries and propagation
 * failure. This proves native hook routing, not authentication to an external DNS provider.
 */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { spawn } = require("node:child_process"),
  { Resolver } = require("node:dns/promises");
const resolverViews = require("./certops-dns-resolver-views");
const interruption = require("./certops-dns-hook-interruption");
const {
  applyRestrictivePermissions,
} = require("../packages/agent/src/platform");
const { createHostGate } = require("../packages/agent/scripts/host-gate"),
  { createDnsSolver } = require("../packages/agent/src/dns");
async function portFree(port, udp = false) {
  await new Promise((resolve, reject) => {
    const socket = udp
      ? require("node:dgram").createSocket("udp4")
      : require("node:net").createServer();
    socket.once("error", (error) => {
      try {
        socket.close();
      } catch {}
      reject(error);
    });
    if (udp) socket.bind(port, "127.0.0.1", () => socket.close(resolve));
    else socket.listen(port, "127.0.0.1", () => socket.close(resolve));
  });
}
const scenarios = [
  "dns-routing-longest-zone",
  "dns-routing-provider-policy",
  "dns-routing-dot-boundary",
  "dns-routing-zone-policy",
  "dns-routing-propagation-outage",
  "dns-routing-owned-cleanup",
  resolverViews.SCENARIO,
];
async function stop(child) {
  if (!child?.pid || child.exitCode !== null || child.signalCode !== null)
    return;
  const exit = new Promise((resolve) => child.once("exit", resolve));
  child.kill("SIGTERM");
  let timer;
  await Promise.race([
    exit,
    new Promise((resolve) => {
      timer = setTimeout(resolve, 5000);
    }),
  ]);
  clearTimeout(timer);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await Promise.race([
      exit,
      new Promise((resolve) => {
        timer = setTimeout(resolve, 5000);
      }),
    ]);
    clearTimeout(timer);
  }
  assert.ok(child.exitCode !== null || child.signalCode !== null);
}
async function hook(configDir, domain, value, mode = "present") {
  assert.ok(["present", "cleanup"].includes(mode));
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [
        path.resolve(__dirname, "../packages/agent/bin/certops-dns-hook.js"),
        mode,
      ],
      {
        env: {
          PATH: process.env.PATH,
          ...(process.env.HOME ? { HOME: process.env.HOME } : {}),
          TOKENTIMER_AGENT_CONFIG_DIR: configDir,
          CERTBOT_DOMAIN: domain,
          CERTBOT_VALIDATION: value,
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let stdout = "",
      stderr = "",
      bytes = 0;
    const timeout = setTimeout(() => child.kill("SIGKILL"), 45000);
    const collect = (stream) => (chunk) => {
      bytes += chunk.length;
      if (bytes > 65536) {
        child.kill("SIGKILL");
        return;
      }
      if (stream === "out") stdout += chunk.toString();
      else stderr += chunk.toString();
    };
    child.stdout.on("data", collect("out"));
    child.stderr.on("data", collect("err"));
    child.once("error", () => {
      clearTimeout(timeout);
      reject(new Error("Native DNS hook launch failed"));
    });
    child.once("close", (code, signal) => {
      clearTimeout(timeout);
      if (signal || bytes > 65536)
        reject(new Error("Native DNS hook exceeded runtime/output limit"));
      else resolve({ code, stdout, stderr });
    });
  });
}
async function main() {
  assert.equal(process.env.CERTOPS_DNS_ROUTING_DISPOSABLE_FIXTURE, "1");
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-dns-routing-"),
  );
  applyRestrictivePermissions(directory, { kind: "directory", mode: 0o700 });
  const ownedResolverResources = [];
  const root = `routing-${crypto.randomBytes(6).toString("hex")}.invalid`,
    zone = `child.${root}`,
    records = [];
  let server,
    ready = false,
    primary,
    serverError;
  const resolver = new Resolver({ timeout: 2000, tries: 1 });
  resolver.setServers(["127.0.0.1:8053"]);
  const solver = createDnsSolver({
    provider: "pebble-challtestsrv",
    credentials: {
      baseUrl: "http://127.0.0.1:8055",
      allowInsecureLocalHttp: true,
    },
  });
  const gate = createHostGate({
    suite: "dns-routing-host",
    evidenceLevel: "integration",
    strict: true,
    fixtureSource: {
      file: "scripts/certops-dns-routing-host.js",
      sha256: crypto
        .createHash("sha256")
        .update(fs.readFileSync(__filename))
        .digest("hex"),
    },
    requiredCapabilities: ["native-hook", "native-dns-fixture", "native-pidfd"],
    probeCapabilities: () => ({
      "native-pidfd": {
        available: require("./certops-dns-owned-server").probePidfd(),
      },
      "native-hook": {
        available: fs.existsSync(
          path.resolve(__dirname, "../packages/agent/bin/certops-dns-hook.js"),
        ),
      },
      "native-dns-fixture": {
        available: !serverError && server?.pid > 0 && server.exitCode === null,
      },
    }),
  });
  gate.report.fixtureSources = [...new Set([...resolverViews.REQUIRED_SOURCES, ...interruption.REQUIRED_SOURCES])].map((file) => ({
    file,
    sha256: crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.resolve(__dirname, "..", file)))
      .digest("hex"),
  }));
  async function txt(domain) {
    try {
      return (await resolver.resolveTxt(`_acme-challenge.${domain}`)).map(
        (row) => row.join(""),
      );
    } catch (error) {
      if (["ENODATA", "ENOTFOUND"].includes(error.code)) return [];
      throw error;
    }
  }
  function config(allowedZones = [zone], dnsServers = ["127.0.0.1:8053"], timeoutMs = 1000) {
    const credentials = path.join(directory, "dns.json");
    fs.writeFileSync(
      credentials,
      JSON.stringify({
        baseUrl: "http://127.0.0.1:8055",
        allowInsecureLocalHttp: true,
      }),
      { mode: 0o600 },
    );
    applyRestrictivePermissions(credentials, { kind: "file", mode: 0o600 });
    const file = {
      serverUrl: "http://127.0.0.1:9",
      allowInsecureLocalHttp: true,
      agentId: crypto.randomUUID(),
      execution: { enabled: false, dryRun: true },
      windowsDiscovery: { enabled: false },
      policy: {
        allowedDnsProviders: ["pebble-challtestsrv"],
        allowedDnsZones: allowedZones,
      },
      dnsProviders: {
        cloudflare: {
          credentialsFile: path.join(
            directory,
            "never-read-denied-credentials",
          ),
        },
        "pebble-challtestsrv": { credentialsFile: credentials },
        zoneProviderMap: {
          [root]: "cloudflare",
          [zone]: "pebble-challtestsrv",
        },
      },
      dnsPropagation: {
        resolvers: dnsServers,
        checkAuthoritative: false,
        intervalMs: 100,
        timeoutMs,
      },
    };
    fs.writeFileSync(
      path.join(directory, "config.json"),
      JSON.stringify(file),
      { mode: 0o600 },
    );
  }
  async function invoke(label, expected, options = {}) {
    const domain = `${label}.${zone}`,
      value = "certops-routing-" + crypto.randomBytes(16).toString("hex");
    records.push({ domain, value });
    config(options.allowedZones, options.resolvers);
    const result = await hook(directory, domain, value);
    assert.equal(
      result.code,
      expected,
      "Real DNS hook verdict mismatch; raw output withheld",
    );
    return { ...result, domain, value };
  }
  try {
    // A fresh hosted runner owns these fixed fixture ports. Refuse any existing
    // management listener rather than borrowing somebody else's DNS server.
    for (const port of [8053, 18053]) {
      await portFree(port, true);
      await portFree(port);
    }
    await portFree(8055);
    server = spawn(
      "pebble-challtestsrv",
      [
        "-dns01",
        "127.0.0.1:8053",
        "-management",
        "127.0.0.1:8055",
        "-http01",
        "",
        "-https01",
        "",
        "-tlsalpn01",
        "",
        "-doh",
        "",
      ],
      { stdio: "ignore" },
    );
    server.once("error", () => {
      serverError = true;
    });
    const deadline = Date.now() + 15000;
    let online = false;
    while (Date.now() < deadline && !online) {
      assert.ok(!serverError && server.exitCode === null);
      try {
        await fetch("http://127.0.0.1:8055/", {
          signal: AbortSignal.timeout(1000),
        });
        await txt(`ready.${zone}`);
        online = true;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }
    assert.equal(online, true);
    assert.equal(await gate.preflight(), true);
    ready = true;
    await gate.scenario(scenarios[0], async () => {
      const result = await invoke("longest", 0);
      const event = result.stdout
        .split("\n")
        .filter((line) => line.startsWith("{"))
        .map((line) => JSON.parse(line))
        .find((row) => row.event === "dns.propagation");
      assert.ok(event);
      assert.equal(event.provider, "pebble-challtestsrv");
      assert.equal(event.zone, zone);
      assert.ok((await txt(result.domain)).includes(result.value));
    });
    await gate.scenario(scenarios[1], async () => {
      const domain = `parent.${root}`,
        value = "certops-routing-" + crypto.randomBytes(16).toString("hex");
      config();
      const result = await hook(directory, domain, value);
      assert.equal(result.code, 1);
      const verdict = JSON.parse(result.stderr.trim());
      assert.equal(verdict.allowed, false);
      assert.match(verdict.rejectionReason, /dns_provider/);
      assert.deepEqual(await txt(domain), []);
    });
    await gate.scenario(scenarios[2], async () => {
      const domain = `boundary.bad${zone}`,
        value = "certops-routing-" + crypto.randomBytes(16).toString("hex");
      config();
      const result = await hook(directory, domain, value);
      assert.equal(result.code, 1);
      assert.match(
        JSON.parse(result.stderr.trim()).rejectionReason,
        /dns_provider/,
      );
      assert.deepEqual(await txt(domain), []);
    });
    await gate.scenario(scenarios[3], async () => {
      const result = await invoke("zone-denied", 1, {
        allowedZones: [`unrelated.${root}`],
      });
      assert.match(
        JSON.parse(result.stderr.trim()).rejectionReason,
        /dns_zone/,
      );
      assert.deepEqual(await txt(result.domain), []);
    });
    await gate.scenario(scenarios[4], async () => {
      const result = await invoke("unreachable-resolver", 1, {
        resolvers: ["127.0.0.1:18053"],
      });
      assert.ok(
        (await txt(result.domain)).includes(result.value),
        "Actual mutation is distinct from propagation verification failure",
      );
      const verdict = JSON.parse(result.stderr.trim());
      assert.equal(verdict.ok, false);
    });
    await gate.scenario(resolverViews.SCENARIO, async () => {
      gate.report.nativeResolverViews =
        await resolverViews.qualifyResolverViews({
          directory,
          zone,
          ownedResolverResources,
        });
    });
  } catch (error) {
    primary = error;
    throw error;
  } finally {
    const cleanup = async () => {
      if (!primary) gate.report.nativeDnsHookInterruption = await interruption.qualify({directory, zone, config, hook, txt, records, ownedResolverResources});
      for (const resource of ownedResolverResources)
        resource.assertCleanupSafe();
      const failures = [];
      for (const row of records)
        try {
          assert.ok(row.domain.endsWith(`.${zone}`));
          const result = await solver.cleanupChallenge({
            zone,
            recordName: `_acme-challenge.${row.domain}`,
            txtValue: row.value,
          });
          assert.equal(result.ok, true);
          assert.ok(!(await txt(row.domain)).includes(row.value));
        } catch (error) {
          failures.push(error);
        }
      try {
        await stop(server);
        await assert.rejects(
          fetch("http://127.0.0.1:8055/", {
            signal: AbortSignal.timeout(1000),
          }),
        );
        await assert.rejects(
          resolver.resolveTxt(`_acme-challenge.cleanup.${zone}`),
        );
      } catch (error) {
        failures.push(error);
      }
      if (failures.length)
        throw new AggregateError(failures, "Owned DNS routing cleanup failed");
      for (const resource of ownedResolverResources)
        resource.assertCleanupSafe();
      fs.rmSync(directory, { recursive: true, force: true });
    };
    try {
      if (ready) {
        await gate.scenario(scenarios[5], cleanup);
        await gate.finish({ requiredScenarios: scenarios });
      } else {
        await stop(server);
        fs.rmSync(directory, { recursive: true, force: true });
      }
    } catch (error) {
      if (primary)
        throw new AggregateError(
          [primary, error],
          "DNS routing and cleanup failed",
        );
      throw error;
    }
  }
}
module.exports = { main, scenarios };
if (require.main === module)
  main().catch(() => {
    console.error("DNS routing fixture failed; inspect sanitized report");
    process.exitCode = 1;
  });
