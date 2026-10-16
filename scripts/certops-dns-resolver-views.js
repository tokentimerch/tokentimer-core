"use strict";
/** Actual production DNS-hook all/quorum qualification against two owned DNS
 * views. Each loopback forwarder passes native challtestsrv datagrams unchanged;
 * no DNS answer, clock, provider result or production dependency is substituted.
 * These are configured resolver views, not public recursive cache qualification.
 * Only the owning disposable routing harness may invoke the native qualifier. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  dgram = require("node:dgram"),
  net = require("node:net");
const { spawn } = require("node:child_process"),
  { Resolver } = require("node:dns/promises");
const { createDnsSolver } = require("../packages/agent/src/dns");
const {
  applyRestrictivePermissions,
} = require("../packages/agent/src/platform");
const { startOwnedDnsServer } = require("./certops-dns-owned-server");
const SCOPE = "native-dns-hook-two-configured-views-all-quorum";
const SCENARIO = "dns-routing-two-view-all-quorum";
const FLAGS = Object.freeze([
  "twoIndependentNativeDnsViews",
  "unmodifiedDnsQueriesAndResponses",
  "realProviderWriteObserved",
  "allRefusedReachableDivergence",
  "allRecoveredAfterRealSecondViewWrite",
  "quorumAcceptedOneRealView",
  "bothConfiguredEndpointsActuallyQueried",
  "nativeHookCleanupVerified",
  "ownedRecordsAbsentFromBothViews",
  "ownedUdpSocketsAndChildDrained",
]);
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-dns-resolver-views.js",
  "scripts/certops-dns-owned-server.js",
  "scripts/certops-dns-owned-server.py",
  "scripts/certops-dns-routing-host.js",
  "packages/agent/bin/certops-dns-hook.js",
  "packages/agent/src/dns/hook.js",
  "packages/agent/src/dns/propagate.js",
  "packages/agent/src/dns/index.js",
  "packages/agent/src/dns/internal.js",
  "packages/agent/src/dns/zone.js",
  "packages/agent/src/dns/lockfile.js",
  "packages/agent/src/dns/providers/pebble-challtestsrv.js",
  "packages/agent/src/config/index.js",
  "packages/agent/src/policy/index.js",
  "packages/agent/src/platform/index.js",
  ".github/workflows/certops-dns-routing-qualification.yml",
]);
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "schemaVersion",
      "scope",
      "allAttempts",
      "recoveryAttempts",
      "quorumAttempts",
      "allForwarded",
      "quorumForwarded",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.schemaVersion, 1);
  assert.equal(p.scope, SCOPE);
  assert.ok(
    Number.isSafeInteger(p.allAttempts) &&
      p.allAttempts >= 2 &&
      p.allAttempts <= 100,
  );
  for (const key of ["recoveryAttempts", "quorumAttempts"])
    assert.ok(Number.isSafeInteger(p[key]) && p[key] >= 1 && p[key] <= 100);
  for (const key of ["allForwarded", "quorumForwarded"]) {
    assert.ok(Array.isArray(p[key]) && p[key].length === 2);
    for (const count of p[key])
      assert.ok(
        Number.isSafeInteger(count) &&
          count >= (key === "allForwarded" ? 2 : 1) &&
          count <= 1000,
      );
  }
  for (const flag of FLAGS)
    assert.equal(p[flag], true, `Missing DNS view observation ${flag}`);
  return true;
}
function question(packet) {
  assert.ok(
    Buffer.isBuffer(packet) && packet.length >= 17 && packet.length <= 4096,
    "Bounded native DNS packet required",
  );
  assert.equal(packet.readUInt16BE(4), 1, "Exactly one DNS question required");
  let offset = 12;
  const labels = [];
  while (true) {
    assert.ok(offset < packet.length);
    const size = packet[offset++];
    if (!size) break;
    assert.ok(
      size <= 63 && offset + size <= packet.length,
      "Compressed or incomplete DNS question refused",
    );
    const label = packet.subarray(offset, offset + size).toString("ascii");
    assert.match(label, /^[a-zA-Z0-9_-]+$/);
    labels.push(label.toLowerCase());
    offset += size;
  }
  assert.ok(offset + 4 <= packet.length && labels.join(".").length <= 253);
  assert.equal(packet.readUInt16BE(offset), 16);
  assert.equal(packet.readUInt16BE(offset + 2), 1);
  return labels.join(".");
}
function verifyDatagrams(query, response, expectedName) {
  assert.equal(question(query), expectedName);
  assert.equal(question(response), expectedName);
  assert.equal(query.readUInt16BE(2) & 0x8000, 0);
  assert.equal(response.readUInt16BE(2) & 0x8000, 0x8000);
  assert.equal(
    response.readUInt16BE(2) & 0x0200,
    0,
    "Unexpected truncated native DNS response",
  );
  assert.equal(response.readUInt16BE(0), query.readUInt16BE(0));
  return true;
}
async function until(read, label, timeout = 15000) {
  const start = performance.now();
  do {
    const result = await read();
    if (result) return result;
    await new Promise((resolve) => setTimeout(resolve, 50));
  } while (performance.now() - start < timeout);
  throw new Error(`Owned DNS view timed out: ${label}`);
}
async function free(port, udp = false) {
  await new Promise((resolve, reject) => {
    const socket = udp ? dgram.createSocket("udp4") : net.createServer();
    socket.once("error", reject);
    if (udp) socket.bind(port, "127.0.0.1", () => socket.close(resolve));
    else socket.listen(port, "127.0.0.1", () => socket.close(resolve));
  });
}
/** One retained upstream UDP socket per native query. Kernel-connected remote
 * endpoints reject foreign senders; send uses the identical native response
 * Buffer. Counts are private causal observations, never invented DNS answers. */
async function createForwarder({ upstreamPort, allowedName }) {
  assert.ok(
    Number.isSafeInteger(upstreamPort) &&
      upstreamPort > 1024 &&
      upstreamPort <= 65535,
  );
  const server = dgram.createSocket("udp4"),
    clients = new Set();
  let closing = false,
    failed = false,
    requests = 0,
    forwarded = 0;
  server.on("error", () => {
    failed = true;
  });
  server.on("message", (query, remote) => {
    if (closing) return;
    let name;
    try {
      name = question(query);
      assert.equal(remote.address, "127.0.0.1");
      assert.equal(name, allowedName());
      assert.equal(query.readUInt16BE(2) & 0x8000, 0);
    } catch {
      failed = true;
      return;
    }
    requests++;
    const socket = dgram.createSocket("udp4");
    clients.add(socket);
    let socketClosing = false;
    socket.closeOwned = () => {
      if (!socketClosing) {
        socketClosing = true;
        socket.close();
      }
    };
    const timer = setTimeout(() => {
      failed = true;
      socket.closeOwned();
    }, 5000);
    timer.unref();
    socket.once("close", () => {
      clearTimeout(timer);
      clients.delete(socket);
    });
    socket.once("error", () => {
      failed = true;
      socket.closeOwned();
    });
    socket.once("message", (response) => {
      try {
        verifyDatagrams(query, response, name);
      } catch {
        failed = true;
        socket.closeOwned();
        return;
      }
      server.send(response, remote.port, remote.address, (error) => {
        if (error) failed = true;
        else forwarded++;
        socket.closeOwned();
      });
    });
    socket.connect(upstreamPort, "127.0.0.1", () =>
      socket.send(query, (error) => {
        if (error) {
          failed = true;
          socket.closeOwned();
        }
      }),
    );
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.bind(0, "127.0.0.1", resolve);
  });
  const endpoint = `127.0.0.1:${server.address().port}`;
  return {
    endpoint,
    snapshot: () => ({ requests, forwarded, failed }),
    async close() {
      closing = true;
      for (const socket of clients) socket.closeOwned();
      await until(() => clients.size === 0, "forwarder upstream socket close");
      let closed = false;
      server.once("close", () => {
        closed = true;
      });
      server.close();
      await until(() => closed, "forwarder listener close");
      assert.equal(
        failed,
        false,
        "Native DNS forwarding was not byte-preserving and complete",
      );
    },
  };
}
function nativeHook(configDir, domain, value, mode) {
  return new Promise((resolve, reject) => {
    const env = {
      PATH: process.env.PATH,
      ...(process.env.HOME ? { HOME: process.env.HOME } : {}),
      ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
      TOKENTIMER_AGENT_CONFIG_DIR: configDir,
      CERTBOT_DOMAIN: domain,
      CERTBOT_VALIDATION: value,
    };
    const child = spawn(
      process.execPath,
      [
        path.resolve(__dirname, "../packages/agent/bin/certops-dns-hook.js"),
        mode,
      ],
      { env, stdio: ["ignore", "pipe", "pipe"] },
    );
    let out = "",
      bytes = 0,
      failure = false;
    const timer = setTimeout(() => {
      failure = true;
      // Never signal a numeric PID after an asynchronous observation. The
      // original child must actually close before any caller cleanup proceeds.
    }, 30000);
    timer.unref();
    const collect = (stdout) => (chunk) => {
      bytes += chunk.length;
      if (bytes > 65536) {
        failure = true;
      } else if (stdout) out += chunk.toString("utf8");
    };
    child.stdout.on("data", collect(true));
    child.stderr.on("data", collect(false));
    child.once("error", () => {
      failure = true;
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      if (failure || signal || ![0, 1].includes(code)) {
        reject(
          new Error("Native DNS view hook did not close within its contract"),
        );
        return;
      }
      try {
        const rows = out
          .split(/\r?\n/)
          .filter((line) => line.startsWith("{"))
          .map((line) => JSON.parse(line))
          .filter((row) => row.event === "dns.propagation");
        assert.equal(rows.length, 1);
        resolve({ code, event: rows[0] });
      } catch {
        reject(new Error("Native DNS view hook evidence malformed"));
      }
    });
  });
}
function verifyObservation(
  result,
  { mode, endpoints, matches, ok, phase = "propagation" },
) {
  const e = result.event;
  assert.equal(result.code, ok ? 0 : 1);
  assert.equal(e.ok, ok);
  assert.equal(e.phase, phase);
  assert.equal(e.verificationMode, mode);
  assert.deepEqual(e.servers, endpoints);
  assert.equal(e.serverResults.length, 2);
  for (let index = 0; index < 2; index++) {
    const row = e.serverResults[index];
    assert.equal(row.server, endpoints[index]);
    assert.equal(row.matched, matches[index]);
    assert.equal(
      row.skipped,
      false,
      "Unreachable resolver cannot count as an independently negative view",
    );
  }
  assert.ok(Number.isSafeInteger(e.attempts) && e.attempts >= 1);
  return e.attempts;
}
async function qualifyResolverViews({
  directory,
  zone,
  ownedResolverResources,
}) {
  assert.equal(process.env.CERTOPS_DNS_ROUTING_DISPOSABLE_FIXTURE, "1");
  assert.ok(Array.isArray(ownedResolverResources));
  assert.match(zone, /^child\.routing-[a-f0-9]{12}\.invalid$/);
  const base = fs.lstatSync(directory);
  assert.ok(base.isDirectory() && !base.isSymbolicLink());
  const guard = path.join(directory, "resolver-views-active.json"),
    token = crypto.randomUUID();
  let resolved = false;
  const resource = {
    assertCleanupSafe() {
      assert.equal(resolved, true, "Preserve unresolved DNS view ownership");
      assert.equal(fs.existsSync(guard), false);
    },
  };
  ownedResolverResources.push(resource);
  fs.writeFileSync(guard, JSON.stringify({ token, zone }), {
    flag: "wx",
    mode: 0o600,
  });
  const guardIdentity = fs.lstatSync(guard),
    guardBytes = fs.readFileSync(guard);
  const configDir = path.join(directory, "resolver-views");
  fs.mkdirSync(configDir, { mode: 0o700 });
  applyRestrictivePermissions(configDir, { kind: "directory", mode: 0o700 });
  let server,
    currentName = "",
    primary,
    result;
  const forwarders = [],
    records = [];
  const assertSecondServerOwned = () => {
    assert.ok(server);
    server.assertLive();
  };
  const solvers = [8055, 18055].map((port) =>
    createDnsSolver({
      provider: "pebble-challtestsrv",
      credentials: {
        baseUrl: `http://127.0.0.1:${port}`,
        allowInsecureLocalHttp: true,
      },
    }),
  );
  const resolvers = [8053, 18054].map((port) => {
    const r = new Resolver({ timeout: 1000, tries: 1 });
    r.setServers([`127.0.0.1:${port}`]);
    return r;
  });
  const txt = async (index, domain) => {
    try {
      return (
        await resolvers[index].resolveTxt(`_acme-challenge.${domain}`)
      ).map((value) => value.join(""));
    } catch (error) {
      if (["ENODATA", "ENOTFOUND"].includes(error.code)) return [];
      throw error;
    }
  };
  function config(mode) {
    const credentials = path.join(configDir, "dns.json");
    fs.writeFileSync(
      credentials,
      JSON.stringify({
        baseUrl: "http://127.0.0.1:8055",
        allowInsecureLocalHttp: true,
      }),
      { mode: 0o600 },
    );
    applyRestrictivePermissions(credentials, { kind: "file", mode: 0o600 });
    const value = {
      serverUrl: "http://127.0.0.1:9",
      allowInsecureLocalHttp: true,
      agentId: crypto.randomUUID(),
      execution: { enabled: false, dryRun: true },
      windowsDiscovery: { enabled: false },
      policy: {
        allowedDnsProviders: ["pebble-challtestsrv"],
        allowedDnsZones: [zone],
      },
      dnsProviders: {
        "pebble-challtestsrv": { credentialsFile: credentials },
        zoneProviderMap: { [zone]: "pebble-challtestsrv" },
      },
      dnsPropagation: {
        resolvers: forwarders.map((f) => f.endpoint),
        checkAuthoritative: false,
        timeoutMs: 1500,
        intervalMs: 100,
        verificationMode: mode,
        ...(mode === "quorum" ? { quorumCount: 1 } : {}),
      },
    };
    const file = path.join(configDir, "config.json");
    fs.writeFileSync(file, JSON.stringify(value), { mode: 0o600 });
    applyRestrictivePermissions(file, { kind: "file", mode: 0o600 });
  }
  async function allocate(label) {
    const domain = `${label}-${crypto.randomBytes(6).toString("hex")}.${zone}`,
      value = `certops-resolver-${crypto.randomBytes(16).toString("hex")}`;
    assert.deepEqual(await txt(0, domain), []);
    assert.deepEqual(await txt(1, domain), []);
    const record = { domain, value };
    records.push(record);
    currentName = `_acme-challenge.${domain}`;
    return record;
  }
  async function remove(record, mode) {
    assertSecondServerOwned();
    for (let index = 0; index < 2; index++) {
      const values = await txt(index, record.domain);
      assert.ok(
        values.every((value) => value === record.value),
        "Preserve a foreign value on the owned DNS label",
      );
      if (index === 1 && values.length)
        assert.equal(
          (
            await solvers[1].cleanupChallenge({
              zone,
              recordName: `_acme-challenge.${record.domain}`,
              txtValue: record.value,
            })
          ).ok,
          true,
        );
    }
    config(mode);
    const event = await nativeHook(
      configDir,
      record.domain,
      record.value,
      "cleanup",
    );
    verifyObservation(event, {
      mode,
      endpoints: forwarders.map((f) => f.endpoint),
      matches: [true, true],
      ok: true,
      phase: "cleanup-verify",
    });
    assert.deepEqual(await txt(0, record.domain), []);
    assert.deepEqual(await txt(1, record.domain), []);
  }
  try {
    await free(18054, true);
    await free(18054);
    await free(18055);
    await startOwnedDnsServer((resource) => {
      server = resource;
    });
    assertSecondServerOwned();
    await until(async () => {
      assertSecondServerOwned();
      try {
        const response = await fetch("http://127.0.0.1:18055/", {
          signal: AbortSignal.timeout(500),
        });
        await response.body?.cancel();
        await txt(1, `ready.${zone}`);
        return true;
      } catch {
        return false;
      }
    }, "second actual DNS server");
    for (const upstreamPort of [8053, 18054])
      forwarders.push(
        await createForwarder({ upstreamPort, allowedName: () => currentName }),
      );
    assert.notEqual(forwarders[0].endpoint, forwarders[1].endpoint);
    const endpoints = forwarders.map((f) => f.endpoint),
      all = await allocate("all");
    config("all");
    let before = forwarders.map((f) => f.snapshot().forwarded);
    const failed = await nativeHook(
      configDir,
      all.domain,
      all.value,
      "present",
    );
    const allAttempts = verifyObservation(failed, {
      mode: "all",
      endpoints,
      matches: [true, false],
      ok: false,
    });
    assert.ok(allAttempts >= 2);
    assert.ok((await txt(0, all.domain)).includes(all.value));
    assert.deepEqual(await txt(1, all.domain), []);
    const allForwarded = forwarders.map(
      (f, index) => f.snapshot().forwarded - before[index],
    );
    assert.ok(allForwarded.every((count) => count >= 2));
    assertSecondServerOwned();
    assert.equal(
      (
        await solvers[1].presentChallenge({
          zone,
          recordName: `_acme-challenge.${all.domain}`,
          txtValue: all.value,
        })
      ).ok,
      true,
    );
    const recovered = await nativeHook(
        configDir,
        all.domain,
        all.value,
        "present",
      ),
      recoveryAttempts = verifyObservation(recovered, {
        mode: "all",
        endpoints,
        matches: [true, true],
        ok: true,
      });
    assert.ok(
      (await txt(0, all.domain)).includes(all.value) &&
        (await txt(1, all.domain)).includes(all.value),
    );
    await remove(all, "all");
    const quorum = await allocate("quorum");
    config("quorum");
    before = forwarders.map((f) => f.snapshot().forwarded);
    const accepted = await nativeHook(
        configDir,
        quorum.domain,
        quorum.value,
        "present",
      ),
      quorumAttempts = verifyObservation(accepted, {
        mode: "quorum",
        endpoints,
        matches: [true, false],
        ok: true,
      });
    assert.ok((await txt(0, quorum.domain)).includes(quorum.value));
    assert.deepEqual(await txt(1, quorum.domain), []);
    const quorumForwarded = forwarders.map(
      (f, index) => f.snapshot().forwarded - before[index],
    );
    assert.ok(quorumForwarded.every((count) => count >= 1));
    await remove(quorum, "quorum");
    result = {
      schemaVersion: 1,
      scope: SCOPE,
      allAttempts,
      recoveryAttempts,
      quorumAttempts,
      allForwarded,
      quorumForwarded,
    };
  } catch (error) {
    primary = error;
  }
  const failures = [];
  for (const record of records)
    for (let index = 0; index < 2; index++)
      try {
        if (index === 1) assertSecondServerOwned();
        const values = await txt(index, record.domain);
        assert.ok(values.every((value) => value === record.value));
        if (values.length)
          assert.equal(
            (
              await solvers[index].cleanupChallenge({
                zone,
                recordName: `_acme-challenge.${record.domain}`,
                txtValue: record.value,
              })
            ).ok,
            true,
          );
        assert.deepEqual(await txt(index, record.domain), []);
      } catch {
        failures.push(new Error("Owned DNS view record cleanup unproven"));
      }
  for (const forwarder of forwarders)
    try {
      await forwarder.close();
    } catch {
      failures.push(new Error("Owned DNS forwarder drainage unproven"));
    }
  if (server)
    try {
      await server.stop();
      server.assertCleanupSafe();
    } catch {
      failures.push(new Error("Owned native DNS child drainage unproven"));
    }
  if (!failures.length) {
    try {
      const now = fs.lstatSync(guard),
        parent = fs.lstatSync(directory);
      assert.ok(
        now.isFile() &&
          !now.isSymbolicLink() &&
          now.dev === guardIdentity.dev &&
          now.ino === guardIdentity.ino &&
          parent.isDirectory() &&
          !parent.isSymbolicLink() &&
          parent.dev === base.dev &&
          parent.ino === base.ino &&
          fs.readFileSync(guard).equals(guardBytes),
      );
      fs.unlinkSync(guard);
      resolved = true;
    } catch {
      failures.push(new Error("Owned DNS view guard identity changed"));
    }
  }
  if (primary || failures.length)
    throw new AggregateError(
      [
        ...(primary
          ? [new Error("Actual DNS resolver view qualification failed")]
          : []),
        ...failures,
      ],
      "DNS resolver view qualification/cleanup incomplete",
    );
  const proof = {
    ...result,
    ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
  };
  verifyProof(proof);
  return proof;
}
module.exports = {
  SCOPE,
  SCENARIO,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  question,
  verifyDatagrams,
  verifyObservation,
  createForwarder,
  qualifyResolverViews,
};
