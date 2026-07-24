"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { runDnsHook, resolveProviderForDomain, CHALLENGE_LABEL } = require("./hook.js");

const allow = () => ({ allowed: true });
const rejectWith = (rejectionReason) => () => ({
  allowed: false,
  rejectionReason,
  detail: `rejected: ${rejectionReason}`,
});

function makeStream() {
  const chunks = [];
  return {
    write: (chunk) => {
      chunks.push(String(chunk));
      return true;
    },
    get output() {
      return chunks.join("");
    },
  };
}

/**
 * Builds a full runDnsHook options object with recording fakes; overrides
 * are shallow-merged on top.
 */
function makeHarness(overrides = {}) {
  const solverCalls = [];
  const solver = {
    provider: "cloudflare",
    presentChallenge: async (inputs) => {
      solverCalls.push({ operation: "present", inputs });
      return { ok: true, provider: "cloudflare" };
    },
    cleanupChallenge: async (inputs) => {
      solverCalls.push({ operation: "cleanup", inputs });
      return { ok: true, provider: "cloudflare" };
    },
  };

  const createSolverCalls = [];
  const readCredentialsCalls = [];

  const harness = {
    env: { CERTBOT_DOMAIN: "www.example.com", CERTBOT_VALIDATION: "token-value" },
    argv: ["present"],
    loadConfig: () => ({
      policy: {
        allowedDnsProviders: ["cloudflare"],
        allowedDnsZones: ["example.com"],
      },
      dnsProviders: {
        cloudflare: { credentialsFile: "/etc/tokentimer-agent/dns/cloudflare.json" },
        zoneProviderMap: { "example.com": "cloudflare" },
      },
    }),
    readCredentialsFile: (providerId, config) => {
      readCredentialsCalls.push({ providerId, config });
      return { apiToken: "cf-token" };
    },
    createSolver: (options) => {
      createSolverCalls.push(options);
      return solver;
    },
    policyEngineFactory: () => ({
      checkDnsProvider: allow,
      checkDnsZone: allow,
    }),
    // Instant DNS evidence: skip real network during unit tests.
    propagationDeps: {
      discoverAuthoritativeResolverIps: async () => ["203.0.113.1"],
      resolveTxt: async (_name, _servers) => {
        // present waits for the value; cleanup waits for absence. The hook
        // passes the mode indirectly via expectPresent inside wait helpers;
        // return the challenge value for present-shaped polls and [] when
        // the last solver call was cleanup.
        const last = solverCalls[solverCalls.length - 1];
        if (last && last.operation === "cleanup") {
          return [];
        }
        return ["token-value"];
      },
      sleep: async () => {},
    },
    stdout: makeStream(),
    stderr: makeStream(),
    ...overrides,
  };

  harness.solverCalls = solverCalls;
  harness.createSolverCalls = createSolverCalls;
  harness.readCredentialsCalls = readCredentialsCalls;
  return harness;
}

// ---------------------------------------------------------------------------
// argv / env contract
// ---------------------------------------------------------------------------

test("hook: an unknown mode fails with usage and exit code 2", async () => {
  const harness = makeHarness({ argv: ["bogus"] });
  const exitCode = await runDnsHook(harness);
  assert.equal(exitCode, 2);
  assert.match(harness.stderr.output, /unknown mode/);
  assert.match(harness.stderr.output, /usage: certops-dns-hook/);
});

test("hook: a missing mode fails with exit code 2", async () => {
  const harness = makeHarness({ argv: [] });
  assert.equal(await runDnsHook(harness), 2);
});

test("hook: missing CERTBOT_DOMAIN fails before any work", async () => {
  const harness = makeHarness({ env: { CERTBOT_VALIDATION: "v" } });
  const exitCode = await runDnsHook(harness);
  assert.equal(exitCode, 2);
  assert.match(harness.stderr.output, /CERTBOT_DOMAIN/);
  assert.equal(harness.solverCalls.length, 0);
});

test("hook: missing CERTBOT_VALIDATION fails before any work", async () => {
  const harness = makeHarness({ env: { CERTBOT_DOMAIN: "www.example.com" } });
  const exitCode = await runDnsHook(harness);
  assert.equal(exitCode, 2);
  assert.match(harness.stderr.output, /CERTBOT_VALIDATION/);
});

test("hook: ACME_DOMAIN / ACME_TXT_VALUE work as acme.sh-wrapper fallbacks", async () => {
  const harness = makeHarness({
    env: { ACME_DOMAIN: "www.example.com", ACME_TXT_VALUE: "acme-sh-token" },
    propagationDeps: {
      discoverAuthoritativeResolverIps: async () => ["203.0.113.1"],
      resolveTxt: async () => ["acme-sh-token"],
      sleep: async () => {},
    },
  });
  const exitCode = await runDnsHook(harness);
  assert.equal(exitCode, 0);
  assert.equal(harness.solverCalls[0].inputs.txtValue, "acme-sh-token");
});

// ---------------------------------------------------------------------------
// policy short-circuit: no credentials read, no solver, no network
// ---------------------------------------------------------------------------

test("hook: a provider policy rejection short-circuits before credentials or solver", async () => {
  const harness = makeHarness({
    policyEngineFactory: () => ({
      checkDnsProvider: rejectWith("dns_provider_not_allowlisted"),
      checkDnsZone: allow,
    }),
  });

  const exitCode = await runDnsHook(harness);

  assert.equal(exitCode, 1);
  const rejection = JSON.parse(harness.stderr.output);
  assert.equal(rejection.allowed, false);
  assert.equal(rejection.rejectionReason, "dns_provider_not_allowlisted");
  assert.equal(harness.readCredentialsCalls.length, 0);
  assert.equal(harness.createSolverCalls.length, 0);
  assert.equal(harness.solverCalls.length, 0);
});

test("hook: a zone policy rejection short-circuits the same way", async () => {
  const harness = makeHarness({
    policyEngineFactory: () => ({
      checkDnsProvider: allow,
      checkDnsZone: rejectWith("dns_zone_not_allowlisted"),
    }),
  });

  const exitCode = await runDnsHook(harness);

  assert.equal(exitCode, 1);
  assert.match(harness.stderr.output, /dns_zone_not_allowlisted/);
  assert.equal(harness.readCredentialsCalls.length, 0);
  assert.equal(harness.createSolverCalls.length, 0);
});

// ---------------------------------------------------------------------------
// present / cleanup dispatch
// ---------------------------------------------------------------------------

test("hook: present dispatches presentChallenge with the derived record name", async () => {
  const harness = makeHarness();
  const exitCode = await runDnsHook(harness);

  assert.equal(exitCode, 0);
  assert.deepEqual(harness.solverCalls, [
    {
      operation: "present",
      inputs: {
        zone: "example.com",
        recordName: `${CHALLENGE_LABEL}.www.example.com`,
        txtValue: "token-value",
      },
    },
  ]);
  assert.match(harness.stdout.output, /present ok .* via cloudflare/);
  assert.match(harness.stdout.output, /"event":"dns.propagation"/);
});

test("hook: cleanup dispatches cleanupChallenge", async () => {
  const harness = makeHarness({
    argv: ["cleanup"],
    propagationDeps: {
      discoverAuthoritativeResolverIps: async () => ["203.0.113.1"],
      resolveTxt: async () => [],
      sleep: async () => {},
    },
  });
  const exitCode = await runDnsHook(harness);

  assert.equal(exitCode, 0);
  assert.equal(harness.solverCalls[0].operation, "cleanup");
});

test("hook: acme-dns cleanup skips TXT-absence poll and reports cleanup_not_applicable", async () => {
  let resolveTxtCalls = 0;
  const harness = makeHarness({
    argv: ["cleanup"],
    env: { CERTBOT_DOMAIN: "www.example.com", CERTBOT_VALIDATION: "token-value" },
    loadConfig: () => ({
      policy: {
        allowedDnsProviders: ["acme-dns"],
        allowedDnsZones: ["example.com"],
      },
      dnsProviders: {
        "acme-dns": { credentialsFile: "/etc/tokentimer-agent/dns/acme-dns.json" },
        zoneProviderMap: { "example.com": "acme-dns" },
      },
    }),
    createSolver: () => ({
      provider: "acme-dns",
      presentChallenge: async () => ({ ok: true }),
      cleanupChallenge: async () => ({ ok: true, provider: "acme-dns" }),
    }),
    propagationDeps: {
      discoverAuthoritativeResolverIps: async () => ["203.0.113.1"],
      resolveTxt: async () => {
        resolveTxtCalls += 1;
        return ["token-value"];
      },
      sleep: async () => {},
    },
  });

  const exitCode = await runDnsHook(harness);

  assert.equal(exitCode, 0);
  assert.equal(resolveTxtCalls, 0);
  const evidence = JSON.parse(
    harness.stdout.output
      .split("\n")
      .find((line) => line.includes('"event":"dns.propagation"')),
  );
  assert.equal(evidence.ok, true);
  assert.equal(evidence.provider, "acme-dns");
  assert.equal(evidence.phase, "cleanup-verify");
  assert.equal(evidence.status, "cleanup_not_applicable");
  assert.equal(evidence.attempts, 0);
});

test("hook: cloudflare cleanup still waits for TXT absence", async () => {
  let resolveTxtCalls = 0;
  const harness = makeHarness({
    argv: ["cleanup"],
    propagationDeps: {
      discoverAuthoritativeResolverIps: async () => ["203.0.113.1"],
      resolveTxt: async () => {
        resolveTxtCalls += 1;
        return [];
      },
      sleep: async () => {},
    },
  });

  const exitCode = await runDnsHook(harness);

  assert.equal(exitCode, 0);
  assert.ok(resolveTxtCalls >= 1);
  const evidence = JSON.parse(
    harness.stdout.output
      .split("\n")
      .find((line) => line.includes('"event":"dns.propagation"')),
  );
  assert.equal(evidence.ok, true);
  assert.equal(evidence.provider, "cloudflare");
  assert.equal(evidence.phase, "cleanup-verify");
  assert.notEqual(evidence.status, "cleanup_not_applicable");
});

test("hook: a solver failure result exits nonzero with the redacted result JSON", async () => {
  const harness = makeHarness({
    createSolver: () => ({
      presentChallenge: async () => ({
        ok: false,
        provider: "cloudflare",
        statusCode: 403,
        detail: "[redacted]",
      }),
      cleanupChallenge: async () => ({ ok: true }),
    }),
  });

  const exitCode = await runDnsHook(harness);

  assert.equal(exitCode, 1);
  const failure = JSON.parse(harness.stderr.output);
  assert.equal(failure.ok, false);
  assert.equal(failure.statusCode, 403);
});

test("hook: non-secret config options merge into credentials, file wins", async () => {
  const harness = makeHarness({
    loadConfig: () => ({
      policy: {},
      dnsProviders: {
        cloudflare: {
          credentialsFile: "/etc/tokentimer-agent/dns/cloudflare.json",
          zoneId: "config-zone-id",
        },
        zoneProviderMap: { "example.com": "cloudflare" },
      },
    }),
    readCredentialsFile: () => ({ apiToken: "cf-token" }),
  });

  await runDnsHook(harness);

  assert.equal(harness.createSolverCalls.length, 1);
  assert.deepEqual(harness.createSolverCalls[0], {
    provider: "cloudflare",
    credentials: { zoneId: "config-zone-id", apiToken: "cf-token" },
  });
});

test("hook: missing dnsProviders section fails with a clear message", async () => {
  const harness = makeHarness({ loadConfig: () => ({ policy: {} }) });
  const exitCode = await runDnsHook(harness);
  assert.equal(exitCode, 1);
  assert.match(harness.stderr.output, /no dnsProviders section/);
});

test("hook: a throwing loadConfig maps to exit 1, never a throw", async () => {
  const harness = makeHarness({
    loadConfig: () => {
      throw new Error("config.json is malformed");
    },
  });
  const exitCode = await runDnsHook(harness);
  assert.equal(exitCode, 1);
  assert.match(harness.stderr.output, /config\.json is malformed/);
});

// ---------------------------------------------------------------------------
// provider resolution
// ---------------------------------------------------------------------------

test("resolveProviderForDomain: longest zoneProviderMap match wins", () => {
  const dnsProviders = {
    cloudflare: { credentialsFile: "/a" },
    route53: { credentialsFile: "/b" },
    zoneProviderMap: {
      "example.com": "cloudflare",
      "internal.example.com": "route53",
    },
  };

  const resolved = resolveProviderForDomain(dnsProviders, "host.internal.example.com");
  assert.equal(resolved.provider, "route53");
  assert.equal(resolved.zone, "internal.example.com");
});

test("resolveProviderForDomain: dot boundary prevents evil-suffix matches", () => {
  const dnsProviders = {
    cloudflare: { credentialsFile: "/a" },
    route53: { credentialsFile: "/b" },
    zoneProviderMap: { "example.com": "cloudflare", "evilexample.com": "route53" },
  };

  const resolved = resolveProviderForDomain(dnsProviders, "evilexample.com");
  assert.equal(resolved.provider, "route53");
});

test("resolveProviderForDomain: a single configured provider leaves zone null for discovery", () => {
  const dnsProviders = { cloudflare: { credentialsFile: "/a" } };
  const resolved = resolveProviderForDomain(dnsProviders, "anything.example.net");
  assert.equal(resolved.provider, "cloudflare");
  assert.equal(resolved.zone, null);
});

test("resolveProviderForDomain: multiple providers without a map entry throw", () => {
  const dnsProviders = {
    cloudflare: { credentialsFile: "/a" },
    route53: { credentialsFile: "/b" },
  };
  assert.throws(
    () => resolveProviderForDomain(dnsProviders, "www.example.com"),
    /zoneProviderMap/,
  );
});

test("resolveProviderForDomain: a map entry naming an unconfigured provider throws", () => {
  const dnsProviders = {
    cloudflare: { credentialsFile: "/a" },
    zoneProviderMap: { "example.com": "route53" },
  };
  assert.throws(
    () => resolveProviderForDomain(dnsProviders, "www.example.com"),
    /not configured/,
  );
});
