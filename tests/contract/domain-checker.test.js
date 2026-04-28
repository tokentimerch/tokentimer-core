import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const require = createRequire(import.meta.url);

const {
  lookupDomain,
  normalizeRootDomain,
  parseDiscoveryLines,
} = require("../../apps/api/services/domainChecker");
const {
  buildSubfinderArgs,
} = require("../../apps/api/services/subfinderAdapter");

test("normalizes root domains from URLs and wildcards", () => {
  assert.equal(
    normalizeRootDomain("https://*.Example.COM/path"),
    "example.com",
  );
  assert.equal(normalizeRootDomain("example.com."), "example.com");
  assert.equal(normalizeRootDomain("localhost"), null);
});

test("buildSubfinderArgs adds -all only when requested", () => {
  const defaultArgs = buildSubfinderArgs("example.com");
  assert.equal(defaultArgs.includes("-all"), false);
  const allArgs = buildSubfinderArgs("example.com", { all: true });
  assert.equal(allArgs.includes("-all"), true);
});

test("parses discovery lines and deduplicates hosts", () => {
  const parsed = parseDiscoveryLines(
    {
      subfinder: [
        JSON.stringify({ host: "www.example.com" }),
        JSON.stringify({ host: "api.example.com" }),
        JSON.stringify({ host: "cdn.example.com" }),
        JSON.stringify({ host: "ignored.other" }),
      ],
    },
    "example.com",
  );

  assert.equal(parsed.items.length, 3);
  assert.deepEqual(
    parsed.items.map((item) => item.name),
    ["api.example.com", "cdn.example.com", "www.example.com"],
  );
  assert.deepEqual(
    parsed.items.find((item) => item.name === "www.example.com").sources,
    ["subfinder"],
  );
  assert.equal(
    parsed.items.every((item) => item.checked),
    true,
  );
});

test("lookupDomain returns results when Subfinder succeeds", async () => {
  const runBinary = async ({ onLine }) => {
    onLine(JSON.stringify({ host: "www.example.com" }));
  };

  const result = await lookupDomain("example.com", {
    workspaceId: "test-partial",
    runBinary,
  });
  assert.equal(result.items.length, 1);
  assert.equal(result.partial, false);
  assert.equal(result.toolErrors.length, 0);
});

test("lookupDomain fails when all discovery tools fail", async () => {
  const runBinary = async () => {
    throw Object.assign(new Error("tool failed"), {
      code: "DOMAIN_CHECKER_BINARY_FAILED",
    });
  };

  await assert.rejects(
    lookupDomain("example.com", {
      workspaceId: "test-failed",
      runBinary,
    }),
    /All domain discovery sources failed/,
  );
});

test("lookupDomain enforces one active lookup per workspace and domain", async () => {
  const releases = [];
  const runBinary = () =>
    new Promise((resolve) => {
      releases.push(resolve);
    });

  const first = lookupDomain("example.com", {
    workspaceId: "test-busy",
    runBinary,
  });
  await assert.rejects(
    lookupDomain("example.com", {
      workspaceId: "test-busy",
      runBinary,
    }),
    /already running/,
  );
  releases.forEach((release) => release());
  await first;
});

test("lookupDomain maps all-tool timeouts to a timeout error", async () => {
  const runBinary = async () => {
    throw Object.assign(new Error("timeout"), {
      code: "DOMAIN_CHECKER_TOOL_TIMEOUT",
    });
  };

  await assert.rejects(
    lookupDomain("example.com", {
      workspaceId: "test-timeout",
      runBinary,
    }),
    /timed out/,
  );
});

test("lookupDomain caps results at the configured maximum", async () => {
  const runBinary = async ({ onLine }) => {
    for (let i = 0; i < 3; i += 1) {
      onLine(JSON.stringify({ host: `host${i}.example.com` }));
    }
  };

  const result = await lookupDomain("example.com", {
    workspaceId: "test-cap",
    runBinary,
    maxResults: 2,
  });
  assert.equal(result.items.length, 2);
  assert.equal(result.meta.truncated, true);
});

test("rate-limit contract exposes a dedicated one-per-window domain checker limiter", () => {
  const source = readFileSync(
    resolve(process.cwd(), "apps/api/middleware/rateLimit.js"),
    "utf8",
  );
  assert.match(source, /DOMAIN_CHECKER_LOOKUP_RATE_LIMIT_WINDOW_MS/);
  assert.match(source, /DOMAIN_CHECKER_LOOKUP_RATE_LIMIT_MAX",\s*1/);
  assert.match(source, /getDomainCheckerLookupLimiter/);
  assert.match(source, /DOMAIN_CHECKER_RATE_LIMITED/);
});
