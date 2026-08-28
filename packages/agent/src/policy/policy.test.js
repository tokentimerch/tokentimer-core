"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  loadPolicyConfig,
  createPolicyEngine,
  REJECTION_REASONS,
  SHELL_METACHARACTER_PATTERN,
} = require("./index.js");

function baseRawConfig() {
  return {
    allowedCommands: {
      nginxValidate: { argv: ["nginx", "-t"] },
      nginxReload: { argv: ["systemctl", "reload", "nginx"] },
    },
    allowedPaths: ["/etc/nginx/tls"],
    allowedCaEndpoints: ["https://acme-v02.api.letsencrypt.org/directory"],
    allowedDnsZones: ["example.com"],
    allowedDnsProviders: ["cloudflare-prod"],
  };
}

function baseEngine() {
  const config = loadPolicyConfig(baseRawConfig());
  return createPolicyEngine(config, {
    declaredTargetSelectors: ["host:web-01", "host:web-02"],
  });
}

// ---------------------------------------------------------------------------
// SHELL_METACHARACTER_PATTERN
// ---------------------------------------------------------------------------

test("SHELL_METACHARACTER_PATTERN matches known dangerous characters", () => {
  for (const char of [";", "|", "&", "$", "`", ">", "<", "\n", "\r"]) {
    assert.equal(
      SHELL_METACHARACTER_PATTERN.test(`nginx${char}-t`),
      true,
      `expected pattern to match character ${JSON.stringify(char)}`,
    );
  }
});

test("SHELL_METACHARACTER_PATTERN does not match ordinary argv text", () => {
  assert.equal(SHELL_METACHARACTER_PATTERN.test("nginx"), false);
  assert.equal(SHELL_METACHARACTER_PATTERN.test("--config=/etc/nginx.conf"), false);
});

// ---------------------------------------------------------------------------
// loadPolicyConfig
// ---------------------------------------------------------------------------

test("loadPolicyConfig normalizes a well-formed config", () => {
  const config = loadPolicyConfig(baseRawConfig());

  assert.equal(config.allowedCommands.size, 2);
  assert.deepEqual(config.allowedCommands.get("nginxValidate"), {
    argv: ["nginx", "-t"],
  });
  assert.deepEqual(config.allowedCommands.get("nginxReload"), {
    argv: ["systemctl", "reload", "nginx"],
  });
  assert.equal(config.allowedCaEndpoints.length, 1);
  assert.deepEqual(config.allowedDnsZones, ["example.com"]);
  assert.deepEqual(config.allowedDnsProviders, ["cloudflare-prod"]);
  assert.equal(config.allowedPaths.length, 1);
  assert.ok(require("node:path").isAbsolute(config.allowedPaths[0]));
});

test("loadPolicyConfig tolerates an empty config object", () => {
  const config = loadPolicyConfig({});
  assert.equal(config.allowedCommands.size, 0);
  assert.deepEqual(config.allowedPaths, []);
  assert.deepEqual(config.allowedCaEndpoints, []);
  assert.deepEqual(config.allowedDnsZones, []);
  assert.deepEqual(config.allowedDnsProviders, []);
});

test("loadPolicyConfig throws when the config itself is not an object", () => {
  assert.throws(() => loadPolicyConfig(null), /must be an object/);
  assert.throws(() => loadPolicyConfig("nope"), /must be an object/);
  assert.throws(() => loadPolicyConfig([]), /must be an object/);
});

test("loadPolicyConfig throws on a command profile missing argv", () => {
  assert.throws(
    () => loadPolicyConfig({ allowedCommands: { broken: {} } }),
    /allowedCommands\.broken\.argv must be an array/,
  );
});

test("loadPolicyConfig throws on a command profile with non-array argv", () => {
  assert.throws(
    () =>
      loadPolicyConfig({
        allowedCommands: { broken: { argv: "nginx -t" } },
      }),
    /allowedCommands\.broken\.argv must be an array/,
  );
});

test("loadPolicyConfig throws on a command profile with empty argv", () => {
  assert.throws(
    () => loadPolicyConfig({ allowedCommands: { broken: { argv: [] } } }),
    /must not be empty/,
  );
});

test("loadPolicyConfig throws on argv containing shell metacharacters", () => {
  assert.throws(
    () =>
      loadPolicyConfig({
        allowedCommands: {
          broken: { argv: ["nginx", "-t", "; rm -rf /"] },
        },
      }),
    /disallowed shell metacharacter/,
  );
});

test("loadPolicyConfig throws on argv containing a non-string element", () => {
  assert.throws(
    () =>
      loadPolicyConfig({
        allowedCommands: { broken: { argv: ["nginx", 123] } },
      }),
    /must be a non-empty string/,
  );
});

test("loadPolicyConfig throws when allowedPaths is not an array", () => {
  assert.throws(
    () => loadPolicyConfig({ allowedPaths: "/etc/nginx/tls" }),
    /allowedPaths must be an array/,
  );
});

// ---------------------------------------------------------------------------
// checkCommandRef
// ---------------------------------------------------------------------------

test("checkCommandRef allows a known command ref and returns its argv", () => {
  const engine = baseEngine();
  const result = engine.checkCommandRef("nginxValidate");
  assert.deepEqual(result, { allowed: true, argv: ["nginx", "-t"] });
});

test("checkCommandRef rejects an unknown command ref", () => {
  const engine = baseEngine();
  const result = engine.checkCommandRef("deleteEverything");
  assert.equal(result.allowed, false);
  assert.equal(result.rejectionReason, REJECTION_REASONS.COMMAND_NOT_ALLOWLISTED);
  assert.match(result.detail, /deleteEverything/);
});

// ---------------------------------------------------------------------------
// checkPath
// ---------------------------------------------------------------------------

test("checkPath allows the allowlisted root itself", () => {
  const engine = baseEngine();
  assert.deepEqual(engine.checkPath("/etc/nginx/tls"), { allowed: true });
});

test("checkPath allows a path nested under the allowlisted root", () => {
  const engine = baseEngine();
  assert.deepEqual(engine.checkPath("/etc/nginx/tls/cert.pem"), {
    allowed: true,
  });
});

test("checkPath rejects a sibling path that merely shares a string prefix", () => {
  const engine = baseEngine();
  const result = engine.checkPath("/etc/nginx/tls-evil");
  assert.equal(result.allowed, false);
  assert.equal(result.rejectionReason, REJECTION_REASONS.PATH_NOT_ALLOWLISTED);
});

test("checkPath rejects a path that escapes the allowlisted root via traversal", () => {
  const engine = baseEngine();
  const result = engine.checkPath("/etc/nginx/tls/../../passwd");
  assert.equal(result.allowed, false);
  assert.equal(result.rejectionReason, REJECTION_REASONS.PATH_NOT_ALLOWLISTED);
});

test("checkPath rejects a wholly unrelated path", () => {
  const engine = baseEngine();
  const result = engine.checkPath("/root/.ssh/id_rsa");
  assert.equal(result.allowed, false);
  assert.equal(result.rejectionReason, REJECTION_REASONS.PATH_NOT_ALLOWLISTED);
});

// ---------------------------------------------------------------------------
// checkCaEndpoint
// ---------------------------------------------------------------------------

test("checkCaEndpoint allows an exact match", () => {
  const engine = baseEngine();
  assert.deepEqual(
    engine.checkCaEndpoint("https://acme-v02.api.letsencrypt.org/directory"),
    { allowed: true },
  );
});

test("checkCaEndpoint allows a match differing only by a trailing slash", () => {
  const engine = baseEngine();
  assert.deepEqual(
    engine.checkCaEndpoint("https://acme-v02.api.letsencrypt.org/directory/"),
    { allowed: true },
  );
});

test("checkCaEndpoint rejects a different path on the same host", () => {
  const engine = baseEngine();
  const result = engine.checkCaEndpoint(
    "https://acme-v02.api.letsencrypt.org/other",
  );
  assert.equal(result.allowed, false);
  assert.equal(
    result.rejectionReason,
    REJECTION_REASONS.CA_ENDPOINT_NOT_ALLOWLISTED,
  );
});

test("checkCaEndpoint rejects a different host entirely", () => {
  const engine = baseEngine();
  const result = engine.checkCaEndpoint(
    "https://acme-staging-v02.api.letsencrypt.org/directory",
  );
  assert.equal(result.allowed, false);
  assert.equal(
    result.rejectionReason,
    REJECTION_REASONS.CA_ENDPOINT_NOT_ALLOWLISTED,
  );
});

test("checkCaEndpoint rejects an invalid URL", () => {
  const engine = baseEngine();
  const result = engine.checkCaEndpoint("not-a-url");
  assert.equal(result.allowed, false);
  assert.equal(
    result.rejectionReason,
    REJECTION_REASONS.CA_ENDPOINT_NOT_ALLOWLISTED,
  );
});

// ---------------------------------------------------------------------------
// checkDnsZone
// ---------------------------------------------------------------------------

test("checkDnsZone allows an exact zone match", () => {
  const engine = baseEngine();
  assert.deepEqual(engine.checkDnsZone("example.com"), { allowed: true });
});

test("checkDnsZone allows a subdomain of an allowlisted zone", () => {
  const engine = baseEngine();
  assert.deepEqual(engine.checkDnsZone("sub.example.com"), { allowed: true });
});

test("checkDnsZone rejects a zone that merely shares a suffix string", () => {
  const engine = baseEngine();
  const result = engine.checkDnsZone("evilexample.com");
  assert.equal(result.allowed, false);
  assert.equal(result.rejectionReason, REJECTION_REASONS.DNS_ZONE_NOT_ALLOWLISTED);
});

test("checkDnsZone rejects an unrelated zone", () => {
  const engine = baseEngine();
  const result = engine.checkDnsZone("example.org");
  assert.equal(result.allowed, false);
  assert.equal(result.rejectionReason, REJECTION_REASONS.DNS_ZONE_NOT_ALLOWLISTED);
});

// ---------------------------------------------------------------------------
// checkDnsProvider
// ---------------------------------------------------------------------------

test("checkDnsProvider allows an exact match", () => {
  const engine = baseEngine();
  assert.deepEqual(engine.checkDnsProvider("cloudflare-prod"), {
    allowed: true,
  });
});

test("checkDnsProvider rejects an unknown provider with dns_provider_not_allowlisted", () => {
  const engine = baseEngine();
  const result = engine.checkDnsProvider("route53-prod");
  assert.equal(result.allowed, false);
  assert.equal(
    result.rejectionReason,
    REJECTION_REASONS.DNS_PROVIDER_NOT_ALLOWLISTED,
  );
  assert.match(result.detail, /DNS provider/);
});

// ---------------------------------------------------------------------------
// checkTargetScope
// ---------------------------------------------------------------------------

test("checkTargetScope allows a declared target selector", () => {
  const engine = baseEngine();
  assert.deepEqual(engine.checkTargetScope("host:web-01"), { allowed: true });
});

test("checkTargetScope rejects an undeclared target selector", () => {
  const engine = baseEngine();
  const result = engine.checkTargetScope("host:web-99");
  assert.equal(result.allowed, false);
  assert.equal(result.rejectionReason, REJECTION_REASONS.TARGET_OUT_OF_SCOPE);
});

test("checkTargetScope rejects everything when no target selectors are declared", () => {
  const config = loadPolicyConfig(baseRawConfig());
  const engine = createPolicyEngine(config);
  const result = engine.checkTargetScope("host:web-01");
  assert.equal(result.allowed, false);
  assert.equal(result.rejectionReason, REJECTION_REASONS.TARGET_OUT_OF_SCOPE);
});

// ---------------------------------------------------------------------------
// checkNoKeyExport
// ---------------------------------------------------------------------------

test("checkNoKeyExport allows a job intent that does not request key export", () => {
  const engine = baseEngine();
  assert.deepEqual(engine.checkNoKeyExport({ requestsKeyExport: false }), {
    allowed: true,
  });
  assert.deepEqual(engine.checkNoKeyExport({}), { allowed: true });
});

test("checkNoKeyExport rejects unconditionally when key export is requested", () => {
  const engine = baseEngine();
  const result = engine.checkNoKeyExport({ requestsKeyExport: true });
  assert.equal(result.allowed, false);
  assert.equal(result.rejectionReason, REJECTION_REASONS.KEY_EXPORT_REQUESTED);
});

test("checkNoKeyExport rejects key export even alongside other seemingly-valid fields", () => {
  const engine = baseEngine();
  const result = engine.checkNoKeyExport({
    requestsKeyExport: true,
    commandRef: "nginxValidate",
    targetSelector: "host:web-01",
  });
  assert.equal(result.allowed, false);
  assert.equal(result.rejectionReason, REJECTION_REASONS.KEY_EXPORT_REQUESTED);
});

// ---------------------------------------------------------------------------
// evaluateJob
// ---------------------------------------------------------------------------

test("evaluateJob allows a fully valid job descriptor", () => {
  const engine = baseEngine();
  const result = engine.evaluateJob({
    requestsKeyExport: false,
    targetSelector: "host:web-01",
    commandRef: "nginxValidate",
    path: "/etc/nginx/tls/cert.pem",
    caEndpoint: "https://acme-v02.api.letsencrypt.org/directory",
    dnsZone: "sub.example.com",
    dnsProvider: "cloudflare-prod",
  });
  assert.deepEqual(result, { allowed: true });
});

test("evaluateJob allows a minimal job descriptor with no applicable fields", () => {
  const engine = baseEngine();
  assert.deepEqual(engine.evaluateJob({}), { allowed: true });
});

test("evaluateJob short-circuits on key export even when other fields are invalid", () => {
  const engine = baseEngine();
  const result = engine.evaluateJob({
    requestsKeyExport: true,
    targetSelector: "host:not-declared",
    commandRef: "unknownCommand",
  });
  assert.equal(result.rejectionReason, REJECTION_REASONS.KEY_EXPORT_REQUESTED);
});

test("evaluateJob rejects target_out_of_scope before evaluating command/path/etc", () => {
  const engine = baseEngine();
  const result = engine.evaluateJob({
    targetSelector: "host:not-declared",
    commandRef: "unknownCommand",
    path: "/root/.ssh",
  });
  assert.equal(result.rejectionReason, REJECTION_REASONS.TARGET_OUT_OF_SCOPE);
});

test("evaluateJob returns the first applicable rejection in documented check order", () => {
  const engine = baseEngine();
  const result = engine.evaluateJob({
    targetSelector: "host:web-01",
    commandRef: "unknownCommand",
    path: "/root/.ssh",
    caEndpoint: "https://not-allowed.example/directory",
  });
  assert.equal(result.rejectionReason, REJECTION_REASONS.COMMAND_NOT_ALLOWLISTED);
});

test("evaluateJob falls through to path rejection when command passes", () => {
  const engine = baseEngine();
  const result = engine.evaluateJob({
    targetSelector: "host:web-01",
    commandRef: "nginxValidate",
    path: "/root/.ssh",
  });
  assert.equal(result.rejectionReason, REJECTION_REASONS.PATH_NOT_ALLOWLISTED);
});

// ---------------------------------------------------------------------------
// checkVerifyHost
// ---------------------------------------------------------------------------

function verifyEngine(allowedVerifyHosts = []) {
  const config = loadPolicyConfig({
    ...baseRawConfig(),
    allowedVerifyHosts,
  });
  return createPolicyEngine(config, {
    declaredTargetSelectors: ["host:web-01"],
  });
}

test("checkVerifyHost allows the job's own target reference without extra config", () => {
  const engine = verifyEngine();
  assert.deepEqual(
    engine.checkVerifyHost("web.example.com", { targetReference: "web.example.com" }),
    { allowed: true },
  );
  // Case-insensitive match.
  assert.deepEqual(
    engine.checkVerifyHost("WEB.Example.COM", { targetReference: "web.example.com" }),
    { allowed: true },
  );
});

test("checkVerifyHost rejects a host matching neither target reference nor allowlist", () => {
  const engine = verifyEngine();
  const result = engine.checkVerifyHost("internal-service.corp", {
    targetReference: "web.example.com",
  });
  assert.equal(result.allowed, false);
  assert.equal(result.rejectionReason, REJECTION_REASONS.TARGET_OUT_OF_SCOPE);
});

test("checkVerifyHost hard-denies metadata/link-local/unspecified/multicast destinations even when allowlisted", () => {
  const engine = verifyEngine([
    "169.254.169.254",
    "0.0.0.0",
    "::",
    "fe80::1",
    "ff02::1",
    "::ffff:169.254.169.254",
  ]);
  for (const host of [
    "169.254.169.254",
    "0.0.0.0",
    "::",
    "fe80::1",
    "ff02::1",
    "::ffff:169.254.169.254",
    "[fe80::1]",
  ]) {
    const result = engine.checkVerifyHost(host, { targetReference: host });
    assert.equal(result.allowed, false, `expected ${host} to be denied`);
    assert.equal(result.rejectionReason, REJECTION_REASONS.TARGET_OUT_OF_SCOPE);
  }
});

test("checkVerifyHost allows loopback only when explicitly allowlisted", () => {
  const closed = verifyEngine();
  for (const host of ["127.0.0.1", "::1", "localhost"]) {
    const result = closed.checkVerifyHost(host, { targetReference: host });
    assert.equal(result.allowed, false, `expected ${host} to be rejected`);
    assert.equal(result.rejectionReason, REJECTION_REASONS.TARGET_OUT_OF_SCOPE);
  }

  const open = verifyEngine(["127.0.0.1", "::1", "localhost"]);
  for (const host of ["127.0.0.1", "::1", "localhost"]) {
    assert.deepEqual(open.checkVerifyHost(host), { allowed: true });
  }
});

test("checkVerifyHost hostname allowlist covers subdomains at a dot boundary only", () => {
  const engine = verifyEngine(["example.com"]);
  assert.deepEqual(engine.checkVerifyHost("example.com"), { allowed: true });
  assert.deepEqual(engine.checkVerifyHost("web.example.com"), { allowed: true });

  const result = engine.checkVerifyHost("evilexample.com");
  assert.equal(result.allowed, false);
  assert.equal(result.rejectionReason, REJECTION_REASONS.TARGET_OUT_OF_SCOPE);
});

test("checkVerifyHost IP allowlist entries match exactly, never as suffixes", () => {
  const engine = verifyEngine(["10.0.0.5"]);
  assert.deepEqual(engine.checkVerifyHost("10.0.0.5"), { allowed: true });

  const result = engine.checkVerifyHost("110.0.0.5");
  assert.equal(result.allowed, false);
  assert.equal(result.rejectionReason, REJECTION_REASONS.TARGET_OUT_OF_SCOPE);
});

test("checkVerifyHost rejects empty, non-string, and oversized hosts", () => {
  const engine = verifyEngine(["example.com"]);
  for (const host of ["", undefined, null, 42, "a".repeat(256)]) {
    const result = engine.checkVerifyHost(host);
    assert.equal(result.allowed, false);
    assert.equal(result.rejectionReason, REJECTION_REASONS.TARGET_OUT_OF_SCOPE);
  }
});

// ---------------------------------------------------------------------------
// Trust-store command allowlist isolation (../trust-store's own spec:
// "own, independently allowlisted command profile ... a distinct trust
// allowlist entry so a renew-only agent's policy does not grant
// trust-store command execution and vice versa"). checkCommandRef itself
// has no notion of "trust" vs "renewal" commands -- it is a pure map
// lookup keyed by whatever ref name a caller passes -- so this isolation
// is entirely a property of WHICH ref names appear in a given agent's
// own allowedCommands config, never something policy/index.js has to
// special-case. These tests prove that property against real
// TRUST_STORE_COMMAND_REFS ref names, not stand-in strings.
// ---------------------------------------------------------------------------

const { TRUST_STORE_COMMAND_REFS, trustStoreCommandRefForFamily } = require("../trust-store/index.js");

test("a renew-only agent's policy (no trust-store command refs configured) refuses all three trust-store command refs", () => {
  const config = loadPolicyConfig({
    allowedCommands: {
      "acme:certbot-renew": { argv: ["certbot", "renew"] },
      "nginx:reload": { argv: ["systemctl", "reload", "nginx"] },
    },
  });
  const engine = createPolicyEngine(config);

  const debianVerdict = engine.checkCommandRef(TRUST_STORE_COMMAND_REFS.DEBIAN_UPDATE_CA_CERTIFICATES);
  assert.equal(debianVerdict.allowed, false);
  assert.equal(debianVerdict.rejectionReason, REJECTION_REASONS.COMMAND_NOT_ALLOWLISTED);

  const rhelVerdict = engine.checkCommandRef(TRUST_STORE_COMMAND_REFS.RHEL_UPDATE_CA_TRUST);
  assert.equal(rhelVerdict.allowed, false);
  assert.equal(rhelVerdict.rejectionReason, REJECTION_REASONS.COMMAND_NOT_ALLOWLISTED);

  const windowsVerdict = engine.checkCommandRef(TRUST_STORE_COMMAND_REFS.WINDOWS_CERTUTIL);
  assert.equal(windowsVerdict.allowed, false);
  assert.equal(windowsVerdict.rejectionReason, REJECTION_REASONS.COMMAND_NOT_ALLOWLISTED);

  // The renewal refs this same config DOES grant are unaffected -- this
  // is isolation, not a broken allowlist.
  assert.equal(engine.checkCommandRef("acme:certbot-renew").allowed, true);
  assert.equal(engine.checkCommandRef("nginx:reload").allowed, true);
});

test("a trust-only agent's policy (only trust-store command refs configured) refuses ordinary renewal/reload command refs", () => {
  const config = loadPolicyConfig({
    allowedCommands: {
      [TRUST_STORE_COMMAND_REFS.DEBIAN_UPDATE_CA_CERTIFICATES]: { argv: ["update-ca-certificates"] },
      [TRUST_STORE_COMMAND_REFS.RHEL_UPDATE_CA_TRUST]: { argv: ["update-ca-trust", "extract"] },
      [TRUST_STORE_COMMAND_REFS.WINDOWS_CERTUTIL]: { argv: ["certutil.exe"] },
    },
  });
  const engine = createPolicyEngine(config);

  const renewVerdict = engine.checkCommandRef("acme:certbot-renew");
  assert.equal(renewVerdict.allowed, false);
  assert.equal(renewVerdict.rejectionReason, REJECTION_REASONS.COMMAND_NOT_ALLOWLISTED);

  const reloadVerdict = engine.checkCommandRef("nginx:reload");
  assert.equal(reloadVerdict.allowed, false);
  assert.equal(reloadVerdict.rejectionReason, REJECTION_REASONS.COMMAND_NOT_ALLOWLISTED);

  assert.equal(engine.checkCommandRef(trustStoreCommandRefForFamily("debian")).allowed, true);
  assert.equal(engine.checkCommandRef(trustStoreCommandRefForFamily("rhel")).allowed, true);
  assert.equal(engine.checkCommandRef(trustStoreCommandRefForFamily("windows")).allowed, true);
});

test("an agent configured with BOTH profiles grants each independently, with its own argv", () => {
  const config = loadPolicyConfig({
    allowedCommands: {
      "nginx:reload": { argv: ["systemctl", "reload", "nginx"] },
      [TRUST_STORE_COMMAND_REFS.DEBIAN_UPDATE_CA_CERTIFICATES]: { argv: ["update-ca-certificates"] },
    },
  });
  const engine = createPolicyEngine(config);

  const reloadVerdict = engine.checkCommandRef("nginx:reload");
  assert.equal(reloadVerdict.allowed, true);
  assert.deepEqual(reloadVerdict.argv, ["systemctl", "reload", "nginx"]);

  const trustVerdict = engine.checkCommandRef(TRUST_STORE_COMMAND_REFS.DEBIAN_UPDATE_CA_CERTIFICATES);
  assert.equal(trustVerdict.allowed, true);
  assert.deepEqual(trustVerdict.argv, ["update-ca-certificates"]);
});
