"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  createAcmeAdapter,
  listSupportedAdapters,
  defaultDnsHookPath,
  defaultAcmeDnsApiPath,
  resolveAcmeStatePaths,
  ACME_SH_DNS_HOOK_NAME,
  SHELL_METACHARACTER_PATTERN,
  OUTPUT_EXCERPT_MAX_CHARS,
} = require("./index.js");

const CA_ENDPOINT = "https://acme-v02.api.letsencrypt.org/directory";
const CSR_PATH = "/etc/tokentimer-agent/csr/web-01.csr.pem";
const OUT_CERT_PATH = "/etc/nginx/tls/web-01.crt.pem";
const STATE_DIR = "/opt/tokentimer-agent/state";
const DOMAINS = ["example.com", "www.example.com"];
const DNS_HOOK_PATH = "/opt/tokentimer/bin/certops-dns-hook.js";
const ACME_DNS_API_PATH = "/opt/tokentimer/bin/dns_certops.sh";

const STATE_PATHS = resolveAcmeStatePaths(STATE_DIR);

const allowAll = () => ({ allowed: true });

/**
 * execFile stub factory: records calls, invokes the callback with a
 * configurable outcome. Mimics child_process.execFile's
 * (file, args, options, callback) signature.
 */
function makeExecStub({ error = null, stdout = "", stderr = "" } = {}) {
  const calls = [];
  function execFileStub(file, args, options, callback) {
    calls.push({ file, args, options });
    process.nextTick(() => callback(error, stdout, stderr));
  }
  execFileStub.calls = calls;
  return execFileStub;
}

function certbotAdapter(execFileImpl, extra = {}) {
  return createAcmeAdapter({
    kind: "certbot",
    commandProfile: { argv: ["certbot"] },
    execFileImpl,
    dnsHookPath: DNS_HOOK_PATH,
    acmeDnsApiPath: ACME_DNS_API_PATH,
    ...extra,
  });
}

function acmeShAdapter(execFileImpl, extra = {}) {
  return createAcmeAdapter({
    kind: "acme.sh",
    commandProfile: { argv: ["/root/.acme.sh/acme.sh"] },
    execFileImpl,
    dnsHookPath: DNS_HOOK_PATH,
    acmeDnsApiPath: ACME_DNS_API_PATH,
    ...extra,
  });
}

function baseRenewalInputs(overrides = {}) {
  return {
    caEndpoint: CA_ENDPOINT,
    domains: [...DOMAINS],
    csrPath: CSR_PATH,
    outCertPath: OUT_CERT_PATH,
    stateDir: STATE_DIR,
    checkCaEndpoint: allowAll,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// listSupportedAdapters
// ---------------------------------------------------------------------------

test("listSupportedAdapters returns certbot and acme.sh", () => {
  assert.deepEqual(listSupportedAdapters(), ["certbot", "acme.sh"]);
});

test("listSupportedAdapters returns a fresh copy each call", () => {
  const first = listSupportedAdapters();
  first.push("mutated");
  assert.deepEqual(listSupportedAdapters(), ["certbot", "acme.sh"]);
});

// ---------------------------------------------------------------------------
// createAcmeAdapter validation
// ---------------------------------------------------------------------------

test("createAcmeAdapter throws on an unsupported kind", () => {
  assert.throws(
    () => createAcmeAdapter({ kind: "lego", commandProfile: { argv: ["lego"] } }),
    /unsupported adapter kind/,
  );
});

test("createAcmeAdapter throws on a missing/malformed command profile", () => {
  assert.throws(() => createAcmeAdapter({ kind: "certbot" }), /commandProfile/);
  assert.throws(
    () => createAcmeAdapter({ kind: "certbot", commandProfile: { argv: "certbot" } }),
    /commandProfile/,
  );
  assert.throws(
    () => createAcmeAdapter({ kind: "certbot", commandProfile: { argv: [] } }),
    /must not be empty/,
  );
});

test("createAcmeAdapter throws on shell metacharacters in the profile argv", () => {
  assert.throws(
    () =>
      createAcmeAdapter({
        kind: "certbot",
        commandProfile: { argv: ["certbot", "; rm -rf /"] },
      }),
    /disallowed shell metacharacter/,
  );
});

test("createAcmeAdapter throws on a non-positive timeoutMs", () => {
  assert.throws(
    () =>
      createAcmeAdapter({
        kind: "certbot",
        commandProfile: { argv: ["certbot"] },
        timeoutMs: 0,
      }),
    /timeoutMs/,
  );
});

// ---------------------------------------------------------------------------
// argv construction: certbot
// ---------------------------------------------------------------------------

test("certbot adapter builds the documented argv (dryRun: false)", async () => {
  const execStub = makeExecStub();
  const adapter = certbotAdapter(execStub);

  const result = await adapter.runRenewal(baseRenewalInputs());

  assert.equal(execStub.calls.length, 1);
  assert.equal(execStub.calls[0].file, "certbot");
  assert.deepEqual(execStub.calls[0].args, [
    "certonly",
    "--non-interactive",
    "--preferred-challenges",
    "dns",
    "--manual",
    "--manual-auth-hook",
    `${DNS_HOOK_PATH} present`,
    "--manual-cleanup-hook",
    `${DNS_HOOK_PATH} cleanup`,
    "--csr",
    CSR_PATH,
    "--server",
    CA_ENDPOINT,
    "-d",
    "example.com",
    "-d",
    "www.example.com",
    "--cert-path",
    OUT_CERT_PATH,
    "--config-dir",
    STATE_PATHS.certbotConfigDir,
    "--work-dir",
    STATE_PATHS.certbotWorkDir,
    "--logs-dir",
    STATE_PATHS.certbotLogsDir,
  ]);
  assert.deepEqual(result.argvUsed, ["certbot", ...execStub.calls[0].args]);
  assert.equal(result.renewed, true);
  assert.equal(result.exitCode, 0);
  assert.equal(execStub.calls[0].options.env.CERTOPS_DNS_HOOK, DNS_HOOK_PATH);
});

test("certbot adapter rejects dryRun: true (certbot forbids --dry-run with --csr, which this adapter always uses)", async () => {
  const execStub = makeExecStub();
  const adapter = certbotAdapter(execStub);

  await assert.rejects(
    () => adapter.runRenewal(baseRenewalInputs({ dryRun: true, preferredChain: "ISRG Root X1" })),
    /dryRun is not supported for the certbot adapter/,
  );
  assert.equal(execStub.calls.length, 0, "must reject before any exec, no certbot process spawned");
});

test("certbot adapter maps EAB typed options and redacts hmac in argvUsed", async () => {
  const execStub = makeExecStub();
  const adapter = certbotAdapter(execStub);

  const result = await adapter.runRenewal(
    baseRenewalInputs({
      eabKid: "kid-abc",
      eabHmacKey: "super-secret-hmac",
    }),
  );

  const execArgs = execStub.calls[0].args;
  const kidIdx = execArgs.indexOf("--eab-kid");
  assert.ok(kidIdx >= 0);
  assert.equal(execArgs[kidIdx + 1], "kid-abc");
  assert.equal(execArgs[kidIdx + 2], "--eab-hmac-key");
  assert.equal(execArgs[kidIdx + 3], "super-secret-hmac");

  assert.equal(result.argvUsed.includes("super-secret-hmac"), false);
  assert.equal(result.argvUsed[result.argvUsed.indexOf("--eab-hmac-key") + 1], "[redacted]");
});

// ---------------------------------------------------------------------------
// argv construction: acme.sh
// ---------------------------------------------------------------------------

test("acme.sh adapter builds the documented argv (dryRun: false)", async () => {
  const execStub = makeExecStub();
  const adapter = acmeShAdapter(execStub);

  const result = await adapter.runRenewal(baseRenewalInputs());

  assert.equal(execStub.calls.length, 1);
  assert.equal(execStub.calls[0].file, "/root/.acme.sh/acme.sh");
  assert.deepEqual(execStub.calls[0].args, [
    "--home",
    STATE_PATHS.acmeShHome,
    "--config-home",
    STATE_PATHS.acmeShHome,
    "--signcsr",
    "--csr",
    CSR_PATH,
    "--server",
    CA_ENDPOINT,
    "-d",
    "example.com",
    "-d",
    "www.example.com",
    "--dns",
    ACME_SH_DNS_HOOK_NAME,
    "--cert-file",
    OUT_CERT_PATH,
  ]);
  assert.equal(ACME_SH_DNS_HOOK_NAME, "dns_certops");
  assert.deepEqual(result.argvUsed, [
    "/root/.acme.sh/acme.sh",
    ...execStub.calls[0].args,
  ]);
  assert.equal(result.renewed, true);
  assert.equal(execStub.calls[0].options.env.CERTOPS_DNS_HOOK, DNS_HOOK_PATH);
  assert.equal(execStub.calls[0].options.env.LE_CONFIG_HOME, STATE_PATHS.acmeShHome);
});

test("acme.sh adapter appends --test when dryRun: true", async () => {
  const execStub = makeExecStub();
  const adapter = acmeShAdapter(execStub);

  const result = await adapter.runRenewal(baseRenewalInputs({ dryRun: true }));

  assert.deepEqual(result.argvUsed, [
    "/root/.acme.sh/acme.sh",
    "--home",
    STATE_PATHS.acmeShHome,
    "--config-home",
    STATE_PATHS.acmeShHome,
    "--signcsr",
    "--csr",
    CSR_PATH,
    "--server",
    CA_ENDPOINT,
    "-d",
    "example.com",
    "-d",
    "www.example.com",
    "--dns",
    "dns_certops",
    "--cert-file",
    OUT_CERT_PATH,
    "--test",
  ]);
});

test("acme.sh adapter maps preferredChain and EAB typed options", async () => {
  const execStub = makeExecStub();
  const adapter = acmeShAdapter(execStub);

  const result = await adapter.runRenewal(
    baseRenewalInputs({
      preferredChain: "ISRG Root X1",
      eabKid: "kid-1",
      eabHmacKey: "hmac-1",
    }),
  );

  assert.ok(result.argvUsed.includes("--preferred-chain"));
  assert.equal(
    result.argvUsed[result.argvUsed.indexOf("--preferred-chain") + 1],
    "ISRG Root X1",
  );
  assert.ok(result.argvUsed.includes("--eab-kid"));
  assert.equal(result.argvUsed[result.argvUsed.indexOf("--eab-hmac-key") + 1], "[redacted]");
});

test("createAcmeAdapter defaults resolve shipped hook and dnsapi paths", () => {
  const adapter = createAcmeAdapter({
    kind: "certbot",
    commandProfile: { argv: ["certbot"] },
    execFileImpl: makeExecStub(),
  });
  assert.equal(adapter.dnsHookPath, defaultDnsHookPath());
  assert.equal(adapter.acmeDnsApiPath, defaultAcmeDnsApiPath());
});

// ---------------------------------------------------------------------------
// checkCaEndpoint defense-in-depth re-check
// ---------------------------------------------------------------------------

test("runRenewal short-circuits on CA rejection and never execs", async () => {
  const execStub = makeExecStub();
  const adapter = certbotAdapter(execStub);
  const rejection = {
    allowed: false,
    rejectionReason: "ca_endpoint_not_allowlisted",
    detail: `CA endpoint "${CA_ENDPOINT}" is not present in the agent-local CA endpoint allowlist.`,
  };

  const result = await adapter.runRenewal(
    baseRenewalInputs({ checkCaEndpoint: () => rejection }),
  );

  // Passed through unchanged (same object identity) so dispatch reports it
  // uniformly with every other policy rejection.
  assert.equal(result, rejection);
  assert.equal(execStub.calls.length, 0);
});

test("runRenewal passes the job's caEndpoint to the checkCaEndpoint callback", async () => {
  const execStub = makeExecStub();
  const adapter = certbotAdapter(execStub);
  const seen = [];

  await adapter.runRenewal(
    baseRenewalInputs({
      checkCaEndpoint: (url) => {
        seen.push(url);
        return { allowed: true };
      },
    }),
  );

  assert.deepEqual(seen, [CA_ENDPOINT]);
});

// ---------------------------------------------------------------------------
// programmer-error validation / typed options (no extraArgs)
// ---------------------------------------------------------------------------

test("runRenewal rejects unknown option keys (no generic passthrough)", async () => {
  const execStub = makeExecStub();
  const adapter = certbotAdapter(execStub);

  await assert.rejects(
    adapter.runRenewal(
      baseRenewalInputs({ extraArgs: ["--post-hook", "reload"] }),
    ),
    /unknown option\(s\): extraArgs/,
  );
  assert.equal(execStub.calls.length, 0);
});

test("runRenewal rejects shell metacharacters in preferredChain, without exec", async () => {
  const execStub = makeExecStub();
  const adapter = certbotAdapter(execStub);

  await assert.rejects(
    adapter.runRenewal(
      baseRenewalInputs({ preferredChain: "ISRG; rm -rf /" }),
    ),
    /preferredChain\[0\] contains a disallowed shell metacharacter/,
  );
  assert.equal(execStub.calls.length, 0);
});

test("runRenewal rejects EAB kid without hmac (and the reverse)", async () => {
  const adapter = certbotAdapter(makeExecStub());
  await assert.rejects(
    adapter.runRenewal(baseRenewalInputs({ eabKid: "kid-only" })),
    /eabKid and eabHmacKey must be provided together/,
  );
  await assert.rejects(
    adapter.runRenewal(baseRenewalInputs({ eabHmacKey: "hmac-only" })),
    /eabKid and eabHmacKey must be provided together/,
  );
});

test("runRenewal rejects missing or relative stateDir", async () => {
  const adapter = certbotAdapter(makeExecStub());
  await assert.rejects(
    adapter.runRenewal(baseRenewalInputs({ stateDir: undefined })),
    /stateDir must be an absolute path/,
  );
  await assert.rejects(
    adapter.runRenewal(baseRenewalInputs({ stateDir: "relative/state" })),
    /stateDir must be an absolute path/,
  );
});

test("runRenewal rejects on shell metacharacters in a domain", async () => {
  const adapter = certbotAdapter(makeExecStub());
  await assert.rejects(
    adapter.runRenewal(baseRenewalInputs({ domains: ["example.com", "evil.com`id`"] })),
    /domains\[1\] contains a disallowed shell metacharacter/,
  );
});

test("runRenewal rejects on empty or non-string domains", async () => {
  const adapter = certbotAdapter(makeExecStub());
  await assert.rejects(
    adapter.runRenewal(baseRenewalInputs({ domains: [] })),
    /non-empty domains array/,
  );
  await assert.rejects(
    adapter.runRenewal(baseRenewalInputs({ domains: ["example.com", 42] })),
    /domains\[1\] must be a non-empty string/,
  );
});

test("runRenewal rejects on relative csrPath / outCertPath", async () => {
  const adapter = certbotAdapter(makeExecStub());
  await assert.rejects(
    adapter.runRenewal(baseRenewalInputs({ csrPath: "csr/web-01.csr.pem" })),
    /csrPath must be an absolute path/,
  );
  await assert.rejects(
    adapter.runRenewal(baseRenewalInputs({ outCertPath: "tls/web-01.crt.pem" })),
    /outCertPath must be an absolute path/,
  );
});

test("runRenewal accepts Windows-style absolute paths", async () => {
  const execStub = makeExecStub();
  const adapter = certbotAdapter(execStub);
  const result = await adapter.runRenewal(
    baseRenewalInputs({
      csrPath: "C:\\certops\\csr\\web-01.csr.pem",
      outCertPath: "C:\\certops\\tls\\web-01.crt.pem",
      stateDir: "C:\\certops\\state",
    }),
  );
  assert.equal(result.renewed, true);
  assert.ok(result.argvUsed.some((a) => a.includes("certbot") || a === "--config-dir"));
});

test("runRenewal rejects when checkCaEndpoint is missing", async () => {
  const adapter = certbotAdapter(makeExecStub());
  await assert.rejects(
    adapter.runRenewal(baseRenewalInputs({ checkCaEndpoint: undefined })),
    /checkCaEndpoint callback/,
  );
});

// ---------------------------------------------------------------------------
// exec outcomes: nonzero exit, timeout/kill, spawn failure
// ---------------------------------------------------------------------------

test("nonzero exit => renewed: false with exit code and excerpts", async () => {
  const error = Object.assign(new Error("Command failed"), { code: 1 });
  const execStub = makeExecStub({
    error,
    stdout: "Attempting renewal...",
    stderr: "Some challenges have failed.",
  });
  const adapter = certbotAdapter(execStub);

  const result = await adapter.runRenewal(baseRenewalInputs());

  assert.equal(result.renewed, false);
  assert.equal(result.exitCode, 1);
  assert.equal(result.stdoutExcerpt, "Attempting renewal...");
  assert.equal(result.stderrExcerpt, "Some challenges have failed.");
  assert.ok(Array.isArray(result.argvUsed));
});

test("timeout/kill (no numeric exit code) => renewed: false with exitCode null", async () => {
  // execFile reports a timeout kill with error.killed=true and a non-numeric
  // code (the signal lives on error.signal).
  const error = Object.assign(new Error("timed out"), {
    killed: true,
    signal: "SIGTERM",
  });
  const execStub = makeExecStub({ error, stdout: "partial output" });
  const adapter = certbotAdapter(execStub, { timeoutMs: 5 });

  const result = await adapter.runRenewal(baseRenewalInputs());

  assert.equal(result.renewed, false);
  assert.equal(result.exitCode, null);
  assert.equal(result.stdoutExcerpt, "partial output");
});

test("adapter passes its timeoutMs through to exec options", async () => {
  const execStub = makeExecStub();
  const adapter = certbotAdapter(execStub, { timeoutMs: 123456 });
  await adapter.runRenewal(baseRenewalInputs());
  assert.equal(execStub.calls[0].options.timeout, 123456);
});

test("spawn failure (ENOENT string code) => renewed: false with exitCode null", async () => {
  const error = Object.assign(new Error("spawn certbot ENOENT"), {
    code: "ENOENT",
  });
  const execStub = makeExecStub({ error });
  const adapter = certbotAdapter(execStub);

  const result = await adapter.runRenewal(baseRenewalInputs());

  assert.equal(result.renewed, false);
  assert.equal(result.exitCode, null);
});

// ---------------------------------------------------------------------------
// excerpt bounding and redaction
// ---------------------------------------------------------------------------

test("stdout/stderr excerpts are bounded to the documented maximum", async () => {
  const longOut = "a".repeat(OUTPUT_EXCERPT_MAX_CHARS + 500);
  const longErr = "b".repeat(OUTPUT_EXCERPT_MAX_CHARS + 500);
  const execStub = makeExecStub({ stdout: longOut, stderr: longErr });
  const adapter = certbotAdapter(execStub);

  const result = await adapter.runRenewal(baseRenewalInputs());

  assert.equal(result.stdoutExcerpt.length, OUTPUT_EXCERPT_MAX_CHARS);
  assert.equal(result.stderrExcerpt.length, OUTPUT_EXCERPT_MAX_CHARS);
  assert.equal(result.stdoutExcerpt, longOut.slice(0, OUTPUT_EXCERPT_MAX_CHARS));
});

test("excerpt containing a PRIVATE KEY marker is redacted wholesale", async () => {
  const execStub = makeExecStub({
    stdout: "-----BEGIN RSA PRIVATE KEY-----\nnot-real-key-material\n",
    stderr: "warning: something mentioned a PRIVATE KEY block",
  });
  const adapter = certbotAdapter(execStub);

  const result = await adapter.runRenewal(baseRenewalInputs());

  assert.equal(result.stdoutExcerpt, "[redacted]");
  assert.equal(result.stderrExcerpt, "[redacted]");
});

test("PRIVATE KEY marker beyond the excerpt window still triggers redaction", async () => {
  const stdout = "x".repeat(OUTPUT_EXCERPT_MAX_CHARS + 10) + " PRIVATE KEY ";
  const execStub = makeExecStub({ stdout });
  const adapter = certbotAdapter(execStub);

  const result = await adapter.runRenewal(baseRenewalInputs());

  assert.equal(result.stdoutExcerpt, "[redacted]");
});

// ---------------------------------------------------------------------------
// dns_certops.sh contract (sourced functions, no exec, base-domain strip)
// ---------------------------------------------------------------------------

test("dns_certops.sh defines sourced add/rm functions without exec", () => {
  const scriptPath = path.resolve(__dirname, "..", "..", "bin", "dns_certops.sh");
  const source = fs.readFileSync(scriptPath, "utf8");
  assert.match(source, /dns_certops_add\s*\(\)/);
  assert.match(source, /dns_certops_rm\s*\(\)/);
  assert.match(source, /_certops_base_domain/);
  assert.match(source, /_acme-challenge\.\*/);
  // Must not replace the shell process (acme.sh sources this file).
  assert.equal(/\bexec\s+node\b/.test(source), false);
  assert.match(source, /node "\$_hook" present/);
  assert.match(source, /node "\$_hook" cleanup/);
  assert.match(source, /return \$\?/);
});

// ---------------------------------------------------------------------------
// misc invariants
// ---------------------------------------------------------------------------

test("shell metacharacter pattern matches the policy module's characters", () => {
  for (const char of [";", "|", "&", "$", "`", ">", "<", "\n", "\r"]) {
    assert.equal(SHELL_METACHARACTER_PATTERN.test(`x${char}y`), true);
  }
  assert.equal(SHELL_METACHARACTER_PATTERN.test("--cert-path=/a/b"), false);
});

test("mutating the profile after adapter creation does not change exec argv", async () => {
  const profile = { argv: ["certbot"] };
  const execStub = makeExecStub();
  const adapter = createAcmeAdapter({
    kind: "certbot",
    commandProfile: profile,
    execFileImpl: execStub,
  });

  profile.argv.push("--sneaky-extra");
  const result = await adapter.runRenewal(baseRenewalInputs());

  assert.equal(result.argvUsed.includes("--sneaky-extra"), false);
  assert.equal(execStub.calls[0].file, "certbot");
});

test("resolveAcmeStatePaths nests certbot and acme.sh under stateDir/acme", () => {
  const root = "/var/lib/tokentimer-agent";
  const paths = resolveAcmeStatePaths(root);
  assert.equal(paths.certbotConfigDir, path.join(root, "acme", "certbot", "config"));
  assert.equal(paths.certbotWorkDir, path.join(root, "acme", "certbot", "work"));
  assert.equal(paths.certbotLogsDir, path.join(root, "acme", "certbot", "logs"));
  assert.equal(paths.acmeShHome, path.join(root, "acme", "acme.sh"));
});
