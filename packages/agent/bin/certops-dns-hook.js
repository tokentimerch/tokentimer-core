#!/usr/bin/env node
"use strict";

/**
 * certops-dns-hook: DNS-01 manual-auth-hook for certbot / acme.sh.
 *
 * Thin wrapper wiring src/dns/hook.js to the real implementations:
 * agent config loading, agent-local policy engine, credential file
 * reading, and the native DNS solvers. See docs/certops/agent.md
 * ("DNS-01 providers") for usage.
 */

const configModule = require("../src/config/index.js");
const policyModule = require("../src/policy/index.js");
const { createDnsSolver } = require("../src/dns/index.js");
const { runDnsHook } = require("../src/dns/hook.js");

runDnsHook({
  env: process.env,
  argv: process.argv.slice(2),
  loadConfig: () => configModule.loadAgentConfig(),
  readCredentialsFile: (providerId, config) =>
    configModule.readDnsCredentialsFile(providerId, config),
  createSolver: createDnsSolver,
  policyEngineFactory: (rawPolicy) =>
    policyModule.createPolicyEngine(policyModule.loadPolicyConfig(rawPolicy)),
  stdout: process.stdout,
  stderr: process.stderr,
}).then(
  (exitCode) => {
    process.exitCode = exitCode;
  },
  (err) => {
    // runDnsHook never throws by contract; this is a last-resort guard.
    console.error(`certops-dns-hook: fatal error: ${err?.message || err}`);
    process.exitCode = 1;
  },
);
