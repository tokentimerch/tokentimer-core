#!/usr/bin/env node
"use strict";

/**
 * TokenTimer Agent CLI entry point.
 *
 * The agent is outbound-only (see docs/adr/0002-certops-agent-protocol.md):
 * it polls the control plane and never accepts inbound connections. This
 * entry point wires config loading, the protocol client, local policy
 * engine, and evidence reporting together; each concern lives in its own
 * src/ subdirectory so it can be developed and tested independently.
 */

const { runAgent } = require("../src/index.js");

runAgent(process.argv.slice(2)).catch((err) => {
  console.error(`tokentimer-agent: fatal error: ${err?.message || err}`);
  process.exit(1);
});
