#!/usr/bin/env node
"use strict";

// stdio entry point. stdout belongs to the protocol, so every diagnostic goes
// to stderr, and never includes the credential, a URL or a response body.

const { serveStdio } = require("@modelcontextprotocol/server/stdio");
const { ConfigError, loadConfig } = require("../src/config");
const { createServerFactory } = require("../src/server");

function main() {
  let config;
  try {
    config = loadConfig(process.env);
  } catch (error) {
    const message = error instanceof ConfigError ? error.message : "Configuration could not be loaded";
    process.stderr.write(`tokentimer-mcp: ${message}\n`);
    process.exit(2);
  }

  const handle = serveStdio(createServerFactory(config), {
    legacy: config.legacy,
    onerror: () => {
      process.stderr.write("tokentimer-mcp: a transport error occurred\n");
    },
  });

  const shutdown = () => {
    handle.close().finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main();
