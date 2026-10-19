#!/usr/bin/env node
"use strict";

// Entry point.
//   tokentimer-mcp           serve MCP over stdio (what an assistant launches)
//   tokentimer-mcp enroll    redeem a one-time setup code (what a person runs)
//
// stdout belongs to the protocol when serving, so every diagnostic goes to
// stderr and never includes the credential, a URL or a response body.

const readline = require("node:readline");

// Prompts without echoing what is typed. Only reached on an interactive
// terminal; piped input is read directly and never touches this.
function readHidden(prompt) {
  return new Promise((resolve, reject) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stderr, terminal: true });
    rl.stdoutMuted = false;
    const realWrite = rl._writeToOutput;
    rl.question(prompt, (answer) => {
      rl._writeToOutput = realWrite;
      process.stderr.write("\n");
      rl.close();
      resolve(answer);
    });
    // Everything after the prompt itself is suppressed, so typed characters are not echoed.
    rl._writeToOutput = function writeToOutput(text) {
      if (text === prompt || text.startsWith("\r") || text.startsWith("\n")) realWrite.call(rl, text);
    };
    rl.on("error", reject);
  });
}

async function runEnrollCommand() {
  const { runEnroll } = require("../src/enroll");
  const code = await runEnroll({ argv: process.argv.slice(3), readSecret: readHidden });
  process.exit(code);
}

function serve() {
  const { serveStdio } = require("@modelcontextprotocol/server/stdio");
  const { ConfigError, loadConfig } = require("../src/config");
  const { createServerFactory } = require("../src/server");

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

const command = process.argv[2];
if (command === "enroll") {
  runEnrollCommand().catch(() => {
    process.stderr.write("tokentimer-mcp: setup failed unexpectedly\n");
    process.exit(1);
  });
} else if (command === undefined || command === "serve") {
  serve();
} else {
  process.stderr.write(`tokentimer-mcp: unknown command. Use "enroll" to set up, or no command to serve.\n`);
  process.exit(2);
}
