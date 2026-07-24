"use strict";

/**
 * Install-time serverUrl gate matching packages/agent/src/protocol parseServerUrl.
 *
 *   node validate-server-url.js URL [--allow-insecure-local-http]
 *
 * Exits 0 and prints the normalized origin on success; exits 1 with a clear
 * message on failure so install-agent.sh can reject insecure URLs before
 * writing config.json.
 */

const path = require("node:path");
const { parseServerUrl } = require("../src/protocol");

function main(argv = process.argv.slice(2)) {
  let allowInsecureLocalHttp = false;
  const positionals = [];
  for (const arg of argv) {
    if (arg === "--allow-insecure-local-http") {
      allowInsecureLocalHttp = true;
      continue;
    }
    if (arg === "-h" || arg === "--help") {
      process.stdout.write(
        "Usage: node validate-server-url.js URL [--allow-insecure-local-http]\n",
      );
      return 0;
    }
    positionals.push(arg);
  }
  if (positionals.length !== 1) {
    process.stderr.write(
      "validate-server-url: expected exactly one URL argument\n",
    );
    return 1;
  }
  try {
    const origin = parseServerUrl(positionals[0], { allowInsecureLocalHttp });
    process.stdout.write(`${origin}\n`);
    return 0;
  } catch (error) {
    const hint =
      allowInsecureLocalHttp === false &&
      typeof positionals[0] === "string" &&
      positionals[0].startsWith("http://")
        ? " Plain http:// is rejected unless the host is loopback AND --allow-insecure-local-http is passed (local development only)."
        : "";
    process.stderr.write(
      `validate-server-url: ${error.message}.${hint}\n`,
    );
    return 1;
  }
}

module.exports = { main };

if (require.main === module) {
  process.exitCode = main();
}
