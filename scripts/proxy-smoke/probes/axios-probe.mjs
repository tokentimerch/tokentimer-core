"use strict";

// Spawned as a fresh child process, mirroring fetch-probe.js. Uses .mjs
// because it imports the worker's real ESM webhook sender (axios honors
// proxy env vars regardless of NODE_USE_ENV_PROXY, but bootstrap-time env
// still matters for parity with the fetch probe and to keep both probes
// spawned identically).
import path from "node:path";
import { fileURLToPath } from "node:url";

const targetUrl = process.env.PROXY_SMOKE_TARGET_URL;
const timeoutMs = Number(process.env.PROXY_SMOKE_TIMEOUT_MS || 5000);

function report(result) {
  console.log(`PROXY_SMOKE_RESULT:${JSON.stringify(result)}`);
}

async function main() {
  if (!targetUrl) throw new Error("PROXY_SMOKE_TARGET_URL is required");

  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const webhooksModulePath = path.join(
    __dirname,
    "..",
    "..",
    "..",
    "apps",
    "worker",
    "src",
    "notify",
    "webhooks.js",
  );
  const { postJson } = await import(`file://${webhooksModulePath.replace(/\\/g, "/")}`);

  const timer = setTimeout(() => {
    report({ ok: false, error: `axios probe timed out after ${timeoutMs}ms` });
    process.exit(1);
  }, timeoutMs + 1000);

  try {
    const result = await postJson(targetUrl, { text: "proxy-smoke-test" }, "generic");
    clearTimeout(timer);
    report({ ok: result.success, ...result });
    process.exitCode = result.success ? 0 : 1;
  } catch (err) {
    clearTimeout(timer);
    report({ ok: false, error: err.message });
    process.exitCode = 1;
  }
}

main().catch((err) => {
  report({ ok: false, error: err.message });
  process.exitCode = 1;
});
