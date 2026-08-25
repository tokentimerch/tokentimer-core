"use strict";

// Spawned as a fresh child process so NODE_USE_ENV_PROXY (read at Node
// bootstrap) reflects exactly the env the parent gave this scenario.
// Makes exactly one global-fetch request and prints a single marker line
// so the parent can parse the outcome without getting confused by any
// other stdout noise.
const targetUrl = process.env.PROXY_SMOKE_TARGET_URL;
const timeoutMs = Number(process.env.PROXY_SMOKE_TIMEOUT_MS || 5000);

function report(result) {
  console.log(`PROXY_SMOKE_RESULT:${JSON.stringify(result)}`);
}

async function main() {
  if (!targetUrl) throw new Error("PROXY_SMOKE_TARGET_URL is required");

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(targetUrl, { signal: controller.signal });
    const body = await res.text();
    report({ ok: res.status >= 200 && res.status < 300, status: res.status, body });
    process.exitCode = res.ok ? 0 : 1;
  } catch (err) {
    report({ ok: false, error: err.message, code: err.cause?.code || err.code });
    process.exitCode = 1;
  } finally {
    clearTimeout(timer);
  }
}

main().catch((err) => {
  report({ ok: false, error: err.message });
  process.exitCode = 1;
});
