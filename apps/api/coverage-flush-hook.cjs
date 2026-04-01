"use strict";

if (process.env.NODE_V8_COVERAGE) {
  let flushing = false;

  const flushAndExit = () => {
    if (flushing) return;
    flushing = true;
    try {
      require("node:v8").takeCoverage();
    } catch (_) {}
    process.exit(0);
  };

  process.on("SIGTERM", flushAndExit);
  process.on("SIGINT", flushAndExit);
}
