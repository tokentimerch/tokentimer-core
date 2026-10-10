"use strict";
// Run the ordinary maintenance worker; no harness imports database services.
const { spawn } = require("node:child_process");
let stopped = false,
  child;
process.on("SIGTERM", () => {
  stopped = true;
  child?.kill("SIGTERM");
});
process.on("SIGINT", () => {
  stopped = true;
  child?.kill("SIGTERM");
});
(async () => {
  while (!stopped) {
    child = spawn(
      process.execPath,
      ["/app/apps/worker/src/certops-worker.js"],
      { stdio: "inherit" },
    );
    await new Promise((resolve) => child.once("exit", resolve));
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
})();
