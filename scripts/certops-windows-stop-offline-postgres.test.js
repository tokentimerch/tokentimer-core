"use strict";
/** Bounded argv admission checks only; no PostgreSQL or native API executes. */
const test = require("node:test"),
  assert = require("node:assert/strict");
const {
  validateArguments,
} = require("./certops-windows-stop-offline-postgres");
test("owned cluster requires the exact parsed data directory and loopback port arguments", () => {
  const data = "C:\\owned fixture [pg]\\data",
    args = [
      "C:\\PostgreSQL\\bin\\postgres.exe",
      "-D",
      data,
      "-h",
      "127.0.0.1",
      "-p",
      "55432",
    ];
  validateArguments(args, data);
  for (const bad of [
    [args[0], "-D", data + "-foreign", ...args.slice(3)],
    [args[0], "-D", "C:\\foreign", ...args.slice(3), data],
    [args[0], "--pgdata", data, ...args.slice(3)],
    [...args, "-D", data],
    [...args.slice(0, 4), "0.0.0.0", ...args.slice(5)],
    [...args.slice(0, 6), "5432"],
  ])
    assert.throws(() => validateArguments(bad, data));
});

test("actual stop script releases the validated PID file before ordinary PostgreSQL bookkeeping while retaining process ownership", () => {
  const script =
    require("./certops-windows-stop-offline-postgres").cleanupScript({});
  const retained = script.indexOf("$handle=$held.Handle"),
    fresh = script.indexOf("Cluster changed before stop"),
    unlocked = script.indexOf("$pidFile=$null"),
    stop = script.indexOf("'pg_ctl.exe'"),
    waited = script.indexOf("$held.WaitForExit(30000)"),
    released = script.indexOf("$held.Dispose()");
  assert.ok(
    retained >= 0 &&
      retained < fresh &&
      fresh < unlocked &&
      unlocked < stop &&
      stop < waited &&
      waited < released,
  );
  assert.ok(script.includes("$actual-cne$r.pidFileSha256"));
  assert.doesNotMatch(
    script,
    /Stop-Process|TerminateProcess|taskkill|Remove-Item/,
  );
});
