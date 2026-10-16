"use strict";
/** Controlled timer regression for the real wrapper source. No child, CA,
 * certificate or qualification result is produced by these pure checks. */
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  vm = require("node:vm");
function fixture() {
  const events = [],
    signals = {},
    child = { on: () => child },
    timer = { unref: () => events.push("unref") };
  let armed = true,
    tick,
    expire;
  const root = path.resolve(".build", "barrier-unit"),
    arm = path.join(root, "armed.json");
  const fakeFs = {
    existsSync: (file) => file === arm && armed,
    lstatSync: () => ({ isFile: () => true, isSymbolicLink: () => false }),
    readFileSync: () =>
      JSON.stringify({
        token:
          "a".repeat(8) +
          "-" +
          "a".repeat(4) +
          "-" +
          "a".repeat(4) +
          "-" +
          "a".repeat(4) +
          "-" +
          "a".repeat(12),
      }),
    writeFileSync: () => events.push("receipt"),
  };
  const process = {
    argv: ["node", "wrapper", root, "certbot"],
    pid: 42,
    ppid: 41,
    platform: "unit-only",
    env: {},
    on: (signal, action) => {
      signals[signal] = action;
    },
    exit: (code) => events.push("exit:" + code),
  };
  vm.runInNewContext(
    fs.readFileSync(
      path.join(
        __dirname,
        "../tests/e2e/helpers/certops-acme-command-barrier.js",
      ),
      "utf8",
    ),
    {
      process,
      require: (name) =>
        name === "node:fs"
          ? fakeFs
          : name === "node:path"
            ? path
            : {
                spawn: () => {
                  events.push("spawn");
                  return child;
                },
              },
      setInterval: (fn) => {
        tick = fn;
        return "interval";
      },
      clearInterval: () => events.push("clearInterval"),
      setTimeout: (fn, ms) => {
        assert.equal(ms, 120000);
        expire = fn;
        return timer;
      },
      clearTimeout: (value) => {
        if (value === timer) events.push("clearDeadline");
      },
    },
  );
  return {
    events,
    signals,
    expire,
    release: () => {
      armed = false;
      tick();
    },
  };
}
test("actual wrapper disarms hold deadline BEFORE starting a legitimate native client", () => {
  const f = fixture();
  assert.equal(f.events.includes("spawn"), false);
  f.release();
  assert.ok(f.events.indexOf("clearDeadline") < f.events.indexOf("spawn"));
  assert.equal(f.events.filter((x) => x === "clearDeadline").length, 1);
});
test("holding timeout remains effective and shutdown disarms it", () => {
  const f = fixture();
  assert.throws(f.expire, /barrier deadline/);
  f.signals.SIGTERM();
  assert.ok(f.events.includes("clearDeadline"));
  assert.ok(f.events.includes("exit:143"));
  assert.equal(f.events.includes("spawn"), false);
});
