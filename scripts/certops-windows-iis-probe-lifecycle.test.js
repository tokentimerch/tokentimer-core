"use strict";
/** Controlled socket events execute the actual IIS fixture probe; no network/native work. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  vm = require("node:vm"),
  { EventEmitter } = require("node:events"),
  { createRequire } = require("node:module");
function fixture() {
  const file = path.resolve(
      __dirname,
      "../packages/agent/scripts/host/iis-fixture.js",
    ),
    realRequire = createRequire(file),
    socket = new EventEmitter();
  let secure;
  socket.authorized = true;
  socket.getPeerCertificate = () => ({ fingerprint: "AA:BB" });
  socket.setTimeout = (_ms, fn) => {
    socket.timeout = fn;
  };
  socket.destroy = () => {
    socket.destroyed = true;
  };
  const module = { exports: {} };
  vm.runInNewContext(
    fs.readFileSync(file, "utf8"),
    {
      module,
      exports: module.exports,
      Buffer,
      process,
      setTimeout,
      require: (name) =>
        name === "node:tls"
          ? {
              connect: (_opts, fn) => {
                secure = fn;
                return socket;
              },
            }
          : realRequire(name),
    },
    { filename: file },
  );
  return {
    socket,
    secure: () => secure(),
    probe: module.exports.servedThumbprint,
  };
}
test("actual native IIS TLS probe waits for close on success and every failure path", async () => {
  for (const mode of [
    "success",
    "unauthorized",
    "error",
    "timeout",
    "early-close",
  ]) {
    const f = fixture();
    let settled = false;
    const result = f
      .probe(
        1234,
        "localhost",
        "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----",
      )
      .then(
        (value) => {
          settled = true;
          return { value };
        },
        (error) => {
          settled = true;
          return { error };
        },
      );
    if (mode === "success") f.secure();
    if (mode === "unauthorized") {
      f.socket.authorized = false;
      f.secure();
    }
    if (mode === "error")
      f.socket.emit("error", Error("controlled TLS failure"));
    if (mode === "timeout") {
      f.socket.destroy = (error) => {
        f.socket.destroyed = true;
        if (error) f.socket.emit("error", error);
      };
      f.socket.timeout();
    }
    await Promise.resolve();
    assert.equal(
      settled,
      false,
      mode + " cannot settle before owned socket close",
    );
    f.socket.emit("close");
    const actual = await result;
    if (mode === "success") assert.equal(actual.value, "AABB");
    else assert.ok(actual.error, mode);
  }
});
