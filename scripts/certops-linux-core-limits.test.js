"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { assertCoreDumpLimits } = require("../tests/e2e/linux-systemd-real-journey");

test("native core limit accepts padded proc columns while requiring both zero limits", () => {
  const row = "Max core file size        0                    0                    bytes     ";
  assert.doesNotThrow(() => assertCoreDumpLimits(`Limit Soft Hard Units\n${row}\nMax resident set unlimited\n`));
  assert.doesNotThrow(() => assertCoreDumpLimits("Max core file size\t0\t0\tbytes\n"));
  for (const invalid of [
    "Max core file size 1 0 bytes",
    "Max core file size 0 1 bytes",
    "Max core file size 0 unlimited bytes",
    "Max core file size unlimited 0 bytes",
    "Max core file size 0 0 kilobytes",
    "Other core file size 0 0 bytes",
    "Max core file size 0\n0 bytes",
    "Max core file size 0 0 bytes extra",
  ]) assert.throws(() => assertCoreDumpLimits(invalid));
});
