"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { setTimeout: delay } = require("node:timers/promises");
const watchDestination = require("../tests/e2e/helpers/linux-staging-destination");

test("the staging destination watch detects a transient write with unchanged final bytes", async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tt-staging-watch-"));
  const live = path.join(directory, "live.crt");
  const temporary = path.join(directory, "ephemeral");
  fs.writeFileSync(live, "previous material");
  const watch = watchDestination(directory, async (ready, label, timeout) => {
    const deadline = Date.now() + timeout;
    while (!ready()) {
      assert.ok(Date.now() < deadline, label);
      await delay(10);
    }
  });
  t.after(() => {
    watch.close();
    for (const file of fs.readdirSync(directory)) fs.unlinkSync(path.join(directory, file));
    fs.rmdirSync(directory);
  });
  assert.equal(await watch.checkpoint(), 0);
  assert.equal(await watch.checkpoint(), 0, "Watch markers do not count as destination mutations");
  fs.writeFileSync(temporary, "transient write");
  fs.unlinkSync(temporary);
  assert.deepEqual(fs.readdirSync(directory), ["live.crt"]);
  assert.equal(fs.readFileSync(live, "utf8"), "previous material");
  assert.ok(await watch.checkpoint() > 0, "Temporary writes must invalidate the native proof");
});
