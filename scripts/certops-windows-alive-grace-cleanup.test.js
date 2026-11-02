"use strict";
/** Executes the actual cleanup statements with controlled transports; no native work. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path");
test("actual Windows cleanup drains independent transports and preserves native state after uncertain service stop", async () => {
  const { createRequire } = require("node:module");
  const espree = createRequire(
    require.resolve("../packages/agent/node_modules/eslint/package.json"),
  )("espree");
  const source = fs.readFileSync(
    path.join(__dirname, "../tests/e2e/windows-real-journey.js"),
    "utf8",
  );
  const ast = espree.parse(source, {
      ecmaVersion: "latest",
      sourceType: "script",
      range: true,
    }),
    matches = [];
  function visit(n) {
    if (!n || typeof n !== "object") return;
    if (
      n.type === "TryStatement" &&
      n.finalizer &&
      source.slice(...n.finalizer.range).includes("const stopObserverErrors")
    )
      matches.push(n.finalizer);
    for (const c of Object.values(n))
      if (Array.isArray(c)) c.forEach(visit);
      else if (c && typeof c === "object") visit(c);
  }
  visit(ast);
  assert.equal(matches.length, 1);
  const statements = matches[0].body,
    start = statements.findIndex(
      (n) =>
        n.type === "IfStatement" &&
        source.slice(...n.test.range) === "serviceOwned",
    ),
    end = statements.findIndex(
      (n) =>
        n.type === "IfStatement" &&
        source.slice(...n.test.range) === "werTouched",
    );
  assert.ok(start >= 0 && end > start);
  const body =
    source.slice(statements[start].range[0], statements[end].range[0]) +
    ";calls.push('native-destructive-cleanup');";
  const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor,
    run = new AsyncFunction(
      "serviceOwned",
      "cleanup",
      "ps",
      "spawnSync",
      "command",
      "waitUntil",
      "errors",
      "resultGateway",
      "outputPrivacy",
      "heldResponses",
      "dnsProxy",
      "journeyFailure",
      "calls",
      body,
    );
  for (const fail of [false, true]) {
    const calls = [],
      errors = [];
    const cleanup = async (fn) => {
      try {
        await fn();
      } catch (e) {
        errors.push(e);
      }
    };
    const action = () =>
      run(
        true,
        cleanup,
        () => {
          calls.push("stop");
          if (fail) throw Error("controlled stop failure");
        },
        () => ({ status: 1 }),
        () => {},
        async () => {},
        errors,
        { close: () => calls.push("result-close") },
        { close: () => calls.push("privacy-close") },
        [{ destroy: () => calls.push("held-close") }],
        {
          closeAllConnections: () => calls.push("dns-connections-close"),
          close: (fn) => {
            calls.push("dns-close");
            fn();
          },
        },
        null,
        calls,
      );
    if (fail) {
      await assert.rejects(action, /Preserve native state/);
      assert.equal(calls.includes("native-destructive-cleanup"), false);
      for (const label of [
        "result-close",
        "privacy-close",
        "held-close",
        "dns-close",
      ])
        assert.ok(calls.includes(label));
    } else {
      await action();
      assert.ok(calls.includes("native-destructive-cleanup"));
    }
  }
});
