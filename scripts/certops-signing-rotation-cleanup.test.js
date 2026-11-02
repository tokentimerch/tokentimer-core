"use strict";
/** Execute the current native fixture cleanup with controlled resources only. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");
const source = fs.readFileSync(
    path.join(
      __dirname,
      "../tests/e2e/certops-signing-rotation-native-e2e.test.js",
    ),
    "utf8",
  ),
  start = source.search(/const\s+cleanup\s*=\s*async\s*\(\s*\)\s*=>\s*\{/),
  tail = source.slice(start).search(/\};\s*try\s*\{\s*if\s*\(\s*ready\s*\)/),
  end = start + tail;
assert.ok(start >= 0 && end > start);
const invoke = new (Object.getPrototypeOf(async () => {}).constructor)(
  "agents",
  "stop",
  "proxy",
  "children",
  "closedChildren",
  "attachment",
  "fixture",
  "assert",
  "fs",
  "path",
  "os",
  "root",
  "rootIdentity",
  "directoryIdentity",
  source.slice(start, end + 1) + ";return cleanup();",
);
async function run(options = {}) {
  const calls = [],
    child = {},
    item = {
      directory: path.join(
        os.tmpdir(),
        "certops-signing-rotation-controlled",
        "agent",
      ),
      directoryIdentity: { dev: 1n, ino: 2n },
      resources: [
        {
          hasOwnershipReceipt: () => !!options.receipt,
          hasLiveResource: () => false,
        },
      ],
    };
  const closed = new WeakSet();
  if (!options.unclosed) closed.add(child);
  const proxy = {
    closeAllConnections() {
      calls.push("proxy-drain");
    },
    close(callback) {
      calls.push("proxy-close");
      callback();
    },
  };
  let error;
  try {
    await invoke(
      [item],
      async () => {
        await Promise.resolve();
        calls.push("agent-drain");
        if (options.stopFailure) throw Error("controlled drain refusal");
      },
      proxy,
      [child],
      closed,
      {
        assertCleanupSafe() {
          calls.push("ownership-check");
          if (options.guardFailure) throw Error("controlled ownership refusal");
        },
      },
      {
        cleanup() {
          calls.push("database-delete");
          if (options.databaseFailure)
            throw Error("controlled database refusal");
        },
      },
      assert,
      {
        rmSync() {
          calls.push("private-root-delete");
        },
      },
      path,
      os,
      path.join(
        path.resolve(os.tmpdir()),
        "certops-signing-rotation-controlled",
      ),
      { dev: 1n, ino: 1n },
      (_file) => {
        calls.push("directory-identity");
        if (options.directoryReplacement)
          throw Error("controlled foreign directory replacement");
      },
    );
  } catch (e) {
    error = e;
  }
  return { calls, error };
}
test("actual rotation cleanup drains independent consumers before destructive steps", async () => {
  const success = await run();
  assert.equal(success.error, undefined);
  for (const name of [
    "agent-drain",
    "proxy-drain",
    "proxy-close",
    "ownership-check",
  ])
    assert.ok(
      success.calls.indexOf(name) < success.calls.indexOf("database-delete"),
      name,
    );
  assert.ok(
    success.calls.indexOf("database-delete") <
      success.calls.indexOf("private-root-delete"),
  );
});
test("actual rotation cleanup preserves public and private state after unknown native ownership", async () => {
  for (const option of [
    "stopFailure",
    "unclosed",
    "guardFailure",
    "receipt",
    "directoryReplacement",
  ]) {
    const result = await run({ [option]: true });
    assert.ok(result.error, option);
    assert.ok(result.calls.includes("proxy-close"), option);
    assert.ok(!result.calls.includes("database-delete"), option);
    assert.ok(!result.calls.includes("private-root-delete"), option);
  }
  const db = await run({ databaseFailure: true });
  assert.ok(db.error);
  assert.ok(!db.calls.includes("private-root-delete"));
});

test("retained idle attachment rejects replacement generation before pinning stop authority", () => {
  const {
    validateOriginalBirth,
  } = require("../tests/e2e/helpers/certops-acme-agent-attachment");
  assert.equal(validateOriginalBirth("12345", "12345"), "12345");
  for (const expected of ["12346", "", null, 0])
    assert.throws(() => validateOriginalBirth("12345", expected));
  assert.throws(() => validateOriginalBirth("0", "0"));
});

test("actual original directory guard refuses same-path foreign replacement", () => {
  const begin = source.indexOf("function directoryIdentity("),
    finish = source.indexOf("\ntest(", begin);
  assert.ok(begin >= 0 && finish > begin);
  const observe = new Function(
    "fs",
    "path",
    "assert",
    source.slice(begin, finish) + ";return directoryIdentity;",
  )(fs, path, assert);
  const base = fs.mkdtempSync(
    path.join(
      path.resolve(__dirname, "../.build"),
      "rotation-directory-control-",
    ),
  );
  const parent = fs.realpathSync.native(base),
    agent = path.join(parent, "agent");
  fs.mkdirSync(agent);
  const original = observe(agent),
    moved = path.join(parent, "moved");
  try {
    fs.renameSync(agent, moved);
    fs.mkdirSync(agent);
    fs.writeFileSync(path.join(agent, "sentinel"), "foreign-owned-control");
    assert.throws(() => observe(agent, original));
    assert.equal(
      fs.readFileSync(path.join(agent, "sentinel"), "utf8"),
      "foreign-owned-control",
    );
    assert.deepEqual(observe(moved), original);
  } finally {
    fs.unlinkSync(path.join(agent, "sentinel"));
    fs.rmdirSync(agent);
    fs.rmdirSync(moved);
    fs.rmdirSync(parent);
  }
});
