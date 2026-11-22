const test = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { TestUtils } = require("../integration/setup");

test(
  "runNode terminates a child that exceeds its optional timeout",
  { timeout: 7000 },
  async () => {
    const started = Date.now();
    let childPid;
    await assert.rejects(
      TestUtils.runNode(
        process.execPath,
        ["-e", "setTimeout(() => {}, 5000)"],
        process.cwd(),
        process.env,
        { timeoutMs: 200 },
      ),
      (error) => {
        assert.match(error.message, /timed out after 200 ms; child closed/i);
        childPid = Number(error.message.match(/pid (\d+)/)[1]);
        return true;
      },
    );
    assert.ok(
      Date.now() - started < 4000,
      "the child must not run to its natural exit",
    );
    assert.throws(() => process.kill(childPid, 0), { code: "ESRCH" });
  },
);

test("runNode preserves successful and failing exits without a timeout", async () => {
  assert.deepEqual(
    await TestUtils.runNode(process.execPath, ["-e", "process.exit(0)"]),
    { code: 0 },
  );
  assert.deepEqual(
    await TestUtils.runNode(
      process.execPath,
      ["-e", "process.exit(0)"],
      process.cwd(),
      process.env,
      { timeoutMs: 3000 },
    ),
    { code: 0 },
  );
  await assert.rejects(
    TestUtils.runNode(process.execPath, ["-e", "process.exit(3)"]),
    /exited 3/,
  );
  assert.deepEqual(
    await TestUtils.runNode(
      process.execPath,
      ["-e", "process.exit(3)"],
      process.cwd(),
      process.env,
      { allowExitCodes: [3] },
    ),
    { code: 3 },
  );
});

test("runNode reports spawn errors without leaving its timeout running", async () => {
  await assert.rejects(
    TestUtils.runNode(
      "tt-nonexistent-integration-test-program",
      [],
      process.cwd(),
      process.env,
      { timeoutMs: 3000 },
    ),
    { code: "ENOENT" },
  );
});

test("runNode rejects invalid timeout values before starting a child", async () => {
  await assert.rejects(
    TestUtils.runNode(process.execPath, [], process.cwd(), process.env, {
      timeoutMs: 0,
    }),
    /timeoutMs must be a positive integer/,
  );
});

test(
  "runNode escalates and waits for the child to close",
  { timeout: 4000 },
  async (t) => {
    const child = new EventEmitter();
    child.pid = 12345;
    child.exitCode = null;
    child.signalCode = null;
    const signals = [];
    child.kill = (signal) => {
      signals.push(signal);
      if (signal === "SIGKILL") {
        setTimeout(() => {
          child.signalCode = signal;
          child.emit("close", null, signal);
        }, 25);
      }
      return true;
    };
    const processModule = require("node:child_process");
    t.mock.method(processModule, "spawn", () => child);
    const setupPath = require.resolve("../integration/setup");
    const cachedSetup = require.cache[setupPath];
    delete require.cache[setupPath];
    let isolatedUtils;
    try {
      isolatedUtils = require(setupPath).TestUtils;
    } finally {
      require.cache[setupPath] = cachedSetup;
    }
    await assert.rejects(
      isolatedUtils.runNode("node", [], process.cwd(), process.env, {
        timeoutMs: 20,
      }),
      /timed out after 20 ms; child closed/i,
    );
    assert.deepEqual(signals, ["SIGTERM", "SIGKILL"]);
  },
);

test(
  "runNode reports unconfirmed closure without waiting forever",
  { timeout: 4000 },
  async (t) => {
    const child = new EventEmitter();
    Object.assign(child, { pid: 12346, exitCode: null, signalCode: null });
    child.kill = () => false;
    let unreferenced = false;
    child.unref = () => {
      unreferenced = true;
    };
    t.mock.method(require("node:child_process"), "spawn", () => child);
    const setupPath = require.resolve("../integration/setup");
    const cachedSetup = require.cache[setupPath];
    delete require.cache[setupPath];
    let isolatedUtils;
    try {
      isolatedUtils = require(setupPath).TestUtils;
    } finally {
      require.cache[setupPath] = cachedSetup;
    }
    await assert.rejects(
      isolatedUtils.runNode("node", [], process.cwd(), process.env, {
        timeoutMs: 20,
      }),
      /closure not confirmed after SIGKILL; termination error: SIGKILL could not be sent/i,
    );
    assert.equal(unreferenced, true);
  },
);

if (process.platform !== "win32") {
  test(
    "runNode escalates if a POSIX child ignores SIGTERM",
    { timeout: 5000 },
    async () => {
      const started = Date.now();
      await assert.rejects(
        TestUtils.runNode(
          process.execPath,
          ["-e", "process.on('SIGTERM', () => {}); setTimeout(() => {}, 4000)"],
          process.cwd(),
          process.env,
          { timeoutMs: 600 },
        ),
        /timed out after 600 ms; child closed/i,
      );
      const elapsed = Date.now() - started;
      assert.ok(
        elapsed >= 1000 && elapsed < 3000,
        `expected escalation after SIGTERM grace, got ${elapsed} ms`,
      );
    },
  );
}
