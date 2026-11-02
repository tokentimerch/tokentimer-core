"use strict";
/** Actual harness cleanup functions with benign public files and a recording
 * database stand-in. No service, certificate, key, CA or real DB is touched. */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const { createRequire } = require("node:module");
const journey = require("../tests/e2e/windows-real-journey");
test("original Windows root removal is required before outer database cleanup", async () => {
  const parent = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-windows-ownership-"),
  );
  const root = path.join(parent, "original"),
    moved = path.join(parent, "moved");
  assert.ok(
    [root, moved].every((file) =>
      path.resolve(file).startsWith(path.resolve(parent) + path.sep),
    ),
  );
  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, "public.txt"), "owned public fixture");
  const removeOriginal = journey.registerOwnedCleanupRoot(root);
  try {
    assert.throws(() => journey.assertAllCleanupSafe());
    const source = fs.readFileSync(
      path.resolve(__dirname, "../tests/e2e/certops-agent-e2e.test.js"),
      "utf8",
    );
    const agentRequire = createRequire(
      path.resolve(__dirname, "../packages/agent/package.json"),
    );
    const parser = createRequire(agentRequire.resolve("eslint"))("espree");
    const ast = parser.parse(source, {
      ecmaVersion: "latest",
      sourceType: "commonjs",
      range: true,
    });
    const fn = ast.body.find(
      (node) =>
        node.type === "FunctionDeclaration" &&
        node.id?.name === "cleanupSeededRows",
    );
    assert.ok(fn);
    let queries = 0;
    const cleanup = vm.runInNewContext(`(${source.slice(...fn.range)})`, {
      pool: {
        query: async () => {
          queries++;
          return { rows: [] };
        },
      },
      seeded: { workspaceId: "owned-workspace" },
      process: { env: { CERTOPS_REAL_WINDOWS_REQUIRED: "1" } },
      require: (name) => {
        assert.equal(name, "./windows-real-journey");
        return journey;
      },
    });
    await assert.rejects(() => cleanup());
    assert.equal(
      queries,
      0,
      "Unresolved native ownership must refuse the FIRST database deletion",
    );
    fs.renameSync(root, moved);
    assert.throws(
      () => removeOriginal(),
      "Missing original pathname cannot authorize cleanup",
    );
    fs.mkdirSync(root);
    fs.writeFileSync(path.join(root, "foreign.txt"), "foreign replacement");
    assert.throws(
      () => removeOriginal(),
      "Same-path foreign root must be preserved",
    );
    assert.equal(
      fs.readFileSync(path.join(root, "foreign.txt"), "utf8"),
      "foreign replacement",
    );
    assert.throws(() => journey.assertAllCleanupSafe());
    fs.rmSync(root, { recursive: true });
    fs.renameSync(moved, root);
    removeOriginal();
    journey.assertAllCleanupSafe();
    await cleanup();
    assert.ok(queries > 0);
  } finally {
    // Fixture paths are fixed children of the captured owned temporary parent.
    if (fs.existsSync(moved) && !fs.existsSync(root))
      fs.renameSync(moved, root);
    if (fs.existsSync(root)) {
      try {
        removeOriginal();
      } catch {}
    }
    fs.rmSync(parent, { recursive: true });
  }
});
