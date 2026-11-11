"use strict";
/** Supporting proof, generated native command and owned-public-marker controls only. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os"),
  vm = require("node:vm"),
  { createRequire } = require("node:module");
const h = require("../packages/agent/scripts/host/iis-public-only-fixture");
function actualCleanupPrefixes(root, fixture) {
  const espree = createRequire(
    require.resolve("../packages/agent/node_modules/eslint/package.json"),
  )("espree");
  for (const name of ["iis-fixture.js", "windows-host.test.js"]) {
    const source = fs.readFileSync(
        path.join(__dirname, "../packages/agent/scripts/host", name),
        "utf8",
      ),
      ast = espree.parse(source, {
        ecmaVersion: "latest",
        sourceType: "script",
        range: true,
      });
    let block;
    function visit(n) {
      if (!n || typeof n !== "object") return;
      if (
        name === "iis-fixture.js" &&
        n.type === "TryStatement" &&
        n.finalizer &&
        source
          .slice(...n.finalizer.range)
          .includes("Preserve certificate keys still borrowed")
      )
        block = n.finalizer;
      if (
        name === "windows-host.test.js" &&
        n.type === "CallExpression" &&
        n.arguments[0]?.value === "windows-host-cleanup"
      )
        block = n.arguments[1].body;
      for (const c of Object.values(n))
        if (Array.isArray(c)) c.forEach(visit);
        else if (c && typeof c === "object") visit(c);
    }
    visit(ast);
    assert.ok(block);
    const boundary = block.body.find((n) =>
      name === "iis-fixture.js"
        ? n.type === "ForStatement"
        : n.type === "VariableDeclaration",
    );
    assert.ok(boundary);
    const body =
      source.slice(block.range[0] + 1, boundary.range[0]) + ";mutation();";
    let changed = false;
    const run = new Function("require", "workDir", "mutation", body);
    assert.throws(() =>
      run(
        (id) =>
          id === "./iis-public-only-fixture"
            ? fixture
            : { assertCleanupSafe() {} },
        root,
        () => {
          changed = true;
        },
      ),
    );
    assert.equal(
      changed,
      false,
      "Actual " + name + " cleanup cannot reach native/private mutations",
    );
  }
}
test("public-only association proof cannot qualify installed signed jobs or incomplete native restoration", () => {
  const p = {
    scope: h.SCOPE,
    refusalCode: "BIND_FAILED",
    installedSignedJobQualified: false,
    candidateFingerprint: "a".repeat(64),
    predecessorFingerprint: "b".repeat(64),
    ...Object.fromEntries(h.FLAGS.map((k) => [k, true])),
  };
  h.verifyProof(p);
  for (const k of Object.keys(p)) {
    const value = { ...p };
    delete value[k];
    assert.throws(() => h.verifyProof(value));
  }
  for (const patch of [
    { installedSignedJobQualified: true },
    { refusalCode: "success" },
    { candidateFingerprint: p.predecessorFingerprint },
    { unknown: true },
    ...h.FLAGS.map((k) => ({ [k]: false })),
  ])
    assert.throws(() => h.verifyProof({ ...p, ...patch }));
});
test("actual native command generation requires original key absence and never deletes a key", () => {
  const s = h.scripts({
    thumbprint: "A".repeat(40),
    der: Buffer.from("public").toString("base64"),
    containerName: "owned-container",
  });
  for (const script of Object.values(s)) {
    assert.match(script, /CngKey]::Exists/);
    assert.doesNotMatch(script, /-DeleteKey|.Delete\(/);
  }
  assert.match(s.create, /.Add\(\$c\)/);
  assert.match(s.observe, /HasPrivateKey/);
  assert.match(s.remove, /Remove-Item -LiteralPath \$p/);
  for (const patch of [
    { thumbprint: "';bad" },
    { containerName: "';bad" },
    { der: "';bad" },
  ])
    assert.throws(() =>
      h.scripts({
        thumbprint: "A".repeat(40),
        der: "cHVibGlj",
        containerName: "owned-container",
        ...patch,
      }),
    );
});
test("actual helper registers sticky ownership before parsing failure and removed marker cannot authorize cleanup", async () => {
  const root = fs.mkdtempSync(
      path.join(os.tmpdir(), "iis-public-only-control-"),
    ),
    file = path.resolve(
      __dirname,
      "../packages/agent/scripts/host/iis-public-only-fixture.js",
    ),
    module = { exports: {} },
    r = createRequire(file);
  vm.runInNewContext(
    fs.readFileSync(file, "utf8"),
    {
      module,
      exports: module.exports,
      process: { platform: "win32" },
      Buffer,
      require: r,
    },
    { filename: file },
  );
  try {
    const noNative = () => {
      throw Error("native callback must not run");
    };
    await assert.rejects(() =>
      module.exports.qualify({
        workDir: root,
        certificate: { der: "invalid" },
        predecessor: { der: "invalid" },
        containerName: "owned",
        binding: {},
        powershell: noNative,
        readPrimary: noNative,
        assertPrimaryTls: noNative,
        assertSibling: noNative,
      }),
    );
    assert.throws(() => module.exports.assertCleanupSafe(root));
    fs.unlinkSync(path.join(root, ".iis-public-only-pending.json"));
    assert.throws(() => module.exports.assertCleanupSafe(root));
    actualCleanupPrefixes(root, module.exports);
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});

test("actual bounded original-marker reader refuses growth and same-byte pathname replacement", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "iis-public-marker-")),
    file = path.join(root, "marker"),
    parked = path.join(root, "original"),
    bytes = Buffer.from("public-owned-marker");
  try {
    fs.writeFileSync(file, bytes, { flag: "wx" });
    const stat = fs.lstatSync(file, { bigint: true });
    h.assertOriginalMarker(file, stat, bytes);
    fs.appendFileSync(file, "foreign");
    assert.throws(() => h.assertOriginalMarker(file, stat, bytes));
    fs.writeFileSync(file, bytes);
    h.assertOriginalMarker(file, stat, bytes);
    fs.renameSync(file, parked);
    fs.writeFileSync(file, bytes, { flag: "wx" });
    assert.throws(() => h.assertOriginalMarker(file, stat, bytes));
    assert.ok(fs.readFileSync(file).equals(bytes));
    fs.unlinkSync(file);
    fs.renameSync(parked, file);
    h.assertOriginalMarker(file, stat, bytes);
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});
