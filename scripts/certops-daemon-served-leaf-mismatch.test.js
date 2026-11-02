"use strict";
/** Supporting closed proof and benign file guards; no daemon/native TLS runs. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");
const h = require("./certops-daemon-served-leaf-mismatch");
function proof() {
  return {
    schemaVersion: 1,
    scope: h.SCOPE,
    service: "nginx",
    evidenceTransport: "read-only-local-recorder-not-signed-api",
    fingerprints: ["a", "b"].map((c) => c.repeat(64)),
    ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
  };
}
test("served-leaf mismatch requires actual native reload, mismatch refusal, rollback and trusted TLS", () => {
  for (const service of ["nginx", "apache", "haproxy"])
    assert.equal(h.verifyProof({ ...proof(), service }), true);
  for (const flag of h.FLAGS) {
    const value = proof();
    delete value[flag];
    assert.throws(() => h.verifyProof(value));
    assert.throws(() => h.verifyProof({ ...proof(), [flag]: false }));
  }
  for (const change of [
    { service: "mock" },
    { evidenceTransport: "signed-api" },
    { rawKey: "secret" },
    { fingerprints: ["a", "a"].map((c) => c.repeat(64)) },
  ])
    assert.throws(() => h.verifyProof({ ...proof(), ...change }));
});
test("unknown daemon recovery guard preserves files and snapshot distinguishes replacement semantics", () => {
  const root = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "daemon-rollback-proof-")),
  );
  try {
    const file = path.join(root, "public.txt");
    fs.writeFileSync(file, "original", { mode: 0o600 });
    const before = h.snapshot(file);
    h.assertSnapshot(file, before);
    const replacement = path.join(root, "replacement");
    fs.writeFileSync(replacement, "original", { mode: 0o600 });
    fs.renameSync(replacement, file);
    assert.throws(() => h.assertSnapshot(file, before));
    h.assertSnapshot(file, before, false);
    h.assertCleanupSafe(root);
    fs.writeFileSync(
      path.join(root, ".preserve-daemon-served-leaf-owned.json"),
      "owned",
    );
    assert.throws(() => h.assertCleanupSafe(root));
    assert.ok(fs.existsSync(file));
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});

test("owned alternate configuration preserves daemon syntax and exact key pairing", () => {
  const target = { certPath: "/owned/leaf.crt", keyPath: "/owned/private.key" };
  for (const service of ["nginx", "apache"]) {
    const configText = `certificate "${target.certPath}"; key "${target.keyPath}";`;
    const actual = h
      .alternateConfiguration({
        service,
        configText,
        target,
        staleCert: "/owned/old.crt",
        staleKey: "/owned/old.crt.key",
      })
      .toString();
    assert.equal(
      actual,
      'certificate "/owned/old.crt"; key "/owned/old.crt.key";',
    );
  }
  const haproxy = {
    certPath: "/owned/leaf.crt",
    keyPath: "/owned/leaf.crt.key",
  };
  assert.equal(
    h
      .alternateConfiguration({
        service: "haproxy",
        configText: "bind 127.0.0.1:8443 ssl crt /owned/leaf.crt",
        target: haproxy,
        staleCert: "/owned/old.crt",
        staleKey: "/owned/old.crt.key",
      })
      .toString(),
    "bind 127.0.0.1:8443 ssl crt /owned/old.crt",
  );
  assert.throws(() =>
    h.alternateConfiguration({
      service: "haproxy",
      configText: "crt /owned/leaf.crt",
      target,
      staleCert: "/owned/old.crt",
      staleKey: "/owned/old.crt.key",
    }),
  );
  assert.throws(() =>
    h.alternateConfiguration({
      service: "nginx",
      configText: "foreign configuration",
      target,
      staleCert: "/owned/old.crt",
      staleKey: "/owned/old.crt.key",
    }),
  );
});

test("retained configuration refuses a same-byte foreign pathname before mutation", () => {
  const root = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "daemon-config-fd-")),
  );
  const file = path.join(root, "config"),
    old = path.join(root, "original");
  const digest = (bytes) =>
    require("node:crypto").createHash("sha256").update(bytes).digest("hex");
  let handle;
  try {
    fs.writeFileSync(file, "original", { mode: 0o600 });
    handle = h.retainConfiguration(file);
    handle.replace(digest("original"), Buffer.from("owned alternate"));
    handle.replace(digest("owned alternate"), Buffer.from("original"));
    fs.renameSync(file, old);
    fs.writeFileSync(file, "original", { mode: 0o600 });
    assert.throws(() =>
      handle.replace(digest("original"), Buffer.from("must not write")),
    );
    assert.equal(fs.readFileSync(old, "utf8"), "original");
    assert.equal(fs.readFileSync(file, "utf8"), "original");
  } finally {
    handle?.close();
    fs.rmSync(root, { recursive: true });
  }
});

test("lost guard pathname never authorizes cleanup of unresolved native state", () => {
  const root = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "daemon-sticky-guard-")),
  );
  try {
    const guard = h.beginCleanupGuard(root, "nginx");
    const marker = fs
      .readdirSync(root)
      .find((name) => name.startsWith(".preserve-daemon-served-leaf-"));
    const original = path.join(root, marker),
      retained = path.join(root, "retained-original-marker");
    fs.renameSync(original, retained);
    assert.throws(
      () => h.assertCleanupSafe(root),
      /unresolved daemon served-leaf/,
    );
    assert.throws(() => guard.release());
    fs.renameSync(retained, original);
    guard.release();
    h.assertCleanupSafe(root);
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});

test("actual parent TLS observer settles only after its retained socket closes", async () => {
  const createRequire = require("node:module").createRequire;
  const parser = createRequire(
    require.resolve("../packages/agent/node_modules/eslint/package.json"),
  )("espree");
  const source = fs.readFileSync(
    path.join(__dirname, "certops-nginx-host.js"),
    "utf8",
  );
  const ast = parser.parse(source, {
    ecmaVersion: "latest",
    sourceType: "script",
    range: true,
  });
  const found = [];
  function visit(node) {
    if (!node || typeof node !== "object") return;
    if (node.type === "FunctionDeclaration" && node.id?.name === "observe")
      found.push(node);
    for (const [key, value] of Object.entries(node)) {
      if (key === "range") continue;
      if (Array.isArray(value)) value.forEach(visit);
      else if (value && typeof value === "object") visit(value);
    }
  }
  visit(ast);
  assert.equal(found.length, 1);
  for (const fail of [false, true]) {
    const socket = new (require("node:events").EventEmitter)();
    socket.getPeerCertificate = () => ({
      fingerprint256: "owned-public-fingerprint",
    });
    socket.end = () => {};
    socket.setTimeout = () => {};
    socket.destroy = (error) => socket.emit("error", error);
    let connected;
    const observe = new Function(
      "tls",
      "fs",
      "port",
      "target",
      "ca",
      source.slice(...found[0].range) + ";return observe;",
    )(
      {
        connect(_options, callback) {
          connected = callback;
          return socket;
        },
      },
      {
        readFileSync() {
          return Buffer.from("owned public CA");
        },
      },
      8443,
      { reference: "owned.example.test" },
      "/owned/public-ca",
    );
    let settled = false;
    const result = observe().then(
      (value) => {
        settled = true;
        return value;
      },
      (error) => {
        settled = true;
        return error;
      },
    );
    if (fail) socket.emit("error", new Error("controlled TLS failure"));
    else connected();
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(settled, false);
    socket.emit("close");
    const value = await result;
    if (fail) assert.match(value.message, /controlled TLS failure/);
    else assert.equal(value, "owned-public-fingerprint");
  }
});
