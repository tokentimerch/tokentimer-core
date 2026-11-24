"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFile, spawnSync } = require("node:child_process");
const { promisify } = require("node:util");
const { holdDestinationOwnership } = require("./ownership");

const directory = "deployment-destination-ownership";
const linuxOnly = { skip: process.platform !== "linux" };
const initial = {
  workspaceId: "00000000-0000-4000-8000-000000000001",
  jobId: "original-job",
  operation: {
    version: 1,
    ownerClaimId: "original-claim",
    operationId: "a".repeat(64),
    mutationDomainSha256: "b".repeat(64),
  },
};

function stateDirectory(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-destination-ownership-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function holdFiles(stateDir) {
  return fs.readdirSync(path.join(stateDir, directory)).map((file) => path.join(stateDir, directory, file));
}

test("destination hold storage is unavailable off Linux and leaves state untouched", {
  skip: process.platform === "linux",
}, (t) => {
  const stateDir = stateDirectory(t);
  assert.throws(() => holdDestinationOwnership({ ...initial, stateDir }), {
    code: "destination_execution_ownership_unavailable",
  });
  assert.deepEqual(fs.readdirSync(stateDir), []);
});

test("holds ownership across jobs and claims for a workspace's canonical mutation domain", linuxOnly, (t) => {
  const stateDir = stateDirectory(t);
  assert.equal(holdDestinationOwnership({ ...initial, stateDir }), true);
  const [file] = holdFiles(stateDir);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
  const held = fs.readFileSync(file, "utf8");
  assert.deepEqual(JSON.parse(held), {
    version: 1, workspaceId: initial.workspaceId, jobId: initial.jobId,
    ownerClaimId: initial.operation.ownerClaimId, operationId: initial.operation.operationId,
    mutationDomainSha256: initial.operation.mutationDomainSha256,
  });
  assert.equal(holdDestinationOwnership({
    ...initial, stateDir, jobId: "different-job",
    operation: { ...initial.operation, ownerClaimId: "another-claim", operationId: "c".repeat(64) },
  }), false);
  assert.equal(fs.readFileSync(file, "utf8"), held);
  assert.equal(holdDestinationOwnership({
    ...initial, stateDir, operation: { ...initial.operation, mutationDomainSha256: "d".repeat(64) },
  }), true);
  assert.equal(holdDestinationOwnership({
    ...initial, stateDir, workspaceId: "00000000-0000-4000-8000-000000000002",
  }), true);
  assert.equal(holdFiles(stateDir).length, 3);
});

test("concurrent processes have exactly one winner in the same mutation domain", linuxOnly, async (t) => {
  const stateDir = stateDirectory(t);
  const run = promisify(execFile);
  const code = [
    "const { holdDestinationOwnership } = require(process.argv[1]);",
    'process.stdout.write(holdDestinationOwnership(JSON.parse(process.argv[2])) ? "held" : "conflict");',
  ].join("\n");
  const start = (jobId) => run(process.execPath, ["-e", code, require.resolve("./ownership"),
    JSON.stringify({ ...initial, stateDir, jobId })], { timeout: 5000 });
  const concurrent = await Promise.all([start("concurrent-a"), start("concurrent-b")]);
  assert.deepEqual(concurrent.map(({ stdout }) => stdout).sort(), ["conflict", "held"]);
  assert.equal(holdFiles(stateDir).length, 1);
});

test("a process that dies holding a domain cannot revive ownership or overwrite the marker", linuxOnly, (t) => {
  const stateDir = stateDirectory(t);
  const input = JSON.stringify({ ...initial, stateDir });
  const code = [
    "const { holdDestinationOwnership } = require(process.argv[1]);",
    "if (!holdDestinationOwnership(JSON.parse(process.argv[2]))) process.exit(2);",
    'process.kill(process.pid, "SIGKILL");',
  ].join("\n");
  const child = spawnSync(process.execPath, ["-e", code, require.resolve("./ownership"), input], { timeout: 5000 });
  assert.equal(child.signal, "SIGKILL", child.stderr?.toString());
  const [held] = holdFiles(stateDir);
  assert.equal(holdDestinationOwnership({ ...initial, stateDir, jobId: "replacement-job" }), false);
  assert.equal(JSON.parse(fs.readFileSync(held, "utf8")).jobId, initial.jobId);
  fs.writeFileSync(held, "");
  assert.equal(holdDestinationOwnership({ ...initial, stateDir, jobId: "replacement-job" }), false);
  assert.equal(fs.statSync(held).size, 0);
});

test("a failed durability confirmation leaves the marker held", linuxOnly, (t) => {
  const stateDir = stateDirectory(t);
  const sync = fs.fsyncSync;
  let calls = 0;
  const mock = t.mock.method(fs, "fsyncSync", (fd) => {
    calls += 1;
    if (calls === 3) throw new Error("injected directory sync failure");
    sync(fd);
  });
  assert.throws(() => holdDestinationOwnership({ ...initial, stateDir }), /injected directory sync failure/);
  mock.mock.restore();
  assert.equal(holdDestinationOwnership({ ...initial, stateDir, jobId: "replacement-job" }), false);
  assert.equal(holdFiles(stateDir).length, 1);
});

test("refuses root, directory, or marker substitution during sync without unlinking the markers", linuxOnly, async (t) => {
  for (const substitution of ["root", "hold directory", "marker", "contents", "permissions"]) {
    await t.test(substitution, (subtest) => {
      const temporaryRoot = stateDirectory(subtest);
      const stateDir = path.join(temporaryRoot, "state");
      fs.mkdirSync(stateDir, { mode: 0o700 });
      const holdDirectory = path.join(stateDir, directory);
      const original = path.join(temporaryRoot, "original");
      const sync = fs.fsyncSync;
      let calls = 0;
      let marker;
      let originalMarker;
      subtest.mock.method(fs, "fsyncSync", (fd) => {
        sync(fd);
        calls += 1;
        if (calls !== 3) return;
        [marker] = holdFiles(stateDir);
        if (substitution === "root") {
          fs.renameSync(stateDir, original);
          fs.mkdirSync(stateDir, { mode: 0o700 });
          fs.mkdirSync(holdDirectory, { mode: 0o700 });
          originalMarker = path.join(original, directory, path.basename(marker));
        } else if (substitution === "hold directory") {
          fs.renameSync(holdDirectory, original);
          fs.mkdirSync(holdDirectory, { mode: 0o700 });
          originalMarker = path.join(original, path.basename(marker));
        } else if (substitution === "marker") {
          fs.renameSync(marker, original);
          originalMarker = original;
        } else if (substitution === "permissions") {
          fs.chmodSync(marker, 0o644);
        } else {
          const previous = fs.readFileSync(marker, "utf8");
          fs.writeFileSync(marker, previous.replace("original-job", "altered--job"));
        }
        // The substitute can have the exact owner, mode, and content.
        if (originalMarker) fs.copyFileSync(originalMarker, marker);
      });
      assert.throws(() => holdDestinationOwnership({ ...initial, stateDir }), {
        code: "destination_execution_ownership_unavailable",
      });
      assert(fs.existsSync(marker));
      if (originalMarker) assert(fs.existsSync(originalMarker));
    });
  }
});

test("refuses symlinked and nonprivate state directories", linuxOnly, (t) => {
  const stateDir = stateDirectory(t);
  const other = stateDirectory(t);
  const linked = path.join(stateDir, "symlink");
  fs.symlinkSync(other, linked);
  assert.throws(() => holdDestinationOwnership({ ...initial, stateDir: linked }));
  fs.symlinkSync(other, path.join(stateDir, directory));
  assert.throws(() => holdDestinationOwnership({ ...initial, stateDir }));
  fs.chmodSync(other, 0o750);
  assert.throws(() => holdDestinationOwnership({ ...initial, stateDir: other }), {
    code: "destination_execution_ownership_unavailable",
  });
  assert.deepEqual(fs.readdirSync(other), []);
});
