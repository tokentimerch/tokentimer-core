"use strict";
/** Test-only controller inside an already assigned native Job Object. Launches
 * the unmodified worker CLI, projects bounded lifecycle facts and requests its
 * real graceful stop over IPC. Raw worker logs and environment never persist. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { spawn } = require("node:child_process"),
  { pathToFileURL } = require("node:url"),
  {
    runnerEnvironment,
    observeRecord,
  } = require("./certops-adcs-worker-runner-child");
const directory = process.env.CERTOPS_WORKER_PROTOCOL_DIRECTORY,
  nonce = process.env.CERTOPS_WORKER_OWNERSHIP_NONCE,
  root = path.resolve(__dirname, "../../.."),
  entry = path.join(root, "apps/worker/src/runner.js");
assert.match(nonce, /^[a-f0-9]{32}$/);
assert.ok(path.isAbsolute(directory));
const owner = JSON.parse(
    fs.readFileSync(path.join(directory, "ownership.json"), "utf8"),
  ),
  bridge = path.join(directory, "stop-bridge.mjs"),
  bridgeUrl = pathToFileURL(bridge).href;
assert.equal(owner.nonce, nonce);
assert.equal(
  String(fs.statSync(directory, { bigint: true }).ino),
  owner.directoryId,
);
assert.equal(
  crypto.createHash("sha256").update(fs.readFileSync(bridge)).digest("hex"),
  owner.bridgeSha256,
);
const state = {
  failed: false,
  starts: 0,
  ticks: 0,
  finishes: 0,
  summaries: 0,
  created: 0,
  stops: 0,
  forwarded: false,
  nativeDrained: false,
};
const started = process.hrtime.bigint();
let bytes = 0,
  stopping = false,
  worker;
const buffers = { stdout: "", stderr: "" };
function owned() {
  assert.equal(fs.lstatSync(directory).isSymbolicLink(), false);
  assert.equal(
    String(fs.statSync(directory, { bigint: true }).ino),
    owner.directoryId,
  );
  assert.equal(
    fs.realpathSync(directory).toLowerCase(),
    path.resolve(directory).toLowerCase(),
  );
}
function save() {
  owned();
  const temporary = path.join(directory, `observed-${process.pid}.tmp`),
    target = path.join(directory, "observed.json");
  if (fs.existsSync(target))
    assert.equal(fs.lstatSync(target).isSymbolicLink(), false);
  fs.writeFileSync(
    temporary,
    JSON.stringify({
      nonce,
      controllerPid: process.pid,
      workerPid: worker.pid,
      state,
    }),
    { flag: "wx", mode: 0o600 },
  );
  fs.renameSync(temporary, target);
}
function data(name, chunk) {
  try {
    bytes += chunk.length;
    assert.ok(bytes <= 4 * 1024 * 1024);
    buffers[name] += chunk.toString("utf8");
    let index;
    while ((index = buffers[name].indexOf("\n")) >= 0) {
      assert.ok(index <= 65536);
      const line = buffers[name].slice(0, index).trim();
      buffers[name] = buffers[name].slice(index + 1);
      if (!line) continue;
      if (
        line ===
        "[env] no .env found; using local development defaults (see .env.example)"
      )
        continue;
      let value;
      try {
        value = JSON.parse(line);
      } catch {
        state.failed = true;
        continue;
      }
      observeRecord(
        state,
        value,
        Number(process.hrtime.bigint() - started) / 1e6,
      );
    }
    assert.ok(buffers[name].length <= 65536);
    save();
  } catch {
    state.failed = true;
    save();
  }
}
worker = spawn(process.execPath, ["--import", bridgeUrl, entry, "certops"], {
  cwd: root,
  env: runnerEnvironment(process.env, nonce),
  windowsHide: true,
  stdio: ["ignore", "pipe", "pipe", "ipc"],
});
worker.stdout.on("data", (chunk) => data("stdout", chunk));
worker.stderr.on("data", (chunk) => data("stderr", chunk));
worker.on("error", () => {
  state.failed = true;
  save();
});
worker.on("message", (message) => {
  try {
    assert.equal(message.nonce, nonce);
    assert.equal(message.pid, worker.pid);
    if (message.type === "certops-worker-bridge-ready") {
      assert.deepEqual(message.argv, [process.execPath, entry, "certops"]);
      assert.deepEqual(message.execArgv, ["--import", bridgeUrl]);
      state.bridgeReady = true;
    } else if (message.type === "certops-worker-stop-forwarded")
      state.forwarded = true;
    else state.failed = true;
    save();
  } catch {
    state.failed = true;
    save();
  }
});
const timer = setInterval(() => {
  try {
    owned();
    const command = path.join(directory, "graceful-stop");
    if (!stopping && fs.existsSync(command)) {
      assert.equal(fs.lstatSync(command).isSymbolicLink(), false);
      assert.equal(fs.readFileSync(command, "utf8"), nonce);
      stopping = true;
      worker.send({ type: "certops-worker-stop", nonce }, (error) => {
        if (error) {
          state.failed = true;
          save();
        }
      });
    }
  } catch {
    state.failed = true;
    save();
  }
}, 100);
worker.on("close", (code) => {
  clearInterval(timer);
  if (Object.values(buffers).some((buffer) => buffer.trim().length))
    state.failed = true;
  state.exitCode = code;
  save();
  process.exit(code === 0 && !state.failed ? 0 : 1);
});
