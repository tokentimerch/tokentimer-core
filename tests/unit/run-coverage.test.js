"use strict";

// Importing the mapping must not run the destructive coverage-directory reset.
// These controls exercise actual serialized V8 records consumed by c8.
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const { pathToFileURL, fileURLToPath } = require("node:url");
const { spawnSync } = require("node:child_process");
const { remapContainerCoverage, mergeContainerCoverage } = require("../../scripts/run-coverage");
const repo = path.resolve(__dirname, "../..");
test("importing coverage helpers neither resets directories nor exits its caller", () => {
  const source = `require('node:fs').rmSync=()=>{throw new Error('Unexpected coverage reset')};require(${JSON.stringify(path.join(repo, "scripts/run-coverage.js"))});process.stdout.write('import-ok');`;
  const result = spawnSync(process.execPath, ["-e", source], {
    encoding: "utf8", timeout: 10000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "import-ok");
});
function fixture(url) {
  return JSON.stringify({ result: [{ scriptId: "1", url, functions: [
    { functionName: "", ranges: [{ startOffset: 0, endOffset: 10, count: 1 }], isBlockCoverage: true },
  ] }], timestamp: 1 });
}
for (const component of ["api", "worker"]) {
  test(`serialized ${component} coverage maps to the real repository source URL`, () => {
    const relative = component === "api" ? "index.js" : "src/runner.js";
    const original = fixture(`file:///app/apps/${component}/${relative}`);
    const result = JSON.parse(remapContainerCoverage(original));
    assert.equal(fileURLToPath(result.result[0].url), path.join(repo, "apps", component, relative));
    assert.deepEqual(result.result[0].functions, JSON.parse(original).result[0].functions);
    assert.equal(result.timestamp, 1);
  });
}
test("coverage mapping safely encodes spaces, quotes and platform path separators", () => {
  const source = path.join(repo, ".build", 'coverage root with spaces "quoted" $&');
  const target = pathToFileURL(source + path.sep).href;
  const mapped = JSON.parse(remapContainerCoverage(fixture("file:///app/apps/api/index.js"), [
    ["file:///app/apps/api/", target],
  ]));
  assert.equal(fileURLToPath(mapped.result[0].url), path.join(source, "index.js"));
});
test("coverage mapping preserves unrelated builtin and local script records exactly", () => {
  for (const url of ["node:internal/test_runner/test", pathToFileURL(__filename).href]) {
    const original = fixture(url);
    assert.equal(remapContainerCoverage(original), original);
  }
});
test("actual worker-file merger maps imported API sources as well as worker sources", () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "coverage-worker-merge-"));
  const raw = path.join(temporary, "v8-worker-endpoint");
  const destination = path.join(temporary, "v8");
  fs.mkdirSync(raw);
  fs.mkdirSync(destination);
  const input = path.join(raw, "owned-coverage.json");
  const output = path.join(destination, "container-v8-worker-endpoint-owned-coverage.json");
  const value = { result: [
    ...JSON.parse(fixture("file:///app/apps/worker/src/runner.js")).result,
    ...JSON.parse(fixture("file:///app/apps/api/services/certops/monitorBridge.js")).result,
  ] };
  const bytes = JSON.stringify(value);
  fs.writeFileSync(input, bytes, { flag: "wx" });
  try {
    assert.equal(mergeContainerCoverage({ directories: [{ dir: raw,
      pathMap: [["file:///app/apps/worker/", pathToFileURL(path.join(repo, "apps/worker") + path.sep).href]],
    }], destination }), 1);
    const merged = JSON.parse(fs.readFileSync(output, "utf8"));
    assert.equal(fileURLToPath(merged.result[0].url), path.join(repo, "apps/worker/src/runner.js"));
    assert.equal(fileURLToPath(merged.result[1].url), path.join(repo, "apps/api/services/certops/monitorBridge.js"));
    assert.equal(fs.readFileSync(input, "utf8"), bytes, "Original raw coverage must remain unchanged");
  } finally {
    if (fs.existsSync(output)) fs.unlinkSync(output);
    fs.unlinkSync(input);
    fs.rmdirSync(raw);
    fs.rmdirSync(destination);
    fs.rmdirSync(temporary);
  }
});
