"use strict";
/** Controlled discovery/failure contracts. Synthetic Python files never run. */
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), os = require("node:os");
const runner = require("./run-certops-collector-tests");
test("collector discovery includes original suite, restricts file names and propagates failed children", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-collector-discovery-")), directory = path.join(root, "scripts"); fs.mkdirSync(directory);
  const names = ["certops-release-collector.test.py", "certops-arm64-collector.test.py", "certops-unrelated.test.py", "other-collector.test.py", "certops-collector.test.py"];
  try {
    for (const file of names) fs.writeFileSync(path.join(directory, file), "# inert controlled file\n");
    const expected = ["scripts/certops-arm64-collector.test.py", "scripts/certops-release-collector.test.py"];
    assert.deepEqual(runner.discover(root), expected); const calls = [];
    assert.deepEqual(runner.main({ root, now: () => 100, run: (command, args, options) => { calls.push({ command, args, options }); return { status: 0 }; } }), expected);
    assert.equal(calls.length, 2); assert.equal(calls[0].options.timeout, 180000); assert.equal(calls[0].options.cwd, root); assert.deepEqual(calls[1].args, [expected[1]]);
    for (const result of [{ status: 1 }, { status: null, error: new Error("controlled timeout") }, { status: null, signal: "SIGTERM" }]) assert.throws(() => runner.main({ root, run: () => result }));
    let clockCalls = 0; assert.throws(() => runner.main({ root, now: () => clockCalls++ ? 180001 : 0, run: () => { throw new Error("Must not run after deadline"); } }));
    for(let index=0;index<runner.MAX_COLLECTOR_MODULES-2;index++){const name=`certops-bound-${index}-collector.test.py`;names.push(name);fs.writeFileSync(path.join(directory,name),"# inert bounded inventory\n");}
    assert.equal(runner.discover(root).length, runner.MAX_COLLECTOR_MODULES);
    const overflow="certops-overflow-collector.test.py";names.push(overflow);fs.writeFileSync(path.join(directory,overflow),"# inert overflow\n");
    assert.throws(()=>runner.discover(root),/exceeds reviewed bound/);
    fs.rmSync(path.join(directory,overflow));
    for(const name of names.filter(value=>value.startsWith("certops-bound-")))fs.rmSync(path.join(directory,name));
    fs.rmSync(path.join(directory, "certops-release-collector.test.py")); assert.throws(() => runner.discover(root), /Original release collector/);
  } finally {
    assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
    for (const file of names) fs.rmSync(path.join(directory, file), { force: true }); fs.rmdirSync(directory); fs.rmdirSync(root);
  }
});
