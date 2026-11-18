"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { retain } = require("./openbao-operator-evidence.cjs");
const { dispose } = require("../operator-ca-setup.cjs");

function partialStartup(t) {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "tt-openbao-partial-"));
  t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
  const project = "tt-wildcard-ux-qual-partial-test";
  const output = path.join(scratch, project);
  const ownerFile = path.join(scratch, "owned.json");
  fs.mkdirSync(output);
  const owner = { project, candidateSha: "a".repeat(40), archiveSha256: "b".repeat(64), producerRunId: "123" };
  fs.writeFileSync(ownerFile, JSON.stringify(owner));
  return { input: { output, ownerFile, project, sourceSha: "c".repeat(40), runId: "456" }, owner };
}

test("OpenBao cleanup verifies a partial startup without retaining absent qualification evidence", async t => {
  const { input, owner } = partialStartup(t);
  const { output, ownerFile, project } = input;
  const privateDirectory = output + "-operator-ca-private";
  fs.mkdirSync(path.join(privateDirectory, "bao"), { recursive: true });
  fs.writeFileSync(path.join(privateDirectory, "bao/transport.key"), "disposable temporary test material");
  let cleanups = 0;
  const retained = await retain(input,
    async args => {
      assert.deepEqual(args, { output, ownerFile, owner, project });
      cleanups++;
      dispose(privateDirectory, path.join(output, "operator-ca"));
    });
  assert.equal(retained, null);
  assert.equal(cleanups, 1);
  assert.equal(fs.existsSync(privateDirectory), false);
  assert.equal(fs.existsSync(path.join(output, "openbao-operator-final-package.json")), false);
});

test("OpenBao partial cleanup refuses pre-existing evidence and propagates cleanup errors", async t => {
  const { input } = partialStartup(t);
  const finalFile = path.join(input.output, "openbao-operator-final-package.json");
  fs.writeFileSync(finalFile, "{}");
  let cleanups = 0;
  await assert.rejects(retain(input, async () => { cleanups++; }), /Pre-existing final evidence refused/);
  assert.equal(cleanups, 1);
  fs.unlinkSync(finalFile);
  await assert.rejects(retain(input, async () => { throw new Error("test cleanup failure"); }), /test cleanup failure/);
  assert.equal(fs.existsSync(finalFile), false);
});

test("OpenBao rejects an observation without its exact staged archive and still cleans once", async t => {
  const { input } = partialStartup(t);
  fs.writeFileSync(path.join(input.output, "openbao-operator-observation.json"), "{}");
  let cleanups = 0;
  await assert.rejects(retain(input, async () => { cleanups++; }), { code: "ENOENT" });
  assert.equal(cleanups, 1);
  assert.equal(fs.existsSync(path.join(input.output, "openbao-operator-final-package.json")), false);
});
