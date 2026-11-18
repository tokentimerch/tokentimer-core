"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { retain } = require("./openbao-operator-evidence.cjs");

test("OpenBao cleanup still runs once when startup did not stage the package", async t => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "tt-openbao-partial-"));
  t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
  const project = "tt-wildcard-ux-qual-partial-test";
  const output = path.join(scratch, project);
  const ownerFile = path.join(scratch, "owned.json");
  fs.mkdirSync(output);
  const owner = { project, candidateSha: "a".repeat(40), archiveSha256: "b".repeat(64), producerRunId: "123" };
  fs.writeFileSync(ownerFile, JSON.stringify(owner));
  let cleanups = 0;
  await assert.rejects(retain({ output, ownerFile, project, sourceSha: "c".repeat(40), runId: "456" },
    async args => {
      assert.deepEqual(args, { output, ownerFile, owner, project });
      cleanups++;
    }), { code: "ENOENT" });
  assert.equal(cleanups, 1);
  assert.equal(fs.existsSync(path.join(output, "openbao-operator-final-package.json")), false);
});
