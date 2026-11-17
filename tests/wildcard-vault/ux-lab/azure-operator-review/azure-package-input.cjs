"use strict";
// Caller supplies the producer-authenticated archive and digest. No builder.
const assert = require("node:assert/strict"), path = require("node:path"), fs = require("node:fs");
const { suppliedArchive } = require("./azure-ux-adapter.cjs");
function create({ archivePath, archiveSha256, candidateSha, expectedCandidateSha, root, extractVerified, verifyInstalled }) {
  const selected = suppliedArchive({ archivePath, archiveSha256, candidateSha, expectedCandidateSha });
  assert.equal(typeof extractVerified, "function"); assert.equal(typeof verifyInstalled, "function");
  const roles = new Map();
  return {
    prepare(name) {
      assert.ok(["issuer", "nginx", "haproxy"].includes(name), "unknown agent role");
      assert.equal(roles.has(name), false, "role package already prepared");
      const destination = path.join(root, name);
      assert.equal(fs.existsSync(destination), false, "fresh role directory required");
      const extracted = extractVerified({ tarball: selected.archivePath, expectedSha256: selected.archiveSha256, destination });
      roles.set(name, extracted);
      return extracted.root;
    },
    verify(name) { const item = roles.get(name); assert.ok(item, "role package absent"); verifyInstalled(item.files, item.root); },
    selected: { archiveSha256: selected.archiveSha256, candidateSha: selected.candidateSha },
  };
}
module.exports = { create };
