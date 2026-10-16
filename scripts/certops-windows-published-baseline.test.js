"use strict";
/** Public asset provenance refusal checks. Synthetic metadata is not a release
 * signature or an executed Windows upgrade; actual archive inspection is separate. */
const test = require("node:test"), assert = require("node:assert/strict");
const { published, verifyReleaseMetadata } = require("./certops-windows-published-baseline");
function metadata() {
  return { id: published.releaseId, tag_name: published.tag, draft: false, prerelease: false,
    assets: [{ id: published.assetId, name: `tokentimer-agent-${published.version}.tgz`, size: published.size,
      digest: `sha256:${published.publishedArchiveSha256}`, browser_download_url: published.url }] };
}
test("Windows predecessor provenance requires the exact public release and immutable archive identity", () => {
  assert.equal(verifyReleaseMetadata(metadata()), true);
  for (const patch of [{ id: 1 }, { tag_name: "v0.17.2" }, { draft: true }, { prerelease: true }, { assets: [] }, { assets: null }]) assert.throws(() => verifyReleaseMetadata({ ...metadata(), ...patch }));
  for (const patch of [{ id: 1 }, { name: "other.tgz" }, { size: published.size + 1 }, { digest: "sha256:" + "0".repeat(64) }, { browser_download_url: "https://other.example.test/package.tgz" }]) {
    const value = metadata(); Object.assign(value.assets[0], patch); assert.throws(() => verifyReleaseMetadata(value));
  }
  const duplicate = metadata(); duplicate.assets.push({ ...duplicate.assets[0], id: 1 }); assert.throws(() => verifyReleaseMetadata(duplicate));
  for (const value of [undefined, null, [], true]) assert.throws(() => verifyReleaseMetadata(value));
  for (const field of Object.keys(metadata())) { const value = metadata(); delete value[field]; assert.throws(() => verifyReleaseMetadata(value)); }
  for (const field of Object.keys(metadata().assets[0])) { const value = metadata(); delete value.assets[0][field]; assert.throws(() => verifyReleaseMetadata(value)); }
});
