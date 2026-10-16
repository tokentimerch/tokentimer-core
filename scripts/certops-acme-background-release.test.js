"use strict";
/** Actual release/parser wiring controls use offline fixtures only. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path");
const fixture = require("./test-support/acme-stage-artifact.cjs"),
  h = require("./certops-acme-background-report"),
  helper = require("../tests/e2e/helpers/certops-acme-background-renewals"),
  { verifyMatrix } = require("./certops-release-qualification");
const matrix = require("../docs/certops/release-qualification-matrix.json");
function errors(value) {
  const slot = matrix.slots.find((row) => row.suite === value.suite);
  return verifyMatrix([value], {
    candidateSha: fixture.CANDIDATE,
    specification: { schemaVersion: 1, slots: [slot] },
  });
}
const main = (value) => value.events.find((event) => event.name === h.MAIN);
test("all five Linux slots require actual default-cron evidence and current source", () => {
  for (const scope of h.SCOPES) {
    const value = fixture.artifact(scope);
    assert.deepEqual(errors(value), []);
    delete main(value)[h.FIELD];
    assert.ok(errors(value).length);
  }
  const skipped = fixture.artifact();
  skipped.events.find((event) => event.name === helper.SCENARIO).skip = true;
  assert.ok(errors(skipped).length);
  const stale = fixture.artifact();
  stale.events[0].fixtureSources.find((row) =>
    row.file.endsWith("background-pidfd.py"),
  ).sha256 = "0".repeat(64);
  assert.ok(errors(stale).length);
});
test("background continuity cannot be spliced from another profile, leaf, key or job", () => {
  const value = fixture.artifact(),
    event = main(value),
    base = event[h.FIELD];
  assert.equal(
    h.verifyForScope(base, event.nativeAcmeKeyReuse, value.suite),
    true,
  );
  for (const patch of [
    { sourceProfileId: "99999999-9999-4999-8999-999999999999" },
    { fingerprints: ["d".repeat(64), "e".repeat(64), "f".repeat(64)] },
    { spkiFingerprints: ["1".repeat(64), "2".repeat(64), "3".repeat(64)] },
    { jobIds: [event.nativeAcmeKeyReuse.jobIds[0], base.jobIds[1]] },
    { client: "acme.sh" },
  ])
    assert.throws(() =>
      h.verifyForScope(
        { ...base, ...patch },
        event.nativeAcmeKeyReuse,
        value.suite,
      ),
    );
});
test("bounded sidecar reader binds both clients and excludes unrelated events", () => {
  const parent = path.resolve(__dirname, "../.build"),
    root = fs.mkdtempSync(path.join(parent, "acme-background-reader-"));
  fs.mkdirSync(path.join(root, "qualification-results"));
  try {
    for (const scope of h.SCOPES) {
      const client = scope.includes("acmesh") ? "acme.sh" : "certbot",
        file = path.join(
          root,
          "qualification-results",
          `acme-background-${client === "certbot" ? "certbot" : "acmesh"}.json`,
        ),
        proof = require("./test-support/acme-background-proof.cjs").proof(
          client,
        );
      fs.writeFileSync(file, JSON.stringify(proof));
      assert.deepEqual(h.readProof(scope, h.MAIN, root), proof);
      fs.writeFileSync(
        file,
        JSON.stringify({
          ...proof,
          client: client === "certbot" ? "acme.sh" : "certbot",
        }),
      );
      assert.throws(() => h.readProof(scope, h.MAIN, root));
    }
    assert.equal(h.readProof("foreign/../../secret", h.MAIN, root), undefined);
    assert.equal(h.readProof(h.SCOPES[0], "unrelated", root), undefined);
  } finally {
    for (const file of fs.readdirSync(path.join(root, "qualification-results")))
      fs.unlinkSync(path.join(root, "qualification-results", file));
    fs.rmdirSync(path.join(root, "qualification-results"));
    fs.rmdirSync(root);
  }
});
