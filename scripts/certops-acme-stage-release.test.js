"use strict";
/** Offline native stack proof/source adversaries. No CA/client/agent runs. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const report = require("./certops-acme-stage-report"),
  helper = require("../tests/e2e/helpers/certops-acme-stage-faults");
const { verifyMatrix } = require("./certops-release-qualification"),
  fixture = require("./test-support/acme-stage-artifact.cjs");
const errors = (value) =>
  verifyMatrix([value], {
    candidateSha: fixture.CANDIDATE,
    specification: {
      schemaVersion: 1,
      slots: [
        require("../docs/certops/release-qualification-matrix.json").slots.find(
          (s) => s.suite === value.suite,
        ),
      ],
    },
  });
const main = (value) =>
  value.events.find((event) => event.name === report.JOURNEY);
test("five native ACME scopes require stage tests, closed causal proof and every critical source", () => {
  for (const scope of report.SCOPES)
    assert.deepEqual(errors(fixture.artifact(scope)), []);
  for (const flag of helper.FLAGS) {
    const value = fixture.artifact();
    delete main(value).nativeAcmeStageFaults[flag];
    assert.ok(errors(value).length);
  }
  for (const file of helper.REQUIRED_SOURCES) {
    const value = fixture.artifact();
    for (const event of value.events)
      event.fixtureSources.find((s) => s.file === file).sha256 = "f".repeat(64);
    assert.ok(errors(value).length);
  }
});
test("stage refusal cannot promote wrong clients, forwarded failures, unrelated orders or skipped native jobs", () => {
  for (const mutate of [
    (v) => delete main(v).nativeAcmeStageFaults,
    (v) => {
      main(v).nativeAcmeStageFaults.client = "acme.sh";
    },
    (v) => {
      main(v).nativeAcmeStageFaults.cases[1].forwardedFaultRequests = 1;
    },
    (v) => {
      main(v).nativeAcmeStageFaults.cases[1].certificateId =
        main(v).nativeAcmeStageFaults.cases[0].certificateId;
    },
    (v) => {
      main(v).nativeAcmeStageFaults.cases[1].identifiersSha256 = "b".repeat(64);
    },
    (v) => {
      main(v).nativeAcmeStageFaults.rawJws = "private";
    },
    (v) => {
      v.events.find((e) => e.name === helper.SCENARIOS[0]).skip = true;
    },
  ]) {
    const value = fixture.artifact();
    mutate(value);
    assert.ok(errors(value).length);
  }
});
test("reporter reads only bounded client-bound sidecars and fingerprints the full causal inventory", () => {
  const fs = require("node:fs"),
    os = require("node:os"),
    path = require("node:path");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "acme-stage-report-"));
  try {
    fs.mkdirSync(path.join(root, "qualification-results"));
    const file = path.join(
        root,
        "qualification-results",
        "acme-stage-faults-certbot.json",
      ),
      proof = require("./test-support/acme-stage-proof.cjs").proof();
    fs.writeFileSync(file, JSON.stringify(proof), { mode: 0o600 });
    assert.deepEqual(
      report.readProof(report.SCOPES[0], report.JOURNEY, root),
      proof,
    );
    assert.equal(
      report.readProof("agent-protocol-api-worker", report.JOURNEY, root),
      undefined,
    );
    fs.writeFileSync(file, JSON.stringify({ ...proof, client: "acme.sh" }));
    assert.throws(() =>
      report.readProof(report.SCOPES[0], report.JOURNEY, root),
    );
    fs.writeFileSync(file, Buffer.alloc(65537, 32));
    assert.throws(() =>
      report.readProof(report.SCOPES[0], report.JOURNEY, root),
    );
    const sources = require("./certops-stack-reporter").supplementalSources(
      report.SCOPES[0],
    );
    for (const name of helper.REQUIRED_SOURCES)
      assert.equal(
        sources.filter(
          (source) =>
            source.file === name && /^[a-f0-9]{64}$/.test(source.sha256),
        ).length,
        1,
      );
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});
