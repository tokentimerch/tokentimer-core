"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const workflow = fs.readFileSync(path.resolve(__dirname, "../../.github/workflows/release.yml"), "utf8");

function verifyGate(source) {
  const job = source.match(/^  build-and-push-docker:\r?\n([\s\S]*?)(?=^  [a-z][a-z0-9-]*:)/m)?.[1];
  assert.ok(job);
  const build = job.indexOf("uses: docker/build-push-action@");
  const scan = job.indexOf("- name: Scan the release architecture");
  const publish = job.indexOf("- name: Publish the scanned OCI archive");
  assert.ok(build >= 0 && build < scan && scan < publish, "Build, scan and publish must be ordered");
  assert.doesNotMatch(job, /push: true|continue-on-error: true|load: true/);
  assert.match(job.slice(build, scan), /push: false/);
  assert.match(job.slice(build, scan), /platforms: linux\/amd64\r?\n/);
  assert.doesNotMatch(job, /setup-qemu-action|linux\/arm64/);
  assert.match(job.slice(build, scan), /outputs: type=oci,dest=\$\{\{ runner\.temp \}\}\/release-image\.tar/);
  const scanning = job.slice(scan, publish);
  assert.match(scanning, /for architecture in amd64; do/);
  assert.match(scanning, /copy --override-os linux --override-arch "\$architecture"[\s\S]*?--preserve-digests/);
  assert.match(scanning, /oci-archive:\/release\/release-image\.tar[\s\S]*?"oci-archive:\/release\/release-image-\$architecture\.tar"/);
  assert.match(scanning, /test "\$\(cat "\$RUNNER_TEMP\/release-image-\$architecture\.digest"\)" = "\$EXPECTED_DIGEST"/);
  assert.match(scanning, /grype" "oci-archive:\$RUNNER_TEMP\/release-image-\$architecture\.tar"/);
  assert.match(scanning, /--platform "linux\/\$architecture" --fail-on high --only-fixed/);
  assert.match(scanning, /test "\$SCAN_FAILED" -eq 0/);
  assert.match(scanning, /\.source\.target\.manifestDigest == \$digest and \.descriptor\.name == "grype"/);
  assert.match(scanning, /\.architecture == \$architecture and \.os == "linux"/);
  assert.match(scanning, /\.config\.Labels\["org\.opencontainers\.image\.revision"\] == \$revision/);
  const publishing = job.slice(publish);
  assert.match(publishing, /sha256sum --check "\$RUNNER_TEMP\/release-image\.tar\.sha256"/);
  assert.match(publishing, /copy --all --preserve-digests/);
  assert.match(publishing, /oci-archive:\/release\/release-image\.tar "docker:\/\/\$IMAGE"/);
  assert.match(publishing, /test "\$\(cat "\$RUNNER_TEMP\/release-image\.digest"\)" = "\$EXPECTED_DIGEST"/);
  assert.match(publishing, /test "\$ACTUAL_DIGEST" = "\$\{EXPECTED_DIGEST#sha256:\}"/);
}

test("release images scan the exact published architecture without expanding platform support", () => {
  verifyGate(workflow);
});

test("release scan gate rejects early publication, changed platforms or content and soft failures", () => {
  const scanStep = workflow.match(/^      - name: Scan the release architecture[\s\S]*?(?=^      - name: )/m)?.[0];
  // The positive test reports an absent gate; keep mutation cases focused once it exists.
  assert.ok(scanStep, "Architecture scan step absent");
  for (const changed of [
    workflow.replace("push: false", "push: true"),
    workflow.replace("platforms: linux/amd64", "platforms: linux/amd64,linux/arm64"),
    workflow.replace("for architecture in amd64; do", "for architecture in arm64; do"),
    workflow.replace("copy --all --preserve-digests", "copy --preserve-digests"),
    workflow.replace("copy --all --preserve-digests", "copy --all"),
    workflow.replace('test "$SCAN_FAILED" -eq 0', 'echo "$SCAN_FAILED"'),
    workflow.replace('.source.target.manifestDigest == $digest', 'true'),
    workflow.replace('sha256sum --check "$RUNNER_TEMP/release-image.tar.sha256"', "echo unchecked"),
    workflow.replace('grype" "oci-archive:$RUNNER_TEMP/release-image-$architecture.tar"', 'grype" "oci-archive:$RUNNER_TEMP/unrelated.tar"'),
    workflow.replace(scanStep, "").replace("      - name: Publish the scanned OCI archive", `      - name: Publish the scanned OCI archive\n${scanStep}`),
  ]) assert.throws(() => verifyGate(changed));
});
