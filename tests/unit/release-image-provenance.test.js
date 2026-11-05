"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const workflow = fs.readFileSync(path.resolve(__dirname,"../../.github/workflows/release.yml"),"utf8");

function verifyPublisher(source) {
  const job=source.match(/^  build-and-push-docker:\r?\n([\s\S]*?)(?=^  [a-z][a-z0-9-]*:)/m)?.[1];
  assert.ok(job,"Shared Docker publication job absent");
  assert.deepEqual([...job.matchAll(/^\s+- component: (\S+)\s*$/gm)].map(match=>match[1]).sort(),["api","dashboard","k8s-controller","worker"]);
  assert.equal((source.match(/uses: docker\/build-push-action@/g)||[]).length,1,"Review provenance of every image publisher");
  const producer=job.indexOf("id: source_identity");
  const publish=job.indexOf("uses: docker/build-push-action@");
  assert.ok(producer>=0&&producer<publish,"Resolve checked-out source before publishing");
  const identity=job.slice(producer,publish);
  assert.match(identity,/REVISION="\$\(git rev-parse --verify HEAD\)"/);
  assert.match(identity,/EVENT_REVISION="\$\(git rev-parse --verify "\$\{GITHUB_SHA\}\^\{commit\}"\)"/);
  assert.match(identity,/test "\$REVISION" = "\$EVENT_REVISION"/);
  assert.match(identity,/printf 'revision=%s\\n' "\$REVISION" >> "\$GITHUB_OUTPUT"/);
  const publishing=job.slice(publish);
  assert.match(publishing,/file: \$\{\{ matrix\.dockerfile \}\}/);
  assert.match(publishing,/push: false/);
  assert.match(publishing,/org\.opencontainers\.image\.revision=\$\{\{ steps\.source_identity\.outputs\.revision \}\}/);
  assert.match(publishing,/org\.opencontainers\.image\.source=https:\/\/github\.com\/\$\{\{ github\.repository \}\}/);
}

test("all Core published image variants carry the checked-out source commit and repository",()=>{
  verifyPublisher(workflow);
});

test("publication guard rejects absent, hardcoded or prematurely published provenance",()=>{
  const identityStep=workflow.match(/^      - name: Resolve checked-out image source[\s\S]*?(?=^      - name: )/m)?.[0];
  assert.ok(identityStep);
  for(const changed of [
    workflow.replace(/\s+org\.opencontainers\.image\.revision=.*\r?\n/,"\n"),
    workflow.replace("org.opencontainers.image.revision=${{ steps.source_identity.outputs.revision }}","org.opencontainers.image.revision=0000000000000000000000000000000000000000"),
    workflow.replace("org.opencontainers.image.source=https://github.com/${{ github.repository }}","org.opencontainers.image.source=https://example.test/unrelated"),
    workflow.replace("id: source_identity","id: unbound_identity"),
    workflow.replace('test "$REVISION" = "$EVENT_REVISION"','echo "identity comparison omitted"'),
    workflow.replace(identityStep,"").replace("          cache-to: type=gha,mode=max",`          cache-to: type=gha,mode=max\n${identityStep}`),
    workflow+'\n  uncovered-publisher:\n    steps:\n      - uses: docker/build-push-action@unreviewed\n',
  ])assert.throws(()=>verifyPublisher(changed));
});
