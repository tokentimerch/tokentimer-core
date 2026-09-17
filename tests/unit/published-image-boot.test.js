"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.join(__dirname, "..", "..");
const { ROLES } = require("../../scripts/boot-published-images.js");

function readRepoFile(...parts) {
  return fs.readFileSync(path.join(repoRoot, ...parts), "utf8");
}

describe("published image boot probes", () => {
  it("covers every image the CI scan job builds", () => {
    assert.deepStrictEqual([...ROLES].sort(), [
      "api",
      "controller",
      "dashboard",
      "worker",
    ]);
  });

  it("matches the published API and controller CMD", () => {
    assert.match(
      readRepoFile("deploy", "compose", "Dockerfile.api"),
      /CMD \["node", "apps\/api\/index\.js"\]/,
    );
    assert.match(
      readRepoFile("apps", "k8s-controller", "Dockerfile"),
      /CMD \["node", "src\/index\.js"\]/,
    );
  });

  it("matches the published dashboard entrypoint and nginx config", () => {
    const dockerfile = readRepoFile("deploy", "compose", "Dockerfile.dashboard");
    assert.match(dockerfile, /COPY deploy\/compose\/nginx\.conf \/etc\/nginx\/nginx\.conf/);
    assert.match(dockerfile, /ENTRYPOINT \["\/docker-entrypoint\.sh"\]/);
    assert.match(
      readRepoFile("deploy", "compose", "docker-entrypoint-dashboard.sh"),
      /exec nginx -g 'daemon off;'/,
    );
  });
});
