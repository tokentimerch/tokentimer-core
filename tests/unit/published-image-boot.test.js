"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.join(__dirname, "..", "..");
const {
  ROLES,
  workerBootFailure,
} = require("../../scripts/boot-published-images.js");

function readRepoFile(...parts) {
  return fs.readFileSync(path.join(repoRoot, ...parts), "utf8");
}

describe("published image boot probes", () => {
  it("accepts the expected PostgreSQL refusal but rejects unrelated startup failures", () => {
    const refused =
      "AggregateError [ECONNREFUSED] at /app/node_modules/pg-pool/index.js";
    assert.equal(workerBootFailure({ status: 1 }, refused), null);
    assert.equal(workerBootFailure({ status: 0 }, "completed"), null);
    for (const output of [
      "Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'pg' imported from worker.js",
      "Error: Cannot find module './missing'",
      "SyntaxError: Unexpected token",
      "ReferenceError: config is not defined",
      "TypeError: cannot read properties of undefined",
      "unrecognized fatal error",
      "ECONNREFUSED contacting the Docker daemon",
      refused + "\nReferenceError: shutdown is not defined",
    ]) {
      assert.ok(workerBootFailure({ status: 1 }, output), output);
    }
    assert.ok(workerBootFailure({ status: 0 }, "Error [ERR_MODULE_NOT_FOUND]"));
    assert.ok(
      workerBootFailure(
        { status: null, error: { code: "ETIMEDOUT" } },
        refused,
      ),
    );
    assert.ok(workerBootFailure({ status: null, signal: "SIGTERM" }, refused));
  });
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
    const dockerfile = readRepoFile(
      "deploy",
      "compose",
      "Dockerfile.dashboard",
    );
    assert.match(
      dockerfile,
      /COPY deploy\/compose\/nginx\.conf \/etc\/nginx\/nginx\.conf/,
    );
    assert.match(dockerfile, /ENTRYPOINT \["\/docker-entrypoint\.sh"\]/);
    assert.match(
      readRepoFile("deploy", "compose", "docker-entrypoint-dashboard.sh"),
      /exec nginx -g 'daemon off;'/,
    );
  });
});
