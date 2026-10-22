"use strict";

// Dry-run coverage for install-agent.sh. The installer is POSIX shell and
// only starts on Linux/macOS, so these skip elsewhere.

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const installer = path.join(__dirname, "install-agent.sh");
const supported = process.platform === "linux" || process.platform === "darwin";

function dryRun(extraArgs) {
  return spawnSync(
    "sh",
    [
      installer,
      "--dry-run",
      "--api-url",
      "https://cp.example.com",
      "--workspace-id",
      "ws-1",
      "--no-trust-store",
      ...extraArgs,
    ],
    { encoding: "utf8" },
  );
}

describe(
  "install-agent.sh polkit grants on re-run",
  { skip: !supported },
  () => {
    it("merges --reload-service with the rule already on the host by default", () => {
      const result = dryRun(["--reload-service", "nginx"]);
      assert.equal(result.status, 0, result.stderr);
      assert.match(
        result.stdout,
        /polkit --user tokentimer-agent --rule-file \S+ --reload-service nginx/,
      );
      assert.doesNotMatch(result.stdout, /--replace/);
    });

    it("only replaces when --replace-reload-services is passed", () => {
      const result = dryRun([
        "--replace-reload-services",
        "--reload-service",
        "haproxy",
      ]);
      assert.equal(result.status, 0, result.stderr);
      assert.match(
        result.stdout,
        /polkit --user tokentimer-agent --rule-file \S+ --replace --reload-service haproxy/,
      );
    });

    it("leaves an existing rule alone when no reload flags are given", () => {
      const result = dryRun([]);
      assert.equal(result.status, 0, result.stderr);
      assert.match(
        result.stdout,
        /no --reload-service set; leaving \S+ untouched/,
      );
    });

    it("removes the rule only on an explicit replace with no services", () => {
      const result = dryRun(["--replace-reload-services"]);
      assert.equal(result.status, 0, result.stderr);
      assert.match(
        result.stdout,
        /polkit --user tokentimer-agent --rule-file \S+ --replace$/m,
      );
    });
  },
);
