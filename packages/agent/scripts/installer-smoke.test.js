"use strict";

/**
 * B9 installer smoke test: package the agent, extract it OUTSIDE the monorepo,
 * install production deps, and prove entrypoint imports resolve without any
 * monorepo-relative path layout.
 */

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const packageRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(packageRoot, "..", "..");

function npmCommand() {
  // On Windows, npm is a .cmd shim; shell:true is required for spawnSync.
  return "npm";
}

function runOrThrow(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    shell: process.platform === "win32",
    ...options,
  });
  if (result.error || result.status !== 0) {
    const detail = [
      `$ ${command} ${args.join(" ")}`,
      result.error ? String(result.error) : "",
      result.stdout || "",
      result.stderr || "",
    ].join("\n");
    throw new Error(
      `command failed (exit ${result.status}):\n${detail}`,
    );
  }
  return result;
}

describe("installer packaging smoke (B9)", () => {
  let stagingRoot;
  let extractedRoot;

  before(() => {
    stagingRoot = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-agent-pack-"));
    // Guarantees the extract dir is outside the monorepo tree.
    assert.equal(
      path.relative(repoRoot, stagingRoot).startsWith("..") ||
        path.isAbsolute(path.relative(repoRoot, stagingRoot)),
      true,
      `staging dir must be outside the monorepo: ${stagingRoot}`,
    );

    const pack = runOrThrow(
      npmCommand(),
      ["pack", "--pack-destination", stagingRoot],
      { cwd: packageRoot },
    );
    const tarballName = pack.stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .pop();
    assert.ok(tarballName && tarballName.endsWith(".tgz"), `npm pack produced no tarball: ${pack.stdout}`);

    const tarballPath = path.join(stagingRoot, tarballName);
    assert.ok(fs.existsSync(tarballPath), `missing packed tarball ${tarballPath}`);

    runOrThrow(
      process.platform === "win32" ? "tar.exe" : "tar",
      ["-xzf", tarballPath, "-C", stagingRoot],
    );
    extractedRoot = path.join(stagingRoot, "package");
    assert.ok(fs.existsSync(path.join(extractedRoot, "package.json")));
    assert.ok(fs.existsSync(path.join(extractedRoot, "src", "index.js")));

    // Production install in isolation. Agent currently has no runtime npm
    // deps; this still materializes node_modules and proves package.json is
    // installable outside the workspace.
    runOrThrow(
      npmCommand(),
      ["install", "--omit=dev", "--ignore-scripts"],
      { cwd: extractedRoot },
    );
  });

  after(() => {
    if (stagingRoot) {
      fs.rmSync(stagingRoot, { recursive: true, force: true });
    }
  });

  it("loads the agent entry module with only package-local resolution", () => {
    const probe = `
      const path = require('node:path');
      const modulePath = path.join(process.cwd(), 'src', 'index.js');
      const mod = require(modulePath);
      if (typeof mod.runAgent !== 'function') {
        throw new Error('runAgent export missing after isolated require');
      }
      // Touch modules that historically imported monorepo paths.
      require(path.join(process.cwd(), 'src', 'evidence', 'index.js'));
      require(path.join(process.cwd(), 'src', 'keys', 'index.js'));
      require(path.join(process.cwd(), 'src', 'logging', 'index.js'));
      require(path.join(process.cwd(), 'src', 'signing', 'index.js'));
      require(path.join(process.cwd(), 'src', 'protocol', 'index.js'));
      require(path.join(process.cwd(), 'src', 'discovery', 'index.js'));
      require(path.join(process.cwd(), 'src', 'config', 'index.js'));
      console.log('installer-smoke: imports-ok');
    `;
    const result = spawnSync(process.execPath, ["-e", probe], {
      cwd: extractedRoot,
      encoding: "utf8",
      env: { ...process.env, NODE_PATH: "" },
    });
    assert.equal(
      result.status,
      0,
      `isolated require failed:\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
    assert.match(result.stdout, /installer-smoke: imports-ok/);
  });

  it("does not ship monorepo-relative secretMaterial or log-scrub requires", () => {
    const evidence = fs.readFileSync(
      path.join(extractedRoot, "src", "evidence", "index.js"),
      "utf8",
    );
    assert.doesNotMatch(
      evidence,
      /require\s*\(\s*["'][^"']*apps\/api\/utils\/secretMaterial/,
    );
    assert.doesNotMatch(
      evidence,
      /require\s*\(\s*["']\.\.\/\.\.\/\.\.\/log-scrub\//,
    );
    assert.match(
      evidence,
      /require\s*\(\s*["']\.\.\/\.\.\/vendor\/log-scrub\/secret-material\.js["']\s*\)/,
    );
    assert.ok(
      fs.existsSync(
        path.join(extractedRoot, "vendor", "log-scrub", "secret-material.js"),
      ),
    );
    assert.ok(
      fs.existsSync(
        path.join(extractedRoot, "vendor", "contracts", "canonical-json.cjs"),
      ),
    );
  });
});
