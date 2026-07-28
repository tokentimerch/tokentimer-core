"use strict";

/**
 * B9 installer smoke test: package the agent, extract it OUTSIDE the monorepo,
 * install production deps, and prove entrypoint imports resolve without any
 * monorepo-relative path layout.
 *
 * Also covers the actual install-agent.sh flow directly: that script never
 * runs npm/pnpm install at all (it tars this directory excluding
 * node_modules and swaps it into place), so a separate test below
 * re-extracts the same tarball with zero install step and boots the real
 * bin/tokentimer-agent.js entrypoint to catch missing-runtime-dependency
 * regressions the npm-install-based tests above cannot catch.
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

  it("boots with NO install step at all, matching install-agent.sh's tar-copy-only flow", () => {
    // install-agent.sh never runs npm/pnpm install; it stages this package
    // directory with `tar --exclude=./node_modules` and swaps it into place
    // (see scripts/install-agent.sh). Re-extract a FRESH copy of the same
    // tarball with no node_modules whatsoever and prove the real entrypoint
    // (bin/tokentimer-agent.js, not just src/index.js in isolation) starts
    // far enough to reach config loading, i.e. it never throws
    // MODULE_NOT_FOUND for a missing runtime dependency.
    const noInstallRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), "tokentimer-agent-noinstall-"),
    );
    const tarball = fs.readdirSync(stagingRoot).find((name) => name.endsWith(".tgz"));
    assert.ok(tarball, "no packed tarball found to re-extract");
    runOrThrow(
      process.platform === "win32" ? "tar.exe" : "tar",
      ["-xzf", path.join(stagingRoot, tarball), "-C", noInstallRoot],
    );
    const noInstallExtracted = path.join(noInstallRoot, "package");
    assert.ok(
      !fs.existsSync(path.join(noInstallExtracted, "node_modules")),
      "precondition: this extraction must have no node_modules, matching install-agent.sh",
    );

    // Run the actual bin entrypoint with a bogus config dir and a short-lived
    // abort signal: it should fail on config/network, never on require().
    const configDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "tokentimer-agent-noinstall-config-"),
    );
    try {
      const result = spawnSync(
        process.execPath,
        [path.join(noInstallExtracted, "bin", "tokentimer-agent.js")],
        {
          encoding: "utf8",
          timeout: 5000,
          env: {
            ...process.env,
            NODE_PATH: "",
            TOKENTIMER_AGENT_CONFIG_DIR: configDir,
          },
        },
      );
      const output = `${result.stdout || ""}\n${result.stderr || ""}`;
      assert.doesNotMatch(
        output,
        /MODULE_NOT_FOUND/,
        `agent entrypoint failed to resolve a require() with no node_modules present:\n${output}`,
      );
    } finally {
      fs.rmSync(configDir, { recursive: true, force: true });
    }
    fs.rmSync(noInstallRoot, { recursive: true, force: true });
  });
});
