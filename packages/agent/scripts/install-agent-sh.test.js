"use strict";

// Dry-run coverage for install-agent.sh. The installer is POSIX shell and
// only starts on Linux/macOS, so these skip elsewhere.

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const { spawnSync } = require("node:child_process");

const installer = path.join(__dirname, "install-agent.sh");
const supported = process.platform === "linux" || process.platform === "darwin";

function runInstaller(args, env = {}) {
  const result = spawnSync("sh", [installer, "--dry-run", ...args], {
    encoding: "utf8",
    timeout: 15_000,
    env: { ...process.env, TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: "", ...env },
  });
  assert.ifError(result.error);
  return result;
}

function dryRun(extraArgs, env = {}) {
  return runInstaller(
    ["--api-url", "https://cp.example.com", "--workspace-id", "ws-1", "--no-trust-store", ...extraArgs],
    env,
  );
}

describe(
  "install-agent.sh polkit grants on re-run",
  // skip-reason: platform - install-agent.sh is POSIX shell and only runs on Linux/macOS
  { skip: !supported },
  () => {
    it("refuses the legacy backend before claiming a reload rule was installed", () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-polkit-check-"));
      try {
        fs.writeFileSync(path.join(dir, "pkaction"), '#!/bin/sh\nprintf "pkaction version 0.105\\n"\n', { mode: 0o755 });
        const result = dryRun(["--reload-service", "nginx"], { PATH: `${dir}${path.delimiter}${process.env.PATH}` });
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /polkit JavaScript rules/);
        assert.doesNotMatch(result.stdout, /Installing agent package/);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
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

const installRoot = "/opt/tokentimer-agent";
const unitPath = "/etc/systemd/system/tokentimer-agent.service";
const dropInPath = `${unitPath}.d/override.conf`;
const polkitPath = "/etc/polkit-1/rules.d/50-tokentimer-agent.rules";

function fileSnapshot(filename) {
  try {
    const stat = fs.lstatSync(filename, { throwIfNoEntry: false });
    return stat ? [stat.ino, stat.mode, stat.size, stat.mtimeMs, stat.ctimeMs] : null;
  } catch (error) {
    // A dry run under the maintainer's unprivileged account cannot modify
    // entries it cannot traverse. Also snapshot the policy directory itself.
    if (error.code === "EACCES") return "inaccessible";
    throw error;
  }
}

function linuxHostSnapshot(writePath) {
  const user = spawnSync("getent", ["passwd", "tokentimer-agent"], { encoding: "utf8" });
  assert.ifError(user.error);
  assert.ok([0, 2].includes(user.status), user.stderr);
  const paths = [
    installRoot, `${installRoot}/app`, `${installRoot}/state`,
    `${installRoot}/state/config.json`, `${installRoot}/state/bootstrap.env`,
    unitPath, `${unitPath}.d`, dropInPath, path.dirname(polkitPath), polkitPath, writePath,
  ];
  return {
    user: user.stdout,
    files: Object.fromEntries(paths.map(filename => [filename, fileSnapshot(filename)])),
  };
}

describe(
  "install-agent.sh Linux systemd dry runs",
  // skip-reason: platform - validates Linux systemd paths and system account state
  { skip: process.platform !== "linux" },
  () => {
    it("previews installation and removal without changing files or the service account", t => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-agent-dry-run-"));
      t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
      const writePath = path.join(dir, "certificates");
      const unexpectedSystemctl = path.join(dir, "unexpected-systemctl");
      fs.writeFileSync(
        path.join(dir, "systemctl"),
        "#!/bin/sh\n[ \"$1\" = list-unit-files ] && exit 0\nprintf '%s\\n' \"$*\" >> \"$UNEXPECTED_SYSTEMCTL\"\nexit 1\n",
        { mode: 0o755 },
      );
      const env = {
        PATH: `${dir}${path.delimiter}${process.env.PATH}`,
        UNEXPECTED_SYSTEMCTL: unexpectedSystemctl,
      };
      const before = linuxHostSnapshot(writePath);

      const install = dryRun(["--write-path", writePath], env);
      assert.equal(install.status, 0, install.stderr);
      assert.ok(install.stdout.includes(`[dry-run] mkdir -p ${installRoot}/state`));
      assert.ok(install.stdout.includes(
        `[dry-run] write ${installRoot}/state/config.json (0600) with serverUrl=https://cp.example.com workspaceId=ws-1`,
      ));
      assert.ok(install.stdout.includes(`[dry-run] mkdir -p ${writePath}`));
      assert.ok(install.stdout.includes(`[dry-run]   ReadWritePaths=${installRoot}/state ${writePath}`));
      assert.ok(install.stdout.includes(`[dry-run] write ${dropInPath} from:`));
      assert.match(install.stdout, /\[dry-run\] systemctl restart tokentimer-agent\.service/);
      assert.deepEqual(linuxHostSnapshot(writePath), before);

      const uninstall = runInstaller(["--uninstall"], env);
      assert.equal(uninstall.status, 0, uninstall.stderr);
      assert.match(uninstall.stdout, /\[dry-run\] systemctl stop tokentimer-agent\.service/);
      assert.match(uninstall.stdout, /\[dry-run\] systemctl disable tokentimer-agent\.service/);
      assert.ok(uninstall.stdout.includes(`[dry-run] rm -f ${unitPath}`));
      assert.ok(uninstall.stdout.includes(`[dry-run] rm -f ${dropInPath}`));
      assert.ok(uninstall.stdout.includes(`[dry-run] rm -f ${polkitPath}`));
      assert.ok(uninstall.stdout.includes(`[dry-run] rm -rf ${installRoot}/app`));
      assert.ok(uninstall.stdout.includes(`  - ${installRoot}/state (agent credential, keys, replay store)`));
      assert.doesNotMatch(uninstall.stdout, /\[dry-run\] (?:userdel|deluser)\b/);
      assert.deepEqual(linuxHostSnapshot(writePath), before);
      assert.equal(fs.existsSync(unexpectedSystemctl), false);
    });

    it("fails closed on missing and invalid required arguments", () => {
      for (const [args, message] of [
        [["--workspace-id", "ws-1"], /--api-url is required/],
        [["--api-url", "https://cp.example.com"], /--workspace-id is required/],
        [["--api-url", "http://cp.example.com", "--workspace-id", "ws-1"], /--api-url was rejected/],
      ]) {
        const result = runInstaller(args);
        assert.equal(result.status, 1, result.stdout);
        assert.match(result.stderr, message);
        assert.doesNotMatch(result.stdout, /\[dry-run\] (?:mkdir|write|systemctl)\b/);
      }
    });
  },
);
