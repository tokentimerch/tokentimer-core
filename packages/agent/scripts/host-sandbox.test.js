"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const {
  validateAbsolutePath,
  trustStoreWritePaths,
  isSystemTrustStorePath,
  isTrustStoreRecursiveAclPath,
  buildSystemdOverride,
  buildPolkitRule,
  planPolkitRule,
  parseExistingPolkitUnits,
  mapReloadService,
  assertPolkitJavascriptVersion,
} = require("./host-sandbox.js");

describe("reload authorization backend", () => {
  it("rejects legacy/local-authority and unrecognized versions instead of promising an ineffective grant", () => {
    assert.throws(() => assertPolkitJavascriptVersion("pkaction version 0.105"), /JavaScript/);
    assert.throws(() => assertPolkitJavascriptVersion("unknown"), /version/);
  });
  it("accepts JavaScript-rule versions including the current integer version scheme", () => {
    for (const version of ["pkaction version 0.106", "pkaction version 0.120", "pkaction version 124"]) {
      assert.doesNotThrow(() => assertPolkitJavascriptVersion(version));
    }
  });
});

describe("host-sandbox path validation", () => {
  it("accepts absolute concrete paths", () => {
    assert.equal(validateAbsolutePath("/etc/letsencrypt"), "/etc/letsencrypt");
    assert.equal(validateAbsolutePath("/etc/nginx/certs/"), "/etc/nginx/certs");
  });

  it("rejects relative, broad, and unsafe paths", () => {
    assert.throws(() => validateAbsolutePath("etc/ssl"), /absolute/);
    assert.throws(() => validateAbsolutePath("/"), /too broad/);
    assert.throws(() => validateAbsolutePath("/etc"), /concrete/);
    assert.throws(() => validateAbsolutePath("/etc/../ssl"), /normalized/);
    assert.throws(() => validateAbsolutePath("/tmp/evil;rm"), /disallowed/);
  });
});

describe("host-sandbox systemd override", () => {
  it("always includes the state dir and operator write paths", () => {
    const text = buildSystemdOverride({
      stateDir: "/opt/tokentimer-agent/state",
      writePaths: ["/etc/letsencrypt", "/etc/nginx/certs"],
    });
    assert.match(text, /\[Service\]/);
    assert.match(
      text,
      /ReadWritePaths=\/opt\/tokentimer-agent\/state \/etc\/letsencrypt \/etc\/nginx\/certs/,
    );
    assert.doesNotMatch(text, /ReadWritePaths=\/etc\b/);
  });

  it("deduplicates paths", () => {
    const text = buildSystemdOverride({
      stateDir: "/opt/tokentimer-agent/state",
      writePaths: ["/etc/ssl/certs", "/etc/ssl/certs"],
    });
    assert.equal(
      (text.match(/\/etc\/ssl\/certs/g) || []).length,
      1,
    );
  });
});

describe("host-sandbox trust-store paths", () => {
  it("returns Debian write paths without granting all of /etc", () => {
    const paths = trustStoreWritePaths("debian");
    assert.deepEqual(paths, [
      "/usr/local/share/ca-certificates",
      "/etc/ssl/certs",
    ]);
    assert.ok(paths.every((p) => p !== "/etc" && p !== "/usr"));
  });

  it("returns RHEL write paths without granting all of /etc", () => {
    const paths = trustStoreWritePaths("rhel");
    assert.deepEqual(paths, [
      "/etc/pki/ca-trust/source/anchors",
      "/etc/pki/ca-trust/extracted",
      "/etc/pki/tls/certs",
    ]);
    assert.ok(paths.every((p) => p !== "/etc" && !p.startsWith("/etc/pki/ca-trust/source/anchors/")));
  });

  it("rejects an unknown family", () => {
    assert.throws(() => trustStoreWritePaths("windows"), /debian or rhel/);
    assert.throws(() => trustStoreWritePaths(""), /debian or rhel/);
  });

  it("identifies OS-owned trust-store directories so the installer will not chown them", () => {
    assert.equal(isSystemTrustStorePath("/etc/ssl/certs"), true);
    assert.equal(isSystemTrustStorePath("/usr/local/share/ca-certificates/"), true);
    assert.equal(isSystemTrustStorePath("/etc/pki/ca-trust/source/anchors"), true);
    assert.equal(isSystemTrustStorePath("/etc/nginx/certs"), false);
    assert.equal(isSystemTrustStorePath("/etc/ssl/tokentimer"), false);
  });

  it("marks only RHEL extracted/ as needing a recursive ACL", () => {
    assert.equal(isTrustStoreRecursiveAclPath("/etc/pki/ca-trust/extracted"), true);
    assert.equal(isTrustStoreRecursiveAclPath("/etc/pki/ca-trust/source/anchors"), false);
    assert.equal(isTrustStoreRecursiveAclPath("/etc/ssl/certs"), false);
    assert.equal(isTrustStoreRecursiveAclPath("/usr/local/share/ca-certificates"), false);
  });
});

describe("host-sandbox polkit reload rules", () => {
  it("maps supported reload services to concrete units", () => {
    assert.equal(mapReloadService("nginx").unit, "nginx.service");
    assert.equal(mapReloadService("apache").unit, "apache2.service");
    assert.equal(mapReloadService("httpd").unit, "httpd.service");
    assert.equal(mapReloadService("haproxy").unit, "haproxy.service");
    assert.throws(() => mapReloadService("sshd"), /unsupported/);
  });

  it("emits a reload-only polkit rule for selected units", () => {
    const rule = buildPolkitRule({
      user: "tokentimer-agent",
      reloadServices: ["nginx", "haproxy"],
    });
    assert.match(rule, /tokentimer-agent/);
    assert.match(rule, /nginx\.service/);
    assert.match(rule, /haproxy\.service/);
    assert.match(rule, /verb !== "reload"/);
    assert.doesNotMatch(rule, /start|stop|restart/);
  });

  it("returns null when no reload services are configured", () => {
    assert.equal(
      buildPolkitRule({ user: "tokentimer-agent", reloadServices: [] }),
      null,
    );
  });
});

describe("host-sandbox polkit re-run behavior", () => {
  const user = "tokentimer-agent";
  const nginxRule = buildPolkitRule({ user, reloadServices: ["nginx"] });

  it("reads the units back out of a generated rule", () => {
    assert.deepEqual(parseExistingPolkitUnits(nginxRule), ["nginx.service"]);
    assert.equal(parseExistingPolkitUnits("polkit.addRule(function () {});"), null);
    assert.equal(parseExistingPolkitUnits(null), null);
  });

  it("merges a new service with the grants already on the host", () => {
    const plan = planPolkitRule({
      user,
      reloadServices: ["haproxy"],
      existingRuleText: nginxRule,
    });
    assert.match(plan.rule, /"nginx\.service", "haproxy\.service"/);
    assert.deepEqual(plan.added, ["haproxy.service"]);
    assert.deepEqual(plan.dropped, []);
  });

  it("does not duplicate a service that is already granted", () => {
    const plan = planPolkitRule({
      user,
      reloadServices: ["nginx"],
      existingRuleText: nginxRule,
    });
    assert.deepEqual(parseExistingPolkitUnits(plan.rule), ["nginx.service"]);
    assert.deepEqual(plan.added, []);
  });

  it("replace makes the requested list authoritative and reports what it drops", () => {
    const plan = planPolkitRule({
      user,
      reloadServices: ["haproxy"],
      existingRuleText: nginxRule,
      replace: true,
    });
    assert.deepEqual(parseExistingPolkitUnits(plan.rule), ["haproxy.service"]);
    assert.deepEqual(plan.dropped, ["nginx.service"]);
  });

  it("replace with no services removes the rule", () => {
    const plan = planPolkitRule({
      user,
      reloadServices: [],
      existingRuleText: nginxRule,
      replace: true,
    });
    assert.equal(plan.rule, null);
    assert.deepEqual(plan.dropped, ["nginx.service"]);
  });

  it("never carries a unit outside the allowlist forward", () => {
    const tampered = nginxRule.replace('"nginx.service"', '"nginx.service", "sshd.service"');
    const plan = planPolkitRule({
      user,
      reloadServices: ["haproxy"],
      existingRuleText: tampered,
    });
    assert.doesNotMatch(plan.rule, /sshd/);
    assert.deepEqual(plan.dropped, ["sshd.service"]);
  });

  it("flags an existing file that this installer did not write", () => {
    const plan = planPolkitRule({
      user,
      reloadServices: ["nginx"],
      existingRuleText: "polkit.addRule(function () { return polkit.Result.YES; });",
    });
    assert.equal(plan.unrecognizedExisting, true);
    assert.deepEqual(parseExistingPolkitUnits(plan.rule), ["nginx.service"]);
  });

  describe("CLI with --rule-file", () => {
    function runCli(args) {
      return spawnSync(process.execPath, [path.join(__dirname, "host-sandbox.js"), ...args], {
        encoding: "utf8",
      });
    }

    it("merges by default, warns on replace, and tolerates a missing file", () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-polkit-"));
      try {
        const ruleFile = path.join(dir, "50-tokentimer-agent.rules");
        fs.writeFileSync(ruleFile, nginxRule);

        const merged = runCli(["polkit", "--user", user, "--rule-file", ruleFile, "--reload-service", "haproxy"]);
        assert.equal(merged.status, 0);
        assert.deepEqual(parseExistingPolkitUnits(merged.stdout), ["nginx.service", "haproxy.service"]);
        assert.match(merged.stderr, /keeping existing reload grants: nginx\.service/);

        const replaced = runCli(["polkit", "--user", user, "--rule-file", ruleFile, "--replace", "--reload-service", "haproxy"]);
        assert.equal(replaced.status, 0);
        assert.deepEqual(parseExistingPolkitUnits(replaced.stdout), ["haproxy.service"]);
        assert.match(replaced.stderr, /WARNING: dropping reload grants no longer listed: nginx\.service/);

        const fresh = runCli(["polkit", "--user", user, "--rule-file", path.join(dir, "absent.rules"), "--reload-service", "nginx"]);
        assert.equal(fresh.status, 0);
        assert.deepEqual(parseExistingPolkitUnits(fresh.stdout), ["nginx.service"]);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });
});
