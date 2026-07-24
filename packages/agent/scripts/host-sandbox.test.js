"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  validateAbsolutePath,
  buildSystemdOverride,
  buildPolkitRule,
  mapReloadService,
} = require("./host-sandbox.js");

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
