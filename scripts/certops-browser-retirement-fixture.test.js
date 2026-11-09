"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { endpointConfiguration } = require("../tests/e2e/helpers/certops-browser-retirement-fixture");

test("retirement endpoint uses loopback unless the disposable Docker bridge is selected", () => {
  assert.deepEqual(endpointConfiguration({}), { bind: "127.0.0.1", monitorHost: "127.0.0.1" });
  assert.throws(() => endpointConfiguration({ CERTOPS_BROWSER_RETIREMENT_DOCKER: "1" }), /disposable stack/);
  assert.deepEqual(endpointConfiguration({ CERTOPS_BROWSER_RETIREMENT_DOCKER: "1", CERTOPS_CSR_DISPOSABLE_STACK: "1" }), { bind: "0.0.0.0", monitorHost: "host.docker.internal" });
});
