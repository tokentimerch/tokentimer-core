"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const { browserFailure } = require("../tests/e2e/helpers/certops-adcs-browser-session");
test("browser failures retain the owned stage, source coordinate and HTTP status", () => {
  const error = new assert.AssertionError({ message: "private response", actual: 403, expected: 200 });
  error.stack = "AssertionError: private response\n at decide (C:\\private\\certops-adcs-browser-job-approval.js:321:9)";
  error.nativeBrowserStatus = 403;
  const failure = browserFailure(error, "approval-decision-response");
  assert.equal(failure.code, "NATIVE_BROWSER_ACTION_FAILED");
  assert.equal(failure.message, "Native AD CS browser session failed at approval-decision-response; AssertionError; certops-adcs-browser-job-approval.js:321; HTTP 403");
});
test("browser failures exclude credentials, DOM snapshots, arbitrary codes and paths", () => {
  const error = new Error("password=hunter2 Bearer secret; <input value='private'>");
  error.code = "PRIVATE_SECRET";
  error.stack = "Error: password=hunter2\n at login (C:\\private-user\\untrusted.js:12:9)";
  error.nativeBrowserStatus = "token";
  const failure = browserFailure(error, "https://private:password@example.test");
  assert.equal(failure.message, "Native AD CS browser session failed at browser-action; Error");
  assert.equal(failure.cause, undefined);
  assert.doesNotMatch(failure.stack, /hunter2|Bearer|private-user|input|example/);
});
