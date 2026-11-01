"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

test("default Helm ingress routes recipient confirmation and Twilio consent to the API", () => {
  const values = fs.readFileSync(path.join(__dirname, "../../deploy/helm/values.yaml"), "utf8");
  for (const expected of ["/verify/recipient", "/webhooks/twilio/whatsapp/inbound"]) {
    const block = values.split(/\r?\n\s*- path: /).find(entry => entry.startsWith(`${expected}\n`) || entry.startsWith(`${expected}\r\n`));
    assert.ok(block && /\n\s*service: api(?:\r?\n|$)/.test(block), expected);
  }
});
