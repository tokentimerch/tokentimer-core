"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

for (const file of ["values.yaml", "examples/values-external-db.yaml", "examples/values-full-test.yaml"]) test(`${file} routes recipient confirmation and Twilio consent to the API`, () => {
  const values = fs.readFileSync(path.join(__dirname, "../../deploy/helm", file), "utf8");
  for (const expected of ["/verify/recipient", "/webhooks/twilio/whatsapp/inbound"]) {
    const block = values.split(/\r?\n\s*- path: /).find(entry => entry.startsWith(`${expected}\n`) || entry.startsWith(`${expected}\r\n`));
    assert.ok(block && /\n\s*service: api(?:\r?\n|$)/.test(block), expected);
  }
});
