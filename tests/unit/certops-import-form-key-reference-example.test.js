"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const FORM_SOURCE_PATH = path.resolve(
  __dirname,
  "../../apps/dashboard/src/components/certops/ImportCertificateForm.jsx",
);

// ARC-07: UI placeholders, docs, fixtures, and mocks must contain no
// private-key path as keyReference. A prior placeholder read
// "agent-id:/etc/ssl/private/wildcard.key", which taught users to type a
// private-key file path into the one field the zero-custody design promises
// never becomes a leak vector.
describe("ImportCertificateForm keyReference example (C5 / ARC-07)", () => {
  const source = fs.readFileSync(FORM_SOURCE_PATH, "utf8");

  it("does not show a private-key-shaped filesystem path as the keyReference placeholder", () => {
    const placeholderMatch = source.match(/placeholder=(['"])(.*?)\1/s);
    assert.ok(placeholderMatch, "keyReference Textarea placeholder not found");
    const placeholder = placeholderMatch[2];

    assert.doesNotMatch(placeholder, /\.key\b/i);
    assert.doesNotMatch(placeholder, /private/i);
  });

  it("only demonstrates schemes the backend validator actually accepts", () => {
    const placeholderMatch = source.match(/placeholder=(['"])(.*?)\1/s);
    const placeholder = placeholderMatch[2];
    const schemeMatches = placeholder.match(/\b[a-z][a-z0-9+.-]*:/gi) || [];
    assert.ok(schemeMatches.length > 0, "placeholder should show at least one scheme example");
    for (const scheme of schemeMatches) {
      assert.match(scheme, /^(vault|pkcs11|token|object):$/i);
    }
  });
});
