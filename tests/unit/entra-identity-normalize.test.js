"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  decodeEntraGuestUpn,
  isEntraGuestUpn,
  normalizeEntraIdentityClaims,
} = require("../../apps/api/sso/entra-identity-normalize");

test("decodeEntraGuestUpn decodes B2B guest UPN to real email", () => {
  const guestUpn = "janedoe_example.com#EXT#@contoso.onmicrosoft.com";
  assert.equal(decodeEntraGuestUpn(guestUpn), "janedoe@example.com");
  assert.equal(isEntraGuestUpn(guestUpn), true);
});

test("decodeEntraGuestUpn returns null for normal email", () => {
  assert.equal(decodeEntraGuestUpn("user@example.com"), null);
  assert.equal(isEntraGuestUpn("user@example.com"), false);
});

test("normalizeEntraIdentityClaims decodes guest email from subjectId", () => {
  const guestUpn = "janedoe_example.com#EXT#@contoso.onmicrosoft.com";
  const result = normalizeEntraIdentityClaims({
    email: guestUpn,
    displayName: guestUpn,
    subjectId: guestUpn,
  });
  assert.equal(result.email, "janedoe@example.com");
  assert.equal(result.displayName, "janedoe");
});

test("normalizeEntraIdentityClaims prefers given and surname for display name", () => {
  const result = normalizeEntraIdentityClaims({
    email: "janedoe@example.com",
    displayName: "janedoe_example.com#EXT#@contoso.onmicrosoft.com",
    givenName: "Jane",
    surname: "Doe",
    subjectId: "janedoe_example.com#EXT#@contoso.onmicrosoft.com",
  });
  assert.equal(result.email, "janedoe@example.com");
  assert.equal(result.displayName, "Jane Doe");
});

test("normalizeEntraIdentityClaims keeps proper email and display name", () => {
  const result = normalizeEntraIdentityClaims({
    email: "user@example.com",
    displayName: "User Name",
    subjectId: "abc-123",
  });
  assert.equal(result.email, "user@example.com");
  assert.equal(result.displayName, "User Name");
});
