"use strict";
/** Pure pinned-route and bounded stream checks; never launches a CA or TLS proxy. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const { Readable } = require("node:stream");
const h = require("../tests/e2e/helpers/certops-acme-transparent-proxy");
const request = (rawPath, method = "POST") => ({
  authority: "127.0.0.1:14443",
  expectedAuthority: "127.0.0.1:14443",
  method,
  rawPath,
  upstreamDirectory: "https://127.0.0.1:14000/dir",
});
test("pinned Pebble routes preserve exact signed authority and request path", () => {
  for (const [file, stage] of [
    ["/dir", "directory"],
    ["/nonce-plz", "other"],
    ["/sign-me-up", "account"],
    ["/order-plz", "new-order"],
    ["/finalize-order/abc_def-123", "finalize"],
    ["/authZ/abc", "authorization"],
    ["/my-order/abc", "order-observation"],
    ["/certZ/abc", "other"],
  ]) {
    const selected = h.route(request(file));
    assert.equal(selected.path, file);
    assert.equal(selected.host, "127.0.0.1:14443");
    assert.equal(selected.upstreamOrigin, "https://127.0.0.1:14000");
    assert.equal(selected.stage, stage);
  }
  assert.equal(h.route(request("/nonce-plz", "HEAD")).path, "/nonce-plz");
});
test("foreign authority, escaped paths and unpinned upstream cannot reach the CA", () => {
  for (const file of [
    "https://outside.test/order-plz",
    "//outside.test/order-plz",
    "/dir?url=http://outside",
    "/dir#fragment",
    "/%2e%2e/dir",
    "/my-order/../order-plz",
    "/my-order/%2fabc",
    "/my-order/a\\b",
    "/dir\n",
    "/roots/0",
    "/intermediate-keys/0",
  ])
    assert.throws(() => h.route(request(file)));
  for (const change of [
    { authority: "localhost:14443" },
    { expectedAuthority: "127.0.0.1:99999" },
    { method: "DELETE" },
    { upstreamDirectory: "https://outside.test:14000/dir" },
    { upstreamDirectory: "https://user:secret@127.0.0.1:14000/dir" },
    { upstreamDirectory: "http://127.0.0.1:14000/dir" },
  ])
    assert.throws(() => h.route({ ...request("/order-plz"), ...change }));
  assert.throws(() => h.route(request("/order-plz", "GET")));
});
test("bounded stream reader preserves original request bytes and rejects oversized payloads", async () => {
  const original = Buffer.from(
    '{"protected":"original","payload":"unchanged","signature":"unchanged"}',
  );
  assert.deepEqual(
    await h.readBounded(
      Readable.from([original.subarray(0, 15), original.subarray(15)]),
    ),
    original,
  );
  await assert.rejects(
    h.readBounded(Readable.from([Buffer.alloc(h.LIMIT), Buffer.from("x")])),
  );
});

test("finalization readiness binds the actual order and every one of its authorization URLs", () => {
  const observer = h.createOrderObserver({
    authority: request("/dir").authority,
    upstreamDirectory: request("/dir").upstreamDirectory,
  });
  const ids = [
    { type: "dns", value: "a.example.test" },
    { type: "dns", value: "*.a.example.test" },
  ];
  const order = (id) => ({
    finalize: `https://127.0.0.1:14443/finalize-order/${id}`,
    authorizations: [1, 2].map(
      (n) => `https://127.0.0.1:14443/authZ/${id}_${n}`,
    ),
    identifiers: ids,
  });
  observer.observe(h.route(request("/order-plz")), 201, order("one"));
  observer.observe(h.route(request("/order-plz")), 201, order("two"));
  for (const id of ["one_1", "one_2", "two_1"])
    observer.observe(h.route(request(`/authZ/${id}`)), 200, {
      status: "valid",
    });
  assert.equal(
    observer.refusal("/finalize-order/one").allAuthorizationsValid,
    true,
  );
  assert.equal(
    observer.refusal("/finalize-order/two").allAuthorizationsValid,
    false,
  );
  observer.observe(h.route(request("/authZ/two_99")), 200, { status: "valid" });
  assert.equal(
    observer.refusal("/finalize-order/two").allAuthorizationsValid,
    false,
  );
  assert.throws(() =>
    observer.observe(h.route(request("/order-plz")), 201, {
      ...order("two"),
      authorizations: order("one").authorizations,
    }),
  );
  assert.deepEqual(observer.refusal("/finalize-order/foreign"), {
    knownOrder: false,
  });
  assert.equal(
    observer.refusal("/finalize-order/one").identifiersSha256,
    h.identifiersDigest([...ids].reverse()),
  );
  assert.throws(() =>
    observer.observe(h.route(request("/order-plz")), 201, {
      ...order("foreign"),
      finalize: "https://outside.test/finalize-order/foreign",
    }),
  );
});
