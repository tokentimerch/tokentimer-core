"use strict";
const { test } = require("node:test"), assert = require("node:assert/strict");
const { check } = require("./sink-isolation.cjs");
test("isolated sink preflight rejects shared roots and shared UID", () => {
  const dir = (uid, mode=0o700) => ({uid,mode,isDirectory:()=>true,isSymbolicLink:()=>false});
  const file = uid => ({uid,mode:0o600,isFile:()=>true,isSymbolicLink:()=>false});
  const io={ lstatSync:p=>p.endsWith("token.json")?file(p.startsWith("/issuer")?10001:10002):dir(p==="/issuer"?10001:10002),
    statSync:p=>dir(p==="/issuer"?10001:10002), realpathSync:p=>p };
  assert.equal(check({issuer:{directory:"/issuer"},consumer:{directory:"/consumer"}},io,"linux").status,"local-check-only");
  assert.throws(()=>check({issuer:{directory:"/issuer"},consumer:{directory:"/issuer"}},io,"linux"));
  assert.throws(()=>check({issuer:{directory:"/issuer"},consumer:{directory:"/consumer"}},{...io,statSync:()=>dir(10001)},"linux"),/owner mismatch/);
});
