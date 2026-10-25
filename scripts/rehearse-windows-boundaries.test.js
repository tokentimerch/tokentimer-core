"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { parseArgs, assertOwnedState, assertArchivePaths, assertOwnedObservation } = require("./rehearse-windows-boundaries");

test("Windows boundary smoke requires independently supplied archive and source identities", () => {
  const args = ["--archive", "candidate.tgz", "--archive-sha256", "a".repeat(64), "--source-sha", "b".repeat(40), "--out", "receipt.json"];
  assert.equal(parseArgs(args)["archive-sha256"], "a".repeat(64));
  assert.throws(() => parseArgs(args.slice(0, 2)), /Missing/);
  assert.throws(() => parseArgs([...args, "--archive", "other.tgz"]));
  const invalid = [...args]; invalid[3] = "not-a-checksum";
  assert.throws(() => parseArgs(invalid));
});

test("native cleanup identity cannot escape its unique site, pool, store or directory", () => {
  const owner = "tt-core-delta-" + "a".repeat(24);
  const directory = path.resolve(owner + "-random");
  const state = { owner, directory, site: owner, pool: owner, store: "TokenTimerSmoke" + "a".repeat(24), port: 54321, certificates: [] };
  assertOwnedState(state, directory);
  for (const [key, value] of [["site", "Default Web Site"], ["pool", "DefaultAppPool"], ["store", "Root"], ["directory", path.dirname(directory)], ["port", 443], ["owner", "tt-core-delta-wrong"]]) {
    assert.throws(() => assertOwnedState({ ...state, [key]: value }, directory));
  }
  assert.throws(() => assertOwnedState({ ...state, certificates: [{ kind: "foreign" }] }, directory));
});

test("archive extraction refuses traversal, links and nonpackage paths", () => {
  assertArchivePaths(["package/bin/agent.js"], ["-rwxr-xr-x entry"]);
  for (const name of ["../outside", "package/../../outside", "package/..\\outside", "other/file", "package/control\nfile"]) {
    assert.throws(() => assertArchivePaths([name], ["-rw-r--r-- entry"]));
  }
  for (const mode of ["lrwxrwxrwx link", "hrw-r--r-- hardlink"]) assert.throws(() => assertArchivePaths(["package/bin/agent.js"], [mode]));
});

test("a store query only passes for the exact SAN-only public certificate observation", () => {
  const expected = { fingerprint: "a".repeat(64), store: "TokenTimerSmoke" + "a".repeat(24), san: "nginx.wildcard.test" };
  const observation = { fingerprintSha256: expected.fingerprint, storeName: expected.store, subject: null, keyPresent: false, subjectAltNames: [expected.san] };
  assertOwnedObservation(observation, expected);
  for (const replacement of [{ subject: "" }, { keyPresent: true }, { fingerprintSha256: "b".repeat(64) }, { storeName: "My" }, { subjectAltNames: [] }]) assert.throws(() => assertOwnedObservation({ ...observation, ...replacement }, expected));
  assert.throws(() => assertOwnedObservation(undefined, expected));
});
