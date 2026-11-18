"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { FaultBoundary } = require("../../../e2e/helpers/azure-keyvault-live-io.cjs");

const PROVIDER_OBJECT = /^tt-[a-f0-9]{64}$/;
const VAULT_HOST = /^ttkv[a-f0-9]{20}\.vault\.azure\.net$/;
const ENVELOPE_LIMIT = 64 * 1024;
const PHASES = ["interrupt", "resume", "observe"];

function observationPath({ name, objectName, phase }) {
  assert.ok(["issuer", "nginx", "haproxy"].includes(name));
  assert.match(objectName || "", PROVIDER_OBJECT);
  assert.ok(PHASES.includes(phase) && (phase === "observe") === (name !== "issuer"));
  return path.join("/lab", name, "provider-" + objectName + "-" + phase + ".jsonl");
}

function readEvents(observation) {
  const target = observationPath(observation);
  const stat = fs.lstatSync(target, { throwIfNoEntry: false });
  if (!stat) return [];
  assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.size <= ENVELOPE_LIMIT);
  return fs.readFileSync(target, "utf8").trim().split("\n").filter(Boolean).map(line => JSON.parse(line));
}

function install(observation) {
  const { vaultHost, objectName, phase, name } = observation;
  assert.match(vaultHost || "", VAULT_HOST);
  assert.equal(name, path.basename(process.env.TOKENTIMER_AGENT_CONFIG_DIR || ""));
  const file = observationPath(observation);
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL |
    fs.constants.O_NOFOLLOW, 0o600);
  process.once("exit", () => fs.closeSync(fd));
  let total = 0;
  const objectPath = "/secrets/" + objectName;
  const boundary = new FaultBoundary(vaultHost, { objectPath, observe(event) {
    const record = JSON.stringify(event) + "\n";
    total += Buffer.byteLength(record);
    assert.ok(total <= ENVELOPE_LIMIT, "Azure operator observation limit exceeded");
    fs.writeFileSync(fd, record);
  } });
  if (phase === "interrupt") boundary.set("ambiguous-put", objectPath, { blockReads: true });
  return boundary.install();
}

// Loaded with --require for the one owned agent process selected by the lab.
if (process.env.TT_UX_AZURE_PROVIDER_OBSERVATION)
  install(JSON.parse(process.env.TT_UX_AZURE_PROVIDER_OBSERVATION));

module.exports = { observationPath, readEvents };
