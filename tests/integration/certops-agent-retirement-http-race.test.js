"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const { spawn } = require("node:child_process");

describe("HTTP agent retirement race isolation", function () {
  this.timeout(180000);
  it("runs the database and route fixture in a separate process", async () => {
    const fixture = path.join(__dirname, "fixtures", "certops-agent-retirement-http-race.fixture.cjs");
    const mocha = require.resolve("mocha/bin/mocha");
    const result = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [mocha, fixture, "--reporter", "spec"], { env: process.env, stdio: ["ignore", "pipe", "pipe"] });
      let output = "";
      child.stdout.on("data", chunk => { output += chunk; });
      child.stderr.on("data", chunk => { output += chunk; });
      child.on("error", reject);
      child.on("close", (code, signal) => resolve({ code, signal, output }));
    });
    assert.equal(result.signal, null, result.output);
    assert.equal(result.code, 0, result.output);
    assert.match(result.output, /2 passing/);
  });
});
