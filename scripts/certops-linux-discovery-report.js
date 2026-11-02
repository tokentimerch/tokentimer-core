"use strict";
/**
 * Verifies the mandatory OpenSSL discovery parser regression inventory from a JSONL test report.
 * Invoked after the Linux discovery workflow; this supporting parser evidence does not imply
 * that a native Windows certificate store or locale matrix executed.
 */
const fs = require("node:fs");
const { verify } = require("./certops-stack-report");
const required = require("../tests/e2e/linux-discovery-required-tests.json");
try {
  const result = verify(fs.readFileSync(process.argv[2], "utf8"), required, "windows.test.js", "openssl-discovery-parser-regression");
  console.log(JSON.stringify({ ...result, scope: "openssl-discovery-parser-regression" }));
} catch (error) { console.error(error.message); process.exitCode = 1; }
