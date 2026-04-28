"use strict";

/**
 * @param {string} domain
 * @param {{ all?: boolean }} [options]
 */
function buildSubfinderArgs(domain, options = {}) {
  const args = ["-silent", "-oJ", "-timeout", "30", "-d", domain];
  if (options.all) args.push("-all");
  return args;
}

function parseSubfinderLine(line) {
  try {
    const record = JSON.parse(line);
    return record.host || record.input || null;
  } catch (_err) {
    return line;
  }
}

module.exports = { buildSubfinderArgs, parseSubfinderLine };
