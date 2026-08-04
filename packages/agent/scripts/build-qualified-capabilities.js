"use strict";

/**
 * Compiles packages/agent/src/capabilities/qualified-capabilities.json (the
 * build INPUT) into packages/agent/src/capabilities/qualified-capabilities.generated.js
 * (the frozen, code-embedded module the agent actually requires at
 * runtime -- see ../src/capabilities/index.js).
 *
 * This is the ADR-0012 decision 14 fix for the manifest being a
 * runtime-readable JSON file: an operator who can edit a file sitting next
 * to the running agent and restart the process could otherwise change what
 * the agent advertises without rebuilding anything, defeating the whole
 * point of the gate. Moving the manifest into the build output removes that
 * lever entirely -- the qualified list is now part of the same artifact a
 * release promotes, not something read from the filesystem the operator
 * controls.
 *
 * Every failure mode below (missing input, invalid JSON, unrecognized
 * capability entry) exits non-zero with a clear message: a bad manifest
 * must fail the BUILD, so it can never reach a shipped artifact in the
 * first place.
 *
 *   node packages/agent/scripts/build-qualified-capabilities.js
 */

const fs = require("node:fs");
const path = require("node:path");

const { GATED_CAPABILITIES } = require("../src/capabilities/gated-capabilities.js");

const GATED_CAPABILITY_SET = new Set(GATED_CAPABILITIES);

const capabilitiesDir = path.resolve(__dirname, "..", "src", "capabilities");
const DEFAULT_INPUT_PATH = path.join(capabilitiesDir, "qualified-capabilities.json");
const DEFAULT_OUTPUT_PATH = path.join(
  capabilitiesDir,
  "qualified-capabilities.generated.js",
);

class QualifiedCapabilitiesBuildError extends Error {}

/**
 * Reads, parses, and validates the qualified-capabilities.json build input.
 * Throws QualifiedCapabilitiesBuildError (never exits directly), so tests
 * can assert on the failure without spawning a subprocess.
 *
 * @param {string} inputPath
 * @returns {string[]} the validated list of qualified capability strings
 */
function readAndValidateManifest(inputPath) {
  let raw;
  try {
    raw = fs.readFileSync(inputPath, "utf8");
  } catch (err) {
    throw new QualifiedCapabilitiesBuildError(
      `qualified-capabilities manifest is missing at ${inputPath}: ${err?.message || err}`,
    );
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new QualifiedCapabilitiesBuildError(
      `qualified-capabilities manifest at ${inputPath} is not valid JSON: ${err?.message || err}`,
    );
  }

  const qualified = Array.isArray(parsed?.qualified) ? parsed.qualified : null;
  if (!qualified) {
    throw new QualifiedCapabilitiesBuildError(
      `qualified-capabilities manifest at ${inputPath} must have a "qualified" array`,
    );
  }

  for (const entry of qualified) {
    if (typeof entry !== "string" || !GATED_CAPABILITY_SET.has(entry)) {
      throw new QualifiedCapabilitiesBuildError(
        `qualified-capabilities manifest at ${inputPath} names unrecognized ` +
          `capability ${JSON.stringify(entry)}; must be one of ${GATED_CAPABILITIES.join(", ")}`,
      );
    }
  }

  return qualified;
}

/**
 * Renders the generated module source for a validated qualified list.
 * @param {string[]} qualified
 * @returns {string}
 */
function renderGeneratedModule(qualified) {
  const header = [
    "/*",
    " * GENERATED FILE - do not edit by hand.",
    " * Compiled from qualified-capabilities.json by",
    " * scripts/build-qualified-capabilities.js (ADR-0012 decision 14).",
    " * Regenerate with: node packages/agent/scripts/build-qualified-capabilities.js",
    " * Editing this file directly (instead of qualified-capabilities.json and",
    " * regenerating) defeats the build-embedded/immutable requirement this",
    " * gate exists to enforce.",
    " */",
    "",
    '"use strict";',
    "",
  ].join("\n");
  const body = `module.exports = Object.freeze({ qualified: Object.freeze(${JSON.stringify(qualified)}) });\n`;
  return `${header}${body}`;
}

/**
 * @param {{ inputPath?: string, outputPath?: string }} [options]
 * @returns {{ inputPath: string, outputPath: string, qualified: string[] }}
 */
function main(options = {}) {
  const inputPath = options.inputPath || DEFAULT_INPUT_PATH;
  const outputPath = options.outputPath || DEFAULT_OUTPUT_PATH;

  const qualified = readAndValidateManifest(inputPath);
  const generated = renderGeneratedModule(qualified);

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, generated);
  process.stdout.write(
    `Wrote ${path.relative(path.resolve(__dirname, ".."), outputPath)} ` +
      `(${qualified.length} qualified capabilit${qualified.length === 1 ? "y" : "ies"})\n`,
  );

  return { inputPath, outputPath, qualified };
}

module.exports = {
  main,
  readAndValidateManifest,
  renderGeneratedModule,
  QualifiedCapabilitiesBuildError,
  DEFAULT_INPUT_PATH,
  DEFAULT_OUTPUT_PATH,
};

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`build-qualified-capabilities: ${error.message}\n`);
    process.exitCode = 1;
  }
}
