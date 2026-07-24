"use strict";

/**
 * Precompiles the agent-protocol schema into a standalone validator module
 * with NO runtime dependency on ajv/ajv-formats, so the shipped agent
 * package stays truly self-contained (the installer never runs `npm
 * install`; it only copies packages/agent, excluding node_modules).
 *
 * ajv and ajv-formats are devDependencies used only here, at build time.
 * Regenerate after any change to packages/contracts/certops/agent-protocol.schema.json:
 *   node packages/agent/scripts/build-protocol-validator.js
 * (sync-vendor.js calls this automatically after refreshing the vendored schema.)
 *
 * Two format keywords are used by the schema: "uuid" and "date-time". Both
 * are registered here as plain RegExp (matching ajv-formats' "fast" mode),
 * so ajv's standalone codegen inlines them directly with no external
 * reference. This is intentionally the fast/shape-level date-time check
 * (no calendar validation, e.g. it accepts day 31 in April), consistent
 * with this module's "shape/enum/type checks only" scope.
 *
 * The only remaining runtime require ajv's codegen emits is the tiny
 * ucs2length helper (used for unicode-aware minLength/maxLength), which we
 * vendor byte-for-byte under vendor/ajv-runtime/ and rewrite the require to
 * point at.
 */

const fs = require("node:fs");
const path = require("node:path");
const Ajv = require("ajv");
const standaloneCode = require("ajv/dist/standalone").default;

const packageRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(packageRoot, "..", "..");

const schemaPath = path.join(
  packageRoot,
  "vendor",
  "contracts",
  "agent-protocol.schema.json",
);
const outputPath = path.join(
  packageRoot,
  "vendor",
  "contracts",
  "agent-protocol-validator.generated.js",
);
const ucs2lengthSourcePath = require.resolve("ajv/dist/runtime/ucs2length.js", {
  paths: [repoRoot],
});
const ucs2lengthVendorDir = path.join(packageRoot, "vendor", "ajv-runtime");
const ucs2lengthVendorPath = path.join(ucs2lengthVendorDir, "ucs2length.js");
const UCS2LENGTH_REQUIRE_RE = /require\(["']ajv\/dist\/runtime\/ucs2length["']\)/g;
const UCS2LENGTH_RELATIVE_REQUIRE = 'require("../ajv-runtime/ucs2length")';

// Same regex literals as ajv-formats "fast" mode (node_modules/ajv-formats/dist/formats.js).
const UUID_FORMAT = /^(?:urn:uuid:)?[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
const DATE_TIME_FORMAT =
  /^\d\d\d\d-[0-1]\d-[0-3]\dt(?:[0-2]\d:[0-5]\d:[0-5]\d|23:59:60)(?:\.\d+)?(?:z|[+-]\d\d(?::?\d\d)?)$/i;

function main() {
  if (!fs.existsSync(schemaPath)) {
    process.stderr.write(`build-protocol-validator: missing schema ${schemaPath}\n`);
    process.exit(1);
  }
  const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));

  const ajv = new Ajv({
    allErrors: true,
    strict: false,
    code: { source: true, esm: false },
  });
  ajv.addFormat("uuid", UUID_FORMAT);
  ajv.addFormat("date-time", DATE_TIME_FORMAT);

  const validate = ajv.compile(schema);
  let code = standaloneCode(ajv, validate);

  if (!UCS2LENGTH_REQUIRE_RE.test(code)) {
    process.stderr.write(
      "build-protocol-validator: expected ucs2length require not found; " +
        "ajv's codegen output shape changed, review this script.\n",
    );
    process.exit(1);
  }
  code = code.replace(UCS2LENGTH_REQUIRE_RE, UCS2LENGTH_RELATIVE_REQUIRE);

  if (/require\(["'](?!\.\.\/ajv-runtime\/ucs2length)/.test(code)) {
    process.stderr.write(
      "build-protocol-validator: generated validator has an unexpected " +
        "require; the shipped agent must not depend on ajv/ajv-formats at " +
        "runtime.\n",
    );
    process.exit(1);
  }

  const header = [
    "/*",
    " * GENERATED FILE - do not edit by hand.",
    " * Standalone (ajv/ajv-formats-free) validator compiled from",
    " * vendor/contracts/agent-protocol.schema.json.",
    " * Regenerate with: node packages/agent/scripts/build-protocol-validator.js",
    " * (also run automatically by scripts/sync-vendor.js)",
    " */",
    "",
  ].join("\n");

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${header}${code}`);
  process.stdout.write(`Wrote ${path.relative(packageRoot, outputPath)}\n`);

  fs.mkdirSync(ucs2lengthVendorDir, { recursive: true });
  const ucs2lengthSourceRaw = fs.readFileSync(ucs2lengthSourcePath, "utf8");
  // Drop the `.code` metadata line: it is a string literal ajv's own codegen
  // uses to reference this file as a runtime import when *this* file is the
  // compile-time source. We only ever require() it directly at runtime, and
  // the literal text "require(...)" inside that string would otherwise trip
  // a naive shipped-sources bare-specifier scan.
  const ucs2lengthSource = ucs2lengthSourceRaw
    .split("\n")
    .filter((line) => !line.includes("ucs2length.code ="))
    .join("\n");
  const ucs2lengthHeader = [
    "/*",
    " * VENDORED COPY for self-contained agent distribution.",
    " * Source: ajv/dist/runtime/ucs2length.js (MIT License, ajv project).",
    " * Used only by the generated protocol validator's minLength/maxLength",
    " * checks. Refresh with: node packages/agent/scripts/build-protocol-validator.js",
    " */",
    "",
  ].join("\n");
  fs.writeFileSync(ucs2lengthVendorPath, `${ucs2lengthHeader}${ucs2lengthSource}`);
  process.stdout.write(`Wrote ${path.relative(packageRoot, ucs2lengthVendorPath)}\n`);
}

main();
