"use strict";

/**
 * Precompiles the CertOps agent schemas into standalone validator modules
 * with NO runtime dependency on ajv/ajv-formats, so the shipped agent
 * package stays truly self-contained (the installer never runs `npm
 * install`; it only copies packages/agent, excluding node_modules).
 *
 * Two validators are emitted:
 *   - agent-protocol-validator.generated.js  (outgoing message envelopes)
 *   - job-payload-validator.generated.js     (incoming signed job dispatch)
 *
 * ajv and ajv-formats are devDependencies used only here, at build time.
 * Regenerate after any change to the vendored schemas:
 *   node packages/agent/scripts/build-protocol-validator.js
 * (sync-vendor.js calls this automatically after refreshing them.)
 *
 * Three format keywords are used across the schemas: "uuid", "date-time",
 * and "uri". All are registered here as plain RegExp (matching ajv-formats'
 * literals), so ajv's standalone codegen inlines them directly with no
 * external reference. date-time is intentionally the fast/shape-level check
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
const jobPayloadSchemaPath = path.join(
  packageRoot,
  "vendor",
  "contracts",
  "job-payload.schema.json",
);
const jobPayloadOutputPath = path.join(
  packageRoot,
  "vendor",
  "contracts",
  "job-payload-validator.generated.js",
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
// job-payload.schema.json uses "uri" (caEndpoint). Same literal ajv-formats
// uses for "uri" in both fast and full mode.
const URI_FORMAT =
  /^(?:[a-z][a-z0-9+\-.]*:)(?:\/?\/(?:(?:[a-z0-9\-._~!$&'()*+,;=:]|%[0-9a-f]{2})*@)?(?:\[(?:(?:(?:(?:[0-9a-f]{1,4}:){6}|::(?:[0-9a-f]{1,4}:){5}|(?:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){4}|(?:(?:[0-9a-f]{1,4}:){0,1}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){3}|(?:(?:[0-9a-f]{1,4}:){0,2}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){2}|(?:(?:[0-9a-f]{1,4}:){0,3}[0-9a-f]{1,4})?::[0-9a-f]{1,4}:|(?:(?:[0-9a-f]{1,4}:){0,4}[0-9a-f]{1,4})?::)(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2}))|(?:(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4})?::[0-9a-f]{1,4}|(?:(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4})?::)|[Vv][0-9a-f]+\.[a-z0-9\-._~!$&'()*+,;=:]+)\]|(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})|(?:[a-z0-9\-._~!$&'()*+,;=]|%[0-9a-f]{2})*)(?::\d*)?(?:\/(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*|\/(?:(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})+(?:\/(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*)?|(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})+(?:\/(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*)(?:\?(?:[a-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9a-f]{2})*)?(?:#(?:[a-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9a-f]{2})*)?$/i;

function compileStandaloneValidator({ sourceSchemaPath, targetPath, sourceLabel }) {
  if (!fs.existsSync(sourceSchemaPath)) {
    process.stderr.write(
      `build-protocol-validator: missing schema ${sourceSchemaPath}\n`,
    );
    process.exit(1);
  }
  const schema = JSON.parse(fs.readFileSync(sourceSchemaPath, "utf8"));

  const ajv = new Ajv({
    allErrors: true,
    strict: false,
    code: { source: true, esm: false },
  });
  ajv.addFormat("uuid", UUID_FORMAT);
  ajv.addFormat("date-time", DATE_TIME_FORMAT);
  ajv.addFormat("uri", URI_FORMAT);

  const validate = ajv.compile(schema);
  let code = standaloneCode(ajv, validate);

  // ucs2length is only emitted when the schema actually uses
  // minLength/maxLength; rewrite it when present, and reject any *other*
  // bare require so the shipped agent never gains an ajv runtime dependency.
  if (UCS2LENGTH_REQUIRE_RE.test(code)) {
    code = code.replace(UCS2LENGTH_REQUIRE_RE, UCS2LENGTH_RELATIVE_REQUIRE);
  }

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
    ` * vendor/contracts/${sourceLabel}.`,
    " * Regenerate with: node packages/agent/scripts/build-protocol-validator.js",
    " * (also run automatically by scripts/sync-vendor.js)",
    " */",
    "",
  ].join("\n");

  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.writeFileSync(targetPath, `${header}${code}`);
  process.stdout.write(`Wrote ${path.relative(packageRoot, targetPath)}\n`);
}

function main() {
  compileStandaloneValidator({
    sourceSchemaPath: schemaPath,
    targetPath: outputPath,
    sourceLabel: "agent-protocol.schema.json",
  });
  compileStandaloneValidator({
    sourceSchemaPath: jobPayloadSchemaPath,
    targetPath: jobPayloadOutputPath,
    sourceLabel: "job-payload.schema.json",
  });

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
