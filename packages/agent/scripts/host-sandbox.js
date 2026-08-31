"use strict";

/**
 * Generate narrowly-scoped host sandbox snippets for the CertOps agent.
 *
 * Used by install-agent.sh at install time so ProtectSystem=strict units get
 * only the operator-selected certificate/deploy write paths, and so reload of
 * nginx/apache/haproxy is granted via polkit (not a blanket /etc write grant
 * and not sudo — NoNewPrivileges=true blocks setuid helpers).
 *
 * CLI:
 *   node host-sandbox.js override --state-dir DIR [--write-path DIR ...]
 *   node host-sandbox.js polkit --user NAME [--reload-service UNIT ...]
 *   node host-sandbox.js validate-path PATH
 *   node host-sandbox.js map-reload-service NAME
 *   node host-sandbox.js trust-store-paths FAMILY
 *   node host-sandbox.js is-trust-store-path PATH
 *   node host-sandbox.js is-trust-store-recursive-acl PATH
 */

/**
 * OS-owned trust-store directories the agent must write for
 * distribute-trust / revoke-trust. These are NOT ordinary --write-path
 * targets: the installer must never chown or chmod them (that would take
 * /etc/ssl/certs away from the rest of the host). --trust-store only adds
 * them to ReadWritePaths and grants a write ACL.
 *
 * Debian: anchors dir plus /etc/ssl/certs (update-ca-certificates writes
 * pem symlinks, hash links, and ca-certificates.crt there).
 * RHEL: source anchors plus extracted bundles (update-ca-trust extract).
 * `extracted` needs a recursive ACL because extract writes into
 * extracted/pem, extracted/openssl, and extracted/java, not only the
 * parent directory.
 */
const TRUST_STORE_WRITE_PATHS = Object.freeze({
  debian: Object.freeze([
    "/usr/local/share/ca-certificates",
    "/etc/ssl/certs",
  ]),
  rhel: Object.freeze([
    "/etc/pki/ca-trust/source/anchors",
    "/etc/pki/ca-trust/extracted",
    "/etc/pki/tls/certs",
  ]),
});

/** Paths whose children, not just the directory itself, must be writable. */
const TRUST_STORE_RECURSIVE_ACL_PATHS = Object.freeze([
  "/etc/pki/ca-trust/extracted",
]);

const ALLOWED_RELOAD_SERVICES = Object.freeze({
  nginx: Object.freeze({ unit: "nginx.service", validateBinaries: ["nginx"] }),
  apache: Object.freeze({
    unit: "apache2.service",
    aliases: ["apache2", "httpd"],
    validateBinaries: ["apachectl", "apache2ctl", "httpd"],
  }),
  apache2: Object.freeze({
    unit: "apache2.service",
    aliases: ["apache", "httpd"],
    validateBinaries: ["apachectl", "apache2ctl", "httpd"],
  }),
  httpd: Object.freeze({
    unit: "httpd.service",
    aliases: ["apache", "apache2"],
    validateBinaries: ["apachectl", "apache2ctl", "httpd"],
  }),
  haproxy: Object.freeze({
    unit: "haproxy.service",
    validateBinaries: ["haproxy"],
  }),
});

function fail(message) {
  const error = new Error(message);
  error.code = "HOST_SANDBOX_INVALID";
  throw error;
}

/**
 * Absolute path validation for systemd ReadWritePaths entries.
 * Rejects relative paths, shell metacharacters, and whitespace.
 * @param {string} value
 * @returns {string}
 */
function validateAbsolutePath(value) {
  if (typeof value !== "string" || value.length === 0) {
    fail("write path must be a non-empty string");
  }
  if (value.trim() !== value) {
    fail(`write path must not include leading/trailing whitespace: ${JSON.stringify(value)}`);
  }
  if (!value.startsWith("/")) {
    fail(`write path must be absolute (start with /): ${JSON.stringify(value)}`);
  }
  if (value.includes("\0") || /[\r\n\t ;|&$`<>"'\\]/.test(value)) {
    fail(`write path contains disallowed characters: ${JSON.stringify(value)}`);
  }
  if (value.includes("//") || value.includes("/./") || value.includes("/../") || value.endsWith("/..")) {
    fail(`write path must be normalized (no //, /./, or /../): ${JSON.stringify(value)}`);
  }
  if (value === "/") {
    fail("refusing to grant ReadWritePaths=/ (too broad)");
  }
  // Refuse whole-tree /etc grants; operators must name concrete leaf dirs.
  if (value === "/etc" || value === "/etc/") {
    fail("refusing ReadWritePaths=/etc; pass concrete cert/deploy directories instead");
  }
  return value.replace(/\/+$/, "") || "/";
}

/**
 * @param {string} family
 * @returns {string[]}
 */
function trustStoreWritePaths(family) {
  if (typeof family !== "string" || family.length === 0) {
    fail("trust-store family must be debian or rhel");
  }
  const key = family.toLowerCase();
  const paths = TRUST_STORE_WRITE_PATHS[key];
  if (!paths) {
    fail(`unknown trust-store family: ${JSON.stringify(family)} (debian or rhel)`);
  }
  return [...paths];
}

/**
 * True when PATH is one of the OS-owned trust-store directories above.
 * Used by install-agent.sh so --write-path of those dirs never chowns them.
 * @param {string} value
 * @returns {boolean}
 */
function isSystemTrustStorePath(value) {
  const normalized = validateAbsolutePath(value);
  for (const family of Object.keys(TRUST_STORE_WRITE_PATHS)) {
    if (TRUST_STORE_WRITE_PATHS[family].includes(normalized)) return true;
  }
  return false;
}

/**
 * True when POSIX ACL/group-write must be applied recursively.
 * RHEL `update-ca-trust extract` writes into extracted/{pem,openssl,java}.
 * @param {string} value
 * @returns {boolean}
 */
function isTrustStoreRecursiveAclPath(value) {
  return TRUST_STORE_RECURSIVE_ACL_PATHS.includes(validateAbsolutePath(value));
}

function uniquePreserveOrder(values) {
  const seen = new Set();
  const out = [];
  for (const value of values) {
    if (seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}

/**
 * @param {{ stateDir: string, writePaths?: string[] }} options
 * @returns {string}
 */
function buildSystemdOverride({ stateDir, writePaths = [] } = {}) {
  const state = validateAbsolutePath(stateDir);
  const paths = uniquePreserveOrder([
    state,
    ...writePaths.map((entry) => validateAbsolutePath(entry)),
  ]);
  const lines = [
    "# Generated by install-agent.sh (host-sandbox.js).",
    "# Narrow ReadWritePaths for ProtectSystem=strict: state dir plus",
    "# operator-selected certificate/deploy directories only.",
    "[Service]",
    `ReadWritePaths=${paths.join(" ")}`,
    "",
  ];
  return lines.join("\n");
}

/**
 * Map an operator-facing reload service name to a concrete systemd unit.
 * @param {string} name
 * @returns {{ key: string, unit: string, validateBinaries: string[] }}
 */
function mapReloadService(name) {
  if (typeof name !== "string" || name.trim() !== name || name.length === 0) {
    fail("reload service name must be a non-empty, unpadded string");
  }
  const key = name.toLowerCase();
  if (!/^[a-z][a-z0-9_-]{0,31}$/.test(key)) {
    fail(`reload service name is invalid: ${JSON.stringify(name)}`);
  }
  const mapped = ALLOWED_RELOAD_SERVICES[key];
  if (!mapped) {
    fail(
      `unsupported --reload-service ${JSON.stringify(name)} ` +
        `(allowed: nginx, apache/apache2/httpd, haproxy)`,
    );
  }
  return {
    key,
    unit: mapped.unit,
    validateBinaries: [...mapped.validateBinaries],
  };
}

/**
 * Build a polkit rule that allows tokentimer-agent to reload only the
 * selected units via D-Bus (compatible with NoNewPrivileges=true).
 *
 * Why polkit instead of sudoers: the base unit sets NoNewPrivileges=true,
 * which blocks setuid helpers such as sudo. systemctl reload talks to PID 1
 * over D-Bus; polkit can authorize that without widening filesystem writes.
 *
 * @param {{ user: string, reloadServices?: string[] }} options
 * @returns {string|null} JS polkit rule, or null when no reload services
 */
function buildPolkitRule({ user, reloadServices = [] } = {}) {
  if (typeof user !== "string" || !/^[a-z_][a-z0-9_-]{0,31}$/.test(user)) {
    fail(`agent user name is invalid: ${JSON.stringify(user)}`);
  }
  const units = uniquePreserveOrder(
    reloadServices.map((name) => mapReloadService(name).unit),
  );
  if (units.length === 0) return null;

  const unitList = units.map((unit) => JSON.stringify(unit)).join(", ");
  return [
    "// Generated by install-agent.sh (host-sandbox.js).",
    "// Allows the CertOps agent user to reload ONLY the listed units.",
    "// Safe because: (1) verbs are limited to reload, (2) units are an",
    "// install-time allowlist, (3) NoNewPrivileges stays enabled.",
    "polkit.addRule(function (action, subject) {",
    `  var allowedUnits = [${unitList}];`,
    `  if (subject.user !== ${JSON.stringify(user)}) {`,
    "    return polkit.Result.NOT_HANDLED;",
    "  }",
    '  if (action.id !== "org.freedesktop.systemd1.manage-units") {',
    "    return polkit.Result.NOT_HANDLED;",
    "  }",
    '  var verb = action.lookup("verb");',
    '  var unit = action.lookup("unit");',
    '  if (verb !== "reload") {',
    "    return polkit.Result.NOT_HANDLED;",
    "  }",
    "  if (allowedUnits.indexOf(unit) === -1) {",
    "    return polkit.Result.NOT_HANDLED;",
    "  }",
    "  return polkit.Result.YES;",
    "});",
    "",
  ].join("\n");
}

function printUsage() {
  process.stdout.write(
    "Usage:\n" +
      "  node host-sandbox.js override --state-dir DIR [--write-path DIR ...]\n" +
      "  node host-sandbox.js polkit --user NAME [--reload-service UNIT ...]\n" +
      "  node host-sandbox.js validate-path PATH\n" +
      "  node host-sandbox.js map-reload-service NAME\n" +
      "  node host-sandbox.js trust-store-paths FAMILY\n" +
      "  node host-sandbox.js is-trust-store-path PATH\n" +
      "  node host-sandbox.js is-trust-store-recursive-acl PATH\n",
  );
}

function parseArgs(argv) {
  const command = argv[0];
  const options = {
    stateDir: "",
    user: "",
    writePaths: [],
    reloadServices: [],
    path: "",
    service: "",
    family: "",
  };
  for (let i = 1; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--state-dir") {
      options.stateDir = argv[++i] || "";
    } else if (arg.startsWith("--state-dir=")) {
      options.stateDir = arg.slice("--state-dir=".length);
    } else if (arg === "--user") {
      options.user = argv[++i] || "";
    } else if (arg.startsWith("--user=")) {
      options.user = arg.slice("--user=".length);
    } else if (arg === "--write-path") {
      options.writePaths.push(argv[++i] || "");
    } else if (arg.startsWith("--write-path=")) {
      options.writePaths.push(arg.slice("--write-path=".length));
    } else if (arg === "--reload-service") {
      options.reloadServices.push(argv[++i] || "");
    } else if (arg.startsWith("--reload-service=")) {
      options.reloadServices.push(arg.slice("--reload-service=".length));
    } else if (command === "validate-path" && !options.path) {
      options.path = arg;
    } else if (command === "map-reload-service" && !options.service) {
      options.service = arg;
    } else if (command === "trust-store-paths" && !options.family) {
      options.family = arg;
    } else if (command === "is-trust-store-path" && !options.path) {
      options.path = arg;
    } else if (command === "is-trust-store-recursive-acl" && !options.path) {
      options.path = arg;
    } else {
      fail(`unknown argument: ${arg}`);
    }
  }
  return { command, options };
}

function main(argv = process.argv.slice(2)) {
  if (argv.length === 0 || argv[0] === "-h" || argv[0] === "--help") {
    printUsage();
    return 0;
  }
  const { command, options } = parseArgs(argv);
  if (command === "override") {
    process.stdout.write(
      buildSystemdOverride({
        stateDir: options.stateDir,
        writePaths: options.writePaths,
      }),
    );
    return 0;
  }
  if (command === "polkit") {
    const rule = buildPolkitRule({
      user: options.user,
      reloadServices: options.reloadServices,
    });
    if (rule) process.stdout.write(rule);
    return 0;
  }
  if (command === "validate-path") {
    process.stdout.write(`${validateAbsolutePath(options.path)}\n`);
    return 0;
  }
  if (command === "map-reload-service") {
    process.stdout.write(`${JSON.stringify(mapReloadService(options.service))}\n`);
    return 0;
  }
  if (command === "trust-store-paths") {
    process.stdout.write(`${trustStoreWritePaths(options.family).join("\n")}\n`);
    return 0;
  }
  if (command === "is-trust-store-path") {
    process.stdout.write(isSystemTrustStorePath(options.path) ? "yes\n" : "no\n");
    return 0;
  }
  if (command === "is-trust-store-recursive-acl") {
    process.stdout.write(isTrustStoreRecursiveAclPath(options.path) ? "yes\n" : "no\n");
    return 0;
  }
  fail(`unknown command: ${command}`);
  return 1;
}

module.exports = {
  ALLOWED_RELOAD_SERVICES,
  TRUST_STORE_WRITE_PATHS,
  TRUST_STORE_RECURSIVE_ACL_PATHS,
  validateAbsolutePath,
  trustStoreWritePaths,
  isSystemTrustStorePath,
  isTrustStoreRecursiveAclPath,
  buildSystemdOverride,
  buildPolkitRule,
  mapReloadService,
  main,
};

if (require.main === module) {
  try {
    process.exitCode = main();
  } catch (error) {
    process.stderr.write(`host-sandbox: ${error.message}\n`);
    process.exitCode = 1;
  }
}
