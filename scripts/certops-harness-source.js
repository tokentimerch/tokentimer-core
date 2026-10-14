"use strict";
/**
 * Check qualification scenario registrations without executing privileged harnesses.
 * The shared gate accepts one ID, an executable callback and optional metadata.
 * A malformed registration can parse successfully but fail only after a costly lab
 * boot. The cheap tooling lane parses source with the agent's declared ESLint runtime.
 * --explain-native additionally checks literal native SQL against an explicitly
 * disposable migrated database; SQL validity does not prove a query's semantic meaning.
 */
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");
const { Linter } = createRequire(path.resolve(__dirname, "../packages/agent/package.json"))("eslint");

function validateScenarioCalls(source) {
  const rule = {
    meta: { type: "problem", schema: [] },
    create(context) {
      return {
        CallExpression(node) {
          const callee = node.callee;
          if (callee.type !== "MemberExpression" || callee.computed || callee.object.type !== "Identifier" || callee.object.name !== "gate" || callee.property.name !== "scenario") return;
          const callback = node.arguments[1];
          if (node.arguments.length < 2 || node.arguments.length > 3 || !callback || ["Literal", "ArrayExpression", "ObjectExpression", "TemplateLiteral", "SpreadElement"].includes(callback.type)) {
            context.report({ node, message: "gate.scenario requires one ID, an executable callback and optional metadata" });
          }
        },
      };
    },
  };
  return new Linter().verify(source, [{ languageOptions: { ecmaVersion: "latest", sourceType: "commonjs" }, plugins: { qualification: { rules: { "scenario-call": rule } } }, rules: { "qualification/scenario-call": "error" } }]).filter(message => message.severity === 2).map(message => ({ line: message.line, message: message.message }));
}

function readOnlyQueries(source) {
  const queries = [];
  const rule = {
    meta: { type: "problem", schema: [] },
    create() {
      return { CallExpression(node) {
        if (node.callee.type !== "MemberExpression" || node.callee.property.name !== "query") return;
        const argument = node.arguments[0];
        const sql = argument?.type === "Literal" && typeof argument.value === "string" ? argument.value : argument?.type === "TemplateLiteral" && argument.expressions.length === 0 ? argument.quasis[0].value.cooked : null;
        if (sql && /^\s*SELECT\b/i.test(sql)) queries.push({ sql, line: node.loc.start.line });
      } };
    },
  };
  const messages = new Linter().verify(source, [{ languageOptions: { ecmaVersion: "latest", sourceType: "commonjs" }, plugins: { qualification: { rules: { queries: rule } } }, rules: { "qualification/queries": "error" } }]);
  if (messages.some(message => message.severity === 2)) throw new Error("Cannot parse native harness read-only SQL oracles");
  return queries;
}

/** Parse native Windows and AD CS database oracles against the actual migrated schema.
 * EXPLAIN (without ANALYZE), null parameters and READ ONLY transactions never
 * execute the native harness or modify fixture rows. This catches stale column
 * names before paying for a domain lab. Explicit disposable DB authorization applies.
 */
async function explainNativeQueries(root = path.resolve(__dirname, "..")) {
  if (process.env.CERTOPS_CSR_DISPOSABLE_STACK !== "1") throw new Error("Explicit disposable schema-check stack required");
  const { Pool } = createRequire(path.join(root, "apps/api/package.json"))("pg");
  for (const name of ["DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD"]) if (!process.env[name]) throw new Error("Explicit disposable database configuration required");
  const files = ["tests/e2e/certops-adcs-real-e2e.test.js", "tests/e2e/windows-real-journey.js", "tests/e2e/windows-adoption-retention-journey.js", ...fs.readdirSync(path.join(root, "tests/e2e/helpers")).filter(name => /^certops-(?:adcs|windows)-.*\.js$/.test(name)).map(name => "tests/e2e/helpers/" + name)];
  const queries = files.flatMap(file => readOnlyQueries(fs.readFileSync(path.join(root, file), "utf8")).map(query => ({ ...query, file })));
  if (queries.length < 20) throw new Error("Native Windows/AD CS SQL inventory unexpectedly empty or narrowed");
  const pool = new Pool({ host: process.env.DB_HOST, port: Number(process.env.DB_PORT), database: process.env.DB_NAME, user: process.env.DB_USER, password: process.env.DB_PASSWORD, connectionTimeoutMillis: 5000 });
  const failures = [];
  let client;
  try {
    client = await pool.connect();
    for (const { file, line, sql } of queries) {
      try {
        await client.query("BEGIN READ ONLY");
        await client.query("SET LOCAL statement_timeout = '5s'");
        const count = Math.max(0, ...[...sql.matchAll(/\$([1-9][0-9]*)/g)].map(match => Number(match[1])));
        await client.query("EXPLAIN " + sql, Array(count).fill(null));
      } catch (error) {
        failures.push(`${file}:${line}: native SQL oracle rejected (${String(error.code || "unknown").slice(0, 32)})`);
      } finally { await client.query("ROLLBACK"); }
    }
  } finally { client?.release(); await pool.end(); }
  if (failures.length) throw new Error(failures.join("\n"));
  return queries.length;
}

function validateHarnessSources(root = path.resolve(__dirname, "..")) {
  const errors = [];
  function visit(relative) {
    const absolute = path.join(root, relative);
    for (const entry of fs.readdirSync(absolute, { withFileTypes: true })) {
      const file = path.posix.join(relative, entry.name);
      if (entry.isDirectory()) visit(file);
      else if (entry.isFile() && entry.name.endsWith(".js")) {
        const source = fs.readFileSync(path.join(root, file), "utf8");
        if (!source.includes("gate.scenario")) continue;
        for (const error of validateScenarioCalls(source)) errors.push(`${file}:${error.line}: ${error.message}`);
      }
    }
  }
  for (const relative of ["tests/e2e", "packages/agent/scripts/host"]) visit(relative);
  for (const file of fs.readdirSync(path.join(root, "scripts")).filter(name => name.startsWith("certops-") && name.endsWith(".js"))) {
    const source = fs.readFileSync(path.join(root, "scripts", file), "utf8");
    if (!source.includes("gate.scenario")) continue;
    for (const error of validateScenarioCalls(source)) errors.push(`scripts/${file}:${error.line}: ${error.message}`);
  }
  return errors;
}
if (require.main === module) {
  if (["--explain-native", "--explain-adcs"].includes(process.argv[2])) {
    explainNativeQueries().then(count => console.log(`${count} native Windows/AD CS read-only SQL oracles match the migrated schema`)).catch(error => { console.error(error.message); process.exitCode = 1; });
  } else {
    const errors = validateHarnessSources();
    if (errors.length) { console.error(errors.join("\n")); process.exitCode = 1; }
    else console.log("CertOps harness scenario registrations are structurally valid");
  }
}
module.exports = { validateScenarioCalls, validateHarnessSources, readOnlyQueries, explainNativeQueries };
