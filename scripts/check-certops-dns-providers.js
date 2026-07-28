#!/usr/bin/env node

// DNS-01 provider catalogue drift guard.
//
// The supported provider list is duplicated by necessity across the agent
// runtime (the solver registry), the agent config validator, and the operator
// documentation. The first two already guard each other with a unit test, but
// documentation drifted once before: PR #96 advertised DigitalOcean (never
// implemented) while omitting acme-dns (fully implemented), and the counts
// coincidentally matched so nobody noticed.
//
// The wire contract (agent-protocol.schema.json supportedDnsProviders)
// deliberately stays a free-form string array rather than an enum: pinning an
// enum there would make adding a provider a breaking contract revision and
// would let an older control plane reject a newer agent. Provider validity is
// enforced agent-side at config load, and this check keeps the human-facing
// catalogue honest.

const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..");

const {
  listSupportedDnsProviders,
} = require(path.join(repoRoot, "packages/agent/src/dns/index.js"));

const providers = listSupportedDnsProviders();

function fail(message) {
  console.error(`check-certops-dns-providers: ${message}`);
  process.exit(1);
}

if (!Array.isArray(providers) || providers.length === 0) {
  fail("the agent DNS registry exported no providers");
}

const problems = [];

// --- docs/certops/agent.md: id list + per-provider credentials table ---
const agentDocRel = "docs/certops/agent.md";
const agentDocPath = path.join(repoRoot, agentDocRel);
if (!fs.existsSync(agentDocPath)) {
  fail(`${agentDocRel} is missing`);
}
const agentDoc = fs.readFileSync(agentDocPath, "utf8");

for (const provider of providers) {
  // Every implemented provider must appear as a backticked id somewhere in
  // the operator reference.
  if (!agentDoc.includes(`\`${provider}\``)) {
    problems.push(
      `${agentDocRel} never mentions implemented provider \`${provider}\``,
    );
  }
}

// A provider named in the credentials table but absent from the registry is
// the inverse drift (advertising something that does not exist). Scope the
// scan to that one table: the document has many other two-column tables whose
// first cell is a backticked config key, not a provider id.
const credentialsTable = extractCredentialsTable(agentDoc);
if (credentialsTable === null) {
  problems.push(
    `${agentDocRel} no longer contains the "Credentials file fields" table this guard relies on`,
  );
} else {
  const documentedProviders = new Set();
  const tableRowPattern = /^\|\s*`([a-z0-9-]+)`\s*\|/gm;
  let match;
  while ((match = tableRowPattern.exec(credentialsTable)) !== null) {
    const documented = match[1];
    documentedProviders.add(documented);
    if (!providers.includes(documented)) {
      problems.push(
        `${agentDocRel} documents provider \`${documented}\` which the agent registry does not implement`,
      );
    }
  }
  // Each implemented provider needs a credentials row: that table is what an
  // operator actually follows to configure it.
  for (const provider of providers) {
    if (!documentedProviders.has(provider)) {
      problems.push(
        `${agentDocRel} has no credentials-table row for provider \`${provider}\``,
      );
    }
  }
}

/**
 * Returns the markdown body of the provider credentials table (the rows
 * following the "| Provider | Credentials file fields |" header), or null
 * when that header is gone.
 */
function extractCredentialsTable(source) {
  const lines = source.split("\n");
  const headerIndex = lines.findIndex(
    (line) => /^\|\s*Provider\s*\|/i.test(line) && /Credentials/i.test(line),
  );
  if (headerIndex === -1) return null;

  const rows = [];
  // Skip the header and its |---|---| separator, then take rows until the
  // table ends (first line that is not a table row).
  for (let i = headerIndex + 2; i < lines.length; i += 1) {
    if (!lines[i].trimStart().startsWith("|")) break;
    rows.push(lines[i]);
  }
  return rows.join("\n");
}

// --- CHANGELOG.md provider count ---
const changelogRel = "CHANGELOG.md";
const changelogPath = path.join(repoRoot, changelogRel);
if (fs.existsSync(changelogPath)) {
  const changelog = fs.readFileSync(changelogPath, "utf8");
  const countPattern = /DNS-01 solvers for (\w+) providers/i;
  const countMatch = changelog.match(countPattern);
  if (countMatch) {
    const spelled = numberWord(providers.length);
    const found = countMatch[1].toLowerCase();
    if (found !== spelled && found !== String(providers.length)) {
      problems.push(
        `${changelogRel} claims DNS-01 solvers for "${countMatch[1]}" providers but ${providers.length} are implemented (expected "${spelled}")`,
      );
    }
  }
}

function numberWord(n) {
  const words = [
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
    "twelve",
    "thirteen",
    "fourteen",
    "fifteen",
    "sixteen",
  ];
  return words[n] || String(n);
}

if (problems.length > 0) {
  fail(
    `DNS-01 provider catalogue drift detected:\n${problems
      .map((problem) => `  - ${problem}`)
      .join("\n")}\n` +
      "Update the documentation to match packages/agent/src/dns/index.js (the source of truth).",
  );
}

console.log(
  `check-certops-dns-providers: ok (${providers.length} providers: ${providers.join(", ")})`,
);
