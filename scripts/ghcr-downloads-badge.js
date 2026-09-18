#!/usr/bin/env node
// Sums GHCR "Total downloads" across the public TokenTimer Core packages and
// writes a shields.io endpoint JSON. GitHub only renders this figure on the
// package page (the Packages REST API does not expose it), so we scrape the
// same number ghcr-badge does. Counts artifact pulls, not installations: one
// deployment pulls several images (and possibly the Helm chart).
//
// Usage: node scripts/ghcr-downloads-badge.js [--out <file>] [--owner <owner>] [--repo <repo>]

const fs = require('node:fs');
const path = require('node:path');

const PACKAGES = [
  'tokentimer-core-api',
  'tokentimer-core-dashboard',
  'tokentimer-core-worker',
  'tokentimer-core-k8s-controller',
  'charts/tokentimer',
];

const TOTAL_DOWNLOADS_RE = /Total downloads<\/span>\s*<h3 title="(\d+)"/;

function parseArgs(argv) {
  const opts = { owner: 'tokentimerch', repo: 'tokentimer-core', out: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--out') opts.out = argv[++i];
    else if (arg === '--owner') opts.owner = argv[++i];
    else if (arg === '--repo') opts.repo = argv[++i];
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return opts;
}

function parseTotalDownloads(html) {
  const match = TOTAL_DOWNLOADS_RE.exec(html);
  if (!match) return null;
  return Number.parseInt(match[1], 10);
}

async function fetchPackageDownloads(owner, repo, pkg) {
  const url = `https://github.com/${owner}/${repo}/pkgs/container/${encodeURIComponent(pkg)}`;
  const res = await fetch(url, {
    headers: { 'user-agent': 'tokentimer-core-badges (+https://github.com/tokentimerch/tokentimer-core)' },
  });
  if (!res.ok) throw new Error(`${pkg}: HTTP ${res.status}`);
  const count = parseTotalDownloads(await res.text());
  if (count === null) throw new Error(`${pkg}: could not find "Total downloads" in page`);
  return count;
}

function formatCompact(n) {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 100_000 ? 1 : 0).replace(/\.0$/, '')}k`;
  return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`;
}

function buildBadge(total) {
  return {
    schemaVersion: 1,
    label: 'Downloads',
    message: formatCompact(total),
    color: '2496ED',
    namedLogo: 'docker',
    logoColor: 'white',
    cacheSeconds: 3600,
  };
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const counts = await Promise.all(PACKAGES.map((pkg) => fetchPackageDownloads(opts.owner, opts.repo, pkg)));
  const total = counts.reduce((sum, n) => sum + n, 0);

  PACKAGES.forEach((pkg, i) => console.error(`${pkg.padEnd(32)} ${counts[i]}`));
  console.error(`${'total'.padEnd(32)} ${total}`);

  const badge = buildBadge(total);
  const json = `${JSON.stringify(badge, null, 2)}\n`;
  if (opts.out) {
    fs.mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
    fs.writeFileSync(opts.out, json);
  } else {
    process.stdout.write(json);
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err.message || err);
    process.exit(1);
  });
}

module.exports = { PACKAGES, parseTotalDownloads, formatCompact, buildBadge };
