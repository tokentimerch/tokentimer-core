import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repository = 'tokentimerch/tokentimer-core';
const active = new Set(['pre-v1', 'v1', 'alongside-0.x', 'later']);
const status = value => String(value ?? '').toLowerCase().replace(/[\s_-]/g, '');
const positive = value => Number.isSafeInteger(value) && value > 0;
const implementations = item => [...new Set([item.implementationPr, ...(item.implementationPrs ?? [])].filter(Boolean))];
function issueNumber(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.host !== 'github.com' || url.username || url.password) return undefined;
    const match = url.pathname.match(/^\/tokentimerch\/tokentimer-core\/issues\/(\d+)\/?$/);
    return match ? Number(match[1]) : undefined;
  } catch { return undefined; }
}
function feedbackSlug(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.host !== 'tokentimer.featurebase.app' || url.username || url.password) return undefined;
    return url.pathname.match(/^\/(?:[a-z]{2}\/)?p\/([^/]+)\/?$/)?.[1];
  } catch { return undefined; }
}
function roadmapLinks(roadmap) {
  const refs = new Map();
  let horizon;
  for (const line of roadmap.split(/\r?\n/)) {
    if (/^## /.test(line)) {
      horizon = /^## Before v1\.0\.0\b/.test(line) ? 'pre-v1' :
        /^## Alongside 0\.x\b/.test(line) ? 'alongside-0.x' :
        /^## v1\.0\.0 -- RBAC and role model cleanup$/.test(line) ? 'v1' :
        /^## Later\b/.test(line) ? 'later' : undefined;
    }
    for (const match of line.matchAll(/https:\/\/github\.com\/tokentimerch\/tokentimer-core\/issues\/(\d+)/g)) {
      const number = Number(match[1]);
      if (!refs.has(number)) refs.set(number, new Set());
      if (horizon) refs.get(number).add(horizon);
    }
  }
  return refs;
}
function referencedIssues(body) {
  const refs = new Set();
  for (const match of (body ?? '').matchAll(/\b(?:refs?|closes?|fix(?:es)?|implements?)\s+((?:#\d+[\s,;]*)+)/gi)) {
    for (const number of match[1].matchAll(/#(\d+)/g)) refs.add(Number(number[1]));
  }
  return refs;
}

export function audit(index, roadmap, snapshot, companion, now = Date.now()) {
  if (index.schemaVersion !== 1 || index.repository !== repository || !Array.isArray(index.outcomes)) {
    throw Error('Invalid Core outcome index');
  }
  if (!Array.isArray(snapshot.issues) || !Number.isFinite(Date.parse(snapshot.capturedAt))) {
    throw Error('Snapshot requires issues[] and a valid capturedAt');
  }
  const findings = [];
  const add = (code, outcome, detail) => findings.push({ code, outcome, detail });
  const age = (date, label) => {
    const milliseconds = now - Date.parse(date);
    const tolerance = /^\d{4}-\d{2}-\d{2}$/.test(date ?? '') ? 86400000 : 300000;
    if (!Number.isFinite(milliseconds) || milliseconds < -tolerance) throw Error('Invalid or future timestamp: ' + label);
    if (milliseconds > 7 * 86400000) add('STALE_EVIDENCE', label, 'Evidence is more than seven days old');
  };
  age(snapshot.capturedAt, 'github');
  age(index.reviewedAt, 'outcome-index');
  const reviewed = roadmap.match(/Last reviewed:\s*(\d{4}-\d{2}-\d{2})/);
  if (!reviewed) add('ROADMAP_REVIEW_MISSING', 'roadmap', 'Last reviewed date is unavailable');
  else age(reviewed[1], 'roadmap');
  const refs = roadmapLinks(roadmap);
  const known = new Map();
  for (const issue of snapshot.issues) {
    if (!positive(issue.number) || known.has(issue.number) || !['open', 'closed'].includes(issue.state)) {
      throw Error('Invalid or duplicate GitHub issue state/number');
    }
    known.set(issue.number, issue);
  }
  if (companion) {
    if (!Number.isFinite(Date.parse(companion.capturedAt))) throw Error('Companion requires capturedAt');
    if (!Array.isArray(companion.planning) || !Array.isArray(companion.feedback)) throw Error('Companion requires planning[] and feedback[]');
    age(companion.planningCapturedAt ?? companion.capturedAt, 'planning');
    age(companion.feedbackCapturedAt ?? companion.capturedAt, 'feedback');
  }
  const ids = new Set();
  const mapped = new Set();
  for (const item of index.outcomes) {
    if (!item.id || ids.has(item.id) || !positive(item.issue) || mapped.has(item.issue) ||
        item.edition !== 'core' || !(active.has(item.horizon) || item.horizon === 'shipped') ||
        typeof item.inRoadmap !== 'boolean' ||
        (item.implementationPrs !== undefined && !Array.isArray(item.implementationPrs)) ||
        (item.relatedIssues !== undefined && !Array.isArray(item.relatedIssues))) throw Error('Invalid or duplicate outcome: ' + item.id);
    if (!implementations(item).every(positive) || !(item.relatedIssues ?? []).every(positive)) throw Error('Invalid related issue or PR number');
    ids.add(item.id);
    mapped.add(item.issue);
    const placements = refs.get(item.issue);
    if (item.inRoadmap && !placements) add('ROADMAP_MISSING', item.id, '#' + item.issue + ' has no roadmap link');
    else if (item.inRoadmap && (!placements.has(item.horizon) || [...placements].some(h => h !== item.horizon))) {
      add('ROADMAP_HORIZON', item.id, 'Roadmap section differs from ' + item.horizon);
    } else if (item.horizon === 'shipped' && placements?.size) {
      add('SHIPPED_ROADMAP', item.id, 'Shipped outcome is still in an active roadmap section');
    }
    const issue = known.get(item.issue);
    if (!issue || issue.pull_request) add('ISSUE_MISSING', item.id, 'Delivery issue #' + item.issue + ' unavailable');
    else if (active.has(item.horizon) && issue.state !== 'open') add('CLOSED_ACTIVE', item.id, 'Active outcome issue is closed');
    else if (item.horizon === 'shipped' && issue.state !== 'closed') add('SHIPPED_OPEN', item.id, 'Released baseline issue remains open');
    if (item.horizon === 'shipped') {
      if (!item.release) add('RELEASE_MISSING', item.id, 'Shipped outcome has no release reference');
      else {
        const release = snapshot.releases?.find(r => r.tag_name === item.release);
        if (!release || release.draft !== false || release.prerelease !== false ||
            !Number.isFinite(Date.parse(release.published_at)) || Date.parse(release.published_at) > now) {
          add('RELEASE_UNVERIFIED', item.id, 'A published non-prerelease release was not established');
        }
      }
    }
    for (const number of implementations(item)) {
      const pr = snapshot.pulls?.find(p => p.number === number);
      if (!pr) add('IMPLEMENTATION_UNVERIFIED', item.id, 'PR #' + number + ' evidence unavailable');
      else if (pr.state === 'closed' && !pr.merged_at) add('IMPLEMENTATION_CLOSED', item.id, 'PR #' + number + ' closed without merging');
      else if (!['open', 'closed'].includes(pr.state)) throw Error('Invalid implementation PR state');
    }
    if (!companion) continue;
    const plans = companion.planning.filter(p => p.issue === item.issue);
    if (!plans.length) add('PLANNING_UNVERIFIED', item.id, 'No planning evidence supplied');
    for (const plan of plans) {
      const leaf = plan.deliveryIssue ?? item.issue;
      const allowed = [item.issue, ...(item.relatedIssues ?? [])];
      if (!allowed.includes(leaf) || !plan.links?.some(url => issueNumber(url) === leaf)) {
        add('PLANNING_LINK', item.id, 'Planning evidence lacks an observed canonical delivery link');
      }
      const leafIssue = known.get(leaf);
      if (leaf !== item.issue && (!leafIssue || leafIssue.pull_request)) {
        add('PLANNING_CHILD_UNVERIFIED', item.id, 'Canonical child issue #' + leaf + ' unavailable');
      }
      const expected = leaf === item.issue ?
        (item.planningStatus ?? (item.horizon === 'shipped' ? 'Done' : undefined)) :
        (leafIssue?.state === 'closed' ? 'Done' : undefined);
      if (expected && status(plan.status) !== status(expected)) add('PLANNING_STATUS', item.id, 'Expected ' + expected + ', observed ' + plan.status);
      else if (!expected && !['backlog', 'todo', 'inprogress', 'inreview'].includes(status(plan.status))) {
        add('PLANNING_STATUS', item.id, 'Open scope has incompatible planning status ' + plan.status);
      }
    }
    for (const related of item.relatedIssues ?? []) {
      if (!plans.some(p => (p.deliveryIssue ?? item.issue) === related)) add('PLANNING_CHILD_UNVERIFIED', item.id, 'No planning mapping for related #' + related);
    }
    for (const card of item.feedback ?? []) {
      const observed = companion.feedback.filter(c => feedbackSlug(c.url) === card.slug);
      if (observed.length !== 1) { add('FEEDBACK_UNVERIFIED', item.id, 'Missing or ambiguous canonical card ' + card.slug); continue; }
      const row = observed[0];
      if (!Array.isArray(row.issues) || !row.issues.every(positive)) throw Error('Invalid feedback issue evidence');
      if (row.edition !== item.edition) add('EDITION_MISMATCH', item.id, 'Card edition differs from mapped scope');
      if (!row.issues?.includes(item.issue)) add('FEEDBACK_LINK', item.id, 'Card lacks delivery issue link');
      if (status(row.status) !== status(card.status)) add('FEEDBACK_STATUS', item.id, 'Expected ' + card.status + ', observed ' + row.status);
      for (const pr of card.implementationPrs ?? []) {
        if (!row.implementationPrs?.includes(pr)) add('FEEDBACK_IMPLEMENTATION_LINK', item.id, 'Card lacks active PR #' + pr);
      }
    }
  }
  for (const ref of refs.keys()) if (!mapped.has(ref)) add('INDEX_MISSING', '#' + ref, 'Roadmap issue is absent from the outcome index');
  for (const pr of snapshot.issues.filter(i => i.pull_request && i.state === 'open')) {
    const targets = referencedIssues(pr.body);
    const owners = index.outcomes.filter(o => [o.issue, ...(o.relatedIssues ?? [])].some(n => targets.has(n)));
    for (const item of owners) if (!implementations(item).includes(pr.number)) {
      add('ACTIVE_PR_UNMAPPED', item.id, 'Open PR #' + pr.number + ' explicitly references mapped scope');
    }
  }
  return {
    coverage: companion ? (findings.some(f => /UNVERIFIED|MISSING/.test(f.code)) ? 'partial-mapped-evidence' : 'mapped-status-and-link-evidence') :
      'github-only; companion evidence not supplied',
    verification: 'Mechanical status, links and roadmap placement only; not implementation acceptance, merge readiness or production qualification.',
    capturedAt: snapshot.capturedAt, outcomes: index.outcomes.length, findings
  };
}

function readJson(path) { return JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, '')); }
function github(path) {
  return JSON.parse(execFileSync('gh', ['api', '--method', 'GET', path],
    { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, timeout: 60000 }));
}
function live(index) {
  const issues = [];
  for (let page = 1; ; page++) {
    const batch = github('repos/' + repository + '/issues?state=all&per_page=100&page=' + page);
    if (!Array.isArray(batch)) throw Error('Unexpected GitHub issue response');
    issues.push(...batch);
    if (batch.length < 100) break;
  }
  const pulls = [...new Set(index.outcomes.flatMap(implementations))].map(n => github('repos/' + repository + '/pulls/' + n));
  const releases = [...new Set(index.outcomes.filter(o => o.horizon === 'shipped').map(o => o.release).filter(Boolean))]
    .map(tag => github('repos/' + repository + '/releases/tags/' + encodeURIComponent(tag)));
  return { capturedAt: new Date().toISOString(), issues, pulls, releases };
}

export function main(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--json') options.json = true;
    else if (['--snapshot', '--companion', '--root'].includes(arg)) {
      if (!argv[i + 1] || argv[i + 1].startsWith('--')) throw Error('Missing value: ' + arg);
      options[arg.slice(2)] = argv[++i];
    } else throw Error('Unknown option: ' + arg);
  }
  const root = resolve(options.root ?? fileURLToPath(new URL('..', import.meta.url)));
  const index = readJson(resolve(root, 'docs/roadmap/outcomes.json'));
  if (index.repository !== repository) throw Error('Invalid Core outcome index repository');
  const roadmap = readFileSync(resolve(root, 'ROADMAP.md'), 'utf8');
  const snapshot = options.snapshot ? readJson(resolve(options.snapshot)) : live(index);
  const result = audit(index, roadmap, snapshot, options.companion ? readJson(resolve(options.companion)) : undefined);
  if (options.json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log('Coverage: ' + result.coverage);
    console.log(result.verification);
    console.log('Mapped outcomes: ' + result.outcomes + '; findings: ' + result.findings.length);
    for (const f of result.findings) console.log(f.code + ' | ' + f.outcome + ' | ' + f.detail);
  }
  return result.findings.length ? 1 : 0;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = main(process.argv.slice(2)); }
  catch (error) { console.error('Roadmap check failed: ' + error.message); process.exitCode = 2; }
}
