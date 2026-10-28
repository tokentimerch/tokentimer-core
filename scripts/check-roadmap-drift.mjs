import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const active = new Set(['pre-v1', 'v1', 'alongside-0.x', 'later']);
const status = (value) => String(value ?? '').toLowerCase().replace(/[\s_-]/g, '');
const slug = (url) => String(url).split('/').filter(Boolean).at(-1);
const days = (date, now) => (now - new Date(date).getTime()) / 86400000;

export function audit(index, roadmap, snapshot, companion, now = Date.now()) {
  if (index.schemaVersion !== 1 || !Array.isArray(index.outcomes) ||
      !index.repository?.match(/^[\w.-]+\/[\w.-]+$/)) throw Error('Invalid outcome index');
  if (!Array.isArray(snapshot.issues) || !Number.isFinite(Date.parse(snapshot.capturedAt))) {
    throw Error('Snapshot requires issues[] and a valid capturedAt');
  }
  const findings = [];
  const add = (code, outcome, detail) => findings.push({ code, outcome, detail });
  const age = (date, label) => {
    if (!Number.isFinite(Date.parse(date)) || days(date, now) < -1) {
      throw Error('Invalid or future timestamp: ' + label);
    }
    if (days(date, now) > 7) add('STALE_EVIDENCE', label, 'Evidence is more than seven days old');
  };
  age(snapshot.capturedAt, 'github');
  age(index.reviewedAt, 'outcome-index');
  const reviewed = roadmap.match(/Last reviewed:\s*(\d{4}-\d{2}-\d{2})/);
  if (!reviewed) add('ROADMAP_REVIEW_MISSING', 'roadmap', 'Last reviewed date is unavailable');
  else age(reviewed[1], 'roadmap');
  const ids = new Set();
  const refs = new Set([...roadmap.matchAll(/github\.com\/tokentimerch\/tokentimer-core\/issues\/(\d+)/g)].map(m => Number(m[1])));
  const known = new Map(snapshot.issues.map(i => [i.number, i]));
  const mapped = new Set();
  if (companion) {
    if (!Number.isFinite(Date.parse(companion.capturedAt))) throw Error('Companion requires capturedAt');
    if (!Array.isArray(companion.planning) || !Array.isArray(companion.feedback)) {
      throw Error('Companion requires planning[] and feedback[]');
    }
    age(companion.capturedAt, 'companion');
  }
  for (const item of index.outcomes) {
    if (!item.id || ids.has(item.id) || !Number.isInteger(item.issue) || item.issue < 1 ||
        !['core'].includes(item.edition) || !(active.has(item.horizon) || item.horizon === 'shipped') ||
        typeof item.inRoadmap !== 'boolean') throw Error('Invalid or duplicate outcome: ' + item.id);
    ids.add(item.id);
    mapped.add(item.issue);
    if (item.inRoadmap && !refs.has(item.issue)) add('ROADMAP_MISSING', item.id, '#' + item.issue + ' has no roadmap link');
    const issue = known.get(item.issue);
    if (!issue || issue.pull_request) {
      add('ISSUE_MISSING', item.id, 'Delivery issue #' + item.issue + ' unavailable');
    } else if (!['open','closed'].includes(issue.state)) {
      throw Error('Unknown GitHub issue state for #' + item.issue);
    } else if (active.has(item.horizon) && issue.state !== 'open') {
      add('CLOSED_ACTIVE', item.id, 'Active outcome issue is closed');
    } else if (item.horizon === 'shipped' && issue.state !== 'closed') {
      add('SHIPPED_OPEN', item.id, 'Released baseline issue remains open');
    }
    if (item.horizon === 'shipped' && !item.release) add('RELEASE_MISSING', item.id, 'Shipped outcome has no release reference');
    if (item.implementationPr) {
      const pr = snapshot.pulls?.find(p => p.number === item.implementationPr);
      if (!pr) add('IMPLEMENTATION_UNVERIFIED', item.id, 'Implementation PR evidence unavailable');
      else if (pr.state === 'closed' && !pr.merged_at) add('IMPLEMENTATION_CLOSED', item.id, 'Implementation PR closed without merging');
    }
    if (!companion) continue;
    const plans = companion.planning.filter(p => p.issue === item.issue);
    if (!plans.length) add('PLANNING_UNVERIFIED', item.id, 'No internal planning evidence supplied');
    for (const plan of plans) {
      const expected = item.planningStatus ?? (item.horizon === 'shipped' ? 'Done' : 'Backlog');
      if (status(plan.status) !== status(expected)) add('PLANNING_STATUS', item.id, 'Expected ' + expected + ', observed ' + plan.status);
    }
    for (const card of item.feedback ?? []) {
      const observed = companion.feedback.find(c => slug(c.url) === card.slug);
      if (!observed) { add('FEEDBACK_UNVERIFIED', item.id, 'Missing card ' + card.slug); continue; }
      if (observed.edition !== item.edition) add('EDITION_MISMATCH', item.id, 'Card edition differs from mapped outcome');
      if (!observed.issues?.includes(item.issue)) add('FEEDBACK_LINK', item.id, 'Card lacks delivery issue link');
      if (status(observed.status) !== status(card.status)) add('FEEDBACK_STATUS', item.id, 'Expected ' + card.status + ', observed ' + observed.status);
    }
  }
  for (const ref of refs) if (!mapped.has(ref)) add('INDEX_MISSING', '#' + ref, 'Roadmap issue is absent from the outcome index');
  return { coverage: companion ? 'mapped-github-planning-feedback' : 'github-only; companion evidence not supplied',
    capturedAt: snapshot.capturedAt, outcomes: index.outcomes.length, findings };
}

function readJson(path) { return JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, '')); }
function github(path) {
  return JSON.parse(execFileSync('gh', ['api', '--method', 'GET', path],
    { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, timeout: 60000 }));
}
function live(index) {
  const issues = [];
  for (let page = 1; ; page++) {
    const batch = github('repos/' + index.repository + '/issues?state=all&per_page=100&page=' + page);
    if (!Array.isArray(batch)) throw Error('Unexpected GitHub issue response');
    issues.push(...batch);
    if (batch.length < 100) break;
  }
  const pulls = [...new Set(index.outcomes.map(o => o.implementationPr).filter(Boolean))]
    .map(n => github('repos/' + index.repository + '/pulls/' + n));
  return { capturedAt: new Date().toISOString(), issues, pulls };
}

export function main(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--json') options.json = true;
    else if (['--snapshot','--companion','--root'].includes(arg)) {
      if (!argv[i + 1] || argv[i + 1].startsWith('--')) throw Error('Missing value: ' + arg);
      options[arg.slice(2)] = argv[++i];
    } else throw Error('Unknown option: ' + arg);
  }
  const root = resolve(options.root ?? fileURLToPath(new URL('..', import.meta.url)));
  const index = readJson(resolve(root, 'docs/roadmap/outcomes.json'));
  const roadmap = readFileSync(resolve(root, 'ROADMAP.md'), 'utf8');
  const snapshot = options.snapshot ? readJson(resolve(options.snapshot)) : live(index);
  const result = audit(index, roadmap, snapshot, options.companion ? readJson(resolve(options.companion)) : undefined);
  if (options.json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log('Coverage: ' + result.coverage);
    console.log('Mapped outcomes: ' + result.outcomes + '; findings: ' + result.findings.length);
    for (const f of result.findings) console.log(f.code + ' | ' + f.outcome + ' | ' + f.detail);
  }
  return result.findings.length ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = main(process.argv.slice(2)); }
  catch (error) { console.error('Roadmap check failed: ' + error.message); process.exitCode = 2; }
}
